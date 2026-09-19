"""Local specialist annotations, kept outside the scanner's read-only state.

The sidecar contains identifiers only, never evidence or target paths. Reads
attach a pinned read-only inode; an absent sidecar is represented in memory and
does not create any persistent files. Only an explicit review action writes.
"""

import ctypes
import errno
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
import uuid

from man_spider.path_safety import require_local_file_descriptor, require_local_write_path
from man_spider.state import (
    StateNotFoundError,
    _connect_local_sqlite,
    _state_directory_descriptor,
    _validate_sqlite_sidecars,
)


_APPLICATION_ID = 0x4D535256  # MSRV, independent of ScanState's schema/version.
_VERSION = 1
_TABLE_SQL = (
    "CREATE TABLE reviewed_findings (run_id TEXT NOT NULL, finding_id TEXT NOT NULL, "
    "PRIMARY KEY(run_id, finding_id)) WITHOUT ROWID"
)
_INITIALIZE_LOCK = threading.Lock()


class ReviewError(RuntimeError):
    def __init__(self, message, status=409):
        super().__init__(message)
        self.status = status


def review_path(state_path):
    path = Path(state_path)
    return path.with_name(path.name + ".review")


def review_expression(alias="f"):
    """A bounded primary-key lookup, not a Python set of every reviewed ID."""
    return (
        "EXISTS (SELECT 1 FROM review.reviewed_findings r "
        f"WHERE r.run_id={alias}.run_id AND r.finding_id={alias}.finding_id)"
    )


def review_predicate(status, alias="f"):
    if not status:
        return ""
    return " AND " + ("NOT " if status == "unreviewed" else "") + review_expression(alias)


def _validate_schema(connection, schema="main"):
    # schema is internal, never an HTTP parameter. Exact DDL also excludes
    # triggers, views, virtual tables, extra indexes and alternate constraints.
    rows = connection.execute(f"SELECT type,name,sql FROM {schema}.sqlite_schema LIMIT 3").fetchall()
    if (
        connection.execute(f"PRAGMA {schema}.application_id").fetchone()[0] != _APPLICATION_ID
        or connection.execute(f"PRAGMA {schema}.user_version").fetchone()[0] != _VERSION
        or len(rows) != 1
        or tuple(rows[0]) != ("table", "reviewed_findings", _TABLE_SQL)
    ):
        raise ReviewError("Unsupported review sidecar; no automatic migration is performed")


def attach_reviews(connection, state_path, *, timeout):
    """Attach before query_only/BEGIN, without opening writable scan state."""
    if not _INITIALIZE_LOCK.acquire(timeout=timeout):
        raise ReviewError("Review database is busy", 503)
    try:
        _attach_reviews(connection, state_path)
    finally:
        _INITIALIZE_LOCK.release()


def _attach_reviews(connection, state_path):
    path = require_local_write_path(review_path(state_path), purpose="finding review sidecar")
    with _state_directory_descriptor(
        path.parent, create=False, require_private=True, purpose="finding review directory",
    ) as parent_descriptor:
        _validate_sqlite_sidecars(parent_descriptor, path.name, creating=False)
        try:
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_descriptor)
        except FileNotFoundError:
            # An orphan WAL/journal may contain previously committed marks;
            # never silently reinterpret that damaged store as unreviewed.
            _validate_sqlite_sidecars(parent_descriptor, path.name, creating=True)
            connection.execute("ATTACH DATABASE ':memory:' AS review")
            connection.execute(_TABLE_SQL.replace("CREATE TABLE ", "CREATE TABLE review.", 1))
            return
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise ReviewError("Finding review sidecar must be a private owned regular file")
            require_local_file_descriptor(descriptor, purpose="finding review sidecar")
            connection.execute("ATTACH DATABASE ? AS review", (f"file:/proc/self/fd/{descriptor}?mode=ro",))
            _validate_schema(connection, "review")
        finally:
            os.close(descriptor)


def _open_existing_review(path, timeout, deadline):
    # Read-only validation must precede _connect_local_sqlite's writable
    # permission hardening, including when another process wins creation.
    connection = _connect_local_sqlite(path, read_only=True, timeout=timeout, isolation_level=None)
    try:
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        _validate_schema(connection)
    finally:
        connection.close()
    return _connect_local_sqlite(path, timeout=timeout, isolation_level=None)


def _configure_writer(connection, deadline):
    connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute("PRAGMA cache_size=-512")


def _rename_noreplace(parent_descriptor, source, destination):
    """Publish with one Linux atomic no-clobber rename, never hard links."""
    try:
        rename = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError) as exc:
        raise ReviewError("Atomic local review publication is not supported on this platform") from exc
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent_descriptor, os.fsencode(source), parent_descriptor, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, os.strerror(error), destination)
        if error in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
            raise ReviewError("Filesystem does not support atomic no-clobber review publication")
        raise OSError(error, os.strerror(error), destination)


def _publish_new_review(path, run_id, finding_id, timeout, deadline):
    """Initialize off-catalog; the final pathname only ever names a full DB.

    An ordinary failure removes only the exact private temporary inode we opened.
    A hard crash may leave an ignored .tmp (or its journal), but cannot publish an
    empty/incomplete .review. renameat2 avoids both overwrite and a two-hard-links
    crash window; an unsupported primitive fails closed.
    """
    path = require_local_write_path(path, purpose="finding review sidecar")
    with _state_directory_descriptor(
        path.parent, create=False, require_private=True, purpose="finding review directory",
    ) as parent_descriptor:
        try:
            os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            return False  # Another process published since our first lookup.
        _validate_sqlite_sidecars(parent_descriptor, path.name, creating=True)
        temporary_name = ".manspider-review-init-" + uuid.uuid4().hex + ".tmp"
        _validate_sqlite_sidecars(parent_descriptor, temporary_name, creating=True)
        descriptor = os.open(
            temporary_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=parent_descriptor,
        )
        original = os.fstat(descriptor)
        connection = None
        try:
            require_local_file_descriptor(descriptor, purpose="temporary finding review sidecar")
            connection = sqlite3.connect(
                f"file:/proc/self/fd/{descriptor}?mode=rw", uri=True, timeout=timeout, isolation_level=None,
            )
            _configure_writer(connection, deadline)
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_TABLE_SQL)
            connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={_VERSION}")
            connection.execute(
                "INSERT INTO reviewed_findings(run_id,finding_id) VALUES (?,?)", (run_id, finding_id),
            )
            connection.execute("COMMIT")
            connection.close()
            connection = None
            os.fsync(descriptor)
            # DELETE-mode initialization must have no live SQLite sidecars at
            # publication; inspect names relative to the same pinned directory.
            _validate_sqlite_sidecars(parent_descriptor, temporary_name, creating=True)
            current = os.stat(temporary_name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (current.st_dev, current.st_ino, current.st_nlink) != (original.st_dev, original.st_ino, 1):
                raise ReviewError("Temporary review sidecar changed before publication")
            require_local_file_descriptor(descriptor, purpose="temporary finding review sidecar")
            try:
                os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                _validate_sqlite_sidecars(parent_descriptor, path.name, creating=True)
            try:
                _rename_noreplace(parent_descriptor, temporary_name, path.name)
            except FileExistsError:
                return False
            os.fsync(parent_descriptor)
            return True
        finally:
            try:
                if connection is not None:
                    connection.close()
            finally:
                try:
                    try:
                        current = os.stat(temporary_name, dir_fd=parent_descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        current = None
                    if current is not None and (
                        current.st_dev, current.st_ino, current.st_uid, current.st_nlink,
                    ) == (original.st_dev, original.st_ino, os.geteuid(), 1):
                        os.unlink(temporary_name, dir_fd=parent_descriptor)
                finally:
                    os.close(descriptor)


def set_review(state_path, run_id, finding_id, reviewed, *, timeout):
    """Write only the isolated sidecar after the caller validates the finding."""
    path = review_path(state_path)
    connection = None
    deadline = time.monotonic() + timeout
    try:
        # Bound local thread contention. Cross-process first creation remains
        # safe independently through atomic no-clobber publication below.
        if not _INITIALIZE_LOCK.acquire(timeout=timeout):
            raise ReviewError("Review database is busy", 503)
        try:
            try:
                connection = _open_existing_review(path, timeout, deadline)
            except StateNotFoundError:
                if not reviewed:
                    return
                if _publish_new_review(path, run_id, finding_id, timeout, deadline):
                    return
                connection = _open_existing_review(path, timeout, deadline)
            _configure_writer(connection, deadline)
            # Validate before BEGIN IMMEDIATE so an unrelated database is
            # never treated as one of our writable annotation databases.
            _validate_schema(connection)
            connection.execute("BEGIN IMMEDIATE")
            _validate_schema(connection)
            if reviewed:
                connection.execute(
                    "INSERT OR IGNORE INTO reviewed_findings(run_id,finding_id) VALUES (?,?)", (run_id, finding_id),
                )
            else:
                connection.execute(
                    "DELETE FROM reviewed_findings WHERE run_id=? AND finding_id=?", (run_id, finding_id),
                )
            connection.execute("COMMIT")
        finally:
            _INITIALIZE_LOCK.release()
    finally:
        if connection is not None:
            connection.close()
