import shutil
import tempfile
import logging
import os
import re
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

from man_spider.lib.util import *
from man_spider.lib.errors import *
from man_spider.lib.finding_log import display_text
from man_spider.lib.localfs import require_guarded_local_output
from man_spider.path_safety import (
    local_directory_descriptor,
    safe_temporary_directory,
)


log = logging.getLogger("manspider.file")
MAX_CHANGED_FILE_RETRIES = 3  # First attempt plus at most three complete re-reads.
MAX_NETWORK_READ_RETRIES = 1  # One additional full read after a proven SMB transport failure.
_SAFE_TEMP_DIRECTORY_FDS = (
    hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
)


# Windows file attribute values from [MS-FSCC] 2.6. The Impacket version used
# by MANSPIDER exposes OFFLINE but not both recall indicators, so keep the
# complete protocol-level mask here instead of silently missing HSM providers
# which intentionally omit FILE_ATTRIBUTE_OFFLINE.
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
RECALL_ATTRIBUTE_NAMES = (
    (FILE_ATTRIBUTE_OFFLINE, "OFFLINE"),
    (FILE_ATTRIBUTE_RECALL_ON_OPEN, "RECALL_ON_OPEN"),
    (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "RECALL_ON_DATA_ACCESS"),
)


def recall_attribute_names(smb_attributes):
    """Return every advertised offline/HSM recall indicator."""

    if smb_attributes is None:
        return ()
    return tuple(name for flag, name in RECALL_ATTRIBUTE_NAMES if int(smb_attributes) & flag)


def safe_loot_component(value) -> str:
    """Keep network names readable while preventing local path traversal."""

    component = str(value).replace("\x00", "_").replace("/", "_").replace("\\", "_")
    if component == ".":
        return "_dot_"
    if component == "..":
        return "_dotdot_"
    return component or "_empty_"


def remote_loot_destination(base_dir, remote_file, *, atomic_replace=False) -> Path:
    base_dir = Path(base_dir).expanduser().resolve()
    target_component = safe_loot_component(remote_file.target.host)
    if remote_file.target.port != 445:
        target_component = f"{target_component}_port-{remote_file.target.port}"
    network_parts = [
        safe_loot_component(part) for part in str(remote_file.name).replace("/", "\\").split("\\") if part
    ]
    destination = base_dir / target_component / safe_loot_component(remote_file.share) / Path(*network_parts)
    # Only the atomic descriptor writer may replace an existing final symlink.
    # Historical path-based consumers retain the stricter full-path check.
    guarded_path = destination.parent if atomic_replace else destination
    if not guarded_path.resolve(strict=False).is_relative_to(base_dir):
        raise FileRetrievalError(f"Unsafe local loot destination for {remote_file}")
    return destination


class _LazyDirectorySpool(tempfile.SpooledTemporaryFile):
    """Prepare a caller-supplied directory only when bytes actually spill."""

    def __init__(self, *, directory, **kwargs):
        self._spool_directory = directory
        self._spool_directory_prepared = False
        super().__init__(dir=directory, **kwargs)

    def rollover(self):
        if self._rolled:
            return
        if not _SAFE_TEMP_DIRECTORY_FDS:
            raise FileRetrievalError("Safe temporary spooling requires no-follow directory descriptors")
        descriptor = None
        temporary_name = None
        descriptor_ready = False
        with local_directory_descriptor(
            self._spool_directory,
            purpose="temporary spool root",
            create=True,
        ) as (root_descriptor, resolved_root):
            self._spool_directory = resolved_root
            file_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            try:
                for _attempt in range(16):
                    temporary_name = f".manspider-spool-{secrets.token_hex(16)}.tmp"
                    try:
                        descriptor = os.open(temporary_name, file_flags, 0o600, dir_fd=root_descriptor)
                    except FileExistsError:
                        continue
                    break
                else:
                    raise FileRetrievalError(
                        f"Unable to reserve a private temporary spool below {self._spool_directory}"
                    )
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise FileRetrievalError("Temporary spool is not a private regular file")
                os.unlink(temporary_name, dir_fd=root_descriptor)
                temporary_name = None
                descriptor_ready = True
            finally:
                if temporary_name is not None:
                    try:
                        os.unlink(temporary_name, dir_fd=root_descriptor)
                    except (FileNotFoundError, OSError):
                        pass
                if descriptor is not None and not descriptor_ready:
                    os.close(descriptor)

        old_file = self._file
        arguments = self._TemporaryFileArgs
        try:
            if "b" in arguments["mode"]:
                new_file = os.fdopen(descriptor, arguments["mode"], arguments["buffering"])
            else:
                new_file = os.fdopen(
                    descriptor,
                    arguments["mode"],
                    arguments["buffering"],
                    encoding=arguments["encoding"],
                    errors=arguments["errors"],
                    newline=arguments["newline"],
                )
        except BaseException:
            os.close(descriptor)
            raise
        self._file = new_file
        del self._TemporaryFileArgs
        position = old_file.tell()
        if hasattr(new_file, "buffer"):
            new_file.buffer.write(old_file.detach().getvalue())
        else:
            new_file.write(old_file.getvalue())
        new_file.seek(position, 0)
        self._rolled = True
        self._spool_directory_prepared = True


class RemoteFile:
    """
        Represents a file on an SMB share
        Passed from a spiderling up to its parent spide
    r"""

    memory_spool_limit = 8 * 1024 * 1024

    def __init__(
        self,
        name,
        share,
        target,
        size=None,
        mtime=None,
        file_id=None,
        tmp_dir=None,
        smb_attributes=None,
        last_write_time=None,
    ):

        self.share = share
        self.target = target
        self.name = name
        self.size = 0 if size is None else size
        self._size_known = size is not None
        self.mtime = mtime
        # SMB exposes LastWriteTime separately from ChangeTime. ChangeTime is
        # retained in ``mtime`` for stable read/resume identity, while user
        # date filters and reporting use the actual last-write timestamp.
        self.last_write_time = mtime if last_write_time is None else last_write_time
        self.file_id = file_id
        self.smb_attributes = smb_attributes
        self.object_id = None
        self.changed = False
        self.retrieved = False
        # Passive observation: retained even after cleanup, and true when a
        # failed retrieval delivered only part of a file. Not an analysis flag.
        self.content_read = False
        self.smb_client = None
        self.scope_values = {
            "share": share,
            "directory": Path(name).parent,
            "filename": Path(name).name,
            "date_match": True,
        }
        self.rule_route = None
        self.unclassified_record = None
        self.skip_content = False
        self._content = None
        self._retrieved_size = None
        self.post_read_identity = None
        self.post_read_verification_finalized = False
        self.post_read_verification_failed = False
        self.precomputed_representations = {}
        self.retrieval_error = None

        self._temporary_root = Path(tmp_dir) if tmp_dir is not None else safe_temporary_directory()
        self._tmp_filename = None
        self._tmp_directory_prepared = False
        self._tmp_filename_owned = False
        self._tmp_filename_exposed = False
        self._tmp_filename_identity = None
        self._temporary_root_identity = None
        self._tmp_materialized = False

    @staticmethod
    def _safe_suffix(name):
        """Return a short inert suffix, never a Windows ADS/device fragment."""

        suffix = Path(str(name).replace("\\", "/")).suffix.lower()
        if not re.fullmatch(r"\.[a-z0-9][a-z0-9._-]{0,30}", suffix):
            return ".bin"
        return suffix

    def _prepare_temporary_root(self):
        with local_directory_descriptor(
            self._temporary_root,
            purpose="temporary materialization",
            create=True,
        ) as (descriptor, root):
            current = os.fstat(descriptor)
            identity = (current.st_dev, current.st_ino)
            if self._temporary_root_identity is not None and identity != self._temporary_root_identity:
                raise FileRetrievalError(f"Temporary materialization root was replaced: {root}")
            self._temporary_root = root
            self._temporary_root_identity = identity
        self._tmp_directory_prepared = True
        return root

    @contextmanager
    def _temporary_root_descriptor(self):
        if not _SAFE_TEMP_DIRECTORY_FDS:
            raise FileRetrievalError(
                "Safe temporary materialization requires no-follow directory descriptors on this platform"
            )
        with local_directory_descriptor(
            self._temporary_root,
            purpose="temporary materialization root",
            create=True,
        ) as (descriptor, root):
            current = os.fstat(descriptor)
            identity = (current.st_dev, current.st_ino)
            if self._temporary_root_identity is not None and identity != self._temporary_root_identity:
                raise FileRetrievalError(f"Temporary materialization root changed while opening: {root}")
            self._temporary_root = root
            self._temporary_root_identity = identity
            self._tmp_directory_prepared = True
            yield descriptor

    def _remember_owned_file(self, path, current):
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            raise FileRetrievalError(f"Temporary materialization is not a private regular file: {path}")
        self._tmp_filename = path
        self._tmp_filename_owned = True
        self._tmp_filename_identity = (current.st_dev, current.st_ino)
        self._tmp_materialized = False
        return path

    def _prepare_tmp_filename(self):
        if self._tmp_filename is None:
            root = self._prepare_temporary_root()
            suffix = self._safe_suffix(self.name)
            with self._temporary_root_descriptor() as root_descriptor:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                for _attempt in range(16):
                    filename = f"manspider-{secrets.token_hex(16)}{suffix}"
                    try:
                        descriptor = os.open(filename, flags, 0o600, dir_fd=root_descriptor)
                    except FileExistsError:
                        continue
                    try:
                        current = os.fstat(descriptor)
                    finally:
                        os.close(descriptor)
                    self._remember_owned_file(root / filename, current)
                    break
                else:
                    raise FileRetrievalError(f"Unable to reserve a private temporary file below {root}")
        return self._tmp_filename

    @property
    def tmp_filename(self):
        """Return a newly reserved private path inside the owned local root.

        Cleanup removes that inode at most once. If a caller later recreates
        the same pathname, it is no longer owned and will be preserved.
        """

        path = self._prepare_tmp_filename()
        self._tmp_filename_exposed = True
        return path

    @tmp_filename.setter
    def tmp_filename(self, value):
        root = self._prepare_temporary_root()
        candidate = Path(value).expanduser().absolute()
        if candidate.parent.resolve(strict=False) != root.resolve(strict=True):
            raise FileRetrievalError(f"Temporary filename must be a new file directly below {root}: {candidate}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            with self._temporary_root_descriptor() as root_descriptor:
                descriptor = os.open(candidate.name, flags, 0o600, dir_fd=root_descriptor)
                try:
                    current = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
        except OSError as exc:
            raise FileRetrievalError(f"Unable to reserve private temporary file {candidate}: {exc}") from exc
        self._remember_owned_file(candidate, current)
        self._tmp_filename_exposed = True

    def _owned_tmp_stat(self):
        path = self._tmp_filename
        if path is None or not self._tmp_filename_owned or self._tmp_filename_identity is None:
            raise FileRetrievalError("Temporary file is not owned by this remote object")
        try:
            with self._temporary_root_descriptor() as root_descriptor:
                current = os.stat(path.name, dir_fd=root_descriptor, follow_symlinks=False)
        except OSError as exc:
            raise FileRetrievalError(f"Unable to verify temporary file {path}: {exc}") from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != self._tmp_filename_identity
        ):
            raise FileRetrievalError(f"Temporary file was replaced or linked: {path}")
        return current

    def _unlink_owned_tmp(self):
        if self._tmp_filename is None or not self._tmp_filename_owned:
            return
        path = self._tmp_filename
        try:
            with self._temporary_root_descriptor() as root_descriptor:
                current = os.stat(path.name, dir_fd=root_descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_nlink != 1
                    or (current.st_dev, current.st_ino) != self._tmp_filename_identity
                ):
                    raise FileRetrievalError(f"Temporary file changed before cleanup: {path}")
                os.unlink(path.name, dir_fd=root_descriptor)
        except FileNotFoundError:
            pass
        finally:
            self._tmp_filename = None
            self._tmp_filename_owned = False
            self._tmp_filename_exposed = False
            self._tmp_filename_identity = None
            self._tmp_materialized = False

    def get(self, smb_client=None):
        """
        Retrieve a complete file into a bounded in-memory spool.

        NOTE: SMBConnection() can't be passed through a multiprocessing queue
              This means that smb_client must be set after the file arrives at Spider()
        """

        if smb_client is None and self.smb_client is None:
            raise FileRetrievalError("Please specify smb_client")
        if smb_client is None:
            smb_client = self.smb_client

        self.cleanup()
        self.retrieval_error = None
        self.post_read_identity = None
        self.post_read_verification_finalized = False
        self.post_read_verification_failed = False
        expected_identity = (self.size if self._size_known else None, self.mtime, self.file_id)
        retained = None
        retained_identity = None
        retained_size = None
        retained_verification_failed = False
        content = None
        attempt = 0
        network_retries = 0
        try:
            while attempt <= MAX_CHANGED_FILE_RETRIES:
                content = _LazyDirectorySpool(
                    max_size=self.memory_spool_limit,
                    mode="w+b",
                    directory=self._temporary_root,
                )
                try:
                    def accept_content(chunk):
                        if chunk:
                            self.content_read = True
                        return content.write(chunk)

                    identity = smb_client.retrieve_file(self.share, self.name, accept_content)
                    # A successful read of an empty file is still a completed
                    # content access even if the callback was never invoked.
                    self.content_read = True
                    received_size = content.tell()
                    verification_failed = False
                    if identity is None:
                        identity, verification_failed = self._fallback_read_identity(smb_client)
                except BaseException as exc:
                    content.close()
                    content = None
                    if is_network_unavailable(exc) and network_retries < MAX_NETWORK_READ_RETRIES:
                        network_retries += 1
                        # Never combine attempts, nor fall back to a snapshot
                        # retained before the connection broke. Reconnection
                        # and its interruptible delay belong to SMBClient.
                        if retained is not None:
                            retained.close()
                            retained = None
                            retained_identity = None
                            retained_size = None
                            retained_verification_failed = False
                        log.warning(
                            f"{display_text(self)}: SMB connection interrupted; restarting full read "
                            f"{display_text(network_retries)}/{display_text(MAX_NETWORK_READ_RETRIES)}"
                        )
                        continue
                    if not isinstance(exc, FileChangedDuringRead):
                        raise
                    self.changed = True
                    if attempt < MAX_CHANGED_FILE_RETRIES:
                        log.warning(f"{display_text(self)}: incomplete/changed read; retry {display_text(attempt + 1)}/{display_text(MAX_CHANGED_FILE_RETRIES)}")
                        attempt += 1
                        continue
                    if retained is None:
                        raise FileRetrievalError(
                            f"File remained incomplete after {MAX_CHANGED_FILE_RETRIES + 1} attempts: {self}"
                        ) from exc
                    log.warning(f"{display_text(self)}: still unstable after {display_text(attempt)} retries; last complete snapshot retained")
                    break

                changed = expected_identity[0] is not None and received_size != expected_identity[0]
                if identity is not None:
                    changed = (
                        changed
                        or received_size != identity[0]
                        or any(
                            (
                                expected_identity[0] is not None and identity[0] != expected_identity[0],
                                expected_identity[1] is not None and identity[1] != expected_identity[1],
                                bool(expected_identity[2] and identity[2] and identity[2] != expected_identity[2]),
                            )
                        )
                    )
                if retained is not None:
                    retained.close()
                retained, retained_identity, retained_size = content, identity, received_size
                content = None
                retained_verification_failed = verification_failed
                if not changed:
                    if verification_failed:
                        self.changed = True
                        log.warning(
                            f"{display_text(self)}: post-read metadata unavailable; complete snapshot retained as unverified"
                        )
                    break
                self.changed = True
                if attempt == MAX_CHANGED_FILE_RETRIES:
                    reason = (
                        "still unstable and post-read metadata unavailable"
                        if verification_failed
                        else "still unstable"
                    )
                    log.warning(f"{display_text(self)}: {display_text(reason)} after {display_text(attempt)} retries; last complete snapshot retained")
                    break
                log.warning(f"{display_text(self)}: changed while reading; retry {display_text(attempt + 1)}/{display_text(MAX_CHANGED_FILE_RETRIES)}")
                # Compare the next snapshot with the latest observation, not
                # stale directory metadata, so a one-off change needs one retry.
                if identity is not None:
                    expected_identity = identity
                else:
                    expected_identity = (received_size, None, None)
                attempt += 1

            self.post_read_identity = retained_identity
            self.post_read_verification_finalized = True
            self.post_read_verification_failed = retained_verification_failed
            self._retrieved_size = retained_size
            retained.seek(0)
            self._content = retained
        except BaseException as e:
            if content is not None:
                content.close()
            if retained is not None:
                retained.close()
            if not isinstance(e, Exception) or isinstance(e, (ReadOnlySMBViolation, DFSReferralBlocked)):
                raise
            smb_client.handle_impacket_error(e, self.share, self.name)
            reason = network_error_reason(e)
            message = f'Error retrieving file "{str(self)}": {reason[:200]}'
            if is_network_unavailable(e):
                error = mark_network_unavailable(FileRetrievalError(f"{NETWORK_UNAVAILABLE_MARKER} {message}"))
            else:
                error = FileRetrievalError(message)
            raise error from e

    def _fallback_read_identity(self, smb_client):
        """Verify legacy transports before parsing, inside the same retry budget.

        Normal SMB2 CLOSE and SMB1 post-query paths do not need a listing.
        Return (identity, unavailable). Failure is resolved before the parser;
        it must not trigger a new unbudgeted verification after parsing.
        """

        list_directory = getattr(smb_client, "ls", None)
        if list_directory is None:
            return None, True
        normalized = str(self.name).replace("/", "\\")
        directory, _, basename = normalized.rpartition("\\")
        try:
            for entry in list_directory(self.share, directory):
                if entry.is_directory() or entry.get_longname().casefold() != basename.casefold():
                    continue
                file_id = None
                for attribute in ("get_file_id", "get_fileid"):
                    getter = getattr(entry, attribute, None)
                    if getter is not None:
                        file_id = str(getter())
                        break
                return (entry.get_filesize(), entry.get_mtime_epoch(), file_id), False
            # A disappeared file is an observed change, not a metadata failure.
            return (None, None, None), False
        except ReadOnlySMBViolation:
            raise
        except Exception as exc:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self)}: post-read listing unavailable: {display_text(exc)}")
            return None, True

    @property
    def retrieved_size(self):
        if self._retrieved_size is not None:
            return self._retrieved_size
        if self._tmp_filename is None:
            return None
        try:
            return self._owned_tmp_stat().st_size
        except (OSError, FileRetrievalError):
            return None

    def content_bytes(self):
        """Return the complete retrieved bytes without changing the spool cursor."""

        if self._content is None:
            self._owned_tmp_stat()
            with self._temporary_root_descriptor() as root_descriptor:
                descriptor = os.open(self._tmp_filename.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_descriptor)
                current = os.fstat(descriptor)
                if (current.st_dev, current.st_ino) != self._tmp_filename_identity or current.st_nlink != 1:
                    os.close(descriptor)
                    raise FileRetrievalError(f"Temporary file changed before reading: {self._tmp_filename}")
                with os.fdopen(descriptor, "rb") as source:
                    return source.read()
        position = self._content.tell()
        try:
            self._content.seek(0)
            return self._content.read()
        finally:
            self._content.seek(position)

    def materialize(self):
        """Create a named file lazily for extractors which require a path."""

        if self._tmp_filename is not None and self._tmp_materialized:
            self._owned_tmp_stat()
            return self.tmp_filename
        externally_requested = self._tmp_filename is not None and self._tmp_filename_exposed
        if self._content is None and not externally_requested:
            raise FileRetrievalError(f"Retrieved content is unavailable for {self}")
        path = self._prepare_tmp_filename()
        if self._content is None:
            # Compatibility for callers which explicitly requested the private
            # path and then populated it themselves.
            self._owned_tmp_stat()
            self._tmp_materialized = True
            return self.tmp_filename
        position = self._content.tell()
        try:
            self._content.seek(0)
            with self._temporary_root_descriptor() as root_descriptor:
                descriptor = os.open(path.name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=root_descriptor)
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != self._tmp_filename_identity or current.st_nlink != 1:
                os.close(descriptor)
                raise FileRetrievalError(f"Temporary file changed before materialization: {path}")
            # Truncate only after the opened inode has been proven to be the
            # private file reserved by this object.
            os.ftruncate(descriptor, 0)
            with os.fdopen(descriptor, "wb") as destination:
                shutil.copyfileobj(self._content, destination)
            self._tmp_materialized = True
        except BaseException:
            self._unlink_owned_tmp()
            raise
        finally:
            self._content.seek(position)
        return self.tmp_filename

    def save_to(self, destination):
        """Reject the historical arbitrary-path writer.

        Production loot uses ``copy_to`` with ``loot_storage_file`` so the
        destination is pinned beneath the validated local loot root. Keeping a
        general move/open("wb") API would allow an accidental UNC or mounted
        network destination and could also move (delete) the temporary source.
        """

        raise FileRetrievalError(
            "RemoteFile.save_to() is disabled; use copy_to() with the guarded local loot writer"
        )

    def copy_to(self, output):
        """Copy complete retrieved bytes into an already safely opened output."""

        output = require_guarded_local_output(output)

        if self._tmp_filename is not None and self._tmp_filename_owned:
            self._owned_tmp_stat()
            with self._temporary_root_descriptor() as root_descriptor:
                descriptor = os.open(
                    self._tmp_filename.name,
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=root_descriptor,
                )
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != self._tmp_filename_identity or current.st_nlink != 1:
                os.close(descriptor)
                raise FileRetrievalError(f"Temporary file changed before copying: {self._tmp_filename}")
            with os.fdopen(descriptor, "rb") as source:
                shutil.copyfileobj(source, output)
        elif self._content is not None:
            position = self._content.tell()
            try:
                self._content.seek(0)
                shutil.copyfileobj(self._content, output)
            finally:
                self._content.seek(position)
        else:
            raise FileRetrievalError(f"Retrieved content is unavailable for {self}")

    def cleanup(self):
        """Release memory/disk spool resources and remove named temporary data."""

        if self._content is not None:
            self._content.close()
            self._content = None
        self._retrieved_size = None
        self.precomputed_representations.clear()
        if self._tmp_filename is not None and self._tmp_filename_owned:
            self._unlink_owned_tmp()

    def __str__(self):

        return f"{self.target}\\{self.share}\\{self.name}"

    @property
    def unc_path(self):
        """Return a complete UNC path suitable for operator warnings."""

        remote_path = str(self.name).replace("/", "\\").lstrip("\\")
        return f"\\\\{self.target.host}\\{self.share}\\{remote_path}"

    @property
    def recall_attributes(self):
        """Return every advertised offline/HSM recall indicator."""

        return recall_attribute_names(self.smb_attributes)
