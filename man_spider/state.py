import hashlib
import json
import logging
import math
import os
import sqlite3
import stat
import threading
import uuid
from contextlib import contextmanager
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Mapping, Sequence

from man_spider.error_policy import (
    DFS_SCOPE_BLOCKED_MARKER, NETWORK_ACCESS_DENIED_MARKER, NETWORK_UNAVAILABLE_MARKER,
    is_network_access_denied,
)
from man_spider.evidence_storage import configure_evidence_reader, context_join, finding_projection
from man_spider.formats import CONTENT_FORMAT_RESOLUTION
from man_spider.filters import normalize_directory_filter
from man_spider.path_safety import (
    UnsafeWritePath,
    local_directory_descriptor,
    require_local_file_descriptor,
    require_local_path,
    require_local_write_path,
)
from man_spider.rules import build_rule_representation_plan

if os.name == "posix":
    import fcntl
elif os.name == "nt":
    import msvcrt

if TYPE_CHECKING:
    from man_spider.lib.util import Target


SCHEMA_VERSION = 9
RUN_STATUSES = {
    "running",
    "complete",
    "complete_with_errors",
    "interrupted",
    "preflight_failed",
}
OBJECT_TERMINAL_STATUSES = {"processed", "skipped", "error"}
OBJECT_STATUSES = OBJECT_TERMINAL_STATUSES | {"pending", "in_progress"}
ANALYSIS_STATUSES = frozenset({"unknown", "not_analyzed", "partial", "analyzed"})
# A blocked descendant has not consumed a new attempt of its own. Keep this
# durable reason marker distinct from ordinary retrieval/inspection errors.
ANCESTOR_BLOCKED_REASON_PREFIX = "Blocked by ancestor "
# Keep failed files terminal until actually claimed. A file removed while the
# network was down must not become unexplained pending work on resume.
NETWORK_RESUME_READY_PREFIX = f"{NETWORK_UNAVAILABLE_MARKER} [resume-ready] "
_REMOTE_NETWORK_OBJECT_PREDICATE = """
    ((kind='file' AND substr(object_key, 1, 4)='smb|')
     OR (kind='directory' AND substr(object_key, 1, 14)='directory|smb|')
     OR (kind='share' AND substr(object_key, 1, 10)='share|smb|')
     OR (kind='target' AND substr(object_key, 1, 11)='target|smb|')
     OR (kind='share_enumeration' AND substr(object_key, 1, 29)='share-enumeration|target|smb|'))
"""
_LEGACY_SIZE_SKIP_PREDICATE = """
    run_id=? AND kind='file' AND status='skipped' AND size >= 0
    AND reason = ('size ' || size || ' exceeds active retrieval policy')
"""

# Keep the durable manifest representation compact. The public JSONL report
# expands these stable bits back into the original ordered reason strings.
UNCLASSIFIED_REASON_BITS = {
    "extensionless": 1 << 0,
    "unrecognized_extension": 1 << 1,
    "no_active_rule_match": 1 << 2,
    "not_selected_by_active_filters": 1 << 3,
    "content_not_analyzed_size_policy": 1 << 4,
    "content_not_analyzed_format_policy": 1 << 5,
}
UNCLASSIFIED_KNOWN_REASON_MASK = sum(UNCLASSIFIED_REASON_BITS.values())

def _network_access_error_is_non_status_affecting(*, kind, share, reason) -> bool:
    """Keep expected SMB authorization gaps visible without degrading the run."""

    is_remote_resource = share is not None or kind == "share_enumeration"
    return is_remote_resource and is_network_access_denied(reason)


def _network_resume_ready(row) -> bool:
    prefixes = {
        "file": "smb|", "directory": "directory|smb|", "share": "share|smb|",
        "target": "target|smb|", "share_enumeration": "share-enumeration|target|smb|",
    }
    prefix = prefixes.get(row["kind"])
    return bool(
        prefix and row["object_key"].startswith(prefix)
        and (row["reason"] or "").startswith(NETWORK_RESUME_READY_PREFIX)
    )


class StateError(RuntimeError):
    pass


class StateExistsError(StateError):
    pass


class ResumeMismatchError(StateError):
    pass


class StateNotFoundError(StateError):
    pass


@contextmanager
def _state_directory_descriptor(
    directory: str | Path,
    *,
    create: bool,
    require_private: bool,
    purpose: str,
):
    """Open a local directory component-by-component without following links.

    SQLite creates predictable ``-wal`` and ``-shm`` siblings itself.  A
    descriptor-safe main database is therefore insufficient when another UID
    can plant or replace those names.  Writable state directories must be
    owned by this process' effective UID and not writable by group/other.
    """

    try:
        with local_directory_descriptor(
            directory,
            purpose=purpose,
            create=create,
            created_mode=0o700,
        ) as (descriptor, resolved):
            info = os.fstat(descriptor)
            if require_private:
                effective_uid = os.geteuid()
                if info.st_uid != effective_uid:
                    raise StateError(
                        f"Unsafe {purpose}: directory must be owned by effective UID {effective_uid}: {resolved}"
                    )
                if stat.S_IMODE(info.st_mode) & 0o022:
                    raise StateError(
                        f"Unsafe {purpose}: directory must not be writable by group or other users: {resolved}"
                    )
            yield descriptor
    except UnsafeWritePath as exc:
        raise StateError(str(exc)) from exc


def _chmod_local_entry(path: Path, mode: int, *, directory: bool, purpose: str) -> None:
    """Change permissions through verified descriptor-relative traversal."""

    path = require_local_write_path(path, purpose=purpose)
    if directory:
        with _state_directory_descriptor(
            path,
            create=False,
            require_private=False,
            purpose=purpose,
        ) as descriptor:
            os.fchmod(descriptor, mode)
        return

    with _state_directory_descriptor(
        path.parent,
        create=False,
        require_private=False,
        purpose=f"{purpose} parent",
    ) as parent_descriptor:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise StateError(f"{purpose} is not a private regular file: {path}")
            require_local_file_descriptor(descriptor, purpose=purpose)
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)


def _validate_sqlite_sidecars(parent_descriptor: int, filename: str, *, creating: bool) -> None:
    """Reject links or foreign inodes SQLite could open as state sidecars."""

    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = f"{filename}{suffix}"
        try:
            info = os.stat(sidecar, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if creating:
            raise StateError(f"Unexpected SQLite sidecar already exists for new state: {sidecar}")
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise StateError(f"Unsafe SQLite sidecar is not a private owned regular file: {sidecar}")


def _connect_local_sqlite(
    path: str | Path,
    *,
    create: bool = False,
    read_only: bool = False,
    **connect_options,
) -> sqlite3.Connection:
    """Connect SQLite to a pinned local inode inside a private directory."""

    if create and read_only:
        raise ValueError("A new SQLite state cannot be opened read-only")
    try:
        path = require_local_write_path(path, purpose="SQLite state")
    except UnsafeWritePath as exc:
        raise StateError(str(exc)) from exc

    with _state_directory_descriptor(
        path.parent,
        create=create,
        require_private=True,
        purpose="SQLite state directory",
    ) as parent_descriptor:
        _validate_sqlite_sidecars(parent_descriptor, path.name, creating=create)
        flags = (os.O_RDONLY if read_only else os.O_RDWR) | os.O_NOFOLLOW
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        try:
            descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
        except FileExistsError as exc:
            raise StateExistsError(f"State database already exists: {path}; use --resume to continue it") from exc
        except FileNotFoundError as exc:
            raise StateNotFoundError(f"State database not found: {path}") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise StateError(f"SQLite state must be a private regular file: {path}")
            try:
                require_local_file_descriptor(descriptor, purpose="SQLite state")
            except UnsafeWritePath as exc:
                raise StateError(str(exc)) from exc
            if info.st_uid != os.geteuid():
                raise StateError(f"SQLite state must be owned by effective UID {os.geteuid()}: {path}")
            if not read_only:
                os.fchmod(descriptor, 0o600)

            # SQLite cannot accept an existing file descriptor directly.  On
            # Linux, /proc/self/fd pins the already verified inode; SQLite
            # canonicalizes it to the local backing path for WAL/SHM names.
            descriptor_path = f"/proc/self/fd/{descriptor}"
            if read_only:
                source = f"file:{descriptor_path}?mode=ro"
                connect_options["uri"] = True
            else:
                source = descriptor_path
            return sqlite3.connect(source, **connect_options)
        finally:
            os.close(descriptor)


class ScanLease:
    """Hold an advisory process lock preventing concurrent writers to one scan."""

    def __init__(self, state_path: str | Path, lock_path: Path, handle):
        self.state_path = Path(state_path)
        self.lock_path = lock_path
        self.handle = handle

    @classmethod
    def acquire(cls, state_path: str | Path) -> "ScanLease":
        try:
            state_path = require_local_write_path(state_path, purpose="SQLite state lease")
        except UnsafeWritePath as exc:
            raise StateError(str(exc)) from exc
        lock_path = state_path.with_name(f"{state_path.name}.lock")
        try:
            lock_path = require_local_write_path(lock_path, purpose="SQLite state lease lock")
        except UnsafeWritePath as exc:
            raise StateError(str(exc)) from exc
        handle = None
        try:
            with _state_directory_descriptor(
                lock_path.parent,
                create=True,
                require_private=True,
                purpose="scan-state lease directory",
            ) as parent_descriptor:
                flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
                descriptor = os.open(lock_path.name, flags, 0o600, dir_fd=parent_descriptor)
            handle = os.fdopen(descriptor, "a+b")
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise OSError("scan-state lease must be a private regular file")
            require_local_file_descriptor(handle.fileno(), purpose="scan-state lease")
            os.fchmod(handle.fileno(), 0o600)
        except (OSError, StateError) as exc:
            if handle is not None:
                handle.close()
            raise StateError(f"Unable to prepare scan-state lease {lock_path}: {exc}") from exc

        try:
            if os.name == "posix":
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == "nt":
                if lock_path.stat().st_size == 0:
                    handle.write(b"\0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                raise OSError(f"unsupported platform {os.name!r}")
        except OSError as exc:
            handle.close()
            raise StateError(
                f"Scan state is already in use or cannot be locked: {state_path} ({type(exc).__name__}: {exc})"
            ) from exc
        return cls(state_path, lock_path, handle)

    def release(self) -> None:
        if self.handle is None:
            return
        handle = self.handle
        self.handle = None
        try:
            if os.name == "posix":
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            elif os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            handle.close()

    def __enter__(self) -> "ScanLease":
        return self

    def __exit__(self, _exception_type, _exception_value, _traceback) -> None:
        self.release()

    @classmethod
    def available(cls, state_path: str | Path) -> bool:
        """Report whether a state can be selected without racing an active scan."""

        try:
            lease = cls.acquire(state_path)
        except StateError:
            return False
        lease.release()
        return True


@dataclass(frozen=True)
class FindingRecord:
    rule_id: str
    value: str
    start: int | None = None
    end: int | None = None
    context: str | None = None
    representation: str = "unknown"
    rule_source: str = "unknown"
    rule_schema_version: int | None = None
    rule_pack_id: str | None = None
    rule_pack_version: str | None = None
    severity: str = "medium"
    confidence: str = "medium"
    category: str = "uncategorized"
    tags: tuple[str, ...] = ()
    # Display-only position inside context; persisted evidence/schema unchanged.
    context_offset: int | None = None


@dataclass(frozen=True)
class ObjectDecision:
    object_id: int
    should_process: bool
    changed: bool
    prior_status: str | None


@dataclass(frozen=True)
class ResumableScan:
    path: Path
    run_id: str
    status: str
    created_at: str
    updated_at: str
    targets: tuple[str, ...]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _encode_unclassified_reasons(reasons: Iterable[object]) -> tuple[tuple[str, ...], int]:
    normalized = tuple(dict.fromkeys(str(reason) for reason in reasons if str(reason)))
    if not normalized:
        raise StateError("Unclassified-file observations require at least one reason")
    unknown = tuple(reason for reason in normalized if reason not in UNCLASSIFIED_REASON_BITS)
    if unknown:
        raise StateError(f"Unknown unclassified-file reason(s): {', '.join(unknown)}")
    return normalized, sum(UNCLASSIFIED_REASON_BITS[reason] for reason in normalized)


def _decode_unclassified_reasons(mask: int) -> tuple[str, ...]:
    value = int(mask)
    unknown_bits = value & ~UNCLASSIFIED_KNOWN_REASON_MASK
    if value <= 0 or unknown_bits:
        raise StateError(f"Invalid unclassified-file reason mask: {value}")
    return tuple(reason for reason, bit in UNCLASSIFIED_REASON_BITS.items() if value & bit)


def _json_value(value):
    if value.__class__.__name__ == "Target" and hasattr(value, "host") and hasattr(value, "port"):
        return {"kind": "smb", "host": value.host, "port": value.port}
    if isinstance(value, Path):
        return {"kind": "local", "path": str(value.resolve())}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def normalized_scan_configuration(options) -> dict:
    """Return complete persisted config plus resume-sensitive semantics."""

    targets = [_json_value(target) for target in options.targets]
    semantic = {
        "scope": {
            "targets": targets,
            "shares": list(options.sharenames),
            "excluded_shares": list(options.exclude_sharenames),
            "directories": [normalize_directory_filter(value) for value in options.dirnames],
            "excluded_directories": [normalize_directory_filter(value) for value in options.exclude_dirnames],
        },
        "filters": {
            "filenames": list(options.filenames),
            "extensions": list(options.extensions),
            "excluded_extensions": list(options.exclude_extensions),
            "content": list(options.content),
            "rules": list(getattr(options, "rules", ())),
            "modified_after": _json_value(options.modified_after),
            "modified_before": _json_value(options.modified_before),
            "logic": "OR" if options.or_logic else "AND",
        },
        "policy": {
            "content_format_resolution": CONTENT_FORMAT_RESOLUTION,
            "maxdepth": options.maxdepth,
            "max_filesize": options.max_filesize,
            "download_matches": not options.no_download,
            "allow_external_dfs": bool(getattr(options, "allow_external_dfs", False)),
            "object_retries": getattr(options, "object_retries", 1),
            "large_domain_mode": getattr(options, "large_domain_mode", "auto"),
            "large_domain_target_threshold": getattr(options, "large_domain_target_threshold", 256),
            "large_domain_share_threshold": getattr(options, "large_domain_share_threshold", 1024),
            "effective_large_domain": getattr(options, "large_domain", None),
            "scope_estimate": _json_value(getattr(options, "scope_estimate", None)),
            "non_text_policy": getattr(options, "non_text_policy", "auto"),
            "read_formats": list(getattr(options, "read_formats", ())),
            "skip_formats": list(getattr(options, "skip_formats", ())),
            "blocked_content_extensions": _json_value(getattr(options, "blocked_content_extensions", None)),
        },
    }
    authentication = {
        "username": options.username,
        "password": options.password,
        "domain": options.domain,
        "hash": options.hash,
        "kerberos": options.kerberos,
        "krb5_ccache": getattr(options, "krb5_ccache", None),
        "aes_key": options.aes_key,
        "dc_ip": options.dc_ip,
        "max_failed_logons": options.max_failed_logons,
    }
    execution = {
        "threads": options.threads,
        "max_sessions_per_host": getattr(options, "max_sessions_per_host", 4),
        "quiet": options.quiet,
        "verbose": options.verbose,
        "explicit_scan_approval": bool(getattr(options, "yes", False)),
        "loot_dir": options.loot_dir,
        "rule_files": list(getattr(options, "rule_files", ())),
        "rule_override_files": list(getattr(options, "rule_override_files", ())),
        "rule_representation_plan": build_rule_representation_plan(getattr(options, "rules", ())),
        "rule_controls": {
            "builtin": bool(getattr(options, "builtin_rules", False)),
            "disabled": list(getattr(options, "disable_rules", ())),
        },
        "json_path": getattr(options, "json_path", None),
        "resume_strategy": getattr(options, "resume_strategy", "continue"),
        "preflight_timeout": getattr(options, "preflight_timeout", 10),
        "preflight_time_budget": getattr(options, "preflight_time_budget", 300),
        "passive_smb_metrics": not bool(getattr(options, "no_smb_metrics", False)),
        "smb_metrics_path": getattr(options, "smb_metrics_path", None),
        "dynamic_eta": not bool(getattr(options, "no_eta", False)),
        "unclassified_file_report": not bool(getattr(options, "no_unclassified_report", False)),
        "unclassified_report_path": getattr(options, "unclassified_report_path", None),
    }
    return {"semantic": semantic, "authentication": authentication, "execution": execution}


def configuration_fingerprint(configuration: Mapping) -> str:
    semantic = configuration.get("semantic", configuration)
    payload = json.dumps(_json_value(semantic), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _resume_semantic_fingerprint(configuration: Mapping) -> str:
    """Ignore only target order without changing durable or execution order.

    Target expansion can have a different set iteration order in a new Python
    process.  Sort a JSON-normalized copy, retaining duplicate targets and all
    other ordered arrays.  Keep the ordinary fingerprint format unchanged for
    existing states and use this comparison only as a compatibility fallback.
    """

    semantic = _json_value(configuration.get("semantic", configuration))
    if isinstance(semantic, dict):
        scope = semantic.get("scope")
        if isinstance(scope, dict) and isinstance(scope.get("targets"), list):
            scope["targets"].sort(
                key=lambda target: json.dumps(target, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            )
    return configuration_fingerprint({"semantic": semantic})


def _validate_saved_filter_semantics(configuration: Mapping) -> None:
    """Reject only saved policies known to have the pre-fix filtering meaning.

    New CLI configurations store canonical directory filters and include every
    explicit content block. These recorded values suffice to identify affected
    old runs without a schema change or invalidating unrelated legacy states.
    Never rewrite their manifest or silently reuse files with changed semantics.
    """

    semantic = configuration.get("semantic", configuration)
    if not isinstance(semantic, Mapping):
        return
    scope = semantic.get("scope", {})
    if isinstance(scope, Mapping):
        for field in ("directories", "excluded_directories"):
            if any(isinstance(value, str) and "/" in value for value in scope.get(field, ())):
                raise ResumeMismatchError(
                    "Resume configuration uses legacy scope, filters, rules, or policy semantics: "
                    "directory filters containing '/' previously did not match normalized paths; "
                    "start a new scan to apply corrected directory filters"
                )
    policy = semantic.get("policy", {})
    if not isinstance(policy, Mapping):
        return
    blocked = policy.get("blocked_content_extensions")
    if isinstance(blocked, list) and any(value not in blocked for value in policy.get("skip_formats", ())):
        raise ResumeMismatchError(
            "Resume configuration uses legacy scope, filters, rules, or policy semantics: "
            "the saved content policy does not enforce every explicit --skip-formats restriction; "
            "start a new scan to apply corrected content exclusions"
        )


def default_state_directory(environ: Mapping[str, str] | None = None) -> Path:
    """Return the platform-appropriate private application state directory."""

    environ = os.environ if environ is None else environ
    configured = str(environ.get("MANSPIDER_STATE_DIR", "")).strip()
    if configured:
        return Path(configured).expanduser()

    xdg_state_home = str(environ.get("XDG_STATE_HOME", "")).strip()
    if xdg_state_home:
        return Path(xdg_state_home).expanduser() / "manspider" / "scans"

    if os.name == "nt":
        local_app_data = str(environ.get("LOCALAPPDATA", "")).strip()
        if local_app_data:
            return Path(local_app_data).expanduser() / "MANSPIDER" / "scans"

    home = Path(str(environ.get("HOME", "")).strip()).expanduser() if environ.get("HOME") else Path.home()
    return home / ".local" / "state" / "manspider" / "scans"


def resume_search_directories(environ: Mapping[str, str] | None = None) -> tuple[Path, ...]:
    """Search the current state directory and the former default location."""

    environ = os.environ if environ is None else environ
    home = Path(str(environ.get("HOME", "")).strip()).expanduser() if environ.get("HOME") else Path.home()
    directories = (default_state_directory(environ), home / ".manspider" / "state")
    return tuple(dict.fromkeys(directory.resolve(strict=False) for directory in directories))


def default_state_path(state_directory: str | Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(state_directory) / f"manspider_{timestamp}_{uuid.uuid4().hex[:8]}.sqlite3"


def _target_display(value) -> str:
    if not isinstance(value, Mapping):
        return str(value)
    if value.get("kind") == "smb":
        host = str(value.get("host", "<unknown>"))
        port = value.get("port", 445)
        return host if port == 445 else f"{host}:{port}"
    if value.get("kind") == "local":
        return str(value.get("path", "<unknown>"))
    return str(value)


def discover_resumable_scans(directories: Sequence[str | Path]) -> list[ResumableScan]:
    """Find unlocked interrupted/crashed scans and recorded network failures."""

    candidates = []
    seen = set()
    for directory_value in directories:
        directory = Path(directory_value).expanduser()
        if not directory.is_dir():
            continue
        try:
            directory = require_local_path(directory, purpose="resume discovery directory")
        except UnsafeWritePath:
            continue
        for path in directory.glob("*.sqlite3"):
            try:
                resolved = require_local_path(path, purpose="resume state candidate").resolve(strict=True)
            except (OSError, UnsafeWritePath):
                continue
            if resolved in seen or not path.is_file():
                continue
            seen.add(resolved)
            connection = None
            try:
                connection = _connect_local_sqlite(resolved, read_only=True, timeout=1)
                connection.execute("PRAGMA temp_store=MEMORY")
                connection.row_factory = sqlite3.Row
                row = connection.execute(
                    "SELECT run_id, status, config_json, created_at, updated_at "
                    "FROM runs ORDER BY created_at DESC LIMIT 1"
                ).fetchone()
                if row is None or row["status"] not in {
                    "interrupted", "running", "complete_with_errors", "preflight_failed",
                }:
                    continue
                if row["status"] in {"complete_with_errors", "preflight_failed"}:
                    network_failure = connection.execute(
                        f"""SELECT 1 FROM objects WHERE run_id=? AND status='error'
                        AND substr(reason, 1, ?)=? AND {_REMOTE_NETWORK_OBJECT_PREDICATE} LIMIT 1""",
                        (row["run_id"], len(NETWORK_UNAVAILABLE_MARKER) + 1, NETWORK_UNAVAILABLE_MARKER + " "),
                    ).fetchone()
                    if network_failure is None:
                        continue
                configuration = json.loads(row["config_json"])
                scope = configuration.get("semantic", configuration).get("scope", {})
                targets = tuple(_target_display(target) for target in scope.get("targets", ()))
                candidate = ResumableScan(
                    path=resolved,
                    run_id=row["run_id"],
                    status=row["status"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    targets=targets,
                )
            except (AttributeError, OSError, sqlite3.Error, json.JSONDecodeError, TypeError, ValueError):
                continue
            finally:
                if connection is not None:
                    connection.close()
            if ScanLease.available(resolved):
                candidates.append(candidate)

    return sorted(candidates, key=lambda candidate: (candidate.created_at, str(candidate.path)), reverse=True)


def local_object_key(path: str | Path) -> str:
    """Build a stable identity for a local file without reading its contents."""

    return f"local|{Path(path).resolve()}"


def smb_object_key(target: "Target", share: str, path: str) -> str:
    """Build a case-insensitive identity for one SMB network location."""

    normalized_path = str(path).replace("/", "\\").strip("\\").casefold()
    return f"smb|{target.host.casefold()}|{target.port}|{share.casefold()}|{normalized_path}"


def target_object_key(target) -> str:
    if isinstance(target, Path):
        return f"target|local|{target.resolve()}"
    return f"target|smb|{target.host.casefold()}|{target.port}"


def share_object_key(target: "Target", share: str) -> str:
    return f"share|smb|{target.host.casefold()}|{target.port}|{share.casefold()}"


def directory_object_key(target, share: str | None, path: str | Path) -> str:
    if isinstance(target, Path):
        return f"directory|local|{Path(path).resolve()}"
    normalized_path = str(path).replace("/", "\\").strip("\\").casefold()
    return f"directory|smb|{target.host.casefold()}|{target.port}|{str(share).casefold()}|{normalized_path}"


def _ancestor_object_keys(row):
    """Yield existing-key identities of strict ancestors, nearest first.

    Use the manifest's canonical keys, not path prefixes or filesystem probes.
    A file's own retry allowance is separate from reopening its containers.
    """

    key = row["object_key"]
    kind = row["kind"]
    if kind == "file" and key.startswith("local|"):
        path = Path(key[len("local|"):])
    elif kind == "directory" and key.startswith("directory|local|"):
        path = Path(key[len("directory|local|"):])
    else:
        path = None
    if path is not None:
        if not row["target"]:
            return
        root = Path(row["target"])
        try:
            path.relative_to(root)
        except ValueError:
            return
        if path != root:
            current = path.parent
            while True:
                yield f"directory|local|{current}"
                if current == root:
                    break
                current = current.parent
        yield f"target|local|{root}"
        return

    if kind == "file" and key.startswith("smb|"):
        parts = key.split("|", 4)
        if len(parts) != 5:
            return
        _, host, port, share, relative_path = parts
    elif kind == "directory" and key.startswith("directory|smb|"):
        parts = key.split("|", 5)
        if len(parts) != 6:
            return
        _, _, host, port, share, relative_path = parts
    elif kind == "share" and key.startswith("share|smb|"):
        parts = key.split("|", 4)
        if len(parts) == 5:
            yield f"target|smb|{parts[2]}|{parts[3]}"
        return
    elif kind == "share_enumeration" and key.startswith("share-enumeration|target|smb|"):
        yield key[len("share-enumeration|"):]
        return
    else:
        return

    path_parts = [part for part in relative_path.split("\\") if part]
    if path_parts:
        path_parts.pop()
        while True:
            parent_path = "\\".join(path_parts)
            yield f"directory|smb|{host}|{port}|{share}|{parent_path}"
            if not path_parts:
                break
            path_parts.pop()
    yield f"share|smb|{host}|{port}|{share}"
    yield f"target|smb|{host}|{port}"


class ScanState:
    def __init__(self, path: str | Path, connection: sqlite3.Connection, run_id: str):
        self.path = Path(path)
        self.connection = connection
        self.run_id = run_id
        self.connection.row_factory = sqlite3.Row
        configure_evidence_reader(self.connection)
        self.transaction_lock = threading.RLock()
        self._network_resume_prepared = False

    @classmethod
    def create(cls, path: str | Path, configuration: Mapping, version: str) -> "ScanState":
        try:
            path = require_local_write_path(path, purpose="SQLite state")
        except UnsafeWritePath as exc:
            raise StateError(str(exc)) from exc
        if path.exists():
            raise StateExistsError(f"State database already exists: {path}; use --resume to continue it")
        try:
            connection = _connect_local_sqlite(path, create=True, timeout=30, isolation_level=None)
        except (StateExistsError, StateNotFoundError):
            raise
        except sqlite3.Error as exc:
            raise StateError(f"Unable to create scan state {path}: {exc}") from exc
        try:
            cls._configure(connection)
            cls._create_schema(connection)
            run_id = uuid.uuid4().hex
            now = utc_now()
            config_json = json.dumps(_json_value(configuration), ensure_ascii=False, sort_keys=True)
            fingerprint = configuration_fingerprint(configuration)
            # isolation_level=None means a Connection context manager does not
            # start a transaction itself. Publish run + revision atomically.
            connection.execute("BEGIN IMMEDIATE")
            with connection:
                connection.execute(
                    """
                    INSERT INTO runs (
                        run_id, schema_version, scanner_version, status,
                        config_json, config_fingerprint, created_at, updated_at
                    ) VALUES (?, ?, ?, 'running', ?, ?, ?, ?)
                    """,
                    (run_id, SCHEMA_VERSION, version, config_json, fingerprint, now, now),
                )
                connection.execute(
                    "INSERT INTO counters(run_id,name,value) VALUES (?,'data_revision',0)", (run_id,)
                )
            _chmod_local_entry(path, 0o600, directory=False, purpose="SQLite state")
            return cls(path, connection, run_id)
        except sqlite3.Error as exc:
            connection.close()
            raise StateError(f"Unable to create scan state {path}: {exc}") from exc
        except BaseException:
            connection.close()
            raise

    @classmethod
    def resume(cls, path: str | Path, configuration: Mapping, version: str) -> "ScanState":
        try:
            path = require_local_write_path(path, purpose="SQLite state")
        except UnsafeWritePath as exc:
            raise StateError(str(exc)) from exc
        if not path.is_file():
            raise StateNotFoundError(f"State database not found: {path}")
        try:
            connection = _connect_local_sqlite(path, timeout=30, isolation_level=None)
        except sqlite3.Error as exc:
            raise StateError(f"Unable to resume scan state {path}: {exc}") from exc
        try:
            cls._configure(connection)
            row = connection.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
            if row is None:
                raise StateError(f"State database contains no run: {path}")
            row = cls._ensure_schema_version(connection, row)
            stored = json.loads(row["config_json"])
            _validate_saved_filter_semantics(stored)
            fingerprint = configuration_fingerprint(configuration)
            if row["config_fingerprint"] != fingerprint:
                compatible_target_order = (
                    row["config_fingerprint"] == configuration_fingerprint(stored)
                    and _resume_semantic_fingerprint(stored) == _resume_semantic_fingerprint(configuration)
                )
                if not compatible_target_order:
                    message = (
                        "Resume configuration does not match the stored scope, filters, rules, or policy; start a new scan"
                    )
                    stored_downloads = stored.get("semantic", {}).get("policy", {}).get("download_matches")
                    requested_downloads = configuration.get("semantic", {}).get("policy", {}).get("download_matches")
                    if stored_downloads is True and requested_downloads is False:
                        message += (
                            ". This saved run had downloads enabled; --download is now required to explicitly "
                            "keep that policy. To disable downloads, start a new scan without --download"
                        )
                    raise ResumeMismatchError(message)
            now = utc_now()
            state = cls(path, connection, row["run_id"])
            with state.transaction():
                # Clear the prior invocation before preflight/approval becomes
                # visible, atomically with publishing the resumed run.
                connection.execute(
                    "DELETE FROM checkpoints WHERE run_id=? AND name='scan_timing'", (row["run_id"],)
                )
                connection.execute(
                    """
                    UPDATE runs
                    SET status='running', scanner_version=?, config_json=?, config_fingerprint=?,
                        updated_at=?, completed_at=NULL
                    WHERE run_id=?
                    """,
                    (
                        version,
                        json.dumps(_json_value(configuration), ensure_ascii=False, sort_keys=True),
                        fingerprint,
                        now,
                        row["run_id"],
                    ),
                )
            _chmod_local_entry(path, 0o600, directory=False, purpose="SQLite state")
            return state
        except sqlite3.Error as exc:
            connection.close()
            raise StateError(f"Unable to resume scan state {path}: {exc}") from exc
        except Exception:
            connection.close()
            raise

    @classmethod
    def attach(cls, path: str | Path, run_id: str, *, thread_safe: bool = False) -> "ScanState":
        """Open an existing run without changing its status or configuration."""

        try:
            path = require_local_write_path(path, purpose="SQLite state")
        except UnsafeWritePath as exc:
            raise StateError(str(exc)) from exc
        if not path.is_file():
            raise StateNotFoundError(f"State database not found: {path}")
        try:
            connection = _connect_local_sqlite(
                path,
                timeout=30,
                isolation_level=None,
                check_same_thread=not thread_safe,
            )
        except sqlite3.Error as exc:
            raise StateError(f"Unable to attach scan state {path}: {exc}") from exc
        try:
            cls._configure(connection)
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise StateNotFoundError(f"Run {run_id} was not found in {path}")
            cls._ensure_schema_version(connection, row)
            return cls(path, connection, run_id)
        except sqlite3.Error as exc:
            connection.close()
            raise StateError(f"Unable to attach scan state {path}: {exc}") from exc
        except Exception:
            connection.close()
            raise

    @classmethod
    def attach_latest(cls, path: str | Path) -> "ScanState":
        """Attach to the latest run without exposing its internal identifier."""

        try:
            path = require_local_write_path(path, purpose="SQLite state")
        except UnsafeWritePath as exc:
            raise StateError(str(exc)) from exc
        if not path.is_file():
            raise StateNotFoundError(f"State database not found: {path}")
        try:
            connection = _connect_local_sqlite(path, timeout=30, isolation_level=None)
        except sqlite3.Error as exc:
            raise StateError(f"Unable to attach scan state {path}: {exc}") from exc
        try:
            cls._configure(connection)
            row = connection.execute(
                "SELECT run_id, schema_version FROM runs ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if row is None:
                raise StateNotFoundError(f"State database contains no run: {path}")
            row = cls._ensure_schema_version(connection, row)
            return cls(path, connection, row["run_id"])
        except sqlite3.Error as exc:
            connection.close()
            raise StateError(f"Unable to read scan state {path}: {exc}") from exc
        except Exception:
            connection.close()
            raise

    @classmethod
    def read_configuration(cls, path: str | Path) -> dict:
        try:
            path = require_local_path(path, purpose="SQLite state")
        except UnsafeWritePath as exc:
            raise StateError(str(exc)) from exc
        if not path.is_file():
            raise StateNotFoundError(f"State database not found: {path}")
        try:
            connection = _connect_local_sqlite(path, read_only=True, timeout=30)
            connection.execute("PRAGMA temp_store=MEMORY")
            row = connection.execute("SELECT config_json FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
            if row is None:
                raise StateError(f"State database contains no run: {path}")
            return json.loads(row[0])
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            raise StateError(f"Unable to read scan configuration from {path}: {exc}") from exc
        finally:
            if "connection" in locals():
                connection.close()

    @classmethod
    def interrupt_latest(cls, path: str | Path, reason: str = "Interrupted by user") -> bool:
        """Mark the latest still-running run interrupted from a supervising process."""

        try:
            path = require_local_write_path(path, purpose="SQLite state")
        except UnsafeWritePath as exc:
            raise StateError(str(exc)) from exc
        if not path.is_file():
            return False
        try:
            connection = _connect_local_sqlite(path, timeout=30, isolation_level=None)
        except sqlite3.Error as exc:
            raise StateError(f"Unable to mark scan state interrupted at {path}: {exc}") from exc
        try:
            cls._configure(connection)
            row = connection.execute(
                "SELECT run_id, status, schema_version FROM runs ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if row is None or row["status"] != "running":
                return False
            now = utc_now()
            state = cls(path, connection, row["run_id"])
            with (state.transaction() if row["schema_version"] >= 9 else connection):
                changed = connection.execute(
                    """
                    UPDATE runs
                    SET status='interrupted', error_reason=?, updated_at=?, completed_at=?
                    WHERE run_id=? AND status='running'
                    """,
                    (reason, now, now, row["run_id"]),
                ).rowcount
            if changed:
                state._finish_scan_timing("interrupted", now)
            return bool(changed)
        except sqlite3.Error as exc:
            raise StateError(f"Unable to mark scan state interrupted at {path}: {exc}") from exc
        finally:
            connection.close()

    @staticmethod
    def _configure(connection: sqlite3.Connection) -> None:
        connection.row_factory = sqlite3.Row
        # Never honor SQLITE_TMPDIR/TMPDIR for spills: either may point at a
        # customer share and SQLite otherwise creates/deletes temp databases
        # there outside MANSPIDER's normal output-path validation.
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=30000")

    @classmethod
    def _ensure_schema_version(cls, connection: sqlite3.Connection, row: sqlite3.Row) -> sqlite3.Row:
        version = row["schema_version"]
        if version == 2:
            cls._migrate_schema_2_to_3(connection)
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
            version = row["schema_version"]
        if version == 3:
            cls._migrate_schema_3_to_4(connection)
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
            version = row["schema_version"]
        if version == 4:
            cls._migrate_schema_4_to_5(connection)
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
            version = row["schema_version"]
        if version == 5:
            cls._migrate_schema_5_to_6(connection)
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
            version = row["schema_version"]
        if version == 6:
            cls._migrate_schema_6_to_7(connection)
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
            version = row["schema_version"]
        if version == 7:
            cls._migrate_schema_7_to_8(connection)
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
            version = row["schema_version"]
        if version == 8:
            cls._migrate_schema_8_to_9(connection)
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
            version = row["schema_version"]
        if version != SCHEMA_VERSION:
            raise ResumeMismatchError(
                f"State schema version {version} does not match supported version {SCHEMA_VERSION}"
            )
        return row

    @staticmethod
    def _migrate_schema_2_to_3(connection: sqlite3.Connection) -> None:
        """Add rule provenance without discarding resumable schema-2 work."""

        additions = {
            "representation": "TEXT NOT NULL DEFAULT 'unknown'",
            "rule_source": "TEXT NOT NULL DEFAULT 'legacy-state'",
            "rule_schema_version": "INTEGER",
            "rule_pack_id": "TEXT",
            "rule_pack_version": "TEXT",
        }
        connection.execute("BEGIN IMMEDIATE")
        try:
            existing = {row["name"] for row in connection.execute("PRAGMA table_info(findings)").fetchall()}
            for name, declaration in additions.items():
                if name not in existing:
                    connection.execute(f"ALTER TABLE findings ADD COLUMN {name} {declaration}")
            connection.execute(
                """
                UPDATE findings
                SET representation=CASE
                        WHEN rule_id LIKE 'metadata:%' THEN 'metadata'
                        ELSE 'text'
                    END,
                    rule_source=CASE
                        WHEN rule_id LIKE 'metadata:%' OR rule_id LIKE 'content:%' THEN 'cli'
                        ELSE 'legacy-state'
                    END
                """
            )
            connection.execute("UPDATE runs SET schema_version=3 WHERE schema_version=2")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _migrate_schema_3_to_4(connection: sqlite3.Connection) -> None:
        """Add native rule classification without losing schema-3 findings."""

        additions = {
            "severity": "TEXT NOT NULL DEFAULT 'medium'",
            "confidence": "TEXT NOT NULL DEFAULT 'medium'",
            "category": "TEXT NOT NULL DEFAULT 'uncategorized'",
            "tags_json": "TEXT NOT NULL DEFAULT '[]'",
        }
        connection.execute("BEGIN IMMEDIATE")
        try:
            existing = {row["name"] for row in connection.execute("PRAGMA table_info(findings)").fetchall()}
            for name, declaration in additions.items():
                if name not in existing:
                    connection.execute(f"ALTER TABLE findings ADD COLUMN {name} {declaration}")
            connection.execute("UPDATE runs SET schema_version=4 WHERE schema_version=3")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise

    @classmethod
    def _migrate_schema_4_to_5(cls, connection: sqlite3.Connection) -> None:
        """Add resumable coverage-gap observations without changing scan semantics."""

        connection.execute("BEGIN IMMEDIATE")
        try:
            cls._create_unclassified_schema(connection)
            connection.execute("UPDATE runs SET schema_version=5 WHERE schema_version=4")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _migrate_schema_5_to_6(connection: sqlite3.Connection) -> None:
        """Embed selected-file coverage in its existing manifest update."""

        additions = {
            # Constraint checks on ADD COLUMN can force a full-table validation
            # in modern SQLite. Existing schema-5 rows receive safe constants;
            # fresh schema-6 databases retain the stricter declarations below.
            "coverage_reason_mask": "INTEGER NOT NULL DEFAULT 0",
            "coverage_size": "INTEGER",
            "coverage_mtime": "REAL",
            "coverage_matched_rule_ids_json": "TEXT",
            "coverage_content_status": "TEXT",
            "coverage_content_read": "INTEGER",
            "coverage_processing_status": "TEXT",
            "coverage_processing_reason": "TEXT",
            "coverage_first_seen_at": "TEXT",
            "coverage_last_seen_at": "TEXT",
        }
        connection.execute("BEGIN IMMEDIATE")
        try:
            existing = {row["name"] for row in connection.execute("PRAGMA table_info(objects)").fetchall()}
            for name, declaration in additions.items():
                if name not in existing:
                    connection.execute(f"ALTER TABLE objects ADD COLUMN {name} {declaration}")
            connection.execute("UPDATE runs SET schema_version=6 WHERE schema_version=5")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _migrate_schema_6_to_7(connection: sqlite3.Connection) -> None:
        """Remove the retired finding-review subsystem and its stored marks."""

        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("DROP INDEX IF EXISTS reviews_run_idx")
            connection.execute("DROP TABLE IF EXISTS reviews")
            connection.execute("UPDATE runs SET schema_version=7 WHERE schema_version=6")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _migrate_schema_7_to_8(connection: sqlite3.Connection) -> None:
        """Record explicit analysis evidence without inferring any legacy reads."""

        additions = {
            "analysis_status": (
                "TEXT NOT NULL DEFAULT 'unknown' "
                "CHECK(analysis_status IN ('unknown','not_analyzed','partial','analyzed'))"
            ),
            "analysis_reason": "TEXT",
            "analysis_read": "INTEGER CHECK(analysis_read IN (0,1) OR analysis_read IS NULL)",
        }
        connection.execute("BEGIN IMMEDIATE")
        try:
            existing = {row["name"] for row in connection.execute("PRAGMA table_info(objects)").fetchall()}
            for name, declaration in additions.items():
                if name not in existing:
                    connection.execute(f"ALTER TABLE objects ADD COLUMN {name} {declaration}")
            connection.execute("UPDATE runs SET schema_version=8 WHERE schema_version=7")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _create_context_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS finding_contexts (
                context_id INTEGER PRIMARY KEY CHECK(context_id > 0),
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                object_id INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE,
                context TEXT NOT NULL CHECK(typeof(context)='text')
            )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS finding_contexts_object_idx ON finding_contexts(object_id)"
        )
        # FK checks while retiring one object's contexts must not scan every
        # finding in the run. Inline-only evidence adds no entries to this index.
        connection.execute(
            "CREATE INDEX IF NOT EXISTS findings_context_idx ON findings(context_id) WHERE context_id IS NOT NULL"
        )
        # Contexts are immutable and owned by exactly one object. These checks
        # also protect callers using the connection directly, not just helpers.
        connection.execute(
            """CREATE TRIGGER IF NOT EXISTS finding_contexts_owner_insert BEFORE INSERT ON finding_contexts
            BEGIN SELECT CASE WHEN NOT EXISTS (
                SELECT 1 FROM objects WHERE object_id=NEW.object_id AND run_id=NEW.run_id
            ) THEN RAISE(ABORT,'Finding context owner does not exist') END; END"""
        )
        connection.execute(
            """CREATE TRIGGER IF NOT EXISTS finding_contexts_immutable BEFORE UPDATE ON finding_contexts
            BEGIN SELECT RAISE(ABORT,'Finding contexts are immutable'); END"""
        )
        for event in ("INSERT", "UPDATE"):
            connection.execute(
                f"""CREATE TRIGGER IF NOT EXISTS findings_context_{event.lower()} BEFORE {event} ON findings
                WHEN NEW.context_id IS NOT NULL
                BEGIN SELECT CASE WHEN NEW.context IS NOT NULL OR NOT EXISTS (
                    SELECT 1 FROM finding_contexts WHERE context_id=NEW.context_id
                    AND run_id=NEW.run_id AND object_id=NEW.object_id
                ) THEN RAISE(ABORT,'Invalid finding context reference') END; END"""
            )

    @classmethod
    def _migrate_schema_8_to_9(cls, connection: sqlite3.Connection) -> None:
        """Add context references without rewriting historical evidence or IDs."""
        connection.execute("BEGIN IMMEDIATE")
        try:
            existing = {row["name"] for row in connection.execute("PRAGMA table_info(findings)")}
            if "context_id" not in existing:
                connection.execute(
                    "ALTER TABLE findings ADD COLUMN context_id INTEGER REFERENCES finding_contexts(context_id)"
                )
            cls._create_context_schema(connection)
            connection.execute(
                "INSERT OR IGNORE INTO counters(run_id,name,value) SELECT run_id,'data_revision',0 FROM runs"
            )
            connection.execute("UPDATE runs SET schema_version=9 WHERE schema_version=8")
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _create_unclassified_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS unclassified_files (
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                object_key TEXT NOT NULL,
                target TEXT,
                share TEXT,
                path TEXT NOT NULL,
                full_path TEXT NOT NULL,
                filename TEXT NOT NULL,
                extension TEXT NOT NULL,
                extension_recognized INTEGER NOT NULL CHECK(extension_recognized IN (0,1)),
                size INTEGER,
                mtime REAL,
                reasons_json TEXT NOT NULL,
                matched_rule_ids_json TEXT NOT NULL,
                content_status TEXT NOT NULL,
                content_read INTEGER CHECK(content_read IN (0,1) OR content_read IS NULL),
                processing_status TEXT NOT NULL,
                processing_reason TEXT,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY(run_id, object_key)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS unclassified_files_run_path_idx
            ON unclassified_files(run_id, target, share, path)
            """
        )

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                scanner_version TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('running','complete','complete_with_errors','interrupted','preflight_failed')),
                config_json TEXT NOT NULL,
                config_fingerprint TEXT NOT NULL,
                error_reason TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT
            );

            CREATE TABLE objects (
                object_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                object_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                target TEXT,
                share TEXT,
                path TEXT,
                size INTEGER,
                mtime TEXT,
                file_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','in_progress','processed','skipped','error')),
                reason TEXT,
                changed INTEGER NOT NULL DEFAULT 0 CHECK(changed IN (0,1)),
                attempts INTEGER NOT NULL DEFAULT 0,
                discovered_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                analysis_status TEXT NOT NULL DEFAULT 'unknown'
                    CHECK(analysis_status IN ('unknown','not_analyzed','partial','analyzed')),
                analysis_reason TEXT,
                analysis_read INTEGER CHECK(analysis_read IN (0,1) OR analysis_read IS NULL),
                coverage_reason_mask INTEGER NOT NULL DEFAULT 0 CHECK(coverage_reason_mask >= 0),
                coverage_size INTEGER,
                coverage_mtime REAL,
                coverage_matched_rule_ids_json TEXT,
                coverage_content_status TEXT,
                coverage_content_read INTEGER CHECK(coverage_content_read IN (0,1) OR coverage_content_read IS NULL),
                coverage_processing_status TEXT,
                coverage_processing_reason TEXT,
                coverage_first_seen_at TEXT,
                coverage_last_seen_at TEXT,
                UNIQUE(run_id, object_key)
            );

            CREATE INDEX objects_run_status_idx ON objects(run_id, status);

            CREATE TABLE findings (
                finding_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                object_id INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE,
                rule_id TEXT NOT NULL,
                representation TEXT NOT NULL,
                rule_source TEXT NOT NULL,
                rule_schema_version INTEGER,
                rule_pack_id TEXT,
                rule_pack_version TEXT,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                category TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                match_start INTEGER,
                match_end INTEGER,
                value TEXT NOT NULL,
                context TEXT,
                context_id INTEGER REFERENCES finding_contexts(context_id),
                created_at TEXT NOT NULL
            );

            CREATE INDEX findings_run_idx ON findings(run_id);
            CREATE INDEX findings_object_idx ON findings(object_id);

            CREATE TABLE counters (
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                value INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(run_id, name)
            );

            CREATE TABLE checkpoints (
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(run_id, name)
            );

            CREATE TABLE exclusions (
                exclusion_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                object_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                target TEXT,
                share TEXT,
                path TEXT,
                reason TEXT NOT NULL,
                occurrences INTEGER NOT NULL DEFAULT 1,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                UNIQUE(run_id, object_key)
            );

            CREATE INDEX exclusions_run_idx ON exclusions(run_id);

            """
        )
        ScanState._create_unclassified_schema(connection)
        ScanState._create_context_schema(connection)

    @contextmanager
    def transaction(self, *, telemetry_only=False):
        # Bounded batch methods invoke established single-object operations in
        # one outer transaction.  The reentrant lock also permits one
        # check_same_thread=False target connection to be shared safely by its
        # share workers without allowing another thread to join that open
        # transaction accidentally.
        with self.transaction_lock:
            if self.connection.in_transaction:
                if not telemetry_only:
                    self._transaction_semantic = True
                try:
                    yield
                except sqlite3.Error as exc:
                    raise StateError(f"Persistent-state transaction failed: {exc}") from exc
                return
            try:
                self.connection.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise StateError(f"Unable to begin persistent-state transaction: {exc}") from exc
            initial_changes = self.connection.total_changes
            self._transaction_semantic = not telemetry_only
            try:
                try:
                    yield
                    if self._transaction_semantic and self.connection.total_changes != initial_changes:
                        changed = self.connection.execute(
                            "UPDATE counters SET value=value+1 WHERE run_id=? AND name='data_revision' "
                            "AND typeof(value)='integer' AND value>=0 AND value<9223372036854775807",
                            (self.run_id,),
                        ).rowcount
                        if changed != 1:
                            raise StateError("Missing or invalid persistent-state data revision")
                except sqlite3.Error as exc:
                    raise StateError(f"Persistent-state transaction failed: {exc}") from exc
            except BaseException:
                try:
                    # SQLITE_FULL (and some I/O failures) can roll back the
                    # transaction inside SQLite. Preserve that original cause
                    # instead of masking it with "no transaction is active".
                    if self.connection.in_transaction:
                        self.connection.execute("ROLLBACK")
                except sqlite3.Error as rollback_exc:
                    raise StateError(
                        f"Unable to roll back persistent-state transaction: {rollback_exc}"
                    ) from rollback_exc
                raise
            else:
                try:
                    self.connection.execute("COMMIT")
                except sqlite3.Error as exc:
                    try:
                        self.connection.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise StateError(f"Unable to commit persistent-state transaction: {exc}") from exc

    def register_object(
        self,
        *,
        object_key: str,
        kind: str,
        target: str | None = None,
        share: str | None = None,
        path: str | None = None,
        size: int | None = None,
        mtime: str | int | float | None = None,
        file_id: str | None = None,
        retry_limit: int = 1,
        always_process: bool = False,
    ) -> ObjectDecision:
        now = utc_now()
        mtime_value = None if mtime is None else str(mtime)
        with self.transaction():
            return self._register_object(
                object_key=object_key,
                kind=kind,
                target=target,
                share=share,
                path=path,
                size=size,
                mtime_value=mtime_value,
                file_id=file_id,
                retry_limit=retry_limit,
                always_process=always_process,
                now=now,
            )

    def _register_object(
        self,
        *,
        object_key: str,
        kind: str,
        target: str | None,
        share: str | None,
        path: str | None,
        size: int | None,
        mtime_value: str | None,
        file_id: str | None,
        retry_limit: int,
        always_process: bool,
        now: str,
    ) -> ObjectDecision:
        row = self.connection.execute(
            "SELECT * FROM objects WHERE run_id=? AND object_key=?",
            (self.run_id, object_key),
        ).fetchone()
        if row is None:
            cursor = self.connection.execute(
                """
                INSERT INTO objects (
                    run_id, object_key, kind, target, share, path, size,
                    mtime, file_id, discovered_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.run_id,
                    object_key,
                    kind,
                    target,
                    share,
                    path,
                    size,
                    mtime_value,
                    file_id,
                    now,
                    now,
                ),
            )
            return ObjectDecision(cursor.lastrowid, True, False, None)

        identity_changed = any(
            (
                row["size"] != size,
                row["mtime"] != mtime_value,
                bool(row["file_id"] and file_id and row["file_id"] != file_id),
            )
        )
        prior_status = row["status"]
        if identity_changed:
            self.connection.execute("DELETE FROM findings WHERE object_id=?", (row["object_id"],))
            self.connection.execute("DELETE FROM finding_contexts WHERE object_id=?", (row["object_id"],))
            self.connection.execute(
                """
                UPDATE objects
                SET kind=?, target=?, share=?, path=?, size=?, mtime=?, file_id=?,
                    status='pending', reason=NULL, changed=1, attempts=0, updated_at=?,
                    analysis_status='unknown', analysis_reason=NULL, analysis_read=NULL
                WHERE object_id=?
                """,
                (kind, target, share, path, size, mtime_value, file_id, now, row["object_id"]),
            )
            return ObjectDecision(row["object_id"], True, True, prior_status)

        retry_allowed = row["attempts"] < retry_limit or (
            prior_status == "error" and (row["reason"] or "").startswith(ANCESTOR_BLOCKED_REASON_PREFIX)
        ) or (
            prior_status == "error" and _network_resume_ready(row)
        )
        if always_process:
            should_process = prior_status != "skipped" and (prior_status != "error" or retry_allowed)
        else:
            should_process = prior_status in ("pending", "in_progress") or (
                prior_status == "error" and retry_allowed
            )
        return ObjectDecision(row["object_id"], should_process, bool(row["changed"]), prior_status)

    def claim_object(
        self,
        *,
        object_key: str,
        kind: str,
        target: str | None = None,
        share: str | None = None,
        path: str | None = None,
        size: int | None = None,
        mtime: str | int | float | None = None,
        file_id: str | None = None,
        retry_limit: int = 1,
        always_process: bool = False,
        discovery_counter: str | None = None,
    ) -> ObjectDecision:
        """Register, account for, and begin one object in a single durable transaction."""

        return self._claim_object(
            object_key=object_key,
            kind=kind,
            target=target,
            share=share,
            path=path,
            size=size,
            mtime=mtime,
            file_id=file_id,
            retry_limit=retry_limit,
            always_process=always_process,
            discovery_counter=discovery_counter,
        )

    def _claim_object(
        self,
        *,
        object_key: str,
        kind: str,
        target: str | None = None,
        share: str | None = None,
        path: str | None = None,
        size: int | None = None,
        mtime: str | int | float | None = None,
        file_id: str | None = None,
        retry_limit: int = 1,
        always_process: bool = False,
        discovery_counter: str | None = None,
        counter_updates: dict[str, int] | None = None,
    ) -> ObjectDecision:
        now = utc_now()
        with self.transaction():
            decision = self._register_object(
                object_key=object_key,
                kind=kind,
                target=target,
                share=share,
                path=path,
                size=size,
                mtime_value=None if mtime is None else str(mtime),
                file_id=file_id,
                retry_limit=retry_limit,
                always_process=always_process,
                now=now,
            )
            if decision.prior_status is None:
                self._claim_counter("objects_discovered", counter_updates)
                if discovery_counter:
                    self._claim_counter(discovery_counter, counter_updates)
            if decision.should_process:
                self._begin_object(decision.object_id, now)
            else:
                self._claim_counter("resume_reused", counter_updates)
            return decision

    def _claim_counter(self, name: str, updates: dict[str, int] | None) -> None:
        # Only these internal call sites ignore the resulting counter value.
        # Public increment_counter remains immediately readable and returns
        # the real SQL value, including inside another transaction.
        if updates is None or type(name) is not str:
            self._increment_counter(name, 1)
        else:
            updates[name] = updates.get(name, 0) + 1

    def claim_objects(self, objects: Iterable[Mapping]) -> tuple[ObjectDecision, ...]:
        """Claim a bounded group of independently addressable objects atomically."""

        objects = tuple(objects)
        if not objects:
            return ()
        with self.transaction():
            counter_updates: dict[str, int] = {}
            decisions = tuple(
                self._claim_object(**dict(values), counter_updates=counter_updates) for values in objects
            )
            for name, amount in counter_updates.items():
                self._add_counter(name, amount)
            return decisions

    def begin_object(self, object_id: int) -> None:
        with self.transaction():
            self._begin_object(object_id, utc_now())

    def _begin_object(self, object_id: int, now: str) -> None:
        cursor = self.connection.execute(
            """
            UPDATE objects
            SET status='in_progress', reason=NULL, attempts=attempts+1, updated_at=?,
                analysis_status='unknown', analysis_reason=NULL, analysis_read=NULL
            WHERE run_id=? AND object_id=?
            """,
            (now, self.run_id, object_id),
        )
        if cursor.rowcount != 1:
            raise StateError(f"Unknown object id {object_id}")

    def complete_object(
        self,
        object_id: int,
        status: str,
        *,
        reason: str | None = None,
        findings: Iterable[FindingRecord] = (),
        changed: bool | None = None,
        post_read_identity: tuple[int | None, str | int | float | None, str | None] | None = None,
        checkpoint_name: str | None = None,
        checkpoint_value=None,
        unclassified_record: Mapping | None = None,
        unclassified_records: Iterable[Mapping] = (),
        unclassified_deletions: Iterable[str] = (),
        analysis_status: str | None = None,
        analysis_reason: str | None = None,
        analysis_read: bool | None = None,
    ) -> None:
        """Finish work; omitted analysis_status preserves earlier analysis evidence.

        An explicit analysis_status replaces its complete status/reason/read
        observation. analysis_read records observed content access, never proof
        that the whole source was read or analyzed; None means access is unknown.
        """

        self._complete_object(
            object_id,
            status,
            reason=reason,
            findings=findings,
            changed=changed,
            post_read_identity=post_read_identity,
            checkpoint_name=checkpoint_name,
            checkpoint_value=checkpoint_value,
            unclassified_record=unclassified_record,
            unclassified_records=unclassified_records,
            unclassified_deletions=unclassified_deletions,
            analysis_status=analysis_status,
            analysis_reason=analysis_reason,
            analysis_read=analysis_read,
        )

    def _complete_object(
        self,
        object_id: int,
        status: str,
        *,
        reason: str | None = None,
        findings: Iterable[FindingRecord] = (),
        changed: bool | None = None,
        post_read_identity: tuple[int | None, str | int | float | None, str | None] | None = None,
        checkpoint_name: str | None = None,
        checkpoint_value=None,
        unclassified_record: Mapping | None = None,
        unclassified_records: Iterable[Mapping] = (),
        unclassified_deletions: Iterable[str] = (),
        analysis_status: str | None = None,
        analysis_reason: str | None = None,
        analysis_read: bool | None = None,
        checkpoint_updates: dict[str, tuple[str, str]] | None = None,
        checkpoint_byte_limit: int | None = None,
    ) -> None:
        if status not in OBJECT_TERMINAL_STATUSES:
            raise StateError(f"Invalid terminal object status: {status}")
        if analysis_status is not None and (
            not isinstance(analysis_status, str) or analysis_status not in ANALYSIS_STATUSES
        ):
            raise StateError(f"Invalid content analysis status: {analysis_status}")
        if analysis_reason is not None and not isinstance(analysis_reason, str):
            raise StateError("Content analysis reason must be text or None")
        if analysis_read is not None and (type(analysis_read) not in (bool, int) or analysis_read not in (0, 1)):
            raise StateError("Content analysis read flag must be a boolean or None")
        if analysis_status is None and (analysis_reason is not None or analysis_read is not None):
            raise StateError("Content analysis details require an explicit analysis status")
        findings = tuple(findings)
        unclassified_records = tuple(unclassified_records)
        unclassified_deletions = tuple(unclassified_deletions)
        now = utc_now()
        with self.transaction():
            row = self.connection.execute(
                "SELECT object_key, changed FROM objects WHERE run_id=? AND object_id=?",
                (self.run_id, object_id),
            ).fetchone()
            if row is None:
                raise StateError(f"Unknown object id {object_id}")
            coverage = None
            if unclassified_record is not None:
                observation = dict(unclassified_record)
                observation["object_key"] = row["object_key"]
                observation["processing_status"] = status
                observation["processing_reason"] = reason
                coverage = self._normalize_unclassified_file(observation)
            self.connection.execute("DELETE FROM findings WHERE object_id=?", (object_id,))
            self.connection.execute("DELETE FROM finding_contexts WHERE object_id=?", (object_id,))
            contexts = {}
            repeated_contexts = {
                context for context, count in Counter(
                    finding.context for finding in findings if finding.context is not None
                ).items() if count > 1
            }
            for finding in findings:
                context_id = None
                if finding.context in repeated_contexts:
                    # Exact string-key equality is collision-safe; the cache is
                    # scoped to one completion, not the entire scan/run.
                    if finding.context not in contexts:
                        contexts[finding.context] = self.connection.execute(
                            "INSERT INTO finding_contexts(run_id,object_id,context) VALUES (?,?,?)",
                            (self.run_id, object_id, finding.context),
                        ).lastrowid
                    context_id = contexts[finding.context]
                tags_json = json.dumps(list(finding.tags), ensure_ascii=False, separators=(",", ":"))
                identity = "\x1f".join(
                    (
                        self.run_id,
                        row["object_key"],
                        finding.rule_id,
                        finding.representation,
                        finding.rule_source,
                        str(finding.rule_schema_version),
                        str(finding.rule_pack_id),
                        str(finding.rule_pack_version),
                        finding.severity,
                        finding.confidence,
                        finding.category,
                        tags_json,
                        str(finding.start),
                        str(finding.end),
                        finding.value,
                    )
                )
                if finding.representation in {
                    "inspect:private-key-material",
                    "inspect:kubernetes-secret-json",
                    "inspect:group-policy-preference-password",
                    "inspect:active-directory-ldif-secrets",
                    "inspect:active-directory-json-secrets",
                    "inspect:russian-json-credential-value",
                    "inspect:russian-legacy-credential-value",
                }:
                    # Inspectors can share the same source span and value but
                    # produce independent evidence: different owned locations,
                    # or a key header versus a successfully parsed container.
                    # Change identities only on reprocessing these inspectors;
                    # leave existing rows and all other representations alone.
                    identity += "\x1f" + (finding.context or "")
                finding_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
                self.connection.execute(
                    """
                    INSERT INTO findings (
                        finding_id, run_id, object_id, rule_id, representation,
                        rule_source, rule_schema_version, rule_pack_id,
                        rule_pack_version, severity, confidence, category,
                        tags_json, match_start, match_end, value, context, context_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        self.run_id,
                        object_id,
                        finding.rule_id,
                        finding.representation,
                        finding.rule_source,
                        finding.rule_schema_version,
                        finding.rule_pack_id,
                        finding.rule_pack_version,
                        finding.severity,
                        finding.confidence,
                        finding.category,
                        tags_json,
                        finding.start,
                        finding.end,
                        finding.value,
                        finding.context if context_id is None else None,
                        context_id,
                        now,
                    ),
                )
            changed_value = row["changed"] if changed is None else int(bool(row["changed"]) or changed)
            assignments = ["status=?", "reason=?", "changed=?"]
            values = [status, reason, changed_value]
            if analysis_status is not None:
                assignments.extend(("analysis_status=?", "analysis_reason=?", "analysis_read=?"))
                values.extend((analysis_status, analysis_reason, analysis_read))
            if post_read_identity is not None:
                size, mtime, file_id = post_read_identity
                mtime_value = None if mtime is None else str(mtime)
                assignments.extend(("size=?", "mtime=?", "file_id=?"))
                values.extend((size, mtime_value, file_id))
            if coverage is not None:
                assignments.extend(
                    (
                        "coverage_reason_mask=?",
                        "coverage_size=?",
                        "coverage_mtime=?",
                        "coverage_matched_rule_ids_json=?",
                        "coverage_content_status=?",
                        "coverage_content_read=?",
                        "coverage_processing_status=NULL",
                        "coverage_processing_reason=NULL",
                        "coverage_first_seen_at=COALESCE(coverage_first_seen_at, ?)",
                        "coverage_last_seen_at=?",
                    )
                )
                values.extend(
                    (
                        coverage["reason_mask"],
                        coverage["size"],
                        coverage["mtime"],
                        coverage["manifest_matched_rule_ids_json"],
                        coverage["content_status"],
                        coverage["content_read"],
                        now,
                        now,
                    )
                )
            assignments.append("updated_at=?")
            values.extend((now, self.run_id, object_id))
            self.connection.execute(
                f"UPDATE objects SET {', '.join(assignments)} WHERE run_id=? AND object_id=?",
                values,
            )
            for observation in unclassified_records:
                self._upsert_unclassified_file(observation, now=now)
            if unclassified_deletions:
                self.delete_unclassified_files(unclassified_deletions)
            if checkpoint_name is not None:
                checkpoint_payload = json.dumps(
                    _json_value(checkpoint_value),
                    ensure_ascii=False,
                    sort_keys=True,
                )
                if checkpoint_updates is None:
                    self._write_checkpoint(checkpoint_name, checkpoint_payload, now)
                elif type(checkpoint_name) is not str:
                    # SQLite also accepts non-string bound names. Flush first
                    # so TEXT-affinity aliases (e.g. 1 and "1") keep their
                    # original ordering and invalid bindings still fail.
                    self._flush_checkpoints(checkpoint_updates)
                    self._write_checkpoint(checkpoint_name, checkpoint_payload, now)
                else:
                    # Serialize every observation, even an overwritten one:
                    # invalid/cyclic values must still roll back the batch.
                    # SQLite rejects unpaired surrogates when binding UTF-8;
                    # do not hide that error by discarding an earlier value.
                    name_size = (
                        len(checkpoint_name) if checkpoint_name.isascii() else len(checkpoint_name.encode("utf-8"))
                    )
                    payload_size = (
                        len(checkpoint_payload)
                        if checkpoint_payload.isascii()
                        else len(checkpoint_payload.encode("utf-8"))
                    )
                    # A discarded value must not conceal SQLite's length
                    # limit either. Use a conservative record-size bound;
                    # let SQLite decide borderline values in original order.
                    record_size_bound = name_size + payload_size + len(self.run_id) + len(now) + 128
                    if checkpoint_byte_limit is not None and record_size_bound >= checkpoint_byte_limit:
                        self._flush_checkpoints(checkpoint_updates)
                        self._write_checkpoint(checkpoint_name, checkpoint_payload, now)
                    else:
                        checkpoint_updates[checkpoint_name] = (checkpoint_payload, now)

    def _write_checkpoint(self, name, payload: str, now: str) -> None:
        self.connection.execute(
            """
            INSERT INTO checkpoints(run_id, name, value_json, updated_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(run_id, name)
            DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
            """,
            (self.run_id, name, payload, now),
        )

    def _flush_checkpoints(self, updates: dict[str, tuple[str, str]]) -> None:
        for name, (payload, now) in updates.items():
            self._write_checkpoint(name, payload, now)
        updates.clear()

    def complete_objects(self, completions: Iterable[Mapping]) -> None:
        """Commit terminal states and findings for a bounded group atomically."""

        completions = tuple(completions)
        if not completions:
            return
        with self.transaction():
            get_limit = getattr(self.connection, "getlimit", None)
            checkpoint_byte_limit = get_limit(sqlite3.SQLITE_LIMIT_LENGTH) if get_limit is not None else None
            # Python versions without the SQLite limit API retain the former
            # immediate writes rather than guessing the connection's limits.
            checkpoint_updates: dict[str, tuple[str, str]] | None = {} if get_limit is not None else None
            for values in completions:
                self._complete_object(
                    **dict(values),
                    checkpoint_updates=checkpoint_updates,
                    checkpoint_byte_limit=checkpoint_byte_limit,
                )
            if checkpoint_updates is not None:
                self._flush_checkpoints(checkpoint_updates)

    def mark_object_changed(
        self,
        object_id: int,
        post_read_identity: tuple[int | None, str | int | float | None, str | None] | None = None,
    ) -> None:
        """Accept a completed read and its latest identity without replacing findings."""

        with self.transaction():
            now = utc_now()
            if post_read_identity is None:
                cursor = self.connection.execute(
                    """
                    UPDATE objects SET changed=1, updated_at=?
                    WHERE run_id=? AND object_id=?
                    """,
                    (now, self.run_id, object_id),
                )
            else:
                size, mtime, file_id = post_read_identity
                cursor = self.connection.execute(
                    """
                    UPDATE objects
                    SET changed=1, size=?, mtime=?, file_id=?, updated_at=?
                    WHERE run_id=? AND object_id=?
                    """,
                    (
                        size,
                        None if mtime is None else str(mtime),
                        file_id,
                        now,
                        self.run_id,
                        object_id,
                    ),
                )
            if cursor.rowcount != 1:
                raise StateError(f"Unknown object id {object_id}")

    def increment_counter(self, name: str, amount: int = 1) -> int:
        with self.transaction():
            return self._increment_counter(name, amount)

    def _increment_counter(self, name: str, amount: int) -> int:
        self._add_counter(name, amount)
        row = self.connection.execute(
            "SELECT value FROM counters WHERE run_id=? AND name=?",
            (self.run_id, name),
        ).fetchone()
        return row["value"]

    def _add_counter(self, name: str, amount: int) -> None:
        self.connection.execute(
            """
            INSERT INTO counters(run_id, name, value) VALUES (?, ?, ?)
            ON CONFLICT(run_id, name) DO UPDATE SET value=value+excluded.value
            """,
            (self.run_id, name, amount),
        )

    def record_exclusion(
        self,
        *,
        object_key: str,
        kind: str,
        reason: str,
        target: str | None = None,
        share: str | None = None,
        path: str | None = None,
    ) -> bool:
        """Persist a unique exclusion without creating an object terminal status."""

        now = utc_now()
        with self.transaction():
            row = self.connection.execute(
                "SELECT exclusion_id FROM exclusions WHERE run_id=? AND object_key=?",
                (self.run_id, object_key),
            ).fetchone()
            if row is None:
                self.connection.execute(
                    """
                    INSERT INTO exclusions(
                        run_id, object_key, kind, target, share, path, reason,
                        first_seen_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (self.run_id, object_key, kind, target, share, path, reason, now, now),
                )
                self.connection.execute(
                    """
                    INSERT INTO counters(run_id, name, value) VALUES (?, 'excluded', 1)
                    ON CONFLICT(run_id, name) DO UPDATE SET value=value+1
                    """,
                    (self.run_id,),
                )
                return True
            self.connection.execute(
                """
                UPDATE exclusions
                SET kind=?, target=?, share=?, path=?, reason=?,
                    occurrences=occurrences+1, last_seen_at=?
                WHERE exclusion_id=?
                """,
                (kind, target, share, path, reason, now, row["exclusion_id"]),
            )
            return False

    def upsert_unclassified_files(self, records: Iterable[Mapping]) -> int:
        """Durably merge a bounded batch of passive file-coverage observations."""

        records = tuple(records)
        if not records:
            return 0
        now = utc_now()
        with self.transaction():
            for record in records:
                self._upsert_unclassified_file(record, now=now)
        return len(records)

    @staticmethod
    def _normalize_unclassified_file(record: Mapping) -> dict:
        object_key = str(record.get("object_key", ""))
        full_path = str(record.get("full_path", ""))
        filename = str(record.get("filename", ""))
        reasons = tuple(dict.fromkeys(str(reason) for reason in record.get("reasons", ()) if str(reason)))
        if not object_key or not full_path or not filename or not reasons:
            raise StateError("Unclassified-file observations require object_key, full_path, filename, and reasons")
        reasons, reason_mask = _encode_unclassified_reasons(reasons)
        matched_rule_ids = tuple(
            dict.fromkeys(str(rule_id) for rule_id in record.get("matched_rule_ids", ()) if str(rule_id))
        )
        content_read = record.get("content_read")
        if content_read is not None:
            content_read = int(bool(content_read))
        matched_rule_ids_json = json.dumps(
            matched_rule_ids,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return {
            "object_key": object_key,
            "target": None if record.get("target") is None else str(record.get("target")),
            "share": None if record.get("share") is None else str(record.get("share")),
            "path": str(record.get("path", "")),
            "full_path": full_path,
            "filename": filename,
            "extension": str(record.get("extension", "")),
            "extension_recognized": int(bool(record.get("extension_recognized", False))),
            "size": record.get("size"),
            "mtime": record.get("mtime"),
            "reasons": reasons,
            "reason_mask": reason_mask,
            "reasons_json": json.dumps(reasons, ensure_ascii=False, separators=(",", ":")),
            "matched_rule_ids_json": matched_rule_ids_json,
            "manifest_matched_rule_ids_json": matched_rule_ids_json if matched_rule_ids else None,
            "content_status": str(record.get("content_status", "not_requested")),
            "content_read": content_read,
            "processing_status": str(record.get("processing_status", "observed")),
            "processing_reason": (
                None if record.get("processing_reason") is None else str(record.get("processing_reason"))
            ),
        }

    def _upsert_unclassified_file(self, record: Mapping, *, now: str) -> None:
        normalized = self._normalize_unclassified_file(record)
        manifest_object_id = record.get("_manifest_object_id")
        if manifest_object_id is not None:
            self._update_manifest_unclassified_file(int(manifest_object_id), normalized, now=now)
            return
        values = (
            self.run_id,
            normalized["object_key"],
            normalized["target"],
            normalized["share"],
            normalized["path"],
            normalized["full_path"],
            normalized["filename"],
            normalized["extension"],
            normalized["extension_recognized"],
            normalized["size"],
            normalized["mtime"],
            normalized["reasons_json"],
            normalized["matched_rule_ids_json"],
            normalized["content_status"],
            normalized["content_read"],
            normalized["processing_status"],
            normalized["processing_reason"],
            now,
            now,
        )
        self.connection.execute(
            """
            INSERT INTO unclassified_files(
                run_id, object_key, target, share, path, full_path, filename,
                extension, extension_recognized, size, mtime, reasons_json,
                matched_rule_ids_json, content_status, content_read,
                processing_status, processing_reason, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, object_key) DO UPDATE SET
                target=excluded.target,
                share=excluded.share,
                path=excluded.path,
                full_path=excluded.full_path,
                filename=excluded.filename,
                extension=excluded.extension,
                extension_recognized=excluded.extension_recognized,
                size=excluded.size,
                mtime=excluded.mtime,
                reasons_json=excluded.reasons_json,
                matched_rule_ids_json=excluded.matched_rule_ids_json,
                content_status=excluded.content_status,
                content_read=excluded.content_read,
                processing_status=excluded.processing_status,
                processing_reason=excluded.processing_reason,
                last_seen_at=excluded.last_seen_at
            """,
            values,
        )

    def _update_manifest_unclassified_file(self, object_id: int, record: Mapping, *, now: str) -> None:
        cursor = self.connection.execute(
            """
            UPDATE objects
            SET coverage_reason_mask=?,
                coverage_size=?, coverage_mtime=?,
                coverage_matched_rule_ids_json=?, coverage_content_status=?,
                coverage_content_read=?, coverage_processing_status=?,
                coverage_processing_reason=?,
                coverage_first_seen_at=COALESCE(coverage_first_seen_at, ?),
                coverage_last_seen_at=?
            WHERE run_id=? AND object_id=? AND object_key=?
            """,
            (
                record["reason_mask"],
                record["size"],
                record["mtime"],
                record["manifest_matched_rule_ids_json"],
                record["content_status"],
                record["content_read"],
                record["processing_status"],
                record["processing_reason"],
                now,
                now,
                self.run_id,
                object_id,
                record["object_key"],
            ),
        )
        if cursor.rowcount != 1:
            raise StateError(f"Unknown or mismatched manifest object id {object_id}")

    def delete_unclassified_files(self, object_keys: Iterable[str]) -> int:
        """Remove prior observations which became covered when seen on resume."""

        keys = tuple(dict.fromkeys(str(key) for key in object_keys if str(key)))
        if not keys:
            return 0
        deleted = 0
        with self.transaction():
            for offset in range(0, len(keys), 500):
                batch = keys[offset : offset + 500]
                placeholders = ",".join("?" for _key in batch)
                cursor = self.connection.execute(
                    f"""
                    UPDATE objects
                    SET coverage_reason_mask=0,
                        coverage_size=NULL,
                        coverage_mtime=NULL,
                        coverage_matched_rule_ids_json=NULL,
                        coverage_content_status=NULL,
                        coverage_content_read=NULL,
                        coverage_processing_status=NULL,
                        coverage_processing_reason=NULL,
                        coverage_first_seen_at=NULL,
                        coverage_last_seen_at=NULL
                    WHERE run_id=? AND object_key IN ({placeholders})
                          AND coverage_reason_mask<>0
                    """,
                    (self.run_id, *batch),
                )
                deleted += cursor.rowcount
                cursor = self.connection.execute(
                    f"DELETE FROM unclassified_files WHERE run_id=? AND object_key IN ({placeholders})",
                    (self.run_id, *batch),
                )
                deleted += cursor.rowcount
        return deleted

    def iter_unclassified_files(self):
        """Stream deterministic rows for the adjacent coverage-gap JSONL report."""

        cursor = self.connection.execute(
            """
            SELECT *
            FROM (
                SELECT manifest.object_key,
                       manifest.target,
                       manifest.share,
                       manifest.path,
                       NULL AS full_path,
                       NULL AS filename,
                       NULL AS extension,
                       NULL AS extension_recognized,
                       coverage_size AS size,
                       coverage_mtime AS mtime,
                       NULL AS reasons_json,
                       coverage_reason_mask AS reason_mask,
                       COALESCE(coverage_matched_rule_ids_json, '[]') AS matched_rule_ids_json,
                       coverage_content_status AS content_status,
                       coverage_content_read AS content_read,
                       COALESCE(coverage_processing_status, manifest.status) AS processing_status,
                       CASE
                           WHEN coverage_processing_status IS NULL THEN manifest.reason
                           ELSE coverage_processing_reason
                       END AS processing_reason,
                       COALESCE(legacy.first_seen_at, coverage_first_seen_at) AS first_seen_at,
                       coverage_last_seen_at AS last_seen_at,
                       1 AS manifest_coverage
                FROM objects AS manifest
                LEFT JOIN unclassified_files AS legacy
                  ON legacy.run_id=manifest.run_id
                 AND legacy.object_key=manifest.object_key
                WHERE manifest.run_id=? AND coverage_reason_mask<>0

                UNION ALL

                SELECT legacy.object_key, legacy.target, legacy.share,
                       legacy.path, legacy.full_path, legacy.filename,
                       legacy.extension, legacy.extension_recognized,
                       legacy.size, legacy.mtime, legacy.reasons_json,
                       0 AS reason_mask, legacy.matched_rule_ids_json,
                       legacy.content_status, legacy.content_read,
                       legacy.processing_status, legacy.processing_reason,
                       legacy.first_seen_at, legacy.last_seen_at,
                       0 AS manifest_coverage
                FROM unclassified_files AS legacy
                WHERE legacy.run_id=?
                  AND NOT EXISTS (
                      SELECT 1
                      FROM objects AS manifest
                      WHERE manifest.run_id=legacy.run_id
                        AND manifest.object_key=legacy.object_key
                        AND manifest.coverage_reason_mask<>0
                  )
            )
            ORDER BY COALESCE(target, ''), COALESCE(share, ''), path, object_key
            """,
            (self.run_id, self.run_id),
        )
        for row in cursor:
            result = dict(row)
            if result["reason_mask"]:
                result["reasons_json"] = json.dumps(
                    _decode_unclassified_reasons(result["reason_mask"]),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            if result.pop("manifest_coverage"):
                path = str(result["path"] or "")
                if result["object_key"].startswith("local|"):
                    result["full_path"] = path
                    result["filename"] = Path(path).name
                else:
                    remote_path = path.replace("/", "\\").lstrip("\\")
                    result["filename"] = remote_path.rsplit("\\", 1)[-1]
                    target = str(result["target"] or "")
                    key_parts = result["object_key"].split("|", 4)
                    port = key_parts[2] if len(key_parts) == 5 else "445"
                    port_suffix = f":{port}"
                    host = target[: -len(port_suffix)] if port != "445" and target.endswith(port_suffix) else target
                    result["full_path"] = f"\\\\{host}\\{result['share']}\\{remote_path}"
                result["extension"] = "".join(Path(result["filename"]).suffixes).lower()
                result["extension_recognized"] = int(
                    bool(result["extension"])
                    and not result["reason_mask"] & UNCLASSIFIED_REASON_BITS["unrecognized_extension"]
                )
            result.pop("reason_mask")
            yield result

    def report_unclassified_files(self):
        """Return deterministic coverage-gap rows for callers needing a snapshot."""

        return list(self.iter_unclassified_files())

    def unclassified_count(self) -> int:
        return self.connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM objects WHERE run_id=? AND coverage_reason_mask<>0)
                +
                (
                    SELECT COUNT(*)
                    FROM unclassified_files AS legacy
                    WHERE legacy.run_id=?
                      AND NOT EXISTS (
                          SELECT 1
                          FROM objects AS manifest
                          WHERE manifest.run_id=legacy.run_id
                            AND manifest.object_key=legacy.object_key
                            AND manifest.coverage_reason_mask<>0
                      )
                )
            """,
            (self.run_id, self.run_id),
        ).fetchone()[0]

    def set_checkpoint(self, name: str, value) -> None:
        payload = json.dumps(_json_value(value), ensure_ascii=False, sort_keys=True)
        with self.transaction(telemetry_only=name == "scan_timing"):
            self.connection.execute(
                """
                INSERT INTO checkpoints(run_id, name, value_json, updated_at) VALUES (?, ?, ?, ?)
                ON CONFLICT(run_id, name) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
                """,
                (self.run_id, name, payload, utc_now()),
            )

    def get_checkpoint(self, name: str, default=None):
        row = self.connection.execute(
            "SELECT value_json FROM checkpoints WHERE run_id=? AND name=?",
            (self.run_id, name),
        ).fetchone()
        return default if row is None else json.loads(row["value_json"])

    def set_run_status(self, status: str, reason: str | None = None) -> None:
        if status not in RUN_STATUSES:
            raise StateError(f"Invalid run status: {status}")
        now = utc_now()
        completed_at = (
            now if status in {"complete", "complete_with_errors", "interrupted", "preflight_failed"} else None
        )
        with self.transaction():
            self.connection.execute(
                """
                UPDATE runs SET status=?, error_reason=?, updated_at=?, completed_at=?
                WHERE run_id=?
                """,
                (status, reason, now, completed_at, self.run_id),
            )
        if completed_at is not None:
            self._finish_scan_timing(status, now)

    def _finish_scan_timing(self, status: str, now: str) -> None:
        """Freeze the last monotonic duration, including supervisor interruption.

        A killed scanner can only supply its last heartbeat. Never extrapolate
        elapsed from wall time or let optional telemetry hide a primary error.
        """

        try:
            timing = self.get_checkpoint("scan_timing")
            if not isinstance(timing, dict) or timing.get("version") != 1:
                return
            elapsed = timing.get("elapsed_seconds")
            if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
                return
            if not math.isfinite(elapsed) or elapsed < 0:
                return
            if status in {"complete", "complete_with_errors"} and timing.get("eta") is not None:
                # Imported lazily: progress uses the manifest status constants.
                from man_spider.progress import ETAEstimate

                timing["eta"] = ETAEstimate(
                    status="complete", elapsed_seconds=float(elapsed),
                    remaining_seconds=0.0, lower_seconds=0.0, upper_seconds=0.0,
                    total_seconds=float(elapsed), confidence="high", basis="completed scope",
                ).as_dict()
            else:
                timing["eta"] = None
            timing["updated_at"] = now
            self.set_checkpoint("scan_timing", timing)
        except Exception as exc:
            logging.getLogger("manspider").warning("Unable to finalize local scan timing: %s", exc)

    def update_configuration(self, configuration: Mapping) -> None:
        """Finalize derived policy before the first manifest object is created."""

        object_count = self.connection.execute(
            "SELECT COUNT(*) FROM objects WHERE run_id=?",
            (self.run_id,),
        ).fetchone()[0]
        if object_count:
            raise StateError("Cannot change normalized scan configuration after traversal has started")
        config_json = json.dumps(_json_value(configuration), ensure_ascii=False, sort_keys=True)
        fingerprint = configuration_fingerprint(configuration)
        with self.transaction():
            self.connection.execute(
                "UPDATE runs SET config_json=?, config_fingerprint=?, updated_at=? WHERE run_id=?",
                (config_json, fingerprint, utc_now(), self.run_id),
            )

    def legacy_size_skip_count(self) -> int:
        """Count old size-only omissions for the read-only approval summary."""

        return self.connection.execute(
            f"SELECT COUNT(*) FROM objects WHERE {_LEGACY_SIZE_SKIP_PREDICATE}", (self.run_id,)
        ).fetchone()[0]

    def requeue_legacy_size_skips(self) -> int:
        """Repair old metadata omissions once, only after fresh scan approval.

        Old scanners finalized these files without emitting matched metadata.
        The new policy uses different reasons, so a later resume cannot keep
        rearming a still-oversized file. Keep existing evidence and attempt
        counts; the ordinary frontier reaches only the required ancestors.
        """

        with self.transaction():
            self.connection.execute(
                f"""
                UPDATE unclassified_files SET processing_status='pending', processing_reason=NULL
                WHERE run_id=? AND object_key IN (
                    SELECT object_key FROM objects WHERE {_LEGACY_SIZE_SKIP_PREDICATE}
                )
                """,
                (self.run_id, self.run_id),
            )
            cursor = self.connection.execute(
                f"""
                UPDATE objects SET status='pending', reason=NULL, updated_at=?,
                    analysis_status='unknown', analysis_reason=NULL, analysis_read=NULL,
                    coverage_processing_status=CASE WHEN coverage_reason_mask > 0 THEN 'pending'
                        ELSE coverage_processing_status END,
                    coverage_processing_reason=CASE WHEN coverage_reason_mask > 0 THEN NULL
                        ELSE coverage_processing_reason END
                WHERE {_LEGACY_SIZE_SKIP_PREDICATE}
                """,
                (utc_now(), self.run_id),
            )
            return cursor.rowcount

    def prepare_resume(self, *, retry_limit: int = 2) -> int:
        """Grant network failures and required exhausted ancestors one new visit.

        Run once, after successful preflight and before starting workers. Keep
        attempt counts and evidence intact; normal claims consume the new pending
        visit, and any subsequent failure is again subject to the retry limit.
        Network leaves stay terminal errors with a one-claim reason token, so
        vanished files do not become unexplained pending manifest objects.
        Other exhausted leaves and unrelated failures retain their budgets.
        """

        with self.transaction():
            network_updates = []
            now = utc_now()
            if not self._network_resume_prepared:
                for row in self.connection.execute(
                    f"""SELECT object_id, reason FROM objects WHERE run_id=? AND status='error'
                    AND substr(reason, 1, ?)=? AND {_REMOTE_NETWORK_OBJECT_PREDICATE}""",
                    (self.run_id, len(NETWORK_UNAVAILABLE_MARKER) + 1, NETWORK_UNAVAILABLE_MARKER + " "),
                ):
                    if not row["reason"].startswith(NETWORK_RESUME_READY_PREFIX):
                        reason = NETWORK_RESUME_READY_PREFIX + row["reason"][len(NETWORK_UNAVAILABLE_MARKER):].lstrip()
                        network_updates.append((reason, now, self.run_id, row["object_id"]))
                self.connection.executemany(
                    "UPDATE objects SET reason=?, updated_at=? WHERE run_id=? AND object_id=? AND status='error'",
                    network_updates,
                )
            exhausted = {
                row["object_key"]: row["object_id"]
                for row in self.connection.execute(
                    """
                    SELECT object_key, object_id FROM objects
                    WHERE run_id=? AND kind IN ('target', 'share', 'directory')
                      AND status='error' AND attempts >= ?
                      AND COALESCE(substr(reason, 1, ?), '') != ?
                    """,
                    (self.run_id, retry_limit, len(NETWORK_RESUME_READY_PREFIX), NETWORK_RESUME_READY_PREFIX),
                )
            }
            reopen = set()
            if exhausted:
                for row in self.resumable_objects(retry_limit=retry_limit):
                    reopen.update(
                        exhausted[key] for key in _ancestor_object_keys(row) if key in exhausted
                    )
            self.connection.executemany(
                """
                UPDATE objects SET status='pending', reason=NULL, updated_at=?
                WHERE run_id=? AND object_id=? AND status='error'
                """,
                ((now, self.run_id, object_id) for object_id in sorted(reopen)),
            )
        self._network_resume_prepared = True
        return len(reopen | {update[-1] for update in network_updates})

    def resolve_share_enumeration(self, object_key: str) -> bool:
        """Close an existing failed enumeration after a complete new observation.

        No synthetic object is created on healthy scans, and no file evidence
        or retry history is removed. This is an observation, not another claim.
        """

        with self.transaction():
            cursor = self.connection.execute(
                """UPDATE objects SET status='processed', reason=NULL, updated_at=?
                WHERE run_id=? AND object_key=? AND kind='share_enumeration'
                  AND status IN ('error', 'pending', 'in_progress')""",
                (utc_now(), self.run_id, object_key),
            )
            return cursor.rowcount == 1

    def settle_blocked_objects(self) -> int:
        """Account for unfinished descendants of failed or scope-blocked containers.

        Only call after workers finish normally, never during interruption or
        while workers may still complete objects. An unavailable ancestor means
        a descendant was not completed, not that it was successfully scanned.
        Leave unexplained unfinished work for finish() to reject as before.
        """

        with self.transaction():
            unfinished = self.connection.execute(
                """
                SELECT object_id, object_key, kind, target FROM objects
                WHERE run_id=? AND status IN ('pending', 'in_progress')
                """,
                (self.run_id,),
            ).fetchall()
            if not unfinished:
                return 0
            failed = {
                row["object_key"]: row
                for row in self.connection.execute(
                    """
                    SELECT object_key, reason, status FROM objects
                    WHERE run_id=? AND kind IN ('target', 'share', 'directory')
                      AND (status='error' OR (status='skipped' AND substr(reason, 1, ?)=?))
                    """,
                    (self.run_id, len(DFS_SCOPE_BLOCKED_MARKER), DFS_SCOPE_BLOCKED_MARKER),
                )
            }
            updates = []
            legacy_updates = []
            now = utc_now()
            for row in unfinished:
                for key in _ancestor_object_keys(row):
                    ancestor = failed.get(key)
                    if ancestor is None:
                        continue
                    ancestor_reason = ancestor["reason"] or "ancestor traversal failed"
                    # Classify before including the untrusted resource key.
                    # Keep the leading prefix intact for retry/rehydration.
                    refusal_marker = (
                        f"{NETWORK_ACCESS_DENIED_MARKER} " if is_network_access_denied(ancestor_reason) else ""
                    )
                    reason = (
                        f"{ANCESTOR_BLOCKED_REASON_PREFIX}{refusal_marker}{key}: {ancestor_reason}"
                    )
                    status = ancestor["status"]
                    updates.append((status, reason, now, status, reason, self.run_id, row["object_id"]))
                    legacy_updates.append((status, reason, self.run_id, row["object_key"]))
                    break
            # Do not use complete_object(): no new read occurred, so old
            # findings, identity and content-coverage evidence must survive.
            self.connection.executemany(
                """
                UPDATE objects SET status=?, reason=?, updated_at=?,
                    coverage_processing_status=CASE WHEN coverage_reason_mask > 0
                        THEN ? ELSE coverage_processing_status END,
                    coverage_processing_reason=CASE WHEN coverage_reason_mask > 0
                        THEN ? ELSE coverage_processing_reason END
                WHERE run_id=? AND object_id=?
                  AND status IN ('pending', 'in_progress')
                """,
                updates,
            )
            self.connection.executemany(
                """
                UPDATE unclassified_files SET processing_status=?, processing_reason=?
                WHERE run_id=? AND object_key=?
                """,
                legacy_updates,
            )
            return len(updates)

    def finish(self) -> str:
        nonterminal_rows = self.connection.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM objects
            WHERE run_id=? AND status IN ('pending', 'in_progress')
            GROUP BY status
            ORDER BY status
            """,
            (self.run_id,),
        ).fetchall()
        if nonterminal_rows:
            counts = ", ".join(f"{row['status']}={row['count']}" for row in nonterminal_rows)
            reason = f"Cannot finish scan while manifest objects are non-terminal: {counts}"
            self.set_run_status("interrupted", reason=reason)
            raise StateError(reason)

        error_rows = self.connection.execute(
            """
            SELECT kind, share, reason
            FROM objects
            WHERE run_id=? AND status='error'
            """,
            (self.run_id,),
        )
        status_affecting_error = any(
            not _network_access_error_is_non_status_affecting(
                kind=row["kind"],
                share=row["share"],
                reason=row["reason"],
            )
            for row in error_rows
        )
        status = "complete_with_errors" if status_affecting_error else "complete"
        self.set_run_status(status)
        return status

    def summary(self) -> dict:
        rows = self.connection.execute(
            "SELECT status, COUNT(*) AS count FROM objects WHERE run_id=? GROUP BY status",
            (self.run_id,),
        ).fetchall()
        result = {status: 0 for status in OBJECT_STATUSES}
        result.update({row["status"]: row["count"] for row in rows})
        result["findings"] = self.connection.execute(
            "SELECT COUNT(*) FROM findings WHERE run_id=?", (self.run_id,)
        ).fetchone()[0]
        result["excluded"] = self.connection.execute(
            "SELECT COUNT(*) FROM exclusions WHERE run_id=?", (self.run_id,)
        ).fetchone()[0]
        return result

    def progress_snapshot(self) -> dict:
        grouped = self.connection.execute(
            """
            SELECT kind, status, analysis_status, COUNT(*) AS count, SUM(changed) AS changed_count
            FROM objects WHERE run_id=? GROUP BY kind, status, analysis_status
            """,
            (self.run_id,),
        ).fetchall()
        by_kind = {}
        analysis_counts = {status: 0 for status in sorted(ANALYSIS_STATUSES)}
        changed_files = 0
        for row in grouped:
            by_kind.setdefault(row["kind"], {status: 0 for status in OBJECT_STATUSES})
            by_kind[row["kind"]][row["status"]] += row["count"]
            if row["kind"] == "file":
                analysis_counts[row["analysis_status"]] += row["count"]
                changed_files += row["changed_count"]
        counters = {
            row["name"]: row["value"]
            for row in self.connection.execute(
                "SELECT name, value FROM counters WHERE run_id=? AND name<>'data_revision'",
                (self.run_id,),
            ).fetchall()
        }
        return {
            "run_status": self.run_row()["status"],
            "objects": by_kind,
            "analysis_counts": analysis_counts,
            "changed_files": changed_files,
            "findings": self.connection.execute(
                "SELECT COUNT(*) FROM findings WHERE run_id=?",
                (self.run_id,),
            ).fetchone()[0],
            "excluded": self.connection.execute(
                "SELECT COUNT(*) FROM exclusions WHERE run_id=?",
                (self.run_id,),
            ).fetchone()[0],
            "counters": counters,
        }

    def run_row(self):
        return self.connection.execute("SELECT * FROM runs WHERE run_id=?", (self.run_id,)).fetchone()

    def object_row(self, object_id: int):
        return self.connection.execute(
            "SELECT * FROM objects WHERE run_id=? AND object_id=?", (self.run_id, object_id)
        ).fetchone()

    def resumable_objects(
        self,
        *,
        targets: Iterable[str] | None = None,
        retry_limit: int = 1,
    ) -> tuple[sqlite3.Row, ...]:
        """Return unfinished or still-retriable work used to build a resume frontier."""

        parameters: list[object] = [
            self.run_id, retry_limit, len(ANCESTOR_BLOCKED_REASON_PREFIX), ANCESTOR_BLOCKED_REASON_PREFIX,
            len(NETWORK_RESUME_READY_PREFIX), NETWORK_RESUME_READY_PREFIX,
        ]
        target_clause = ""
        if targets is not None:
            target_values = tuple(dict.fromkeys(str(target) for target in targets))
            if not target_values:
                return ()
            placeholders = ",".join("?" for _target in target_values)
            target_clause = f" AND target IN ({placeholders})"
            parameters.extend(target_values)
        return tuple(
            self.connection.execute(
                f"""
                SELECT object_id, object_key, kind, target, share, path,
                       status, attempts
                FROM objects
                WHERE run_id=?
                  AND (
                      status IN ('pending', 'in_progress')
                      OR (status='error' AND (attempts < ? OR substr(reason, 1, ?) = ?
                                            OR (substr(reason, 1, ?) = ? AND {_REMOTE_NETWORK_OBJECT_PREDICATE})))
                  )
                  {target_clause}
                ORDER BY object_id
                """,
                parameters,
            ).fetchall()
        )

    def findings_for(self, object_id: int):
        return self.connection.execute(
            f"SELECT {finding_projection()} FROM findings f {context_join(9)} "
            "WHERE f.run_id=? AND f.object_id=? ORDER BY f.finding_id",
            (self.run_id, object_id),
        ).fetchall()

    def report_findings(self):
        """Return every current finding with its owning object metadata."""

        return self.connection.execute(
            f"""
            SELECT {finding_projection()}, o.target, o.share, o.path, o.status AS object_status,
                   o.reason AS object_reason, o.changed, o.size, o.mtime,
                   o.analysis_status, o.analysis_reason, o.analysis_read
            FROM findings AS f
            {context_join(9)}
            JOIN objects AS o ON o.object_id=f.object_id AND o.run_id=f.run_id
            WHERE f.run_id=?
            ORDER BY COALESCE(o.target, ''), COALESCE(o.share, ''), o.path,
                     COALESCE(f.match_start, -1), COALESCE(f.match_end, -1),
                     f.rule_id, f.finding_id
            """,
            (self.run_id,),
        ).fetchall()

    def close(self) -> None:
        self.connection.close()
