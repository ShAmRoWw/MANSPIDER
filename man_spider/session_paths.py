"""Names reserved for one local scan session, without importing scan runtime.

SQLite and the scan lease open their sibling files independently. Replacing a
sibling with a report is unsafe even when the database itself is not replaced.
These names remain reserved while absent as well as while actively in use.
"""

import os
from pathlib import Path
import time

from man_spider.path_safety import UnsafeWritePath, local_directory_descriptor


_RESERVED_SESSION_SUFFIXES = {
    "": "SQLite state file",
    "-wal": "SQLite write-ahead log",
    "-shm": "SQLite shared-memory file",
    "-journal": "SQLite rollback journal",
    ".lock": "scan-state lease lock",
    ".review": "finding-review database",
    ".review-wal": "finding-review write-ahead log",
    ".review-shm": "finding-review shared-memory file",
    ".review-journal": "finding-review rollback journal",
}


def iter_scan_state_paths(directory, *, suffixes=(".sqlite3",), warnings=None, deadline=None):
    """Find legacy flat states and states in individual session directories.

    Only one child directory level is inspected: never recursively walk loot,
    arbitrary directory trees, or symlinks. Open every directory through the
    same proven-local, no-follow guard used when reading a state database.
    Discovery is read-only and creates neither directories nor session files.
    """

    directory = Path(directory).expanduser().absolute()
    suffixes = frozenset(suffixes)
    expired = False

    def timed_out():
        nonlocal expired
        if not expired and deadline is not None and time.monotonic() >= deadline:
            expired = True
            if warnings is not None:
                warnings.append("Scan directory discovery time limit reached")
        return expired

    def walk(parent, descend):
        if timed_out():
            return
        try:
            with local_directory_descriptor(parent, purpose="scan discovery directory", create=False) as (fd, _):
                with os.scandir(fd) as entries:
                    for entry in entries:
                        if timed_out():
                            return
                        path = parent / entry.name
                        try:
                            is_directory = entry.is_dir(follow_symlinks=False)
                            is_file = entry.is_file(follow_symlinks=False)
                        except OSError:
                            continue
                        if is_file and path.suffix in suffixes:
                            yield path
                        elif descend and is_directory:
                            yield from walk(path, False)
        except FileNotFoundError:
            return
        except (UnsafeWritePath, OSError):
            if warnings is not None:
                warnings.append(f"Cannot read local scan directory: {parent.name}")

    yield from walk(directory, True)


def session_path_conflict(state_path: str | Path, destination: str | Path) -> str | None:
    """Describe a reserved destination, or return None for an unrelated path.

    Resolve ordinary aliases such as ``..`` consistently with the existing
    local-path validation. This is a name-reservation check, not a substitute
    for no-follow/ownership checks or a repair of existing session storage.
    """

    state = Path(state_path).resolve(strict=False)
    destination = Path(destination).resolve(strict=False)
    for suffix, description in _RESERVED_SESSION_SUFFIXES.items():
        if destination == state.with_name(state.name + suffix):
            return description
    return None
