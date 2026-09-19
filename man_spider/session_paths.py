"""Names reserved for one local scan session, without importing scan runtime.

SQLite and the scan lease open their sibling files independently. Replacing a
sibling with a report is unsafe even when the database itself is not replaced.
These names remain reserved while absent as well as while actively in use.
"""

from pathlib import Path


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
