"""Filename format hints shared by retrieval policy and representation dispatch.

These hints never rewrite a path, a CLI filter, a rule's metadata, or evidence.
They only recognize conventional backup copies of the same underlying format.
"""

import re
from pathlib import PurePosixPath


CONTENT_FORMAT_RESOLUTION = "backup-suffix-v1"
_BACKUP_END = re.compile(
    r"(?:\.(?:bak|old|orig|backup|save)(?:\.[0-9]{1,14})?|\.[0-9]{8}(?:[-_][0-9]{6})?|~)$",
    re.IGNORECASE,
)


def content_name(filename):
    """Remove only recognized trailing backup markers, never arbitrary suffixes."""
    name = str(filename).replace("\\", "/").rsplit("/", 1)[-1]
    while match := _BACKUP_END.search(name):
        if match.start() == 0:
            break
        name = name[: match.start()]
    return name


def content_suffix(filename):
    return PurePosixPath(content_name(filename)).suffix.lower()


def blocked_content_extension(filename, blocked, *, original_extension=None):
    """Apply the same blocks to a backup's real suffix and underlying format."""
    name = str(filename).replace("\\", "/").rsplit("/", 1)[-1]
    if original_extension is None:
        original_extension = "".join(PurePosixPath(name).suffixes).lower()
    hint = content_name(name)
    extensions = (original_extension,)
    if hint != name:
        extensions += ("".join(PurePosixPath(hint).suffixes).lower(),)
    return next(
        (candidate for candidate in blocked if candidate and any(ext.endswith(candidate) for ext in extensions)),
        None,
    )
