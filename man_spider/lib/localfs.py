"""Bound local loot permission changes to the configured storage root."""

import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

from man_spider.path_safety import (
    local_directory_descriptor,
    require_local_directory_descriptor,
    require_local_write_path,
)


_DIRECTORY_FDS = (
    hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "fchmod")
    and os.open in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
    and os.rename in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
)
_LOCAL_OUTPUT_CAPABILITY = object()


class _GuardedLocalOutput:
    """Minimal write capability issued only by the validated loot writer."""

    __slots__ = ("_capability", "_stream")

    def __init__(self, stream):
        self._capability = _LOCAL_OUTPUT_CAPABILITY
        self._stream = stream

    def write(self, data):
        return self._stream.write(data)

    def flush(self):
        return self._stream.flush()

    def fileno(self):
        return self._stream.fileno()


def require_guarded_local_output(output):
    if not isinstance(output, _GuardedLocalOutput) or output._capability is not _LOCAL_OUTPUT_CAPABILITY:
        raise OSError("Remote content may only be copied through the guarded local loot writer")
    return output


@contextmanager
def atomic_local_text_output(destination, *, purpose):
    """Yield a text stream and atomically publish it in a pinned local directory."""

    destination = require_local_write_path(destination, purpose=purpose)
    if not _DIRECTORY_FDS:
        raise OSError("Safe report writing requires no-follow directory descriptor support on this platform")

    with local_directory_descriptor(
        destination.parent,
        purpose=f"{purpose} directory",
        create=True,
        created_mode=0o755,
    ) as (descriptor, parent):
        destination = parent / destination.name
        try:
            existing = os.stat(destination.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise OSError(f"{purpose} destination is not a regular file: {destination}")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        for _attempt in range(16):
            temporary_name = f".manspider-{secrets.token_hex(16)}.tmp"
            try:
                file_descriptor = os.open(temporary_name, flags, 0o600, dir_fd=descriptor)
            except FileExistsError:
                continue
            break
        else:
            raise FileExistsError(f"Unable to allocate a private temporary {purpose} file")

        published = False
        try:
            info = os.fstat(file_descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError(f"Temporary {purpose} output must be a private regular file")
            with os.fdopen(file_descriptor, "w", encoding="utf-8", closefd=False) as stream:
                yield stream
                stream.flush()
                os.fsync(file_descriptor)
                os.fchmod(file_descriptor, 0o664)
            os.close(file_descriptor)
            file_descriptor = None
            os.replace(temporary_name, destination.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
            published = True
            os.fsync(descriptor)
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)
            if not published:
                try:
                    os.unlink(temporary_name, dir_fd=descriptor)
                except FileNotFoundError:
                    pass


def normalize_loot_root(path):
    """Resolve a user-selected root once, before any worker changes its CWD."""

    return require_local_write_path(path, purpose="loot").resolve()


@contextmanager
def _directory_descriptor(path):
    """Open a canonical absolute directory without following swapped symlinks."""

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        require_local_directory_descriptor(descriptor, purpose="loot path component")
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            require_local_directory_descriptor(descriptor, purpose="loot path component")
        yield descriptor
    finally:
        os.close(descriptor)


def prepare_loot_root(path):
    root = normalize_loot_root(path)
    if _DIRECTORY_FDS:
        with local_directory_descriptor(
            root,
            purpose="loot root",
            create=True,
            created_mode=0o755,
        ) as (descriptor, root):
            os.fchmod(descriptor, 0o755)
    else:
        raise OSError("Safe loot preparation requires no-follow directory descriptor support on this platform")
    return root


@contextmanager
def loot_storage_file(root, destination):
    """Atomically publish a new loot inode through pinned directory descriptors.

    Every chmod uses an opened descriptor, never a path or a lexical ancestor
    walk. Directory symlinks below root are rejected. The old final inode is
    never opened for writing: replacing a final symlink/hardlink only replaces
    its directory entry. This assumes a trusted local storage directory, not
    a sandbox against a local owner/admin who can relocate opened directories.
    """

    root = Path(root)
    relative = Path(destination).relative_to(root)
    if not root.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("Loot destination must be a file within an absolute loot root")
    if not _DIRECTORY_FDS:
        raise OSError("Safe loot saving requires no-follow directory descriptor support on this platform")

    with _directory_descriptor(root) as root_descriptor:
        os.fchmod(root_descriptor, 0o755)
        descriptor = os.dup(root_descriptor)
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            for component in relative.parts[:-1]:
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                require_local_directory_descriptor(descriptor, purpose="loot destination component")
                os.fchmod(descriptor, 0o755)

            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            for _attempt in range(8):
                temporary_name = f".manspider-{secrets.token_hex(16)}.tmp"
                try:
                    file_descriptor = os.open(temporary_name, flags, 0o600, dir_fd=descriptor)
                except FileExistsError:
                    continue
                break
            else:
                raise FileExistsError("Unable to allocate a unique temporary loot file")

            published = False
            try:
                try:
                    info = os.fstat(file_descriptor)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise OSError("Temporary loot must be a new regular file without additional hard links")
                    with os.fdopen(file_descriptor, "wb", closefd=False) as output:
                        yield _GuardedLocalOutput(output)
                        output.flush()
                        os.fchmod(file_descriptor, 0o664)
                finally:
                    os.close(file_descriptor)
                os.replace(temporary_name, relative.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
                published = True
            finally:
                if not published:
                    try:
                        os.unlink(temporary_name, dir_fd=descriptor)
                    except FileNotFoundError:
                        pass
        finally:
            os.close(descriptor)
