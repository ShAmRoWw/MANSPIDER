"""Fail-closed checks for paths MANSPIDER may modify.

The SMB client is read-only, but an ordinary filesystem path can itself be a
UNC path or live on a mounted network filesystem.  State, logs, temporary
files, and loot must therefore be proven local before they are created.  This
module deliberately treats an unknown filesystem as unsafe: silently guessing
"local" would defeat the invariant it exists to enforce.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
import sys
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path


class UnsafeWritePath(ValueError):
    """Raised when a path that MANSPIDER may modify is not proven local."""


# Filesystems whose storage is local to the scanner host (or ephemeral in its
# own kernel/container namespace).  Keep this an allowlist rather than trying
# to enumerate every network/distributed filesystem name.
_LINUX_LOCAL_FILESYSTEMS = frozenset(
    {
        "aufs",
        "btrfs",
        "erofs",
        "exfat",
        "ext2",
        "ext3",
        "ext4",
        "f2fs",
        "hfs",
        "hfsplus",
        "jfs",
        "nilfs2",
        "ntfs",
        "ntfs3",
        "overlay",
        "ramfs",
        "reiserfs",
        "squashfs",
        "tmpfs",
        "ubifs",
        "udf",
        "ufs",
        "vfat",
        "xfs",
        "zfs",
    }
)

_REMOTE_URI = re.compile(r"(?i)^(?:smb|cifs|nfs|sshfs|dav|webdav)://")
_MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")
_SAFE_LOCAL_DIRECTORY_FDS = (
    os.name == "posix"
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "fchmod")
    and os.open in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
)
_SAFE_LOCAL_REMOVAL_FDS = (
    _SAFE_LOCAL_DIRECTORY_FDS
    and os.stat in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
    and os.rmdir in os.supports_dir_fd
)


def _has_untrusted_writers(info: os.stat_result) -> bool:
    # POSIX ACL masks are reflected in the group-class mode bits. Treating
    # every group/other write bit as hostile therefore also catches a named
    # ACL such as ``user:nobody:rwx`` even when the owning group is private.
    return bool(stat.S_IMODE(info.st_mode) & 0o022)


def _shared_directory_is_sticky_and_trusted(info: os.stat_result) -> bool:
    """Accept shared sticky directories only when self or root controls them."""

    mode = stat.S_IMODE(info.st_mode)
    return bool(mode & stat.S_ISVTX) and info.st_uid in {0, os.geteuid()}


def _lexical_absolute(path: str | os.PathLike[str]) -> Path:
    """Collapse ``.``/``..`` before classifying or returning a writable path."""

    expanded = Path(path).expanduser()
    return Path(os.path.abspath(os.fspath(expanded)))


def _decode_mount_field(value: str) -> str:
    """Decode the octal escaping used by Linux mountinfo."""

    return _MOUNT_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _nearest_existing_path(path: Path) -> Path:
    candidate = path
    while True:
        try:
            candidate.lstat()
        except FileNotFoundError:
            parent = candidate.parent
            if parent == candidate:
                raise UnsafeWritePath(f"no existing ancestor can establish the filesystem for {path}")
            candidate = parent
        except OSError as exc:
            raise UnsafeWritePath(f"cannot establish the filesystem for {path}: {exc}") from exc
        else:
            try:
                return candidate.resolve(strict=True)
            except FileNotFoundError as exc:
                # lstat succeeded, so this is a dangling symlink (possibly in
                # an intermediate component), not an absent output leaf.  Do
                # not climb to its lexical parent and misclassify the target.
                raise UnsafeWritePath(f"dangling symlink prevents proving {path} is local") from exc
            except OSError as exc:
                raise UnsafeWritePath(f"cannot resolve {path} safely: {exc}") from exc


def _reject_write_symlink_components(path: Path) -> None:
    """Reject every existing symlink component in a path MANSPIDER may write.

    Following even a locally stored symlink can redirect a later create,
    chmod, SQLite open, or log write to a network mount after the backing
    filesystem check.  A strict no-symlink rule is predictable and lets the
    actual writers use descriptor-relative operations as a second layer.
    """

    candidate = _lexical_absolute(path)
    anchor = Path(candidate.anchor)
    current = anchor
    for component in candidate.parts[len(anchor.parts) :]:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise UnsafeWritePath(f"cannot inspect write-path component {current}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise UnsafeWritePath(f"write path contains a symlink component: {current}")
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if os.name == "nt" and reparse_flag and getattr(info, "st_file_attributes", 0) & reparse_flag:
            # Junctions, mount points, and other reparse objects are not
            # necessarily reported as symbolic links and can target UNC.
            raise UnsafeWritePath(f"write path contains a Windows reparse component: {current}")


def _linux_filesystem_type(path: Path, *, mountinfo_path: Path = Path("/proc/self/mountinfo")) -> str:
    existing = _nearest_existing_path(path)
    try:
        lines = mountinfo_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise UnsafeWritePath(f"cannot read {mountinfo_path} to prove {path} is local: {exc}") from exc

    best_mount = None
    best_type = None
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
            mount_point = Path(_decode_mount_field(fields[4]))
            filesystem_type = fields[separator + 1]
        except (ValueError, IndexError):
            continue
        try:
            belongs = existing == mount_point or existing.is_relative_to(mount_point)
        except (OSError, ValueError):
            belongs = False
        if belongs and (best_mount is None or len(mount_point.parts) > len(best_mount.parts)):
            best_mount = mount_point
            best_type = filesystem_type
    if best_type is None:
        raise UnsafeWritePath(f"no mount entry can prove {path} is on a local filesystem")
    return best_type


def _windows_drive_type(path: Path) -> int:
    # Delay ctypes import so importing MANSPIDER on non-Windows platforms has
    # no platform-specific side effect.
    import ctypes

    absolute = str(_lexical_absolute(path))
    buffer_size = 32768
    buffer = ctypes.create_unicode_buffer(buffer_size)
    length = ctypes.windll.kernel32.GetVolumePathNameW(absolute, buffer, buffer_size)
    if not length:
        # GetDriveTypeW still recognizes a normal drive root when the final
        # output path does not exist yet.
        drive, _tail = os.path.splitdrive(absolute)
        root = drive + "\\" if drive else absolute
    else:
        root = buffer.value
    return int(ctypes.windll.kernel32.GetDriveTypeW(root))


def filesystem_type(path: str | os.PathLike[str]) -> str:
    """Return a stable local filesystem description or raise fail-closed."""

    raw = os.fspath(path)
    if not raw or "\x00" in raw:
        raise UnsafeWritePath("write path is empty or contains NUL")
    if _REMOTE_URI.match(raw):
        raise UnsafeWritePath(f"network URI is not a local write path: {raw}")
    # Reject both Windows UNC spelling and POSIX double-slash network spelling
    # before Path normalization can erase the evidence.
    if raw.startswith("\\\\") or raw.startswith("//"):
        raise UnsafeWritePath(f"UNC/network path is not a local write path: {raw}")

    candidate = _lexical_absolute(raw)
    if sys.platform.startswith("linux"):
        return _linux_filesystem_type(candidate)
    if os.name == "nt":
        _reject_write_symlink_components(candidate)
        drive_type = _windows_drive_type(candidate)
        # DRIVE_FIXED=3 and DRIVE_RAMDISK=6 are the only writable types that
        # prove storage is not a mapped/UNC network drive.
        if drive_type not in (3, 6):
            raise UnsafeWritePath(f"Windows drive type {drive_type} is not proven local for {candidate}")
        return "windows-fixed" if drive_type == 3 else "windows-ramdisk"
    raise UnsafeWritePath(f"platform {sys.platform!r} cannot prove that {candidate} is local")


def require_local_path(path: str | os.PathLike[str], *, purpose: str = "path") -> Path:
    """Normalize *path* and reject every filesystem not explicitly local."""

    raw = os.fspath(path)
    try:
        kind = filesystem_type(raw)
    except UnsafeWritePath as exc:
        raise UnsafeWritePath(f"Unsafe {purpose} path: {exc}") from exc
    if sys.platform.startswith("linux") and kind not in _LINUX_LOCAL_FILESYSTEMS:
        raise UnsafeWritePath(
            f"Unsafe {purpose}: filesystem {kind!r} is not in MANSPIDER's local-filesystem allowlist: {raw}"
        )
    return _lexical_absolute(raw)


def require_local_write_path(path: str | os.PathLike[str], *, purpose: str = "output") -> Path:
    """Require a local destination before MANSPIDER may create or change it."""

    candidate = require_local_path(path, purpose=f"{purpose} path")
    try:
        _reject_write_symlink_components(candidate)
    except UnsafeWritePath as exc:
        raise UnsafeWritePath(f"Unsafe {purpose} path: {exc}") from exc
    return candidate


def require_local_directory_descriptor(descriptor: int, *, purpose: str = "directory") -> Path:
    """Prove that an already-open directory still belongs to local storage."""

    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise UnsafeWritePath(f"Cannot inspect opened {purpose} descriptor: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafeWritePath(f"Opened {purpose} descriptor is not a directory")
    if not sys.platform.startswith("linux"):
        raise UnsafeWritePath(f"Platform {sys.platform!r} cannot prove an opened {purpose} is local")
    try:
        resolved = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
    except OSError as exc:
        raise UnsafeWritePath(f"Cannot resolve opened {purpose} descriptor: {exc}") from exc
    return require_local_path(resolved, purpose=f"opened {purpose}")


def require_local_file_descriptor(descriptor: int, *, purpose: str = "file") -> Path:
    """Prove that an already-open regular file is still on local storage."""

    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise UnsafeWritePath(f"Cannot inspect opened {purpose} descriptor: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeWritePath(f"Opened {purpose} descriptor is not a regular file")
    if not sys.platform.startswith("linux"):
        raise UnsafeWritePath(f"Platform {sys.platform!r} cannot prove an opened {purpose} is local")
    try:
        resolved = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
    except OSError as exc:
        raise UnsafeWritePath(f"Cannot resolve opened {purpose} descriptor: {exc}") from exc
    return require_local_path(resolved, purpose=f"opened {purpose}")


def require_safe_output_descriptor(descriptor: int, *, purpose: str = "output stream") -> None:
    """Reject a regular output file unless its backing filesystem is local.

    Pipes and terminal devices are capabilities supplied by the caller and are
    not filesystem paths MANSPIDER can classify. Sockets are rejected;
    responsibility for what a separate downstream process does with a pipe
    remains outside the scanner process boundary.
    """

    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise UnsafeWritePath(f"Cannot inspect {purpose}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        if stat.S_ISFIFO(info.st_mode) or stat.S_ISCHR(info.st_mode):
            return
        raise UnsafeWritePath(f"Unsafe {purpose}: unsupported descriptor type")
    try:
        require_local_file_descriptor(descriptor, purpose=purpose)
    except UnsafeWritePath:
        # An unlinked local TemporaryFile appears as ``... (deleted)`` and
        # cannot be resolved strictly. Classify its former parent mount while
        # retaining the already-open inode capability.
        if sys.platform.startswith("linux"):
            try:
                linked = os.readlink(f"/proc/self/fd/{descriptor}")
            except OSError:
                raise
            if linked.endswith(" (deleted)"):
                require_local_path(linked[: -len(" (deleted)")], purpose=purpose)
                return
        raise


def require_safe_standard_streams() -> None:
    """Ensure direct stdout/stderr file descriptors cannot target a network mount."""

    require_safe_output_descriptor(1, purpose="standard output")
    require_safe_output_descriptor(2, purpose="standard error")


@contextmanager
def local_directory_descriptor(
    path: str | os.PathLike[str],
    *,
    purpose: str = "directory",
    create: bool = False,
    created_mode: int = 0o700,
    require_trusted_owners: bool = True,
):
    """Pin a proven-local directory while optionally creating missing parts.

    Missing components are created with ``mkdirat`` below an already-open
    local descriptor.  This prevents a rename/symlink race from redirecting
    the first creation to customer-mounted storage.
    """

    candidate = require_local_write_path(path, purpose=purpose)
    if not _SAFE_LOCAL_DIRECTORY_FDS:
        raise UnsafeWritePath(f"Safe {purpose} access requires POSIX no-follow directory descriptors")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(candidate.anchor, flags)
    try:
        require_local_directory_descriptor(descriptor, purpose=purpose)
        protected_by_private_ancestor = False
        anchor_parts = len(Path(candidate.anchor).parts)
        for component in candidate.parts[anchor_parts:]:
            parent_info = os.fstat(descriptor)
            parent_is_shared = _has_untrusted_writers(parent_info)
            if (
                require_trusted_owners
                and not protected_by_private_ancestor
                and parent_is_shared
                and not _shared_directory_is_sticky_and_trusted(parent_info)
            ):
                raise UnsafeWritePath(
                    f"Unsafe {purpose}: ancestor is writable by group or other users without sticky protection"
                )
            created = False
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, created_mode, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            require_local_directory_descriptor(descriptor, purpose=purpose)
            child_info = os.fstat(descriptor)
            if (
                require_trusted_owners
                and not protected_by_private_ancestor
                and child_info.st_uid not in {0, os.geteuid()}
            ):
                raise UnsafeWritePath(
                    f"Unsafe {purpose}: path component is controlled by untrusted UID {child_info.st_uid}"
                )
            if (
                require_trusted_owners
                and not protected_by_private_ancestor
                and parent_is_shared
                and child_info.st_uid != os.geteuid()
            ):
                raise UnsafeWritePath(
                    f"Unsafe {purpose}: entry below a shared sticky directory is not owned by "
                    f"effective UID {os.geteuid()}"
                )
            if created:
                os.fchmod(descriptor, created_mode)
                child_info = os.fstat(descriptor)
            if require_trusted_owners and not stat.S_IMODE(child_info.st_mode) & 0o077:
                # Once an owner-controlled directory denies all group/other
                # traversal, descendants cannot be renamed through this path
                # by another UID. ACL access would make the group mask nonzero.
                protected_by_private_ancestor = True
        final_info = os.fstat(descriptor)
        if (
            require_trusted_owners
            and not protected_by_private_ancestor
            and final_info.st_uid not in {0, os.geteuid()}
        ):
            raise UnsafeWritePath(
                f"Unsafe {purpose}: directory is controlled by untrusted UID {final_info.st_uid}"
            )
        if (
            require_trusted_owners
            and not protected_by_private_ancestor
            and _has_untrusted_writers(final_info)
            and not _shared_directory_is_sticky_and_trusted(final_info)
        ):
            raise UnsafeWritePath(
                f"Unsafe {purpose}: directory is writable by group or other users without sticky protection"
            )
        yield descriptor, require_local_directory_descriptor(descriptor, purpose=purpose)
    finally:
        os.close(descriptor)


def create_private_local_directory(
    base: str | os.PathLike[str],
    *,
    prefix: str,
    purpose: str,
) -> tuple[Path, tuple[int, int]]:
    """Create a random 0700 child without a path-based creation window."""

    with local_directory_descriptor(base, purpose=f"{purpose} base") as (base_descriptor, _resolved_base):
        for _attempt in range(32):
            name = f"{prefix}{secrets.token_hex(16)}"
            try:
                os.mkdir(name, 0o700, dir_fd=base_descriptor)
            except FileExistsError:
                continue
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            child_descriptor = os.open(name, flags, dir_fd=base_descriptor)
            try:
                resolved = require_local_directory_descriptor(child_descriptor, purpose=purpose)
                os.fchmod(child_descriptor, 0o700)
                info = os.fstat(child_descriptor)
                return resolved, (info.st_dev, info.st_ino)
            except BaseException:
                # The directory is local and was created by this call, but a
                # failed proof is not enough authority to delete it here.
                raise
            finally:
                os.close(child_descriptor)
    raise FileExistsError(f"Unable to allocate a unique private {purpose}")


@contextmanager
def local_file_descriptor(path: str | os.PathLike[str], *, purpose: str = "local input file"):
    """Open a proven-local regular file without following any path link."""

    candidate = require_local_write_path(path, purpose=purpose)
    with local_directory_descriptor(
        candidate.parent,
        purpose=f"{purpose} parent",
        require_trusted_owners=False,
    ) as (
        parent_descriptor,
        _resolved_parent,
    ):
        descriptor = os.open(candidate.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafeWritePath(f"Unsafe {purpose}: opened object is not a regular file: {candidate}")
            resolved = require_local_file_descriptor(descriptor, purpose=purpose)
            yield descriptor, resolved
        finally:
            os.close(descriptor)


@contextmanager
def anonymous_local_file(base: str | os.PathLike[str], *, purpose: str = "temporary materialization"):
    """Yield an unlinked private local file and a path usable by child tools."""

    with local_directory_descriptor(base, purpose=f"{purpose} directory", create=True) as (
        parent_descriptor,
        _resolved_parent,
    ):
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = None
        name = None
        for _attempt in range(32):
            name = f".manspider-{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
            except FileExistsError:
                continue
            break
        if descriptor is None:
            raise FileExistsError(f"Unable to allocate a private {purpose}")
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise UnsafeWritePath(f"Temporary {purpose} is not a private regular file")
            os.unlink(name, dir_fd=parent_descriptor)
            # `/proc/self` would resolve in a spawned extractor process and
            # refer to its unrelated descriptor table. Pin the owner PID.
            descriptor_path = Path(f"/proc/{os.getpid()}/fd/{descriptor}")
            yield descriptor, descriptor_path
        finally:
            os.close(descriptor)


def _audit_local_tree(descriptor: int, display_path: Path, *, purpose: str) -> None:
    for name in os.listdir(descriptor):
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        child_path = display_path / name
        if stat.S_ISLNK(info.st_mode):
            raise UnsafeWritePath(f"Unsafe {purpose}: temporary tree contains a symlink: {child_path}")
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                require_local_directory_descriptor(child, purpose=purpose)
                _audit_local_tree(child, child_path, purpose=purpose)
            finally:
                os.close(child)
            continue
        if stat.S_ISREG(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if opened.st_nlink != 1:
                    raise UnsafeWritePath(f"Unsafe {purpose}: temporary file has additional hard links: {child_path}")
                require_local_file_descriptor(child, purpose=purpose)
            finally:
                os.close(child)
            continue
        raise UnsafeWritePath(f"Unsafe {purpose}: unsupported temporary-tree object: {child_path}")


def _remove_audited_local_tree(descriptor: int, display_path: Path, *, purpose: str) -> None:
    for name in os.listdir(descriptor):
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        child_path = display_path / name
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                require_local_directory_descriptor(child, purpose=purpose)
                _remove_audited_local_tree(child, child_path, purpose=purpose)
            finally:
                os.close(child)
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (
                info.st_dev,
                info.st_ino,
            ):
                raise UnsafeWritePath(f"Unsafe {purpose}: directory changed before removal: {child_path}")
            os.rmdir(name, dir_fd=descriptor)
            continue
        if stat.S_ISREG(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise UnsafeWritePath(f"Unsafe {purpose}: file changed before removal: {child_path}")
                require_local_file_descriptor(child, purpose=purpose)
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise UnsafeWritePath(f"Unsafe {purpose}: file changed before unlink: {child_path}")
                os.unlink(name, dir_fd=descriptor)
            finally:
                os.close(child)
            continue
        raise UnsafeWritePath(f"Unsafe {purpose}: tree changed to an unsupported object: {child_path}")


def remove_owned_local_tree(
    path: str | os.PathLike[str],
    *,
    expected_identity: tuple[int, int],
    purpose: str = "temporary cleanup",
) -> None:
    """Remove only a proven-owned local tree through pinned descriptors."""

    if not _SAFE_LOCAL_REMOVAL_FDS:
        raise UnsafeWritePath(f"Safe {purpose} requires descriptor-relative removal support")
    candidate = require_local_write_path(path, purpose=purpose)
    with local_directory_descriptor(candidate.parent, purpose=f"{purpose} parent") as (
        parent_descriptor,
        resolved_parent,
    ):
        descriptor = os.open(candidate.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
        try:
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != expected_identity:
                raise UnsafeWritePath(f"Unsafe {purpose}: root identity changed: {candidate}")
            root = resolved_parent / candidate.name
            require_local_directory_descriptor(descriptor, purpose=purpose)
            _audit_local_tree(descriptor, root, purpose=purpose)
            _remove_audited_local_tree(descriptor, root, purpose=purpose)
        finally:
            os.close(descriptor)
        current = os.stat(candidate.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != expected_identity:
            raise UnsafeWritePath(f"Unsafe {purpose}: root changed before removal: {candidate}")
        os.rmdir(candidate.name, dir_fd=parent_descriptor)


def safe_temporary_directory(environ: Mapping[str, str] | None = None) -> Path:
    """Choose an existing, writable local temporary directory without probing it.

    ``tempfile.gettempdir()`` establishes usability by creating and deleting a
    test file.  That normally harmless probe is unacceptable here: an operator
    can point ``TMPDIR``/``TEMP``/``TMP`` at UNC or mounted customer storage,
    which would cause a remote mutation before MANSPIDER could reject the
    location.  This resolver performs only metadata checks; the first actual
    creation is the explicitly guarded MANSPIDER temporary object.

    An explicitly configured temporary directory is authoritative and fails
    closed.  Silently falling back after rejecting it would hide a dangerous
    configuration and make the effective storage location surprising.
    """

    environment = os.environ if environ is None else environ
    for variable in ("TMPDIR", "TEMP", "TMP"):
        raw = environment.get(variable)
        if not raw:
            continue
        candidate = require_local_write_path(raw, purpose=f"temporary storage from ${variable}")
        try:
            with local_directory_descriptor(
                candidate,
                purpose=f"temporary storage from ${variable}",
            ) as (_descriptor, resolved):
                pass
        except FileNotFoundError as exc:
            raise UnsafeWritePath(
                f"Unsafe temporary storage from ${variable}: directory does not exist: {candidate}"
            ) from exc
        except OSError as exc:
            raise UnsafeWritePath(
                f"Unsafe temporary storage from ${variable}: cannot inspect {candidate}: {exc}"
            ) from exc
        if not os.access(candidate, os.W_OK | os.X_OK):
            raise UnsafeWritePath(
                f"Unsafe temporary storage from ${variable}: directory is not writable/searchable: {candidate}"
            )
        return resolved

    if os.name == "nt":
        defaults = []
        system_root = environment.get("SystemRoot") or environment.get("WINDIR")
        if system_root:
            defaults.append(Path(system_root) / "Temp")
        user_profile = environment.get("USERPROFILE")
        if user_profile:
            defaults.append(Path(user_profile) / "AppData" / "Local" / "Temp")
        defaults.append(Path.cwd())
    else:
        defaults = [Path("/tmp"), Path("/var/tmp"), Path("/usr/tmp"), Path.cwd()]

    rejection_reasons = []
    for raw_candidate in defaults:
        try:
            candidate = require_local_write_path(raw_candidate, purpose="temporary storage")
            with local_directory_descriptor(candidate, purpose="temporary storage") as (_descriptor, resolved):
                pass
            if not os.access(candidate, os.W_OK | os.X_OK):
                rejection_reasons.append(f"{candidate}: not writable/searchable")
                continue
            return resolved
        except (OSError, UnsafeWritePath) as exc:
            rejection_reasons.append(f"{raw_candidate}: {exc}")

    details = "; ".join(rejection_reasons) or "no platform candidates"
    raise UnsafeWritePath(f"No proven-local usable temporary directory is available: {details}")
