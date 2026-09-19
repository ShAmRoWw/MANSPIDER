import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import man_spider.lib.spiderling as spiderling_module
import man_spider.lib.localfs as localfs_module
import man_spider.path_safety as path_safety_module
from man_spider.lib.errors import FileRetrievalError
from man_spider.lib.file import (
    FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN,
    RemoteFile,
    remote_loot_destination,
)
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.lib.localfs import loot_storage_file, normalize_loot_root, prepare_loot_root
from man_spider.path_safety import UnsafeWritePath


def remote_file(tmp_path, target, share, name, payload, source_name=None):
    remote = RemoteFile(name, share, target, size=len(payload), tmp_dir=tmp_path)
    remote.tmp_filename = tmp_path / (source_name or f"source-{share}.bin")
    remote.tmp_filename.write_bytes(payload)
    return remote


def test_loot_preserves_bytes_and_network_hierarchy_for_each_location(tmp_path):
    loot_dir = tmp_path / "loot"
    loot_dir.mkdir()
    spiderling = Spiderling.__new__(Spiderling)
    spiderling.parent = SimpleNamespace(loot_dir=loot_dir)
    payload = bytes(range(256)) * 4
    target = Target("server.test.local", 1445)
    first = remote_file(tmp_path, target, "Share One", r"folder\same.bin", payload)
    second = remote_file(tmp_path, target, "Share Two", r"folder\same.bin", payload)

    assert spiderling.save_file(first) is True
    assert spiderling.save_file(second) is True

    first_destination = loot_dir / "server.test.local_port-1445" / "Share One" / "folder" / "same.bin"
    second_destination = loot_dir / "server.test.local_port-1445" / "Share Two" / "folder" / "same.bin"
    assert first_destination.read_bytes() == payload
    assert second_destination.read_bytes() == payload
    assert first_destination != second_destination
    assert stat.S_IMODE(first_destination.stat().st_mode) == 0o664
    assert stat.S_IMODE(first_destination.parent.stat().st_mode) == 0o755


def test_identical_loot_from_different_targets_and_ports_stays_separate(tmp_path):
    loot_dir = tmp_path / "loot"
    loot_dir.mkdir()
    spiderling = Spiderling.__new__(Spiderling)
    spiderling.parent = SimpleNamespace(loot_dir=loot_dir)
    payload = b"identical remote bytes\x00\xff"
    locations = (
        (Target("server-a.test.local"), "source-a.bin"),
        (Target("server-b.test.local"), "source-b.bin"),
        (Target("server-a.test.local", 1445), "source-a-1445.bin"),
    )

    for target, source_name in locations:
        remote = remote_file(
            tmp_path,
            target,
            "Shared",
            r"same\path\secret.bin",
            payload,
            source_name=source_name,
        )
        assert spiderling.save_file(remote) is True

    destinations = (
        loot_dir / "server-a.test.local" / "Shared" / "same" / "path" / "secret.bin",
        loot_dir / "server-b.test.local" / "Shared" / "same" / "path" / "secret.bin",
        loot_dir / "server-a.test.local_port-1445" / "Shared" / "same" / "path" / "secret.bin",
    )
    assert len(set(destinations)) == 3
    assert [destination.read_bytes() for destination in destinations] == [payload] * 3


def test_loot_path_components_cannot_escape_the_configured_root(tmp_path):
    loot_dir = tmp_path / "loot"
    remote = RemoteFile(r"..\folder/..\secret.txt", "../share", Target("host/name"))

    destination = remote_loot_destination(loot_dir, remote)

    assert destination == (
        loot_dir.resolve() / "host_name" / ".._share" / "_dotdot_" / "folder" / "_dotdot_" / "secret.txt"
    )
    assert destination.is_relative_to(loot_dir.resolve())


def test_loot_path_cannot_escape_through_an_existing_symlink(tmp_path):
    loot_dir = tmp_path / "loot"
    outside = tmp_path / "outside"
    loot_dir.mkdir()
    outside.mkdir()
    (loot_dir / "server").symlink_to(outside, target_is_directory=True)
    remote = RemoteFile(r"folder\secret.txt", "share", Target("server"))

    with pytest.raises(FileRetrievalError, match="Unsafe local loot destination"):
        remote_loot_destination(loot_dir, remote)


@pytest.mark.skipif(not localfs_module._DIRECTORY_FDS, reason="Nested-mount guard requires directory descriptors")
def test_loot_writer_rejects_nested_network_mount_before_file_creation(tmp_path, monkeypatch):
    root = tmp_path / "loot"
    nested_mount = root / "server"
    nested_mount.mkdir(parents=True)
    destination = nested_mount / "share" / "secret.txt"

    def filesystem_type(path):
        resolved = Path(path).resolve(strict=False)
        return "cifs" if resolved == nested_mount or resolved.is_relative_to(nested_mount) else "ext4"

    monkeypatch.setattr(path_safety_module, "filesystem_type", filesystem_type)
    with pytest.raises(UnsafeWritePath, match="cifs"):
        with loot_storage_file(root, destination):
            pytest.fail("network-backed destination must be rejected before opening a file")
    assert list(nested_mount.iterdir()) == []


@pytest.mark.parametrize(
    "path_kind", ["relative", "relative_dotdot", "absolute_dotdot", "root_symlink", "ancestor_symlink"]
)
def test_loot_permissions_never_change_ancestors_for_noncanonical_roots(tmp_path, monkeypatch, path_kind):
    workspace = tmp_path / "workspace"
    storage = tmp_path / "storage"
    workspace.mkdir(mode=0o711)
    storage.mkdir(mode=0o700)
    root = storage / "loot"
    root.mkdir()
    monkeypatch.chdir(workspace)
    if path_kind == "relative":
        configured = Path("../storage/loot")
    elif path_kind == "relative_dotdot":
        configured = Path("../storage/missing/../loot")
    elif path_kind == "absolute_dotdot":
        configured = storage / "missing" / ".." / "loot"
    elif path_kind == "root_symlink":
        (workspace / "loot-link").symlink_to(root, target_is_directory=True)
        configured = Path("loot-link")
    else:
        (workspace / "storage-link").symlink_to(storage, target_is_directory=True)
        configured = Path("storage-link/loot")
    ancestors = {path: stat.S_IMODE(path.stat().st_mode) for path in (tmp_path, workspace, storage)}
    path_chmod = Path.chmod
    chmod_targets = []

    def checked_path_chmod(path, mode, **kwargs):
        assert path.resolve().is_relative_to(root), f"Attempted chmod outside loot: {path}"
        chmod_targets.append(path.resolve())
        return path_chmod(path, mode, **kwargs)

    monkeypatch.setattr(Path, "chmod", checked_path_chmod)
    if localfs_module._DIRECTORY_FDS and Path("/proc/self/fd").exists():
        original_fchmod = os.fchmod

        def checked_fchmod(descriptor, mode):
            target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
            assert target.is_relative_to(root), f"Attempted fchmod outside loot: {target}"
            chmod_targets.append(target)
            return original_fchmod(descriptor, mode)

        monkeypatch.setattr(localfs_module.os, "fchmod", checked_fchmod)
    if path_kind in {"root_symlink", "ancestor_symlink"}:
        with pytest.raises(UnsafeWritePath, match="symlink component"):
            prepare_loot_root(configured)
        assert {path: stat.S_IMODE(path.stat().st_mode) for path in ancestors} == ancestors
        return
    assert prepare_loot_root(configured) == root
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=configured)
    remote = remote_file(tmp_path, Target("server"), "share", r"nested\secret.txt", b"UNCHANGED_BYTES")
    assert worker.save_file(remote) is True
    assert (root / "server" / "share" / "nested" / "secret.txt").read_bytes() == b"UNCHANGED_BYTES"
    assert {path: stat.S_IMODE(path.stat().st_mode) for path in ancestors} == ancestors
    assert not (storage / "missing").exists()
    if localfs_module._DIRECTORY_FDS:
        assert root in chmod_targets


def test_loot_root_expands_tilde_without_creating_any_directories():
    expected = (Path.home() / "manspider-nonexistent-normalization-probe" / ".." / "loot").resolve()
    assert normalize_loot_root("~/manspider-nonexistent-normalization-probe/../loot") == expected


def test_scanner_pins_canonical_loot_root_before_worker_cwd_changes(tmp_path, monkeypatch):
    from man_spider.cli import parse_options
    from man_spider.lib.spider import MANSPIDER

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    options = parse_options([str(tmp_path), "-f", "secret", "-l", "unused/../loot", "--download"])
    scanner = MANSPIDER(options)
    try:
        assert scanner.loot_dir == workspace / "loot"
        assert not (workspace / "unused").exists()
        assert scanner.loot_dir.is_dir()
        monkeypatch.chdir(tmp_path)
        worker = Spiderling.__new__(Spiderling)
        worker.parent = scanner
        remote = remote_file(tmp_path, Target("server"), "share", "secret.txt", b"DATA")
        assert worker.save_file(remote) is True
        assert (workspace / "loot" / "server" / "share" / "secret.txt").read_bytes() == b"DATA"
        assert not (tmp_path / "loot").exists()
    finally:
        scanner.spiderling_queue.close()
        scanner.spiderling_queue.join_thread()


def test_loot_canonical_root_is_not_reinterpreted_after_symlink_substitution(tmp_path):
    root = prepare_loot_root(tmp_path / "loot")
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    root.rename(tmp_path / "original-loot")
    root.symlink_to(outside, target_is_directory=True)
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    remote = remote_file(tmp_path, Target("server"), "share", "secret.txt", b"DATA")
    assert worker.save_file(remote) is False
    assert stat.S_IMODE(outside.stat().st_mode) == 0o700
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("inside_root", [False, True])
def test_loot_does_not_chmod_through_directory_symlinks(tmp_path, inside_root):
    root = prepare_loot_root(tmp_path / "loot")
    target = (root if inside_root else tmp_path) / "linked-target"
    target.mkdir(mode=0o700)
    before = stat.S_IMODE(target.stat().st_mode)
    (root / "server").symlink_to(target, target_is_directory=True)
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    remote = remote_file(tmp_path, Target("server"), "share", "secret.txt", b"DATA")
    assert worker.save_file(remote) is False
    assert stat.S_IMODE(target.stat().st_mode) == before
    assert list(target.iterdir()) == []


def test_loot_does_not_chmod_through_file_symlink(tmp_path):
    root = prepare_loot_root(tmp_path / "loot")
    parent = root / "server" / "share"
    parent.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"PRESERVE")
    outside.chmod(0o600)
    (parent / "secret.txt").symlink_to(outside)
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    remote = remote_file(tmp_path, Target("server"), "share", "secret.txt", b"DATA")
    assert worker.save_file(remote) is True
    assert outside.read_bytes() == b"PRESERVE"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o600
    assert not (parent / "secret.txt").is_symlink()
    assert (parent / "secret.txt").read_bytes() == b"DATA"


@pytest.mark.skipif(not localfs_module._DIRECTORY_FDS, reason="No-follow directory descriptor chmod requires POSIX")
def test_loot_rejects_symlink_substituted_after_destination_validation(tmp_path, monkeypatch):
    root = prepare_loot_root(tmp_path / "loot")
    server = root / "server"
    server.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    original_destination = spiderling_module.remote_loot_destination

    def substitute_symlink(base_dir, remote, **kwargs):
        destination = original_destination(base_dir, remote, **kwargs)
        server.rename(root / "original-server")
        server.symlink_to(outside, target_is_directory=True)
        return destination

    monkeypatch.setattr(spiderling_module, "remote_loot_destination", substitute_symlink)
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    remote = remote_file(tmp_path, Target("server"), "share", "secret.txt", b"DATA")
    assert worker.save_file(remote) is False
    assert stat.S_IMODE(outside.stat().st_mode) == 0o700
    assert list(outside.iterdir()) == []


def test_loot_saving_fails_closed_without_safe_descriptor_support(tmp_path, monkeypatch):
    monkeypatch.setattr(localfs_module, "_DIRECTORY_FDS", False)
    monkeypatch.setattr(Path, "chmod", lambda *_args, **_kwargs: pytest.fail("Unsafe path-based chmod fallback"))
    with pytest.raises(OSError, match="no-follow directory descriptor support"):
        prepare_loot_root(tmp_path / "loot")
    assert not (tmp_path / "loot").exists()


def test_loot_permission_helper_rejects_paths_outside_root_without_creation(tmp_path):
    root = prepare_loot_root(tmp_path / "loot")
    with pytest.raises(ValueError):
        with loot_storage_file(root, tmp_path / "outside" / "secret.txt"):
            pytest.fail("Outside destination was accepted")
    assert not (tmp_path / "outside").exists()


def in_memory_remote_file(tmp_path, payload=b"COMPLETE_RETRIEVED_BYTES"):
    remote = RemoteFile("secret.txt", "share", Target("server"), size=len(payload), tmp_dir=tmp_path)

    def retrieve(_share, _name, callback):
        callback(payload)
        return (len(payload), None, None)

    client = SimpleNamespace(retrieve_file=retrieve)
    remote.get(client)
    assert remote._tmp_filename is None
    return remote


@pytest.mark.parametrize("target_inside_root", [False, True])
def test_in_memory_loot_never_writes_through_existing_file_symlink(tmp_path, target_inside_root):
    root = prepare_loot_root(tmp_path / "loot")
    parent = root / "server" / "share"
    parent.mkdir(parents=True)
    target = (root if target_inside_root else tmp_path) / "preserve.txt"
    target.write_bytes(b"PRESERVE")
    target.chmod(0o600)
    (parent / "secret.txt").symlink_to(target)
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    assert worker.save_file(in_memory_remote_file(tmp_path)) is True
    assert target.read_bytes() == b"PRESERVE"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not (parent / "secret.txt").is_symlink()
    assert (parent / "secret.txt").read_bytes() == b"COMPLETE_RETRIEVED_BYTES"


@pytest.mark.skipif(not localfs_module._DIRECTORY_FDS, reason="Safe descriptor-based output requires POSIX")
@pytest.mark.parametrize("replace_directory", [False, True])
@pytest.mark.parametrize("materialized", [False, True])
def test_loot_write_and_chmod_stay_on_open_descriptor_after_symlink_swap(
    tmp_path, monkeypatch, replace_directory, materialized
):
    root = prepare_loot_root(tmp_path / "loot")
    parent = root / "server" / "share"
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    outside_file = outside / "secret.txt"
    outside_file.write_bytes(b"PRESERVE")
    outside_file.chmod(0o600)
    remote = in_memory_remote_file(tmp_path)
    if materialized:
        remote.materialize()
    original_copy = remote.copy_to
    original_output = parent / "secret.txt"
    if replace_directory:
        original_output = parent.parent / "original-share" / "secret.txt"

    def substitute_before_write(output):
        if replace_directory:
            parent.rename(parent.parent / "original-share")
            parent.symlink_to(outside, target_is_directory=True)
        else:
            (parent / "secret.txt").symlink_to(outside_file)
        original_copy(output)

    monkeypatch.setattr(remote, "copy_to", substitute_before_write)
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    assert worker.save_file(remote) is True
    assert original_output.read_bytes() == b"COMPLETE_RETRIEVED_BYTES"
    assert stat.S_IMODE(original_output.stat().st_mode) == 0o664
    assert outside_file.read_bytes() == b"PRESERVE"
    assert stat.S_IMODE(outside_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(outside.stat().st_mode) == 0o700
    assert list(outside.iterdir()) == [outside_file]


def test_in_memory_loot_does_not_truncate_existing_external_hardlink(tmp_path):
    root = prepare_loot_root(tmp_path / "loot")
    parent = root / "server" / "share"
    parent.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"PRESERVE")
    outside.chmod(0o600)
    os.link(outside, parent / "secret.txt")
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    assert worker.save_file(in_memory_remote_file(tmp_path)) is True
    assert outside.read_bytes() == b"PRESERVE"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o600
    assert (parent / "secret.txt").read_bytes() == b"COMPLETE_RETRIEVED_BYTES"
    assert not os.path.samestat(outside.stat(), (parent / "secret.txt").stat())


def test_atomic_loot_replacement_does_not_mutate_hardlink_added_to_old_final(tmp_path, monkeypatch):
    root = prepare_loot_root(tmp_path / "loot")
    destination = root / "server" / "share" / "secret.txt"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"OLD_CONTENT")
    destination.chmod(0o600)
    outside_alias = tmp_path / "late-hardlink.txt"
    original_replace = os.replace

    def add_hardlink_before_publish(source, target, **kwargs):
        assert kwargs["src_dir_fd"] == kwargs["dst_dir_fd"]
        os.link(destination, outside_alias)
        return original_replace(source, target, **kwargs)

    monkeypatch.setattr(localfs_module.os, "replace", add_hardlink_before_publish)
    monkeypatch.setattr(
        localfs_module.os, "ftruncate", lambda *_args: pytest.fail("Old final must never be truncated")
    )
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    assert worker.save_file(in_memory_remote_file(tmp_path)) is True
    assert destination.read_bytes() == b"COMPLETE_RETRIEVED_BYTES"
    assert outside_alias.read_bytes() == b"OLD_CONTENT"
    assert stat.S_IMODE(outside_alias.stat().st_mode) == 0o600
    assert not os.path.samestat(destination.stat(), outside_alias.stat())
    assert sorted(path.name for path in destination.parent.iterdir()) == ["secret.txt"]


@pytest.mark.parametrize("existing_final", [False, True])
@pytest.mark.parametrize("failure", [OSError("copy interrupted"), KeyboardInterrupt(), SystemExit(2)])
def test_atomic_loot_copy_failure_preserves_final_and_removes_staging(tmp_path, monkeypatch, existing_final, failure):
    root = prepare_loot_root(tmp_path / "loot")
    destination = root / "server" / "share" / "secret.txt"
    destination.parent.mkdir(parents=True)
    if existing_final:
        destination.write_bytes(b"OLD_CONTENT")
        destination.chmod(0o600)
    remote = in_memory_remote_file(tmp_path)

    def fail_copy(output):
        assert stat.S_IMODE(os.fstat(output.fileno()).st_mode) == 0o600
        assert destination.exists() == existing_final
        if existing_final:
            assert destination.read_bytes() == b"OLD_CONTENT"
        output.write(b"PARTIAL_NEW_CONTENT")
        raise failure

    monkeypatch.setattr(remote, "copy_to", fail_copy)
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    if isinstance(failure, Exception):
        assert worker.save_file(remote) is False
    else:
        with pytest.raises(type(failure)):
            worker.save_file(remote)
    assert remote._content is None
    assert destination.exists() == existing_final
    if existing_final:
        assert destination.read_bytes() == b"OLD_CONTENT"
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert sorted(path.name for path in destination.parent.iterdir()) == (["secret.txt"] if existing_final else [])


@pytest.mark.parametrize("operation", ["chmod", "publish"])
def test_atomic_loot_finish_failure_preserves_final_and_removes_staging(tmp_path, monkeypatch, operation):
    root = prepare_loot_root(tmp_path / "loot")
    destination = root / "server" / "share" / "secret.txt"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"OLD_CONTENT")
    destination.chmod(0o600)
    if operation == "publish":

        def fail_publish(*_args, **_kwargs):
            raise PermissionError("fixture publish denied")

        monkeypatch.setattr(localfs_module.os, "replace", fail_publish)
    else:
        original_fchmod = os.fchmod

        def fail_final_chmod(descriptor, mode):
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise PermissionError("fixture final chmod denied")
            return original_fchmod(descriptor, mode)

        monkeypatch.setattr(localfs_module.os, "fchmod", fail_final_chmod)
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    assert worker.save_file(in_memory_remote_file(tmp_path)) is False
    assert destination.read_bytes() == b"OLD_CONTENT"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert sorted(path.name for path in destination.parent.iterdir()) == ["secret.txt"]


@pytest.mark.parametrize("symlink_collision", [False, True])
def test_atomic_loot_staging_name_collision_never_overwrites_or_removes_existing_file(
    tmp_path, monkeypatch, symlink_collision
):
    root = prepare_loot_root(tmp_path / "loot")
    destination = root / "server" / "share" / "secret.txt"
    destination.parent.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"PRESERVE")
    collision = destination.parent / ".manspider-collision.tmp"
    if symlink_collision:
        collision.symlink_to(outside)
    else:
        collision.write_bytes(b"PRESERVE")
    monkeypatch.setattr(localfs_module.secrets, "token_hex", lambda _length: "collision")
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=root)
    assert worker.save_file(in_memory_remote_file(tmp_path)) is False
    assert not destination.exists()
    assert collision.read_bytes() == b"PRESERVE"
    assert collision.is_symlink() == symlink_collision
    assert outside.read_bytes() == b"PRESERVE"
    assert list(destination.parent.iterdir()) == [collision]


def test_path_based_loot_destination_still_rejects_final_symlink_outside_root(tmp_path):
    root = prepare_loot_root(tmp_path / "loot")
    destination = root / "server" / "share" / "secret.txt"
    destination.parent.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"PRESERVE")
    destination.symlink_to(outside)
    remote = RemoteFile("secret.txt", "share", Target("server"))
    with pytest.raises(FileRetrievalError, match="Unsafe local loot destination"):
        remote_loot_destination(root, remote)
    assert remote_loot_destination(root, remote, atomic_replace=True) == destination


@pytest.mark.parametrize("spill", [False, True])
@pytest.mark.parametrize("materialized", [False, True])
def test_safe_loot_copy_preserves_complete_bytes_cursor_and_single_remote_read(tmp_path, spill, materialized):
    payload = bytes(range(256)) * 30
    remote = RemoteFile("secret.txt", "share", Target("server"), size=len(payload), tmp_dir=tmp_path)
    remote.memory_spool_limit = 16 if spill else len(payload) + 1
    reads = []

    def retrieve(share, name, callback):
        reads.append((share, name))
        callback(payload)
        return (len(payload), None, None)

    remote.get(SimpleNamespace(retrieve_file=retrieve))
    remote._content.seek(7)
    materialized_path = remote.materialize() if materialized else None
    root = prepare_loot_root(tmp_path / "loot")
    destination = remote_loot_destination(root, remote)
    with loot_storage_file(root, destination) as output:
        remote.copy_to(output)
    assert remote._content.tell() == 7
    assert destination.read_bytes() == payload
    assert reads == [("share", "secret.txt")]
    remote.cleanup()
    if materialized_path is not None:
        assert not materialized_path.exists()


def test_remote_same_size_mtime_change_is_detected_after_complete_read(tmp_path):
    class DirectoryRecord:
        def get_longname(self):
            return "secret.txt"

        def is_directory(self):
            return False

        def get_filesize(self):
            return 4

        def get_mtime_epoch(self):
            return 101

        def get_file_id(self):
            return "same-id"

    class Connection:
        @staticmethod
        def getFile(_share, _name, callback):
            callback(b"DATA")

    class Client:
        conn = Connection()
        retrievals = 0

        @classmethod
        def retrieve_file(cls, share, name, callback):
            cls.retrievals += 1
            return cls.conn.getFile(share, name, callback)

        @staticmethod
        def ls(_share, _path):
            return iter((DirectoryRecord(),))

    spiderling = Spiderling.__new__(Spiderling)
    spiderling.smb_client = Client()
    spiderling.target = Target("server")
    spiderling.parent = SimpleNamespace(state_path=tmp_path / "scan.sqlite3", state_run_id="run-id")
    changed_calls = []
    state = SimpleNamespace(
        mark_object_changed=lambda object_id, post_read_identity=None: changed_calls.append(
            (object_id, post_read_identity)
        )
    )
    spiderling.open_state = lambda: state
    remote = RemoteFile(
        "secret.txt",
        "share",
        Target("server"),
        size=4,
        mtime=100,
        file_id="same-id",
        tmp_dir=tmp_path,
    )
    remote.object_id = 7
    remote.tmp_filename = tmp_path / "downloaded.txt"

    assert spiderling.get_file(remote) is True
    assert remote.content_bytes() == b"DATA"
    assert remote._tmp_filename is None
    assert remote.changed is True
    assert remote.post_read_identity == (4, 101, "same-id")
    assert Client.retrievals == 2
    spiderling.verify_remote_files("share", "", [remote])
    assert remote.changed is True
    assert changed_calls == []
    remote.cleanup()


def test_offline_hsm_read_warns_with_full_unc_path_before_retrieval(tmp_path, monkeypatch):
    events = []

    class Client:
        @staticmethod
        def retrieve_file(share, name, callback):
            events.append(("retrieve", share, name))
            callback(b"DATA")

        @staticmethod
        def handle_impacket_error(*_args):
            raise AssertionError("successful retrieval must not handle an error")

    monkeypatch.setattr(
        spiderling_module.log,
        "warning",
        lambda message: events.append(("warning", message)),
    )
    spiderling = Spiderling.__new__(Spiderling)
    spiderling.smb_client = Client()
    spiderling.target = Target("files.example.test", 1445)
    attributes = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    remote = RemoteFile(
        r"tiered\secret.txt",
        "Archive$",
        spiderling.target,
        size=4,
        tmp_dir=tmp_path,
        smb_attributes=attributes,
    )

    assert spiderling.get_file(remote) is True

    assert events[0][0] == "warning"
    assert r"\\files.example.test\Archive$\tiered\secret.txt" in events[0][1]
    assert "SMB port 1445" in events[0][1]
    assert "OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS" in events[0][1]
    assert events[1] == ("retrieve", "Archive$", r"tiered\secret.txt")
    assert remote.content_bytes() == b"DATA"
    remote.cleanup()


def test_regular_remote_read_does_not_emit_offline_warning(tmp_path, monkeypatch):
    class Client:
        @staticmethod
        def retrieve_file(_share, _name, callback):
            callback(b"DATA")

        @staticmethod
        def handle_impacket_error(*_args):
            raise AssertionError("successful retrieval must not handle an error")

    monkeypatch.setattr(
        spiderling_module.log,
        "warning",
        lambda message: (_ for _ in ()).throw(AssertionError(f"unexpected warning: {message}")),
    )
    spiderling = Spiderling.__new__(Spiderling)
    spiderling.smb_client = Client()
    spiderling.target = Target("files.example.test")
    remote = RemoteFile(
        "regular.txt",
        "Data",
        spiderling.target,
        size=4,
        tmp_dir=tmp_path,
        smb_attributes=0x20,
    )

    assert spiderling.get_file(remote) is True
    remote.cleanup()


def test_postquery_identity_avoids_directory_relisting_and_marks_change(tmp_path):
    class Client:
        @staticmethod
        def retrieve_file(_share, _name, callback):
            callback(b"DATA")
            return 5, 101, None

        @staticmethod
        def ls(_share, _path):
            raise AssertionError("SMB2 post-query identity must avoid a second directory listing")

        @staticmethod
        def handle_impacket_error(*_args):
            raise AssertionError("successful retrieval must not handle an error")

    spiderling = Spiderling.__new__(Spiderling)
    spiderling.smb_client = Client()
    spiderling.target = Target("server")
    spiderling.parent = SimpleNamespace(state_path=tmp_path / "scan.sqlite3", state_run_id="run-id")
    spiderling.pending_state_completions = []
    remote = RemoteFile("secret.txt", "share", Target("server"), size=4, mtime=100)
    remote.object_id = 9

    assert spiderling.get_file(remote) is True
    spiderling.verify_remote_files("share", "", [remote])
    spiderling.complete_file(remote, "processed", changed=remote.changed)

    assert remote.changed is True
    assert len(spiderling.pending_state_completions) == 1
    completion, queued_file, findings = spiderling.pending_state_completions[0]
    assert completion["changed"] is True
    assert completion["post_read_identity"] == (5, 101, None)
    assert queued_file is remote
    assert findings == ()
    remote.cleanup()


def test_small_remote_retrieval_stays_memory_backed_until_materialized(tmp_path):
    payload = b"complete in-memory fixture"

    class Client:
        @staticmethod
        def retrieve_file(_share, _name, callback):
            callback(payload[:8])
            callback(payload[8:])

        @staticmethod
        def handle_impacket_error(*_args):
            raise AssertionError("successful retrieval must not handle an error")

    remote = RemoteFile("secret.txt", "share", Target("server"), size=len(payload), tmp_dir=tmp_path)
    assert remote.memory_spool_limit == 8 * 1024 * 1024
    remote.get(Client())

    assert remote.content_bytes() == payload
    assert remote.retrieved_size == len(payload)
    assert remote._tmp_filename is None
    materialized = remote.materialize()
    assert materialized.read_bytes() == payload
    remote.cleanup()
    assert remote._tmp_filename is None
    assert not materialized.exists()


def test_remote_retrieval_spills_over_fixed_memory_bound_without_truncation(tmp_path):
    payload = bytes(range(32))

    class Client:
        @staticmethod
        def retrieve_file(_share, _name, callback):
            callback(payload)

        @staticmethod
        def handle_impacket_error(*_args):
            raise AssertionError("successful retrieval must not handle an error")

    remote = RemoteFile("large.bin", "share", Target("server"), size=len(payload), tmp_dir=tmp_path)
    remote.memory_spool_limit = 8
    remote.get(Client())

    assert remote._content._rolled is True
    assert remote.content_bytes() == payload
    assert remote.retrieved_size == len(payload)
    remote.cleanup()


def test_default_remote_retrieval_spills_only_after_eight_mib(tmp_path):
    mebibyte = b"x" * (1024 * 1024)

    class Client:
        @staticmethod
        def retrieve_file(_share, _name, callback):
            for _chunk in range(8):
                callback(mebibyte)
            callback(b"y")

        @staticmethod
        def handle_impacket_error(*_args):
            raise AssertionError("successful retrieval must not handle an error")

    remote = RemoteFile(
        "large.bin",
        "share",
        Target("server"),
        size=8 * 1024 * 1024 + 1,
        tmp_dir=tmp_path,
    )
    remote.get(Client())

    assert remote._content._rolled is True
    assert remote.retrieved_size == 8 * 1024 * 1024 + 1
    remote._content.seek(0)
    assert remote._content.read(1) == b"x"
    remote._content.seek(-1, 2)
    assert remote._content.read(1) == b"y"
    remote.cleanup()
