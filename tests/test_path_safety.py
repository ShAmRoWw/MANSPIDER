import os
import secrets
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

import man_spider.path_safety as safety
from man_spider.path_safety import (
    UnsafeWritePath,
    create_private_local_directory,
    require_local_path,
    require_safe_output_descriptor,
    require_local_write_path,
    safe_temporary_directory,
)


@pytest.mark.parametrize(
    "value",
    (
        r"\\server\share\state.sqlite3",
        "//server/share/state.sqlite3",
        "smb://server/share/state.sqlite3",
        "cifs://server/share/state.sqlite3",
        "nfs://server/export/state.sqlite3",
    ),
)
def test_network_syntax_is_rejected_before_path_normalization(value):
    with pytest.raises(UnsafeWritePath, match="network|UNC"):
        safety.filesystem_type(value)


def test_linux_mount_resolution_uses_longest_existing_mount(tmp_path):
    local_root = tmp_path / "local"
    remote_root = local_root / "mounted share"
    remote_root.mkdir(parents=True)
    mountinfo = tmp_path / "mountinfo"
    escaped_remote = str(remote_root).replace(" ", r"\040")
    mountinfo.write_text(
        "1 0 8:1 / / rw - ext4 /dev/root rw\n"
        f"2 1 0:44 / {escaped_remote} rw - cifs //server/share rw\n",
        encoding="utf-8",
    )

    assert safety._linux_filesystem_type(local_root, mountinfo_path=mountinfo) == "ext4"
    assert safety._linux_filesystem_type(remote_root / "future" / "result.json", mountinfo_path=mountinfo) == "cifs"


def test_unknown_filesystem_is_rejected_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(safety, "filesystem_type", lambda _path: "future-network-fs")
    with pytest.raises(UnsafeWritePath, match="not in MANSPIDER's local-filesystem allowlist"):
        require_local_write_path(tmp_path / "state.sqlite3", purpose="state")


def test_dangling_output_symlink_is_rejected_instead_of_using_lexical_parent(tmp_path):
    destination = tmp_path / "state.sqlite3"
    destination.symlink_to(tmp_path / "missing-target.sqlite3")

    with pytest.raises(UnsafeWritePath, match="dangling symlink|symlink component"):
        require_local_write_path(destination, purpose="state")


def test_existing_output_symlink_is_rejected_even_when_target_is_local(tmp_path):
    actual = tmp_path / "actual.sqlite3"
    actual.touch()
    alias = tmp_path / "state.sqlite3"
    alias.symlink_to(actual)

    with pytest.raises(UnsafeWritePath, match="symlink component"):
        require_local_write_path(alias, purpose="state")


def test_symlinked_output_parent_is_rejected(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)

    with pytest.raises(UnsafeWritePath, match="symlink component"):
        require_local_write_path(alias / "report.json", purpose="report")


def test_missing_component_before_dotdot_cannot_hide_destination_filesystem(monkeypatch, tmp_path):
    local = tmp_path / "local"
    remote = tmp_path / "remote"
    local.mkdir()
    remote.mkdir()
    disguised = local / "missing" / ".." / ".." / "remote" / "report.json"

    def filesystem_type(path):
        normalized = Path(os.path.abspath(os.fspath(path)))
        return "cifs" if normalized == remote or normalized.is_relative_to(remote) else "ext4"

    monkeypatch.setattr(safety, "filesystem_type", filesystem_type)
    with pytest.raises(UnsafeWritePath, match="cifs"):
        require_local_write_path(disguised, purpose="report")


def test_known_local_filesystem_is_accepted(monkeypatch, tmp_path):
    monkeypatch.setattr(safety, "filesystem_type", lambda _path: "ext4")
    assert require_local_path(tmp_path / "future", purpose="temporary directory") == (tmp_path / "future").absolute()


def test_current_test_workspace_and_system_temp_are_proven_local():
    # This is also a deployment smoke test for the actual mountinfo parser.
    assert require_local_write_path(Path.cwd() / "future-output", purpose="test output").is_absolute()
    assert require_local_write_path("/tmp/manspider-future", purpose="temporary storage").is_absolute()


def test_explicit_network_temporary_directory_fails_without_tempfile_probe(monkeypatch):
    def forbidden_gettempdir():
        raise AssertionError("tempfile.gettempdir() must never probe a configured path")

    monkeypatch.setattr("tempfile.gettempdir", forbidden_gettempdir)
    with pytest.raises(UnsafeWritePath, match="UNC|network"):
        safe_temporary_directory({"TMPDIR": r"\\server\share\temp"})


def test_explicit_safe_temporary_directory_is_selected_without_probe(monkeypatch, tmp_path):
    monkeypatch.setattr("tempfile.gettempdir", lambda: (_ for _ in ()).throw(AssertionError("probe")))
    assert safe_temporary_directory({"TMPDIR": str(tmp_path)}) == tmp_path.resolve()


def test_temporary_directory_below_nonsticky_shared_ancestor_is_rejected():
    # A normal pytest tmp_path has a 0700 ancestor and therefore safely shields
    # its descendants. Put this adversarial parent directly below /tmp.
    shared = Path("/tmp") / f"manspider-untrusted-{secrets.token_hex(12)}"
    private = shared / "private"
    try:
        shared.mkdir(mode=0o700)
        private.mkdir(mode=0o700)
        shared.chmod(0o777)

        with pytest.raises(UnsafeWritePath, match="ancestor is writable"):
            safe_temporary_directory({"TMPDIR": str(private)})
    finally:
        shared.chmod(0o700)
        private.rmdir()
        shared.rmdir()


def test_standard_sticky_system_temp_is_accepted():
    system_temp = Path("/tmp")
    if not system_temp.exists():
        pytest.skip("system /tmp is unavailable")
    assert safe_temporary_directory({"TMPDIR": str(system_temp)}) == system_temp.resolve()


def test_named_acl_writer_on_temporary_base_is_rejected():
    setfacl = shutil.which("setfacl")
    if setfacl is None:
        pytest.skip("setfacl is unavailable")
    base = Path("/tmp") / f"manspider-acl-{secrets.token_hex(12)}"
    try:
        base.mkdir(mode=0o700)
        subprocess.run([setfacl, "-m", "u:nobody:rwx", str(base)], check=True)
        assert base.stat().st_mode & 0o020  # ACL mask is visible as group-class bits.

        with pytest.raises(UnsafeWritePath, match="writable by group or other"):
            safe_temporary_directory({"TMPDIR": str(base)})
    finally:
        if base.exists():
            subprocess.run([setfacl, "-b", str(base)], check=False)
            base.chmod(0o700)
            base.rmdir()


def test_explicit_missing_temporary_directory_fails_closed(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(UnsafeWritePath, match="does not exist"):
        safe_temporary_directory({"TEMP": str(missing)})


def test_private_temp_creation_stays_on_pinned_local_parent_during_path_swap(monkeypatch, tmp_path):
    base = tmp_path / "base"
    displaced = tmp_path / "displaced"
    remote = tmp_path / "remote"
    base.mkdir()
    remote.mkdir()
    real_mkdir = safety.os.mkdir
    swapped = False

    def racing_mkdir(path, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if dir_fd is not None and not swapped and str(path).startswith("manspider-"):
            swapped = True
            base.rename(displaced)
            base.symlink_to(remote, target_is_directory=True)
        return real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(safety.os, "mkdir", racing_mkdir)
    created, _identity = create_private_local_directory(
        base,
        prefix="manspider-",
        purpose="scan temporary directory",
    )

    assert created.parent == displaced
    assert created.is_dir()
    assert list(remote.iterdir()) == []


def test_cli_rejects_network_backed_outputs_before_scanning(monkeypatch, tmp_path):
    from man_spider.cli import ConfigurationError, parse_options

    monkeypatch.setattr(safety, "filesystem_type", lambda _path: "cifs")
    with pytest.raises(ConfigurationError, match="not in MANSPIDER's local-filesystem allowlist"):
        parse_options([str(tmp_path), "-f", "secret"])


def test_direct_loot_and_report_writers_reject_network_filesystems(monkeypatch, tmp_path):
    from man_spider.lib.localfs import prepare_loot_root
    from man_spider.metrics import write_smb_metrics_report

    monkeypatch.setattr(safety, "filesystem_type", lambda _path: "nfs")
    with pytest.raises(UnsafeWritePath):
        prepare_loot_root(tmp_path / "loot")
    with pytest.raises(UnsafeWritePath):
        write_smb_metrics_report({}, tmp_path / "metrics.json")
    assert not (tmp_path / "loot").exists()
    assert not (tmp_path / "metrics.json").exists()


def test_regular_standard_stream_destination_must_be_local(monkeypatch, tmp_path):
    destination = tmp_path / "console.log"
    with destination.open("wb") as stream:
        monkeypatch.setattr(safety, "filesystem_type", lambda _path: "cifs")
        with pytest.raises(UnsafeWritePath, match="not in MANSPIDER's local-filesystem allowlist"):
            require_safe_output_descriptor(stream.fileno(), purpose="standard output")


def test_pipe_standard_stream_capability_is_allowed():
    reader, writer = os.pipe()
    try:
        require_safe_output_descriptor(writer, purpose="standard output")
    finally:
        os.close(reader)
        os.close(writer)


def test_socket_standard_stream_capability_is_rejected():
    first, second = socket.socketpair()
    try:
        with pytest.raises(UnsafeWritePath, match="unsupported descriptor type"):
            require_safe_output_descriptor(first.fileno(), purpose="standard output")
    finally:
        first.close()
        second.close()
