"""Local-only regression checks for quiet loot saving and its startup notice."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import man_spider.lib.spider as spider_module
import man_spider.lib.spiderling as spiderling_module
from man_spider.cli import parse_options
from man_spider.lib.file import RemoteFile
from man_spider.lib.localfs import prepare_loot_root
from man_spider.lib.spider import MANSPIDER
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target


def _source_identity(path):
    """Reading may change atime; saving loot must not change source contents or metadata."""

    info = path.stat()
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _retrieved_remote(tmp_path, source, name, calls):
    remote = RemoteFile(name, "ReadOnly", Target("fixture.invalid", 1445), size=source.stat().st_size, tmp_dir=tmp_path)

    def retrieve_file(share, path, callback):
        calls.append((share, path))
        payload = source.read_bytes()
        callback(payload)
        return (len(payload), None, None)

    # The fake transport exposes only retrieval, never a remote write operation.
    remote.get(SimpleNamespace(retrieve_file=retrieve_file))
    return remote


@pytest.mark.parametrize("materialized", [False, True])
def test_multiple_successful_loot_saves_are_silent_and_preserve_sources(tmp_path, monkeypatch, materialized):
    source_root = tmp_path / "read-only-server-fixture"
    source_root.mkdir()
    loot_root = prepare_loot_root(tmp_path / "loot")
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=loot_root)
    captured_log = Mock()
    monkeypatch.setattr(spiderling_module, "log", captured_log)
    reads = []

    for index, payload in enumerate((b"password=FixtureOnly123!\n", bytes(range(256)), b"\x00\xffKEY\n")):
        name = rf"nested\secret-{index}.bin"
        source = source_root / f"source-{index}.bin"
        source.write_bytes(payload)
        source.chmod(0o400)
        identity = _source_identity(source)
        remote = _retrieved_remote(tmp_path, source, name, reads)
        materialized_path = remote.materialize() if materialized else None

        assert worker.save_file(remote) is True

        destination = loot_root / "fixture.invalid_port-1445" / "ReadOnly" / "nested" / f"secret-{index}.bin"
        assert destination.read_bytes() == payload
        assert source.read_bytes() == payload
        assert _source_identity(source) == identity
        assert remote._content is None
        if materialized_path is not None:
            assert not materialized_path.exists()

    assert reads == [("ReadOnly", rf"nested\secret-{index}.bin") for index in range(3)]
    assert captured_log.mock_calls == []


def test_loot_save_failure_keeps_warning_and_does_not_modify_source(tmp_path, monkeypatch):
    source = tmp_path / "source-secret.txt"
    payload = b"password=FixtureOnly123!\n"
    source.write_bytes(payload)
    source.chmod(0o400)
    identity = _source_identity(source)
    loot_root = prepare_loot_root(tmp_path / "loot")
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(loot_dir=loot_root)
    captured_log = Mock()
    monkeypatch.setattr(spiderling_module, "log", captured_log)
    reads = []
    remote = _retrieved_remote(tmp_path, source, "secret.txt", reads)

    def fail_copy(_output):
        raise OSError("fixture local disk full")

    monkeypatch.setattr(remote, "copy_to", fail_copy)

    assert worker.save_file(remote) is False

    captured_log.warning.assert_called_once()
    warning = captured_log.warning.call_args.args[0]
    assert f"Error saving {remote}" in warning
    assert "fixture local disk full" in warning
    captured_log.info.assert_not_called()
    assert not (loot_root / "fixture.invalid_port-1445" / "ReadOnly" / "secret.txt").exists()
    assert source.read_bytes() == payload
    assert _source_identity(source) == identity
    assert reads == [("ReadOnly", "secret.txt")]
    assert remote._content is None


@pytest.mark.parametrize("no_download", [False, True])
@pytest.mark.parametrize("quiet", [False, True])
def test_loot_destination_announced_once_before_scan_only_when_downloading(tmp_path, monkeypatch, no_download, quiet):
    scope = tmp_path / "scope"
    scope.mkdir()
    loot_root = tmp_path / "loot"
    arguments = [str(scope), "-f", "secret", "--loot-dir", str(loot_root)]
    if not no_download:
        arguments.append("--download")
    if quiet:
        arguments.append("--quiet")
    options = parse_options(arguments)
    captured_log = Mock()
    monkeypatch.setattr(spider_module, "log", captured_log)
    start = Mock(side_effect=AssertionError("The constructor must not start a scan"))
    monkeypatch.setattr(MANSPIDER, "start", start)

    scanner = MANSPIDER(options)
    try:
        notices = [
            call.args[0]
            for call in captured_log.info.call_args_list
            if call.args[0].startswith("Matching files will be downloaded to ")
        ]
        assert notices == ([] if no_download else [f"Matching files will be downloaded to {loot_root}"])
        assert scanner.loot_dir == loot_root
        assert loot_root.exists() is not no_download
        assert scanner.tmp_dir is None
        assert all(worker is None for worker in scanner.spiderling_pool)
        start.assert_not_called()
    finally:
        scanner.spiderling_queue.close()
        scanner.spiderling_queue.join_thread()
