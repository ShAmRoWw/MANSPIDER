"""Per-invocation log ownership and fail-closed local file creation."""

import os
import queue
import stat
from datetime import datetime
from types import SimpleNamespace

import pytest

from man_spider import path_safety
from man_spider.lib import logger
from man_spider.path_safety import UnsafeWritePath


@pytest.fixture
def isolated_logger(monkeypatch):
    for name in ("listener", "handler", "logpath"):
        monkeypatch.setattr(logger, name, None)
    monkeypatch.setattr(logger, "log_queue", queue.Queue())
    monkeypatch.setattr(logger.logging.getLogger("manspider"), "handlers", [logger.QueueHandler(logger.log_queue)])
    yield logger
    logger.stop_listener(True)


def test_each_preparation_gets_its_own_log_next_to_state(isolated_logger, tmp_path):
    state = tmp_path / "sessions" / "fixture.sqlite3"
    first = logger.prepare_logging(state)
    first_handler = logger.handler
    logger.log_scan_summary("FIRST-INVOCATION")
    logger.stop_listener(True)  # Also closes a prepared but not started listener.
    assert first_handler.stream.closed
    before = first.read_bytes()

    second = logger.prepare_logging(state)
    logger.log_scan_summary("SECOND-INVOCATION")
    logger.stop_listener(True)
    assert first != second
    assert first.parent == second.parent == state.parent
    assert stat.S_IMODE(state.parent.stat().st_mode) == 0o700
    assert first.name.startswith("fixture.run_")
    assert first.read_bytes() == before
    assert b"SECOND-INVOCATION" not in before
    assert "FIRST-INVOCATION" not in second.read_text()
    assert "SECOND-INVOCATION" in second.read_text()
    assert not state.exists()


def test_unstarted_preparation_can_be_replaced_without_leaking_stream(isolated_logger, tmp_path):
    first = logger.prepare_logging(tmp_path / "one.sqlite3")
    first_handler = logger.handler
    second = logger.prepare_logging(tmp_path / "two.sqlite3")
    assert first_handler.stream.closed
    assert first != second


def test_unstarted_listener_flushes_queued_records_before_next_invocation(isolated_logger, tmp_path):
    first = logger.prepare_logging(tmp_path / "one.sqlite3")
    logger.logging.getLogger("manspider").error("EARLY-FIRST-INVOCATION")
    logger.stop_listener(True)
    second = logger.prepare_logging(tmp_path / "two.sqlite3")
    logger.logging.getLogger("manspider").error("SECOND-INVOCATION")
    logger.stop_listener(True)
    assert "EARLY-FIRST-INVOCATION" in first.read_text()
    assert "EARLY-FIRST-INVOCATION" not in second.read_text()
    assert "SECOND-INVOCATION" in second.read_text()
    assert logger.log_queue.unfinished_tasks == 0


def test_unowned_stop_and_active_reconfiguration_preserve_owner(isolated_logger, tmp_path):
    destination = logger.prepare_logging(tmp_path / "one.sqlite3")
    owner = logger.listener
    assert logger.start_listener() is True
    assert logger.start_listener() is False
    logger.stop_listener(False)
    assert logger.listener is owner
    with pytest.raises(ValueError, match="listener is running"):
        logger.prepare_logging(tmp_path / "two.sqlite3")
    logger.log_scan_summary("STILL-FIRST-INVOCATION")
    logger.stop_listener(True)
    assert "STILL-FIRST-INVOCATION" in destination.read_text()
    assert list(tmp_path.glob("two.run_*.log")) == []


def test_standalone_logging_uses_state_directory_not_daily_home_logs(isolated_logger, monkeypatch, tmp_path):
    monkeypatch.setenv("MANSPIDER_STATE_DIR", str(tmp_path / "state"))
    destination = logger.prepare_logging()
    assert destination.parent == tmp_path / "state"
    assert destination.name.startswith("manspider.run_")


def test_network_backed_state_directory_is_rejected_before_creation(isolated_logger, monkeypatch, tmp_path):
    monkeypatch.setattr(path_safety, "filesystem_type", lambda _: "cifs")
    with pytest.raises(UnsafeWritePath):
        logger.prepare_logging(tmp_path / "missing" / "scan.sqlite3")
    assert not (tmp_path / "missing").exists()
    assert logger.listener is logger.handler is logger.logpath is None


def test_symlink_directory_cannot_redirect_log_creation(isolated_logger, tmp_path):
    destination = tmp_path / "destination"
    destination.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(destination, target_is_directory=True)
    with pytest.raises(UnsafeWritePath):
        logger.prepare_logging(alias / "scan.sqlite3")
    assert list(destination.iterdir()) == []


@pytest.mark.parametrize("kind", ["regular", "hardlink", "symlink"])
def test_existing_leaf_is_never_appended_or_overwritten(isolated_logger, monkeypatch, tmp_path, kind):
    instant = datetime(2026, 9, 14, 13, 0, 0)
    monkeypatch.setattr(logger, "datetime", SimpleNamespace(now=lambda: instant))
    monkeypatch.setattr(logger, "uuid4", lambda: SimpleNamespace(hex="a" * 32))
    destination = tmp_path / "scan.run_20260914_130000_000000_aaaaaaaa.log"
    original = tmp_path / "original.txt"
    original.write_text("DO-NOT-CHANGE")
    if kind == "regular":
        destination.write_text("PREVIOUS-LOG")
    elif kind == "hardlink":
        os.link(original, destination)
    else:
        destination.symlink_to(original)
    original_before = original.stat()
    destination_before = destination.read_bytes()
    with pytest.raises((OSError, UnsafeWritePath)):
        logger.prepare_logging(tmp_path / "scan.sqlite3")
    assert destination.read_bytes() == destination_before
    assert original.read_text() == "DO-NOT-CHANGE"
    assert original.stat().st_mtime_ns == original_before.st_mtime_ns
    assert logger.listener is logger.handler is logger.logpath is None


def test_failed_descriptor_validation_closes_file(isolated_logger, monkeypatch, tmp_path):
    descriptors = []

    def reject(descriptor, **_):
        descriptors.append(descriptor)
        raise UnsafeWritePath("injected final descriptor rejection")

    monkeypatch.setattr(logger, "require_local_file_descriptor", reject)
    with pytest.raises(UnsafeWritePath, match="final descriptor rejection"):
        logger.prepare_logging(tmp_path / "scan.sqlite3")
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert logger.listener is logger.handler is logger.logpath is None


@pytest.mark.parametrize("failure_stage", ["Pipe", "Process"])
@pytest.mark.parametrize("failure_type", [OSError, KeyboardInterrupt])
def test_supervisor_closes_prepared_log_if_process_setup_fails(
    isolated_logger, monkeypatch, tmp_path, failure_stage, failure_type
):
    import man_spider.manspider as cli

    scope = tmp_path / "scope"
    scope.mkdir()
    options = SimpleNamespace(verbose=False, state_path=tmp_path / "scan.sqlite3")
    monkeypatch.setattr(cli, "parse_options", lambda *_, **__: options)
    monkeypatch.setattr(cli, "offer_automatic_resume", lambda _: None)
    monkeypatch.setattr(cli, "validate_options", lambda _: None)
    streams = []
    prepare = logger.prepare_logging

    def capture_stream(state):
        path = prepare(state)
        streams.append(logger.handler.stream)
        return path

    def fail(*_, **__):
        raise failure_type("injected setup failure")

    monkeypatch.setattr(cli, "prepare_logging", capture_stream)
    monkeypatch.setattr(cli.multiprocessing, failure_stage, fail)
    if failure_type is KeyboardInterrupt:
        assert cli.main([str(scope), "-f", "secret"]) == 130
    else:
        with pytest.raises(OSError, match="injected setup failure"):
            cli.main([str(scope), "-f", "secret"])
    assert len(streams) == 1
    assert streams[0].closed
    assert logger.listener is logger.handler is logger.logpath is None


@pytest.mark.parametrize("failure_stage", ["listener", "thread"])
def test_direct_go_closes_prepared_log_if_listener_cannot_start(
    isolated_logger, monkeypatch, tmp_path, failure_stage
):
    import man_spider.manspider as cli

    options = SimpleNamespace(kerberos=False, state_path=tmp_path / "scan.sqlite3")
    streams = []
    prepare = logger.prepare_logging

    def capture_stream(state):
        path = prepare(state)
        streams.append(logger.handler.stream)
        return path

    def fail():
        raise OSError("injected listener start failure")

    monkeypatch.setattr(cli, "prepare_logging", capture_stream)
    if failure_stage == "listener":
        monkeypatch.setattr(cli, "start_listener", fail)
    else:
        monkeypatch.setattr("threading.Thread.start", lambda _self: fail())
    with pytest.raises(OSError, match="listener start failure"):
        cli.go(options)
    assert streams[0].closed
    assert logger.listener is logger.handler is logger.logpath is None


def test_unused_legacy_log_directory_does_not_reject_valid_state(monkeypatch, tmp_path):
    from man_spider.cli import parse_options

    home = tmp_path / "home"
    legacy = home / ".manspider"
    legacy.mkdir(parents=True)
    destination = tmp_path / "unrelated-logs"
    destination.mkdir()
    (legacy / "logs").symlink_to(destination, target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    options = parse_options([str(tmp_path), "-f", "secret", "--state-file", str(tmp_path / "state.sqlite3")])
    assert options.state_path == str(tmp_path / "state.sqlite3")
    assert list(destination.iterdir()) == []
