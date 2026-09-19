from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from man_spider.lib import spider as spider_module
from man_spider.lib.spider import MANSPIDER
from man_spider.progress import ETAEstimate
from man_spider.state import ScanState, StateError


class FakeClock:
    value = 100.0

    def __call__(self):
        return self.value


class FakeEstimator:
    initializations = 0
    updates = 0
    estimate = ETAEstimate(
        status="estimated", elapsed_seconds=5.0, remaining_seconds=30.0,
        lower_seconds=20.0, upper_seconds=40.0, total_seconds=35.0,
        confidence="low", basis="share completion",
    )

    def initialize(self, snapshot):
        self.initializations += 1

    def update(self, snapshot, **kwargs):
        self.updates += 1
        return self.estimate


@pytest.fixture
def scan(tmp_path, monkeypatch):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "test")
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.state_path = state.path
    scanner.state_run_id = state.run_id
    scanner.targets = [tmp_path]
    scanner.targets_completed = 0
    scanner.eta_estimator = FakeEstimator()
    clock = FakeClock()
    monkeypatch.setattr(spider_module, "monotonic", clock)
    yield state, scanner, clock
    state.close()


@pytest.mark.parametrize("enabled", [True, False])
def test_main_scan_initializes_timing_without_reusing_preflight_duration(scan, enabled):
    state, scanner, clock = scan
    if not enabled:
        scanner.eta_estimator = None
    assert state.get_checkpoint("scan_timing") is None
    # Arbitrary preflight/approval time must not contribute to main-scan time.
    clock.value = 500.0
    scanner.initialize_progress_tracking()
    timing = state.get_checkpoint("scan_timing")
    assert timing["version"] == 1
    assert timing["elapsed_seconds"] == 0.0
    assert datetime.fromisoformat(timing["started_at"]).utcoffset().total_seconds() == 0
    assert datetime.fromisoformat(timing["updated_at"]).tzinfo == timezone.utc
    if enabled:
        assert timing["eta"]["status"] == "calculating"
        assert scanner.eta_estimator.updates == 0
    else:
        assert timing["eta"] is None


def test_timing_reuses_existing_snapshot_and_estimate_at_normal_cadence(scan, monkeypatch):
    state, scanner, clock = scan
    snapshots = []
    writes = []
    original_snapshot = ScanState.progress_snapshot
    original_checkpoint = ScanState.set_checkpoint

    def snapshot(attached):
        snapshots.append(clock.value)
        return original_snapshot(attached)

    def checkpoint(attached, name, payload):
        writes.append((name, clock.value))
        return original_checkpoint(attached, name, payload)

    monkeypatch.setattr(ScanState, "progress_snapshot", snapshot)
    monkeypatch.setattr(ScanState, "set_checkpoint", checkpoint)
    scanner.initialize_progress_tracking()
    clock.value = 104.9
    scanner.maybe_report_progress()
    assert len(snapshots) == len(writes) == 1
    assert scanner.eta_estimator.updates == 0
    clock.value = 105.0
    scanner.maybe_report_progress()
    timing = state.get_checkpoint("scan_timing")
    assert len(snapshots) == len(writes) == 2
    assert all(name == "scan_timing" for name, _ in writes)
    assert scanner.eta_estimator.updates == 1
    assert timing["elapsed_seconds"] == 5.0
    assert timing["eta"] == scanner.eta_estimator.estimate.as_dict()
    assert state.connection.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0] == 1


def test_no_eta_keeps_monotonic_elapsed_without_initial_manifest_query(scan, monkeypatch):
    state, scanner, clock = scan
    scanner.eta_estimator = None
    monkeypatch.setattr(ScanState, "progress_snapshot", lambda _: pytest.fail("extra manifest query"))
    scanner.initialize_progress_tracking()
    clock.value = 106.0
    scanner.persist_scan_timing()
    assert state.get_checkpoint("scan_timing")["elapsed_seconds"] == 6.0
    clock.value = 103.0
    scanner.persist_scan_timing()
    timing = state.get_checkpoint("scan_timing")
    assert timing["elapsed_seconds"] == 6.0
    assert timing["eta"] is None


@pytest.mark.parametrize("status", ["complete", "complete_with_errors", "interrupted", "preflight_failed"])
@pytest.mark.parametrize("enabled", [True, False])
def test_terminal_status_freezes_elapsed_and_clears_or_completes_eta(scan, status, enabled):
    state, scanner, clock = scan
    if not enabled:
        scanner.eta_estimator = None
    scanner.initialize_progress_tracking()
    clock.value = 108.0
    scanner.report_progress()
    state.set_run_status(status)
    timing = state.get_checkpoint("scan_timing")
    clock.value = 500.0
    assert timing["elapsed_seconds"] == 8.0
    if enabled and status in {"complete", "complete_with_errors"}:
        assert timing["eta"]["status"] == "complete"
        assert timing["eta"]["remaining_seconds"] == 0.0
        assert timing["eta"]["total_seconds"] == 8.0
    else:
        assert timing["eta"] is None
    assert state.get_checkpoint("scan_timing") == timing


def test_supervisor_interruption_suppresses_eta_without_wall_clock_extrapolation(scan):
    state, scanner, clock = scan
    scanner.initialize_progress_tracking()
    clock.value = 105.0
    scanner.report_progress()
    clock.value = 1_000.0
    assert ScanState.interrupt_latest(state.path)
    timing = state.get_checkpoint("scan_timing")
    assert timing["elapsed_seconds"] == 5.0
    assert timing["eta"] is None
    assert not ScanState.interrupt_latest(state.path)
    assert state.get_checkpoint("scan_timing") == timing


def test_resume_clears_previous_invocation_before_main_scan_starts(scan):
    state, scanner, clock = scan
    scanner.initialize_progress_tracking()
    clock.value = 150.0
    scanner.report_progress()
    state.set_run_status("interrupted")
    resumed = ScanState.resume(state.path, {}, "test")
    try:
        assert resumed.run_row()["status"] == "running"
        assert resumed.get_checkpoint("scan_timing") is None
        clock.value = 1_000.0
        scanner.initialize_progress_tracking()
        assert resumed.get_checkpoint("scan_timing")["elapsed_seconds"] == 0.0
    finally:
        resumed.close()


def test_resume_timing_reset_and_status_change_are_atomic(scan):
    state, scanner, _clock = scan
    scanner.initialize_progress_tracking()
    state.set_run_status("interrupted")
    old_timing = state.get_checkpoint("scan_timing")
    state.connection.execute("""
        CREATE TRIGGER reject_resume BEFORE UPDATE ON runs WHEN NEW.status='running'
        BEGIN SELECT RAISE(ABORT, 'resume fixture failure'); END
    """)
    with pytest.raises(StateError, match="resume fixture failure"):
        ScanState.resume(state.path, {}, "test")
    assert state.run_row()["status"] == "interrupted"
    assert state.get_checkpoint("scan_timing") == old_timing


@pytest.mark.parametrize("status", ["complete", "interrupted", "preflight_failed"])
def test_legacy_or_preflight_only_state_has_no_inferred_timing(scan, status):
    state, _scanner, _clock = scan
    state.set_run_status(status)
    assert state.get_checkpoint("scan_timing") is None


def test_finally_captures_sub_interval_main_scan_duration_without_more_snapshots(scan, monkeypatch):
    state, scanner, clock = scan
    scanner.external_log_listener = True
    scanner.prepare_temp_dir = lambda: None
    scanner.cleanup_temp_dir = lambda: None
    scanner.spiderling_queue = SimpleNamespace(close=lambda: None, join_thread=lambda: None)
    scanner._start = lambda: setattr(clock, "value", 102.25)
    monkeypatch.setattr(spider_module, "_install_worker_interrupt_handler", lambda: None)
    scanner.start()
    assert scanner.eta_estimator.initializations == 1
    assert scanner.eta_estimator.updates == 0
    assert state.get_checkpoint("scan_timing")["elapsed_seconds"] == 2.25
    state.finish()
    assert state.get_checkpoint("scan_timing")["eta"]["remaining_seconds"] == 0.0


def test_optional_timing_write_failure_does_not_hide_primary_scan_error(scan, monkeypatch):
    state, scanner, _clock = scan
    scanner.external_log_listener = True
    scanner.prepare_temp_dir = lambda: None
    scanner.cleanup_temp_dir = lambda: None
    scanner.stop_workers = lambda: None
    scanner.spiderling_queue = SimpleNamespace(close=lambda: None, join_thread=lambda: None)
    scanner._start = lambda: (_ for _ in ()).throw(RuntimeError("primary scan failure"))
    monkeypatch.setattr(spider_module, "_install_worker_interrupt_handler", lambda: None)
    monkeypatch.setattr(spider_module, "_ignore_worker_interrupts", lambda: None)

    def fail_checkpoint(*args, **kwargs):
        raise StateError("secondary timing failure")

    monkeypatch.setattr(ScanState, "set_checkpoint", fail_checkpoint)
    with pytest.raises(RuntimeError, match="primary scan failure"):
        scanner.start()
    state.set_run_status("interrupted", reason="primary scan failure")
    assert state.run_row()["error_reason"] == "primary scan failure"


def test_terminal_telemetry_failure_does_not_prevent_primary_status(scan, monkeypatch):
    state, scanner, _clock = scan
    scanner.initialize_progress_tracking()

    def fail_checkpoint(*args, **kwargs):
        raise StateError("secondary timing failure")

    monkeypatch.setattr(ScanState, "set_checkpoint", fail_checkpoint)
    state.set_run_status("interrupted", reason="primary scan failure")
    assert state.run_row()["status"] == "interrupted"
    assert state.run_row()["error_reason"] == "primary scan failure"
