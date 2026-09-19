import json
import stat
from bisect import bisect_left

from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.smbconnection import SessionError

from man_spider.metrics import (
    LATENCY_BUCKETS_NS,
    METRICS_SCHEMA_VERSION,
    SMBMetricsCollector,
    SMBMetricsEmitter,
    classify_smb_error,
    default_smb_metrics_path,
    empty_operation,
    write_smb_metrics_report,
)


def test_real_smb_access_denied_is_classified_without_a_text_heuristic():
    assert classify_smb_error(SessionError(STATUS_ACCESS_DENIED)) == "access_denied"
    assert classify_smb_error(OSError("access denied")) == "access_denied"


class FakeClock:
    def __init__(self):
        self.value = 0

    def __call__(self):
        return self.value

    def advance_ms(self, milliseconds):
        self.value += int(milliseconds * 1_000_000)


def operation_values(*, count, duration_ms, successes=None, error_kind=None, transferred=0):
    values = empty_operation()
    successes = count if successes is None else successes
    values["attempts"] = count
    values["successes"] = successes
    values["failures"] = count - successes
    duration_ns = int(duration_ms * 1_000_000)
    values["duration_ns"] = duration_ns * count
    values["max_duration_ns"] = duration_ns
    values["bytes"] = transferred
    values["latency_buckets"][bisect_left(LATENCY_BUCKETS_NS, duration_ns)] = count
    if error_kind:
        values["errors"][error_kind] = count - successes
    return values


def interval_snapshot(start_seconds, end_seconds, operations, *, reconnects=0):
    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "host": "fileserver.test",
        "port": 445,
        "first_started_ns": int(start_seconds * 1_000_000_000),
        "last_ended_ns": int(end_seconds * 1_000_000_000),
        "operations": operations,
        "sessions_opened": 0,
        "sessions_closed": 0,
        "reconnects": reconnects,
    }


def test_process_emitter_batches_existing_operations_without_storing_payloads():
    clock = FakeClock()
    snapshots = []
    emitter = SMBMetricsEmitter(
        "fileserver.test",
        445,
        snapshots.append,
        flush_interval_seconds=60,
        clock=clock,
    )

    started = emitter.started()
    clock.advance_ms(4)
    emitter.record_operation("directory_list", started, items=17)
    started = emitter.started()
    clock.advance_ms(8)
    emitter.record_operation("file_read", started, bytes_transferred=4096)
    emitter.record_session_opened()
    emitter.record_reconnect()
    emitter.record_session_closed()

    assert snapshots == []
    emitter.flush(force=True)

    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert snapshot["host"] == "fileserver.test"
    assert snapshot["operations"]["directory_list"]["items"] == 17
    assert snapshot["operations"]["file_read"]["bytes"] == 4096
    assert snapshot["sessions_opened"] == 1
    assert snapshot["sessions_closed"] == 1
    assert snapshot["reconnects"] == 1
    assert "payload" not in json.dumps(snapshot)


def test_collector_warns_only_after_sustained_latency_degradation():
    collector = SMBMetricsCollector()
    healthy = {"directory_list": operation_values(count=60, duration_ms=8)}
    slow = {"directory_list": operation_values(count=60, duration_ms=250)}

    assert collector.ingest(interval_snapshot(0, 10, healthy)) == ()
    assert collector.ingest(interval_snapshot(10, 20, slow)) == ()
    warnings = collector.ingest(interval_snapshot(20, 30, slow))

    assert len(warnings) == 1
    assert "directory-list" in warnings[0]
    assert "concurrency was not changed" in warnings[0]
    report = collector.report(run_id="run", run_status="complete", state_path="scan.sqlite3")
    assert report["automatic_throttling"] is False
    assert report["totals"]["degradation_warnings"] == 1


def test_access_denied_is_reported_but_never_treated_as_transport_degradation():
    collector = SMBMetricsCollector()
    denied = {
        "directory_list": operation_values(
            count=20,
            duration_ms=2,
            successes=0,
            error_kind="access_denied",
        )
    }

    assert collector.ingest(interval_snapshot(0, 10, denied)) == ()
    assert collector.ingest(interval_snapshot(10, 20, denied)) == ()
    report = collector.report(run_id="run", run_status="complete_with_errors", state_path="scan.sqlite3")
    host = report["hosts"][0]
    assert host["degradation_warnings"] == []
    assert host["operation_details"]["directory_list"]["errors"]["access_denied"] == 40


def test_timeout_disconnect_warning_requires_two_windows():
    collector = SMBMetricsCollector()
    unstable = {
        "directory_list": operation_values(
            count=20,
            duration_ms=500,
            successes=16,
            error_kind="timeout",
        )
    }

    assert collector.ingest(interval_snapshot(0, 10, unstable)) == ()
    warnings = collector.ingest(interval_snapshot(10, 20, unstable))

    assert len(warnings) == 1
    assert "timeout/disconnect" in warnings[0]


def test_metrics_report_is_atomic_and_adjacent_to_scan_state(tmp_path):
    state_path = tmp_path / "manspider_20260905.sqlite3"
    destination = default_smb_metrics_path(state_path)
    first = {"schema_version": 1, "hosts": []}
    second = {"schema_version": 1, "hosts": [{"host": "replacement"}]}

    assert destination == tmp_path / "manspider_20260905.smb-metrics.json"
    write_smb_metrics_report(first, destination)
    write_smb_metrics_report(second, destination)

    assert json.loads(destination.read_text(encoding="utf-8")) == second
    assert stat.S_IMODE(destination.stat().st_mode) == 0o664
    assert list(tmp_path.glob("*.tmp")) == []
