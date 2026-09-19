"""Saved ETA is exposed read-only, with no remote work or extra polling."""

from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys

import pytest

from man_spider.state import ScanState
from man_spider.web_data import ViewerStore
import man_spider.web_data as web_data


@pytest.fixture
def timing_scan(tmp_path):
    with closing(ScanState.create(tmp_path / "timing.sqlite3", {"dynamic_eta": True}, "test")) as state:
        yield state


def checkpoint(state, *, status="estimated", age=0, **changes):
    now = datetime.now(timezone.utc)
    payload = {
        "version": 1,
        "started_at": (now - timedelta(seconds=125)).isoformat(),
        "updated_at": (now - timedelta(seconds=age)).isoformat(),
        "elapsed_seconds": 125.25,
        "eta": {
            "status": status, "elapsed_seconds": 125.25,
            "remaining_seconds": 360.5, "lower_seconds": 300, "upper_seconds": 450,
            "confidence": "medium", "basis": "private checkpoint text must not reach API",
        },
    }
    payload.update(changes)
    state.set_checkpoint("scan_timing", payload)
    return payload


def viewer(state):
    store = ViewerStore([], files=[state.path])
    return store, store.scans()["scans"][0]["id"]


def test_saved_estimate_is_bounded_allowlisted_and_read_only(timing_scan):
    payload = checkpoint(timing_scan)
    before = timing_scan.connection.total_changes
    store, scan_id = viewer(timing_scan)
    timing = store.summary(scan_id)["timing"]
    assert timing == {
        "elapsed_seconds": 125.25, "remaining_seconds": 360.5,
        "lower_seconds": 300.0, "upper_seconds": 450.0,
        "confidence": "medium", "eta_status": "estimated", "updated_at": payload["updated_at"],
    }
    assert "private checkpoint" not in json.dumps(store.summary(scan_id))
    assert timing_scan.connection.total_changes == before


@pytest.mark.parametrize("status", ["calculating", "unavailable", "not_started"])
def test_non_estimated_status_does_not_show_stored_numbers(timing_scan, status):
    checkpoint(timing_scan, status=status)
    store, scan_id = viewer(timing_scan)
    timing = store.summary(scan_id)["timing"]
    assert timing["eta_status"] == status
    assert timing["remaining_seconds"] is None
    assert timing["elapsed_seconds"] == 125.25


@pytest.mark.parametrize("status", ["complete", "complete_with_errors", "interrupted", "preflight_failed"])
def test_terminal_run_status_overrides_live_checkpoint(timing_scan, status):
    checkpoint(timing_scan, age=60)
    # Simulate legacy/abrupt finalization that did not update telemetry.
    timing_scan.connection.execute("UPDATE runs SET status=?", (status,))
    store, scan_id = viewer(timing_scan)
    timing = store.summary(scan_id)["timing"]
    assert timing["elapsed_seconds"] == 125.25
    assert timing["eta_status"] == ("complete" if status.startswith("complete") else "unavailable")
    assert timing["remaining_seconds"] == (0.0 if status.startswith("complete") else None)


def test_no_eta_keeps_elapsed_and_suppresses_old_forecast(timing_scan):
    checkpoint(timing_scan)
    timing_scan.connection.execute('UPDATE runs SET config_json=\'{"dynamic_eta": false}\'')
    store, scan_id = viewer(timing_scan)
    timing = store.summary(scan_id)["timing"]
    assert timing["eta_status"] == "disabled"
    assert timing["elapsed_seconds"] == 125.25
    assert timing["remaining_seconds"] is None


@pytest.mark.parametrize("age", [31, -10])
def test_stale_or_future_snapshot_cannot_predict_completion(timing_scan, age):
    checkpoint(timing_scan, age=age)
    store, scan_id = viewer(timing_scan)
    timing = store.summary(scan_id)["timing"]
    assert timing["eta_status"] == "stale"
    assert timing["remaining_seconds"] is None
    assert timing["elapsed_seconds"] == 125.25  # Never keep counting an abandoned run.


def test_cached_estimate_expires_without_database_read(timing_scan, monkeypatch):
    checkpoint(timing_scan)
    store, scan_id = viewer(timing_scan)
    first = store.summary(scan_id)
    assert first["timing"]["eta_status"] == "estimated"

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(seconds=40)

    @contextmanager
    def forbidden(*_):
        pytest.fail("Unchanged telemetry unnecessarily reopened SQLite")
        yield

    monkeypatch.setattr(web_data, "datetime", Later)
    monkeypatch.setattr(store, "_connection", forbidden)
    expired = store.summary(scan_id)
    assert expired["timing"]["eta_status"] == "stale"
    assert expired["timing"]["remaining_seconds"] is None
    assert first["timing"]["eta_status"] == "estimated"
    assert expired["revision"] == first["revision"]


@pytest.mark.parametrize("raw", ["null", "[]", "{}", "bad JSON", '{"version":2}', '{"version":true}', '[' * 2000, '"' + 'x' * 8192 + '"'],
                         ids=["null", "list", "empty", "invalid", "version", "bool_version", "nested", "oversized"])
def test_missing_or_malformed_timing_is_unavailable_without_breaking_summary(timing_scan, raw):
    timing_scan.connection.execute(
        "INSERT INTO checkpoints(run_id,name,value_json,updated_at) VALUES (?,?,?,?)",
        (timing_scan.run_id, "scan_timing", raw, datetime.now(timezone.utc).isoformat()),
    )
    store, scan_id = viewer(timing_scan)
    timing = store.summary(scan_id)["timing"]
    assert timing["elapsed_seconds"] is None
    assert timing["remaining_seconds"] is None
    assert timing["eta_status"] == "unavailable"


@pytest.mark.parametrize("value", [True, -1, "60", float("nan"), float("inf"), 1e100, None])
def test_invalid_numeric_fields_do_not_reach_json(timing_scan, value):
    payload = checkpoint(timing_scan, elapsed_seconds=value)
    payload["eta"]["remaining_seconds"] = value
    timing_scan.set_checkpoint("scan_timing", payload)
    store, scan_id = viewer(timing_scan)
    result = store.summary(scan_id)
    assert result["timing"]["elapsed_seconds"] is None
    assert result["timing"]["remaining_seconds"] is None
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize("updated", [None, "bad", "2026-09-19T12:00:00", "x" * 100])
def test_estimate_without_valid_timestamp_is_not_presented_as_live(timing_scan, updated):
    checkpoint(timing_scan, updated_at=updated)
    store, scan_id = viewer(timing_scan)
    timing = store.summary(scan_id)["timing"]
    assert timing["remaining_seconds"] is None
    assert timing["updated_at"] is None


def test_legacy_database_without_checkpoint_table_stays_readable(timing_scan):
    timing_scan.connection.execute("DROP TABLE checkpoints")
    store, scan_id = viewer(timing_scan)
    assert store.summary(scan_id)["timing"]["elapsed_seconds"] is None


def test_resume_does_not_keep_previous_run_duration_or_eta(timing_scan):
    checkpoint(timing_scan)
    timing_scan.set_run_status("interrupted")
    with closing(ScanState.resume(timing_scan.path, {"dynamic_eta": True}, "test")) as resumed:
        assert resumed.get_checkpoint("scan_timing") is None
        store, scan_id = viewer(resumed)
        timing = store.summary(scan_id)["timing"]
        assert timing["elapsed_seconds"] is None
        assert timing["remaining_seconds"] is None


def test_timing_is_in_http_summary(timing_scan):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from man_spider.web import create_app

    checkpoint(timing_scan)
    store, scan_id = viewer(timing_scan)
    with TestClient(create_app(store, port=18765), base_url="http://127.0.0.1:18765") as client:
        response = client.get(f"/api/scans/{scan_id}/summary")
        assert response.status_code == 200
        assert response.json()["timing"]["remaining_seconds"] == 360.5


def test_timing_only_does_not_change_results_revision(timing_scan, monkeypatch):
    monkeypatch.setattr(web_data, "_CACHE_SECONDS", 0)
    checkpoint(timing_scan)
    store, scan_id = viewer(timing_scan)
    before = store.summary(scan_id)
    checkpoint(timing_scan, elapsed_seconds=150)
    after = store.summary(scan_id)
    assert after["timing"]["elapsed_seconds"] == 150
    assert after["revision"] != before["revision"]
    assert after["results_revision"] == before["results_revision"]
    timing_scan.claim_object(object_key="new", kind="file", path="new.txt")
    changed = store.summary(scan_id)
    assert changed["results_revision"] != after["results_revision"]


def test_same_count_reprocessed_finding_changes_results_revision(timing_scan, monkeypatch):
    from man_spider.state import FindingRecord

    monkeypatch.setattr(web_data, "_CACHE_SECONDS", 0)
    decision = timing_scan.claim_object(object_key="one", kind="file", path="one.txt")
    timing_scan.complete_object(decision.object_id, "processed", findings=[FindingRecord("rule:test", "old")])
    store, scan_id = viewer(timing_scan)
    before = store.summary(scan_id)
    timing_scan.complete_object(decision.object_id, "processed", findings=[FindingRecord("rule:test", "new")])
    after = store.summary(scan_id)
    assert after["findings"] == before["findings"] == 1
    assert after["results_revision"] != before["results_revision"]


@pytest.mark.parametrize("eta_enabled", [True, False])
def test_real_local_scan_publishes_frozen_timing_for_viewer(tmp_path, eta_enabled):
    source = tmp_path / "source"
    source.mkdir()
    fixture = source / "secret.txt"
    fixture.write_text("SyntheticOnly=password123", encoding="utf-8")
    before = (fixture.read_bytes(), fixture.stat().st_mtime_ns)
    state_path = tmp_path / "scan.sqlite3"
    result = subprocess.run(
        [sys.executable, "-m", "man_spider.manspider", str(source), "--yes", "-e", "txt",
         "--state-file", str(state_path), *([] if eta_enabled else ["--no-eta"])],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    store = ViewerStore([], files=[state_path])
    scan_id = store.scans()["scans"][0]["id"]
    summary = store.summary(scan_id)
    assert summary["scan"]["status"] == "complete"
    assert summary["timing"]["elapsed_seconds"] > 0
    assert summary["timing"]["eta_status"] == "complete"
    assert summary["timing"]["remaining_seconds"] == 0
    assert summary["findings"] > 0
    assert (fixture.read_bytes(), fixture.stat().st_mtime_ns) == before
