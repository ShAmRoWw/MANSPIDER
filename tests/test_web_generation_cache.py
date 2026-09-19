"""Exact summary reuse and bounded contention; disposable local states only."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
import threading
import time

import pytest

from man_spider import state as state_module, web_data
from man_spider.state import FindingRecord, ScanState
from man_spider.web_data import ViewerError, ViewerStore


@pytest.fixture
def scan(tmp_path, monkeypatch):
    monkeypatch.setattr(web_data, "_CACHE_SECONDS", 0)
    with closing(ScanState.create(tmp_path / "scan.sqlite3", {}, "test")) as state:
        obj = state.claim_object(object_key="one", kind="file", path="one.txt")
        state.complete_object(obj.object_id, "processed", findings=[FindingRecord("rule:one", "SyntheticOnly")])
        store = ViewerStore([], [state.path])
        scan_id = store.scans()["scans"][0]["id"]
        yield state, store, scan_id, obj.object_id


def observe_aggregates(store, monkeypatch):
    calls = []
    original = store._aggregate_summary

    def observed(*args):
        calls.append(True)
        return original(*args)

    monkeypatch.setattr(store, "_aggregate_summary", observed)
    return calls


def heartbeat(state, seconds):
    state.set_checkpoint("scan_timing", {
        "version": 1, "elapsed_seconds": seconds,
        "updated_at": datetime.now(timezone.utc).isoformat(), "eta": None,
    })


def test_one_hundred_heartbeats_reuse_exact_aggregates_with_fresh_timing(scan, monkeypatch):
    state, store, scan_id, _ = scan
    calls = observe_aggregates(store, monkeypatch)
    first = store.summary(scan_id)
    generation = store._summary_keys[scan_id]["generation"]
    for seconds in range(1, 101):
        heartbeat(state, seconds)
        changes = state.connection.total_changes
        current = store.summary(scan_id)
        assert current["timing"]["elapsed_seconds"] == seconds
        assert current["findings"] == first["findings"] == 1
        assert current["results_revision"] == first["results_revision"]
        assert current["revision"] != first["revision"]
        assert store._summary_keys[scan_id]["generation"] == generation
        assert state.connection.total_changes == changes
    assert len(calls) == 1


def test_same_count_replacement_with_frozen_clock_changes_generation(scan, monkeypatch):
    state, store, scan_id, object_id = scan
    monkeypatch.setattr(state_module, "utc_now", lambda: "2000-01-01T00:00:00+00:00")
    state.complete_object(object_id, "processed", findings=[FindingRecord("rule:one", "before")])
    first = store.summary(scan_id)
    calls = observe_aggregates(store, monkeypatch)
    state.complete_object(object_id, "processed", findings=[FindingRecord("rule:one", "after")])
    second = store.summary(scan_id)
    assert first["findings"] == second["findings"] == 1
    assert first["results_revision"] != second["results_revision"]
    assert len(calls) == 1
    assert store.findings(scan_id)["items"][0]["findings"][0]["value"] == "after"


@pytest.mark.parametrize("broken", ["missing", -1, "invalid", 1.5, 2**63 - 1])
def test_missing_or_malformed_generation_falls_back_without_viewer_writes(scan, monkeypatch, broken):
    state, store, scan_id, _ = scan
    if broken == "missing":
        state.connection.execute("DELETE FROM counters WHERE name='data_revision'")
    else:
        state.connection.execute("UPDATE counters SET value=? WHERE name='data_revision'", (broken,))
    calls = observe_aggregates(store, monkeypatch)
    first = store.summary(scan_id)
    heartbeat(state, 5)
    changes = state.connection.total_changes
    second = store.summary(scan_id)
    assert state.connection.total_changes == changes
    assert first["findings"] == second["findings"] == 1
    assert second["timing"]["elapsed_seconds"] == 5
    assert len(calls) == 2


def test_legacy_schema_never_trusts_a_counter_with_the_new_name(scan, monkeypatch):
    state, store, scan_id, _ = scan
    state.connection.execute("UPDATE runs SET schema_version=8")
    calls = observe_aggregates(store, monkeypatch)
    store.summary(scan_id)
    heartbeat(state, 5)
    store.summary(scan_id)
    assert len(calls) == 2
    assert state.run_row()["schema_version"] == 8


@pytest.mark.parametrize("another_viewer", [False, True])
def test_review_only_changes_do_not_recount_main_database(scan, monkeypatch, another_viewer):
    state, store, scan_id, object_id = scan
    calls = observe_aggregates(store, monkeypatch)
    first = store.summary(scan_id)
    finding_id = state.findings_for(object_id)[0]["finding_id"]
    reviewer = ViewerStore([], [state.path]) if another_viewer else store
    reviewer.set_finding_review(scan_id, finding_id, True)
    second = store.summary(scan_id)
    assert len(calls) == 1
    assert first["findings"] == second["findings"]
    assert first["results_revision"] != second["results_revision"]
    assert store.findings(scan_id, review_status="reviewed")["items"]


def test_commit_during_aggregate_never_labels_old_counts_with_new_generation(scan, monkeypatch):
    state, store, scan_id, object_id = scan
    original = store._aggregate_summary
    changed = []

    def commit_after_snapshot(*args):
        if not changed:
            changed.append(True)
            state.complete_object(object_id, "processed", findings=[
                FindingRecord("rule:one", "SyntheticOnly"), FindingRecord("rule:two", "SecondOnly"),
            ])
        return original(*args)

    monkeypatch.setattr(store, "_aggregate_summary", commit_after_snapshot)
    first = store.summary(scan_id)
    first_generation = store._summary_keys[scan_id]["generation"]
    second = store.summary(scan_id)
    assert first["findings"] == 1 and second["findings"] == 2
    assert store._summary_keys[scan_id]["generation"] > first_generation
    assert second["results_revision"] != first["results_revision"]


def test_resume_clears_old_timer_and_keeps_aggregates_correct(scan):
    state, store, scan_id, _ = scan
    heartbeat(state, 500)
    assert store.summary(scan_id)["timing"]["elapsed_seconds"] == 500
    state.set_run_status("interrupted")
    with closing(ScanState.resume(state.path, {}, "test")):
        result = store.summary(scan_id)
    assert result["timing"]["elapsed_seconds"] is None
    assert result["scan"]["status"] == "running"
    assert result["findings"] == 1


def test_parallel_summary_requests_share_one_aggregate(scan, monkeypatch):
    _state, store, scan_id, _ = scan
    entered, release = threading.Event(), threading.Event()
    calls = []
    original = store._aggregate_summary

    def slow(*args):
        calls.append(True)
        entered.set()
        assert release.wait(2)
        return original(*args)

    monkeypatch.setattr(store, "_aggregate_summary", slow)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(store.summary, scan_id)
        assert entered.wait(1)
        second = executor.submit(store.summary, scan_id)
        try:
            assert not threading.Event().wait(.03)
            assert not second.done()
        finally:
            release.set()
        assert first.result(timeout=2) == second.result(timeout=2)
    assert len(calls) == 1
    assert not store._summary_flights


def test_singleflight_wait_is_bounded_and_failure_does_not_poison_cache(scan, monkeypatch):
    _state, store, scan_id, _ = scan
    entered, release = threading.Event(), threading.Event()
    original = store._aggregate_summary
    store.query_timeout = .1

    def slow(*_):
        entered.set()
        assert release.wait(2)
        raise ViewerError("Synthetic bounded query failure", 503)

    monkeypatch.setattr(store, "_aggregate_summary", slow)
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(store.summary, scan_id)
        assert entered.wait(1)
        beginning = time.monotonic()
        try:
            with pytest.raises(ViewerError) as error:
                store.summary(scan_id)
            assert error.value.status == 503
            assert time.monotonic() - beginning < 1
        finally:
            release.set()
        with pytest.raises(ViewerError):
            first.result(timeout=2)
    assert not store._summary_flights
    monkeypatch.setattr(store, "_aggregate_summary", original)
    assert store.summary(scan_id)["findings"] == 1
