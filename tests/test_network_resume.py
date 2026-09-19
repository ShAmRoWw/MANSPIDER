"""Durable network recovery grants one fresh visit, without inventing pending work."""

import subprocess
import sys
from pathlib import Path

import pytest

from man_spider.cli import parse_options
from man_spider.error_policy import NETWORK_UNAVAILABLE_MARKER
from man_spider.state import (
    FindingRecord,
    NETWORK_RESUME_READY_PREFIX,
    ScanLease,
    ScanState,
    discover_resumable_scans,
    normalized_scan_configuration,
)


NETWORK_REASON = f"{NETWORK_UNAVAILABLE_MARKER} ConnectionResetError: peer reset"


def values(kind="file", *, name="secret.txt", host="server"):
    target_key = f"target|smb|{host}|445"
    keys = {
        "target": target_key,
        "share": f"share|smb|{host}|445|data",
        "directory": f"directory|smb|{host}|445|data|folder",
        "file": f"smb|{host}|445|data|folder\\{name}",
        "share_enumeration": f"share-enumeration|{target_key}",
    }
    return dict(
        object_key=keys[kind],
        kind=kind,
        target=host,
        share=None if kind in {"target", "share_enumeration"} else "Data",
        path=host if kind in {"target", "share_enumeration"} else f"folder\\{name}",
    )


def seed(state, object_values=None, *, reason=NETWORK_REASON, attempts=2, status="error", findings=()):
    object_values = values() if object_values is None else object_values
    decision = state.register_object(**object_values)
    for _ in range(attempts):
        state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, status, reason=reason, findings=findings)
    return decision.object_id


@pytest.fixture
def scan(tmp_path):
    configuration = normalized_scan_configuration(parse_options([str(tmp_path), "-f", "secret"]))
    current = ScanState.create(tmp_path / "network.sqlite3", configuration, "2.0.0")
    try:
        yield current, configuration
    finally:
        current.close()


@pytest.mark.parametrize("kind", ["file", "directory", "share", "target", "share_enumeration"])
def test_exhausted_network_object_gets_one_fresh_claim_on_resume(scan, kind):
    state, _configuration = scan
    object_values = values(kind)
    object_id = seed(state, object_values, attempts=7)
    assert not state.claim_object(**object_values, retry_limit=2).should_process
    assert state.prepare_resume(retry_limit=2) == 1
    row = state.object_row(object_id)
    assert row["status"] == "error"
    assert row["reason"].startswith(NETWORK_RESUME_READY_PREFIX)
    assert row["attempts"] == 7
    assert object_id in {row["object_id"] for row in state.resumable_objects(retry_limit=2)}

    claim = state.claim_object(**object_values, retry_limit=2)
    assert claim.should_process
    assert state.object_row(object_id)["attempts"] == 8
    assert state.object_row(object_id)["reason"] is None
    state.complete_object(object_id, "error", reason=NETWORK_REASON)
    assert not state.claim_object(**object_values, retry_limit=2).should_process
    assert state.prepare_resume(retry_limit=2) == 0
    assert not state.claim_object(**object_values, retry_limit=2).should_process
    assert object_id not in {row["object_id"] for row in state.resumable_objects(retry_limit=2)}


def test_each_new_resume_can_recover_after_repeated_outages(scan):
    state, configuration = scan
    object_id = seed(state, attempts=4)
    state.set_run_status("complete_with_errors")
    for expected_attempts in (5, 6, 7):
        resumed = ScanState.resume(state.path, configuration, "2.0.0")
        try:
            assert resumed.prepare_resume(retry_limit=2) == 1
            assert resumed.claim_object(**values(), retry_limit=2).should_process
            assert resumed.object_row(object_id)["attempts"] == expected_attempts
            resumed.complete_object(object_id, "error", reason=NETWORK_REASON)
            assert not resumed.claim_object(**values(), retry_limit=2).should_process
            assert resumed.finish() == "complete_with_errors"
        finally:
            resumed.close()


def test_prepared_network_leaf_that_disappeared_stays_terminal(scan):
    state, _configuration = scan
    object_id = seed(state, attempts=8)
    assert state.prepare_resume(retry_limit=2) == 1
    # A successful parent enumeration need never rediscover this old filename.
    assert state.settle_blocked_objects() == 0
    assert state.finish() == "complete_with_errors"
    row = state.object_row(object_id)
    assert row["status"] == "error"
    assert row["attempts"] == 8
    assert state.summary()["pending"] == state.summary()["in_progress"] == 0


def test_resume_reopens_exhausted_ancestors_and_preserves_findings_and_identity(scan):
    state, _configuration = scan
    ancestor_values = [values(kind) for kind in ("target", "share", "directory")]
    ancestor_ids = [seed(state, item, reason="previous non-network failure") for item in ancestor_values]
    file_values = dict(values(), size=123, mtime=456, file_id="stable-id")
    file_id = seed(state, file_values, findings=(FindingRecord("fixture", "existing evidence"),))
    sibling_id = seed(state, values(name="processed.txt"), status="processed", reason=None)
    before = dict(state.object_row(file_id))
    sibling_before = dict(state.object_row(sibling_id))
    findings_before = [dict(row) for row in state.findings_for(file_id)]
    assert state.prepare_resume(retry_limit=2) == 4
    assert state.prepare_resume(retry_limit=2) == 0
    assert all(state.object_row(object_id)["status"] == "pending" for object_id in ancestor_ids)
    assert all(state.object_row(object_id)["attempts"] == 2 for object_id in ancestor_ids)
    after = dict(state.object_row(file_id))
    for field, old_value in before.items():
        if field not in {"reason", "updated_at"}:
            assert after[field] == old_value, field
    assert [dict(row) for row in state.findings_for(file_id)] == findings_before
    assert dict(state.object_row(sibling_id)) == sibling_before


@pytest.mark.parametrize("reason", [
    "BrokenPipeError: peer reset",
    "TimeoutError: timed out",
    "STATUS_ACCESS_DENIED",
    "[network_access_denied] access refused",
    "parser error",
    f"filename contains {NETWORK_REASON}",
    "[network-unavailable-other] not the actual marker",
])
def test_ordinary_errors_are_not_rearmed_from_arbitrary_text(scan, reason):
    state, _configuration = scan
    object_id = seed(state, reason=reason)
    before = dict(state.object_row(object_id))
    assert state.prepare_resume(retry_limit=2) == 0
    assert dict(state.object_row(object_id)) == before
    assert not state.claim_object(**values(), retry_limit=2).should_process


def test_non_network_error_keeps_its_existing_unexhausted_retry_budget(scan):
    state, _configuration = scan
    object_id = seed(state, reason="parser failure", attempts=1)
    assert state.prepare_resume(retry_limit=2) == 0
    assert state.claim_object(**values(), retry_limit=2).should_process
    state.complete_object(object_id, "error", reason="parser failure")
    assert not state.claim_object(**values(), retry_limit=2).should_process
    assert state.object_row(object_id)["attempts"] == 2


@pytest.mark.parametrize("status", ["processed", "skipped"])
def test_successful_or_skipped_objects_are_not_rearmed_even_with_marker(scan, status):
    state, _configuration = scan
    object_id = seed(state, status=status)
    before = dict(state.object_row(object_id))
    assert state.prepare_resume(retry_limit=2) == 0
    assert dict(state.object_row(object_id)) == before
    assert not state.claim_object(**values(), retry_limit=2).should_process


@pytest.mark.parametrize("kind,key", [
    ("file", "local|/tmp/a.txt"),
    ("directory", "directory|local|/tmp"),
    ("target", "target|local|/tmp"),
    ("share_enumeration", "share-enumeration|local|/tmp"),
    ("file", "not-a-canonical-smb-key"),
])
def test_network_marker_never_rearms_non_smb_objects(scan, kind, key):
    state, _configuration = scan
    object_values = dict(object_key=key, kind=kind, path="/tmp/a.txt")
    object_id = seed(state, object_values)
    before = dict(state.object_row(object_id))
    assert state.prepare_resume(retry_limit=2) == 0
    assert dict(state.object_row(object_id)) == before
    assert not state.claim_object(**object_values, retry_limit=2).should_process


@pytest.mark.parametrize("status", ["error", "pending", "in_progress"])
def test_successful_share_enumeration_resolves_existing_observation_only(scan, status):
    state, _configuration = scan
    object_values = values("share_enumeration")
    object_id = seed(state, object_values, attempts=5, findings=(FindingRecord("fixture", "old evidence"),))
    if status != "error":
        state.connection.execute("UPDATE objects SET status=? WHERE object_id=?", (status, object_id))
    before = dict(state.object_row(object_id))
    findings_before = [dict(row) for row in state.findings_for(object_id)]
    assert state.resolve_share_enumeration(object_values["object_key"])
    after = dict(state.object_row(object_id))
    assert after["status"] == "processed"
    assert after["reason"] is None
    for field, old_value in before.items():
        if field not in {"status", "reason", "updated_at"}:
            assert after[field] == old_value, field
    assert [dict(row) for row in state.findings_for(object_id)] == findings_before
    assert not state.resolve_share_enumeration(object_values["object_key"])
    assert not state.resolve_share_enumeration(values("share_enumeration", host="healthy")["object_key"])
    assert state.connection.execute("SELECT count(*) FROM objects").fetchone()[0] == 1


def create_discovery_scan(directory, name, *, status, reason, hour, object_values=None, object_status="error"):
    configuration = normalized_scan_configuration(parse_options([str(directory), "-f", "secret"]))
    state = ScanState.create(directory / f"{name}.sqlite3", configuration, "2.0.0")
    try:
        if reason is not None:
            seed(state, object_values, reason=reason, status=object_status)
        state.set_run_status(status)
        timestamp = f"2026-09-14T{hour:02}:00:00+00:00"
        state.connection.execute("UPDATE runs SET created_at=?, updated_at=?", (timestamp, timestamp))
        return state.path
    finally:
        state.close()


def test_auto_chooser_includes_only_unfinished_network_errors_and_keeps_order(tmp_path):
    create_discovery_scan(tmp_path, "interrupted", status="interrupted", reason=None, hour=1)
    create_discovery_scan(tmp_path, "network", status="complete_with_errors", reason=NETWORK_REASON, hour=3)
    create_discovery_scan(tmp_path, "ordinary", status="complete_with_errors", reason="BrokenPipeError", hour=4)
    create_discovery_scan(tmp_path, "complete", status="complete", reason=NETWORK_REASON, hour=5)
    create_discovery_scan(tmp_path, "preflight", status="preflight_failed", reason=NETWORK_REASON, hour=6)
    create_discovery_scan(tmp_path, "fresh-preflight", status="preflight_failed", reason=None, hour=10)
    create_discovery_scan(tmp_path, "ordinary-preflight", status="preflight_failed", reason="ordinary", hour=11)
    create_discovery_scan(tmp_path, "running", status="running", reason=None, hour=2)
    create_discovery_scan(tmp_path, "processed", status="complete_with_errors", reason=NETWORK_REASON,
                          object_status="processed", hour=7)
    create_discovery_scan(tmp_path, "local", status="complete_with_errors", reason=NETWORK_REASON,
                          object_values=dict(object_key="local|/tmp/file", kind="file"), hour=8)
    busy_path = create_discovery_scan(tmp_path, "busy", status="complete_with_errors", reason=NETWORK_REASON, hour=9)
    lease = ScanLease.acquire(busy_path)
    try:
        candidates = discover_resumable_scans([tmp_path, tmp_path])
    finally:
        lease.release()
    assert [item.path.stem for item in candidates] == ["preflight", "network", "running", "interrupted"]
    assert candidates[0].status == "preflight_failed"
    assert candidates[1].status == "complete_with_errors"


def test_ready_but_unobserved_network_error_remains_offered_for_next_resume(scan):
    state, _configuration = scan
    seed(state)
    state.prepare_resume(retry_limit=2)
    state.finish()
    assert [item.path for item in discover_resumable_scans([state.path.parent])] == [state.path]


def test_recovery_does_not_change_schema(scan):
    state, _configuration = scan
    schema_before = tuple(state.connection.execute("SELECT type, name, sql FROM sqlite_master ORDER BY name"))
    version_before = state.run_row()["schema_version"]
    seed(state)
    state.prepare_resume(retry_limit=2)
    assert tuple(state.connection.execute("SELECT type, name, sql FROM sqlite_master ORDER BY name")) == schema_before
    assert state.run_row()["schema_version"] == version_before


def test_state_only_import_does_not_load_scanner_or_trigger_lib_import_cycle():
    result = subprocess.run(
        [sys.executable, "-c", "import sys; import man_spider.state; assert 'man_spider.lib' not in sys.modules"],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
