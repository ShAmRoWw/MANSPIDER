"""Analysis statistics are explicit durable evidence, never inferred from hits."""

import sqlite3

import pytest

from man_spider.output import build_json_report
from man_spider.lib.util import Target
from man_spider.state import (
    ANALYSIS_STATUSES,
    SCHEMA_VERSION,
    FindingRecord,
    ScanState,
    StateError,
    share_object_key,
    smb_object_key,
)


@pytest.fixture
def state(tmp_path):
    current = ScanState.create(tmp_path / "scan.sqlite3", {}, "test")
    yield current
    current.close()


def claim(state, key="file|one", **overrides):
    values = dict(object_key=key, kind="file", path="one.txt", size=12, mtime=100, file_id="first")
    values.update(overrides)
    return state.claim_object(**values)


def observation(state, object_id):
    row = state.object_row(object_id)
    return tuple(row[name] for name in ("analysis_status", "analysis_reason", "analysis_read"))


def downgrade_to_schema_seven(state):
    for column in ("analysis_status", "analysis_reason", "analysis_read"):
        state.connection.execute(f"ALTER TABLE objects DROP COLUMN {column}")
    state.connection.execute("UPDATE runs SET schema_version=7")


def test_new_file_is_unknown_even_if_generic_processing_or_findings_are_present(state):
    decision = claim(state)
    assert observation(state, decision.object_id) == ("unknown", None, None)
    state.complete_object(
        decision.object_id, "processed", findings=[FindingRecord("content:password", "example")]
    )
    assert observation(state, decision.object_id) == ("unknown", None, None)
    assert state.progress_snapshot()["analysis_counts"]["unknown"] == 1


@pytest.mark.parametrize("analysis_status", sorted(ANALYSIS_STATUSES))
@pytest.mark.parametrize("analysis_read", [None, False, True])
def test_explicit_observation_round_trips_with_findings_and_report(state, analysis_status, analysis_read):
    decision = claim(state)
    state.complete_object(
        decision.object_id,
        "processed",
        analysis_status=analysis_status,
        analysis_reason="explicit evidence",
        analysis_read=analysis_read,
        findings=[FindingRecord("sample", "visible-value")],
    )
    assert observation(state, decision.object_id) == (analysis_status, "explicit evidence", analysis_read)
    assert state.findings_for(decision.object_id)[0]["value"] == "visible-value"
    assert build_json_report(state)["progress"]["analysis_counts"][analysis_status] == 1
    report_row = state.report_findings()[0]
    assert report_row["analysis_status"] == analysis_status
    assert report_row["analysis_reason"] == "explicit evidence"
    assert report_row["analysis_read"] == analysis_read


def test_schema_seven_migration_never_infers_analysis_from_legacy_evidence(state):
    statuses = ("processed", "skipped", "error")
    decisions = [claim(state, f"file|{status}") for status in statuses]
    for decision, status in zip(decisions, statuses):
        state.complete_object(
            decision.object_id,
            status,
            findings=[FindingRecord("content:password", f"example-{status}")],
        )
    state.connection.execute(
        "UPDATE objects SET coverage_reason_mask=1, coverage_content_read=1, coverage_content_status='analyzed'"
    )
    findings_before = [tuple(row) for row in state.connection.execute("SELECT * FROM findings ORDER BY finding_id")]
    downgrade_to_schema_seven(state)
    state.set_run_status("interrupted")
    path = state.path
    state.close()

    resumed = ScanState.resume(path, {}, "test")
    try:
        assert resumed.run_row()["schema_version"] == SCHEMA_VERSION == 9
        assert [tuple(row) for row in resumed.connection.execute("SELECT * FROM findings ORDER BY finding_id")] == findings_before
        for decision, status in zip(decisions, statuses):
            assert resumed.object_row(decision.object_id)["status"] == status
            assert observation(resumed, decision.object_id) == ("unknown", None, None)
        assert resumed.progress_snapshot()["analysis_counts"] == {
            "unknown": 3, "not_analyzed": 0, "partial": 0, "analyzed": 0,
        }
    finally:
        resumed.close()


def test_migration_is_atomic_when_second_alter_fails(state):
    decision = claim(state)
    state.complete_object(decision.object_id, "processed", findings=[FindingRecord("sample", "retained")])
    downgrade_to_schema_seven(state)
    alterations = 0

    def deny_second_alter(action, *_args):
        nonlocal alterations
        if action == sqlite3.SQLITE_ALTER_TABLE:
            alterations += 1
            if alterations == 2:
                return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    state.connection.set_authorizer(deny_second_alter)
    try:
        with pytest.raises(sqlite3.DatabaseError, match="authorized"):
            ScanState._migrate_schema_7_to_8(state.connection)
    finally:
        state.connection.set_authorizer(None)
    assert state.run_row()["schema_version"] == 7
    assert not state.connection.in_transaction
    names = {row["name"] for row in state.connection.execute("PRAGMA table_info(objects)")}
    assert not names.intersection({"analysis_status", "analysis_reason", "analysis_read"})
    assert state.findings_for(decision.object_id)[0]["value"] == "retained"
    ScanState._migrate_schema_7_to_8(state.connection)
    assert observation(state, decision.object_id) == ("unknown", None, None)


@pytest.mark.parametrize("terminal", ["processed", "skipped", "error"])
def test_terminal_reuse_preserves_analysis_and_does_not_double_count(state, terminal):
    decision = claim(state)
    state.complete_object(
        decision.object_id, terminal, analysis_status="partial", analysis_reason="read limit", analysis_read=True
    )
    before = state.progress_snapshot()["analysis_counts"]
    for _ in range(3):
        reused = claim(state)
        assert reused.should_process is False
        assert observation(state, reused.object_id) == ("partial", "read limit", 1)
    assert state.progress_snapshot()["analysis_counts"] == before
    assert state.progress_snapshot()["counters"] == {"objects_discovered": 1, "resume_reused": 3}


def test_resume_retains_analyzed_terminal_and_resets_only_newly_claimed_work(state):
    completed = claim(state, "file|done")
    unfinished = claim(state, "file|unfinished")
    state.complete_object(completed.object_id, "processed", analysis_status="analyzed", analysis_read=True)
    state.set_run_status("interrupted")
    path = state.path
    state.close()
    resumed = ScanState.resume(path, {}, "test")
    try:
        assert not claim(resumed, "file|done").should_process
        assert observation(resumed, completed.object_id) == ("analyzed", None, 1)
        assert claim(resumed, "file|unfinished").should_process
        assert observation(resumed, unfinished.object_id) == ("unknown", None, None)
    finally:
        resumed.close()


@pytest.mark.parametrize("changed_identity", [{"size": 13}, {"mtime": 101}, {"file_id": "second"}])
def test_changed_identity_invalidates_old_analysis_and_findings(state, changed_identity):
    decision = claim(state)
    state.complete_object(
        decision.object_id,
        "processed",
        analysis_status="analyzed",
        analysis_read=True,
        findings=[FindingRecord("old-rule", "old-value")],
    )
    changed = claim(state, **changed_identity)
    assert changed.should_process and changed.changed
    assert observation(state, changed.object_id) == ("unknown", None, None)
    assert state.findings_for(changed.object_id) == []


def test_registration_alone_invalidates_changed_identity(state):
    decision = claim(state)
    state.complete_object(decision.object_id, "processed", analysis_status="analyzed", analysis_read=True)
    changed = state.register_object(
        object_key="file|one", kind="file", path="one.txt", size=999, mtime=100, file_id="first"
    )
    assert observation(state, changed.object_id) == ("unknown", None, None)


@pytest.mark.parametrize("prior_status,options", [("error", {"retry_limit": 2}), ("processed", {"always_process": True})])
def test_actual_reprocessing_resets_old_observation(state, prior_status, options):
    decision = claim(state)
    state.complete_object(
        decision.object_id, prior_status, analysis_status="partial", analysis_reason="old failure", analysis_read=True
    )
    assert claim(state, **options).should_process
    assert observation(state, decision.object_id) == ("unknown", None, None)
    state.complete_object(
        decision.object_id, "error", reason="new access denial", analysis_status="not_analyzed", analysis_read=False
    )
    assert observation(state, decision.object_id) == ("not_analyzed", None, 0)


def test_omitted_observation_preserves_prior_evidence_but_explicit_unknown_clears_it(state):
    decision = claim(state)
    state.complete_object(
        decision.object_id, "processed", analysis_status="partial", analysis_reason="limit", analysis_read=True
    )
    state.complete_object(decision.object_id, "error", reason="administrative correction")
    assert observation(state, decision.object_id) == ("partial", "limit", 1)
    state.complete_object(decision.object_id, "error", analysis_status="unknown")
    assert observation(state, decision.object_id) == ("unknown", None, None)


def test_ancestor_settlement_never_overwrites_existing_analysis_evidence(state):
    target = Target("server")
    parent = claim(
        state, share_object_key(target, "Data"), kind="share", target=str(target), share="Data", path="Data"
    )
    child = claim(
        state, smb_object_key(target, "Data", "one.txt"), target=str(target), share="Data"
    )
    state.complete_object(parent.object_id, "error", reason="Access denied")
    state.complete_object(
        child.object_id, "processed", analysis_status="partial", analysis_reason="old read limit", analysis_read=True,
        findings=[FindingRecord("sample", "retained")],
    )
    # Simulate a previously interrupted manifest repair, without a new claim
    # or read: settlement must neither infer success nor discard evidence.
    state.connection.execute("UPDATE objects SET status='in_progress' WHERE object_id=?", (child.object_id,))
    assert state.settle_blocked_objects() == 1
    assert observation(state, child.object_id) == ("partial", "old read limit", 1)
    assert state.findings_for(child.object_id)[0]["value"] == "retained"
    assert state.object_row(child.object_id)["status"] == "error"


def test_requeue_legacy_size_omission_invalidates_observation(state):
    decision = claim(state)
    state.complete_object(
        decision.object_id,
        "skipped",
        reason="size 12 exceeds active retrieval policy",
        analysis_status="not_analyzed",
        analysis_reason="size_policy",
        analysis_read=False,
    )
    assert state.requeue_legacy_size_skips() == 1
    assert observation(state, decision.object_id) == ("unknown", None, None)


@pytest.mark.parametrize("bad_observation", [
    {"analysis_status": "finished"},
    {"analysis_status": []},
    {"analysis_status": "analyzed", "analysis_read": "yes"},
    {"analysis_status": "analyzed", "analysis_read": 2},
    {"analysis_status": "analyzed", "analysis_read": 1.0},
    {"analysis_status": "analyzed", "analysis_reason": ["reason"]},
    {"analysis_reason": "missing status"},
    {"analysis_read": False},
])
def test_invalid_batch_rolls_back_findings_analysis_and_checkpoints(state, bad_observation):
    first, second = [claim(state, key) for key in ("file|one", "file|two")]
    state.complete_object(first.object_id, "error", findings=[FindingRecord("retained", "old-value")])
    before = dict(state.object_row(first.object_id))
    with pytest.raises(StateError):
        state.complete_objects([
            dict(
                object_id=first.object_id, status="processed", analysis_status="analyzed", analysis_read=True,
                findings=[FindingRecord("new-rule", "new-value")], checkpoint_name="done", checkpoint_value=1,
            ),
            dict(object_id=second.object_id, status="processed", **bad_observation),
        ])
    assert dict(state.object_row(first.object_id)) == before
    assert state.findings_for(first.object_id)[0]["value"] == "old-value"
    assert state.object_row(second.object_id)["status"] == "in_progress"
    assert state.connection.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0] == 0


@pytest.mark.parametrize("migrated", [False, True])
@pytest.mark.parametrize("column,value", [("analysis_status", "finished"), ("analysis_status", None), ("analysis_read", 2)])
def test_database_constraints_also_reject_invalid_direct_values(state, migrated, column, value):
    decision = claim(state)
    if migrated:
        downgrade_to_schema_seven(state)
        ScanState._migrate_schema_7_to_8(state.connection)
    with pytest.raises(sqlite3.IntegrityError):
        state.connection.execute(f"UPDATE objects SET {column}=? WHERE object_id=?", (value, decision.object_id))
    assert observation(state, decision.object_id) == ("unknown", None, None)


def test_batch_embeds_analysis_in_existing_updates_without_per_object_queries(state):
    decisions = [claim(state, f"file|{number}") for number in range(5)]
    statements = []
    state.connection.set_trace_callback(statements.append)
    state.complete_objects([
        dict(object_id=decision.object_id, status="processed", analysis_status="analyzed", analysis_read=True)
        for decision in decisions
    ])
    state.connection.set_trace_callback(None)
    assert sum("SELECT object_key, changed FROM objects" in sql for sql in statements) == 5
    assert sum("UPDATE objects SET" in sql for sql in statements) == 5
    assert sum("UPDATE objects SET" in sql and "analysis_status=" in sql for sql in statements) == 5
    assert sum(sql == "BEGIN IMMEDIATE" for sql in statements) == 1
    assert sum(sql == "COMMIT" for sql in statements) == 1


def test_snapshot_counts_only_files_once_using_existing_grouped_query(state):
    for analysis_status in sorted(ANALYSIS_STATUSES):
        for number in range(2):
            decision = claim(state, f"file|{analysis_status}-{number}")
            state.complete_object(
                decision.object_id, "processed", analysis_status=analysis_status, changed=bool(number)
            )
    directory = claim(state, "directory|excluded", kind="directory")
    state.complete_object(directory.object_id, "processed", analysis_status="analyzed", changed=True)
    statements = []
    state.connection.set_trace_callback(statements.append)
    snapshot = state.progress_snapshot()
    state.connection.set_trace_callback(None)
    assert snapshot["objects"]["file"]["processed"] == 8
    assert snapshot["analysis_counts"] == {status: 2 for status in ANALYSIS_STATUSES}
    assert snapshot["changed_files"] == 4
    assert sum("FROM objects" in sql for sql in statements) == 1
    state.complete_object(decision.object_id, "processed", analysis_status="analyzed")
    assert sum(state.progress_snapshot()["analysis_counts"].values()) == 8
