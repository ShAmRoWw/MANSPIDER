"""Lossless object-owned context storage and schema-8 compatibility."""

import sqlite3

import pytest

import man_spider.state as state_module

from man_spider.differential import compare_scan_states, StateComparisonError
from man_spider.evidence_storage import configure_evidence_reader, context_join, context_sql, evidence_location
from man_spider.state import FindingRecord, ScanState, StateError


@pytest.fixture
def state(tmp_path):
    state = ScanState.create(tmp_path / "state.sqlite3", {}, "test")
    yield state
    state.close()


def claim(state, key="first", **kwargs):
    return state.claim_object(object_key=key, kind="file", path=key + ".txt", **kwargs).object_id


def revision(state):
    return state.connection.execute(
        "SELECT value FROM counters WHERE run_id=? AND name='data_revision'", (state.run_id,)
    ).fetchone()[0]


@pytest.mark.parametrize("failure", ["authorization", "interrupt"])
def test_create_never_publishes_run_without_revision(tmp_path, monkeypatch, failure):
    original_connect = state_module._connect_local_sqlite

    class FailingConnection(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            if failure == "interrupt" and statement.startswith("INSERT INTO counters(run_id,name,value)"):
                raise KeyboardInterrupt("injected run initialization interruption")
            return super().execute(statement, *args, **kwargs)

    def connect(*args, **kwargs):
        connection = original_connect(*args, factory=FailingConnection, **kwargs)
        if failure == "authorization":
            connection.set_authorizer(
                lambda action, table, *_: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_INSERT and table == "counters" else sqlite3.SQLITE_OK
            )
        return connection

    monkeypatch.setattr(state_module, "_connect_local_sqlite", connect)
    path = tmp_path / "failed.sqlite3"
    with pytest.raises(KeyboardInterrupt if failure == "interrupt" else StateError):
        ScanState.create(path, {}, "test")
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as reader:
        assert reader.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
        assert reader.execute("SELECT COUNT(*) FROM counters").fetchone()[0] == 0
        assert reader.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def make_legacy(state):
    """Convert this fresh fixture, not a real historical state, into schema 8."""
    connection = state.connection
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        "UPDATE findings SET context=(SELECT context FROM finding_contexts c WHERE c.context_id=findings.context_id), "
        "context_id=NULL WHERE context_id IS NOT NULL"
    )
    for name in ("findings_context_insert", "findings_context_update", "finding_contexts_owner_insert", "finding_contexts_immutable"):
        connection.execute(f"DROP TRIGGER {name}")
    connection.execute("DROP INDEX findings_context_idx")
    connection.execute("ALTER TABLE findings DROP COLUMN context_id")
    connection.execute("DROP TABLE finding_contexts")
    connection.execute("DELETE FROM counters WHERE name='data_revision'")
    connection.execute("UPDATE runs SET schema_version=8")
    connection.execute("COMMIT")


def test_full_context_is_stored_once_per_object_with_stable_finding_shape(state):
    context = "x" * (512 * 1024) + "пароль😀\x00end"
    object_id = claim(state)
    findings = [FindingRecord("rule", f"value-{index}", start=index, end=index + 1, context=context) for index in range(32)]
    state.complete_object(object_id, "processed", findings=findings)
    logical = [dict(row) for row in state.findings_for(object_id)]
    assert len(logical) == 32
    assert all(row["context"] == context and "context_id" not in row for row in logical)
    assert state.connection.execute("SELECT COUNT(*) FROM finding_contexts").fetchone()[0] == 1
    assert state.connection.execute("SELECT SUM(length(context)) FROM findings").fetchone()[0] is None
    initial_ids = {row["finding_id"] for row in logical}
    state.complete_object(object_id, "processed", findings=findings)
    assert {row["finding_id"] for row in state.findings_for(object_id)} == initial_ids
    assert state.connection.execute("SELECT COUNT(*) FROM finding_contexts").fetchone()[0] == 1
    other_id = claim(state, "second")
    state.complete_object(other_id, "processed", findings=findings[:2])
    assert state.connection.execute("SELECT COUNT(*) FROM finding_contexts").fetchone()[0] == 2
    assert state.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_null_empty_unicode_and_hash_collisions_remain_distinct(state):
    class Colliding(str):
        def __hash__(self):
            return 42
    contexts = [None, "", Colliding("one"), Colliding("two"), "a\x00b", "пароль😀\r\n"]
    object_id = claim(state)
    state.complete_object(object_id, "processed", findings=[
        FindingRecord(f"r{index}-{repeat}", "value", context=context)
        for index, context in enumerate(contexts) for repeat in (0, 1)
    ])
    assert {row["rule_id"]: row["context"] for row in state.findings_for(object_id)} == {
        f"r{index}-{repeat}": context for index, context in enumerate(contexts) for repeat in (0, 1)
    }
    assert state.connection.execute("SELECT COUNT(*) FROM finding_contexts").fetchone()[0] == 5


def test_unique_contexts_stay_inline_without_extra_storage_rows(state):
    object_id = claim(state)
    state.complete_object(object_id, "processed", findings=[
        FindingRecord("first", "value", context="unique one"),
        FindingRecord("second", "value", context="unique two"),
    ])
    assert state.connection.execute("SELECT COUNT(*) FROM finding_contexts").fetchone()[0] == 0
    assert {row[0] for row in state.connection.execute("SELECT context FROM findings")} == {"unique one", "unique two"}


def test_context_reference_cleanup_has_indexed_lookup(state):
    plan = " ".join(str(tuple(row)) for row in state.connection.execute(
        "EXPLAIN QUERY PLAN SELECT rowid FROM findings WHERE context_id=?", (1,)
    ))
    assert "findings_context_idx" in plan and "SEARCH" in plan


@pytest.mark.parametrize("action", ["empty", "changed", "object_delete", "run_delete"])
def test_context_lifetime_follows_findings_and_object(state, action):
    object_id = claim(state, size=1)
    state.complete_object(object_id, "processed", findings=[
        FindingRecord("rule", "value", context="evidence"), FindingRecord("rule2", "value", context="evidence")
    ])
    if action == "empty":
        state.complete_object(object_id, "processed", findings=[])
    elif action == "changed":
        claim(state, size=2)
    else:
        with state.transaction() if action == "object_delete" else state.connection:
            state.connection.execute("DELETE FROM objects" if action == "object_delete" else "DELETE FROM runs")
    assert state.connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    assert state.connection.execute("SELECT COUNT(*) FROM finding_contexts").fetchone()[0] == 0
    assert state.connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize("failure", ["interrupt", "duplicate", "full"])
def test_failed_replacement_retains_original_evidence_and_revision(state, failure):
    object_id = claim(state)
    state.complete_object(object_id, "processed", findings=[
        FindingRecord("old", "value", context="old context"), FindingRecord("old2", "value", context="old context")
    ])
    before = [dict(row) for row in state.findings_for(object_id)]
    before_revision = revision(state)
    record = FindingRecord("new", "value", context="x" * (1024 * 1024) if failure == "full" else "new context")
    if failure == "full":
        pages = state.connection.execute("PRAGMA page_count").fetchone()[0]
        state.connection.execute(f"PRAGMA max_page_count={pages}")
    with pytest.raises(KeyboardInterrupt if failure == "interrupt" else StateError):
        with state.transaction():
            state.complete_object(object_id, "processed", findings=[record, record] if failure == "duplicate" else [record])
            if failure == "interrupt":
                raise KeyboardInterrupt
    assert [dict(row) for row in state.findings_for(object_id)] == before
    assert revision(state) == before_revision
    assert state.connection.execute("SELECT COUNT(*) FROM finding_contexts").fetchone()[0] == 1
    assert state.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_legacy_migration_is_add_only_and_mixed_evidence_is_exact(state):
    first = claim(state)
    state.complete_object(first, "processed", findings=[FindingRecord("rule", "value", context="old\x00evidence")])
    before = [dict(row) for row in state.findings_for(first)]
    make_legacy(state)
    state.connection.execute("UPDATE runs SET status='interrupted'")
    resumed = ScanState.resume(state.path, {}, "test")
    try:
        assert resumed.run_row()["schema_version"] == 9
        assert [dict(row) for row in resumed.findings_for(first)] == before
        assert resumed.connection.execute("SELECT COUNT(*) FROM finding_contexts").fetchone()[0] == 0
        assert resumed.connection.execute("SELECT context_id FROM findings").fetchone()[0] is None
        second = claim(resumed, "second")
        resumed.complete_object(second, "processed", findings=[FindingRecord("rule", "value", context="new")])
        assert resumed.findings_for(second)[0]["context"] == "new"
        assert resumed.findings_for(first)[0]["context"] == "old\x00evidence"
        assert resumed.finish() == "complete"
    finally:
        resumed.close()


def test_failed_migration_rolls_back_schema_and_preserves_legacy_findings(state):
    object_id = claim(state)
    state.complete_object(object_id, "processed", findings=[FindingRecord("rule", "value", context="retained")])
    before = [dict(row) for row in state.findings_for(object_id)]
    make_legacy(state)
    def deny_context_table(action, table, *_args):
        return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_CREATE_TABLE and table == "finding_contexts" else sqlite3.SQLITE_OK
    state.connection.set_authorizer(deny_context_table)
    with pytest.raises(sqlite3.DatabaseError):
        ScanState._migrate_schema_8_to_9(state.connection)
    state.connection.set_authorizer(None)
    assert state.run_row()["schema_version"] == 8
    assert "context_id" not in {row["name"] for row in state.connection.execute("PRAGMA table_info(findings)")}
    assert [dict(row) for row in state.connection.execute("SELECT * FROM findings")] == before
    ScanState._migrate_schema_8_to_9(state.connection)
    assert [dict(row) for row in state.findings_for(object_id)] == before


def test_differential_accepts_equivalent_old_inline_and_new_normalized_states(state, tmp_path):
    object_id = claim(state)
    state.complete_object(object_id, "processed", findings=[
        FindingRecord("rule", "value", context="retained"), FindingRecord("rule2", "value", context="retained")
    ])
    state.finish()
    backup = sqlite3.connect(tmp_path / "legacy.sqlite3", isolation_level=None)
    state.connection.backup(backup)
    legacy = ScanState(tmp_path / "legacy.sqlite3", backup, state.run_id)
    make_legacy(legacy)
    legacy.close()
    assert compare_scan_states([state.path], [tmp_path / "legacy.sqlite3"]).equal


@pytest.mark.parametrize("corruption", ["missing", "wrong_owner", "inline_and_reference", "blob"])
def test_corrupt_reference_is_error_not_empty_or_substituted_evidence(state, corruption):
    first, second = claim(state), claim(state, "second")
    state.complete_object(first, "processed", findings=[
        FindingRecord("rule", "value", context="first context"), FindingRecord("rule2", "value", context="first context")
    ])
    state.complete_object(second, "processed", findings=[
        FindingRecord("rule", "value", context="second context"), FindingRecord("rule2", "value", context="second context")
    ])
    row = state.connection.execute("SELECT rowid,context_id FROM findings WHERE object_id=?", (first,)).fetchone()
    with pytest.raises(sqlite3.IntegrityError):
        state.connection.execute("UPDATE findings SET context_id=999999 WHERE object_id=?", (first,))
    state.connection.execute("DROP TRIGGER findings_context_update")
    state.connection.execute("DROP TRIGGER finding_contexts_immutable")
    state.connection.execute("PRAGMA foreign_keys=OFF")
    if corruption == "missing":
        state.connection.execute("DELETE FROM finding_contexts WHERE context_id=?", (row[1],))
    elif corruption == "wrong_owner":
        state.connection.execute("UPDATE finding_contexts SET object_id=? WHERE context_id=?", (second, row[1]))
    elif corruption == "inline_and_reference":
        state.connection.execute("UPDATE findings SET context='conflicting' WHERE object_id=?", (first,))
    else:
        state.connection.execute("PRAGMA ignore_check_constraints=ON")
        state.connection.execute("UPDATE finding_contexts SET context=x'00ff' WHERE context_id=?", (row[1],))
    with pytest.raises(sqlite3.DatabaseError):
        state.findings_for(first)
    with pytest.raises(sqlite3.DatabaseError):
        evidence_location(state.connection, row[0], "context")
    state.connection.execute("UPDATE runs SET status='complete'")
    with pytest.raises(StateComparisonError):
        compare_scan_states([state.path], [state.path], check_integrity=False)


def test_evidence_location_plain_tuple_rows_and_readonly_blob(state):
    object_id = claim(state)
    state.complete_object(object_id, "processed", findings=[
        FindingRecord("rule", "value", context="one\x00😀"), FindingRecord("rule2", "value", context="one\x00😀")
    ])
    rowid = state.connection.execute("SELECT rowid FROM findings").fetchone()[0]
    with sqlite3.connect(state.path.as_uri() + "?mode=ro", uri=True) as reader:
        configure_evidence_reader(reader)
        location = evidence_location(reader, rowid, "context")
        assert location[:2] == ("finding_contexts", "context")
        if callable(getattr(reader, "blobopen", None)):
            with reader.blobopen(*location, readonly=True) as blob:
                assert blob.read().decode() == "one\x00😀"
        else:
            table, field, context_rowid = location
            assert reader.execute(
                f"SELECT CAST({field} AS BLOB) FROM {table} WHERE rowid=?", (context_rowid,)
            ).fetchone()[0].decode() == "one\x00😀"
        assert evidence_location(reader, rowid, "value") == ("findings", "value", rowid)
        assert reader.execute(
            f"SELECT {context_sql(9)} FROM findings f {context_join(9)}"
        ).fetchone()[0] == "one\x00😀"


def test_revision_tracks_outer_commits_not_heartbeat_or_rollback(state):
    assert revision(state) == 0
    state.set_checkpoint("scan_timing", {"version": 1})
    assert revision(state) == 0
    with state.transaction():
        first, second = claim(state), claim(state, "second")
        state.set_checkpoint("scan_timing", {"version": 1})
        state.complete_object(first, "processed", findings=[FindingRecord("rule", "value", context="evidence")])
    assert revision(state) == 1
    state.set_checkpoint("scan_timing", {"version": 1})
    assert revision(state) == 1
    with pytest.raises(RuntimeError):
        with state.transaction():
            state.complete_object(second, "processed")
            raise RuntimeError("rollback")
    assert revision(state) == 1
    with state.transaction(telemetry_only=True):
        state.set_checkpoint("scan_timing", {"version": 1})
        state.complete_object(second, "processed")
    assert revision(state) == 2
    state.set_checkpoint("scan_timing", {"version": 1})
    assert revision(state) == 2
    assert "data_revision" not in state.progress_snapshot()["counters"]
    assert ScanState.interrupt_latest(state.path)
    assert revision(state) == 3
    resumed = ScanState.resume(state.path, {}, "test")
    try:
        assert revision(resumed) == 4
        assert resumed.get_checkpoint("scan_timing") is None
    finally:
        resumed.close()
