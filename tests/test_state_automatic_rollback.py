"""SQLite-initiated rollbacks must retain the primary storage failure."""

import sqlite3

import pytest

from man_spider.state import FindingRecord, ScanState, StateError


@pytest.mark.parametrize("case", ["healthy", "constraint", "full", "interrupt", "busy"])
@pytest.mark.parametrize("batched", [False, True])
def test_real_sqlite_transaction_outcomes(tmp_path, case, batched):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "test")
    first, second = state.claim_objects([
        {"object_key": "first", "kind": "file"}, {"object_key": "second", "kind": "file"},
    ])
    statements = []
    state.connection.set_trace_callback(statements.append)
    other = None
    if case == "full":
        count = state.connection.execute("PRAGMA page_count").fetchone()[0]
        state.connection.execute(f"PRAGMA max_page_count={count}")
    elif case == "busy":
        other = ScanState.attach(state.path, state.run_id)
        other.connection.execute("BEGIN IMMEDIATE")
        state.connection.execute("PRAGMA busy_timeout=5")
    record = FindingRecord("test", "X" * (1048576 if case == "full" else 8))
    first_completion = {
        "object_id": first.object_id, "status": "processed",
        "findings": [FindingRecord("test", "first-value")],
        "checkpoint_name": "first", "checkpoint_value": {"completed": True},
    }
    second_completion = {
        "object_id": second.object_id, "status": "processed",
        "findings": [record, record] if case == "constraint" else [record],
    }

    def run():
        with state.transaction():
            if batched:
                state.complete_objects([first_completion, second_completion])
            else:
                state.complete_object(**first_completion)
                state.complete_object(**second_completion)
            if case == "interrupt":
                raise KeyboardInterrupt("fixture")

    try:
        if case == "healthy":
            run()
            assert len(state.report_findings()) == 2
            assert "COMMIT" in statements
        else:
            with pytest.raises(KeyboardInterrupt if case == "interrupt" else StateError) as error:
                run()
            if case == "full":
                assert "database or disk is full" in str(error.value)
                assert isinstance(error.value.__cause__, sqlite3.OperationalError)
                assert error.value.__cause__.sqlite_errorcode == sqlite3.SQLITE_FULL
                # SQLite may roll back either the statement or the whole
                # transaction depending on where FULL is raised (including
                # FK/trigger execution). Both paths must preserve FULL and
                # leave no partial state, without a second rollback masking it.
                assert statements.count("ROLLBACK") <= 1
            elif case == "constraint":
                assert "UNIQUE constraint" in str(error.value)
                assert "ROLLBACK" in statements
            elif case == "busy":
                assert "Unable to begin persistent-state transaction: database is locked" in str(error.value)
                assert "ROLLBACK" not in statements
            else:
                assert "ROLLBACK" in statements
            assert not state.report_findings()
            assert state.get_checkpoint("first") is None
            assert all(state.object_row(item.object_id)["status"] == "in_progress" for item in (first, second))
        assert not state.connection.in_transaction
        assert state.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        if other is not None:
            other.connection.execute("ROLLBACK")
            other.close()
            other = None
        if case != "healthy":
            state.connection.execute("PRAGMA max_page_count=10000")
            second_completion["findings"] = [FindingRecord("test", "recovered-value")]
            state.complete_objects([first_completion, second_completion])
            assert state.finish() == "complete"
            assert len(state.report_findings()) == 2
    finally:
        if other is not None:
            other.connection.execute("ROLLBACK")
            other.close()
        state.close()
