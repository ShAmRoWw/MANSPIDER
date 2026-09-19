"""Durable batching may remove redundant work, never evidence or validation."""

import json
import sqlite3
import threading
from pathlib import Path

import pytest

import man_spider.state as state_module
from man_spider.state import FindingRecord, ScanState, StateError


@pytest.fixture
def state(tmp_path):
    current = ScanState.create(tmp_path / "scan.sqlite3", {}, "2.0.0")
    yield current
    current.close()


def clone_state(state, path):
    connection = sqlite3.connect(path)
    state.connection.backup(connection)
    connection.close()
    return ScanState.attach(path, state.run_id)


def rows(state, table):
    return [tuple(row) for row in state.connection.execute(f"SELECT * FROM {table} ORDER BY 1, 2")]


def objects(count=64):
    return [
        {
            "object_key": f"file|{index}",
            "kind": "file",
            "path": f"{index}.txt",
            "size": 10,
            "mtime": "100",
            "discovery_counter": "files_discovered",
        }
        for index in range(count)
    ]


def assert_integrity(state):
    assert state.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert state.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_claim_batch_coalesces_counters_without_changing_manifest(state, tmp_path, monkeypatch):
    reference = clone_state(state, tmp_path / "reference.sqlite3")
    monkeypatch.setattr(state_module, "utc_now", lambda: "fixed")
    baseline_sql = []
    candidate_sql = []
    reference.connection.set_trace_callback(baseline_sql.append)
    state.connection.set_trace_callback(candidate_sql.append)
    try:
        with reference.transaction():
            expected = tuple(reference.claim_object(**value) for value in objects())
        actual = state.claim_objects(objects())
        reference.connection.set_trace_callback(None)
        state.connection.set_trace_callback(None)
        assert actual == expected
        for table in ("objects", "counters"):
            assert rows(state, table) == rows(reference, table)
        # One revision update is shared by the entire outer transaction.
        assert len(baseline_sql) == 451
        assert len(candidate_sql) == 197
        assert sum("INSERT INTO counters" in sql for sql in candidate_sql) == 2
        assert not any("SELECT value FROM counters" in sql for sql in candidate_sql)
        assert sum(sql == "BEGIN IMMEDIATE" for sql in candidate_sql) == 1
        assert sum(sql == "COMMIT" for sql in candidate_sql) == 1
        assert state.connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert state.connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert_integrity(state)
    finally:
        reference.close()


def test_public_counter_returns_current_value_inside_and_outside_batches(state):
    assert state.increment_counter("files_discovered", 3) == 3
    with state.transaction():
        state.claim_objects(objects(2))
        assert state.increment_counter("files_discovered", 4) == 9
        assert state.increment_counter("files_discovered", -2) == 7
        state.claim_object(object_key="file|extra", kind="file", discovery_counter="files_discovered")
        assert state.increment_counter("files_discovered", 0) == 8
    assert state.progress_snapshot()["counters"]["files_discovered"] == 8


@pytest.mark.parametrize("name", ["custom", "objects_discovered", "resume_reused", "", None, 1, b"binary"])
def test_custom_discovery_counter_semantics_match_single_claims(state, tmp_path, monkeypatch, name):
    reference = clone_state(state, tmp_path / "reference.sqlite3")
    monkeypatch.setattr(state_module, "utc_now", lambda: "fixed")
    values = [dict(value, discovery_counter=name) for value in objects(3)]
    try:
        with reference.transaction():
            expected = tuple(reference.claim_object(**value) for value in values)
        assert state.claim_objects(values) == expected
        assert rows(state, "counters") == rows(reference, "counters")
        assert rows(state, "objects") == rows(reference, "objects")
    finally:
        reference.close()


def test_claim_batch_preserves_duplicate_retry_changed_and_resume_decisions(state, tmp_path, monkeypatch):
    initial = state.claim_objects(objects(4))
    state.complete_objects(
        {"object_id": decision.object_id, "status": "error" if index == 1 else "processed"}
        for index, decision in enumerate(initial)
    )
    reference = clone_state(state, tmp_path / "reference.sqlite3")
    monkeypatch.setattr(state_module, "utc_now", lambda: "fixed")
    values = objects(4)
    values[1]["retry_limit"] = 2
    values[2]["size"] = 11
    values[3]["always_process"] = True
    values.extend([dict(values[1]), dict(values[2])])
    try:
        with reference.transaction():
            expected = tuple(reference.claim_object(**value) for value in values)
        actual = state.claim_objects(values)
        assert actual == expected
        assert actual[0].should_process is False
        assert actual[1].should_process is True
        assert actual[2].changed is True
        assert rows(state, "objects") == rows(reference, "objects")
        assert rows(state, "counters") == rows(reference, "counters")
        assert_integrity(state)
    finally:
        reference.close()


@pytest.mark.parametrize("failure_stage", ["begin", "counter"])
def test_claim_batch_failure_rolls_back_manifest_and_all_counter_deltas(state, monkeypatch, failure_stage):
    original = state._begin_object if failure_stage == "begin" else state._add_counter
    calls = 0

    def failing(*args):
        nonlocal calls
        calls += 1
        original(*args)
        if calls == 2:
            raise StateError("injected failure")

    method = "_begin_object" if failure_stage == "begin" else "_add_counter"
    monkeypatch.setattr(state, method, failing)
    with pytest.raises(StateError, match="injected failure"):
        state.claim_objects(objects(3))
    assert rows(state, "objects") == []
    assert rows(state, "counters") == [(state.run_id, "data_revision", 0)]
    monkeypatch.setattr(state, method, original)
    state.claim_objects(objects(1))
    assert state.progress_snapshot()["counters"] == {"objects_discovered": 1, "files_discovered": 1}


def completions(decisions):
    return [
        {
            "object_id": decision.object_id,
            "status": "processed",
            "findings": (FindingRecord("fixture", f"secret-{index}", tags=("credentials", "русский")),),
            "checkpoint_name": "target:synthetic",
            "checkpoint_value": {"object_id": decision.object_id, "path": f"{index}.txt", "status": "processed"},
        }
        for index, decision in enumerate(decisions)
    ]


def test_completion_batch_coalesces_checkpoint_writes_with_identical_findings(state, tmp_path, monkeypatch):
    values = completions(state.claim_objects(objects()))
    reference = clone_state(state, tmp_path / "reference.sqlite3")
    baseline_sql = []
    candidate_sql = []
    try:
        for current, statements in ((reference, baseline_sql), (state, candidate_sql)):
            timestamps = iter(f"time-{index:03}" for index in range(64))
            monkeypatch.setattr(state_module, "utc_now", lambda: next(timestamps))
            current.connection.set_trace_callback(statements.append)
            if current is reference:
                with current.transaction():
                    for value in values:
                        current.complete_object(**value)
            else:
                current.complete_objects(values)
            current.connection.set_trace_callback(None)
        for table in ("objects", "findings", "checkpoints"):
            assert rows(state, table) == rows(reference, table)
        # Context cleanup/ownership trigger traces plus one revision update
        # do not change the 63 redundant checkpoint writes being coalesced.
        assert len(baseline_sql) == 451
        coalescing_supported = hasattr(state.connection, "getlimit")
        assert len(candidate_sql) == (388 if coalescing_supported else 451)
        assert sum("INSERT INTO checkpoints" in sql for sql in candidate_sql) == (1 if coalescing_supported else 64)
        assert sum(sql == "COMMIT" for sql in candidate_sql) == 1
        assert state.get_checkpoint("target:synthetic") == values[-1]["checkpoint_value"]
        assert rows(state, "checkpoints")[0][-1] == "time-063"
        assert_integrity(state)
    finally:
        reference.close()


@pytest.mark.parametrize("names", [
    ["first", "second", "first", None, "second", "first"],
    ["1", 1, "1", 1, "1", 1],
    [1, "1", 1, "1", 1, "1"],
    ["", "ключ", b"binary", "ключ", "", b"binary"],
])
def test_checkpoint_custom_names_and_sqlite_affinity_keep_last_observation(state, tmp_path, monkeypatch, names):
    values = completions(state.claim_objects(objects(len(names))))
    for value, name in zip(values, names, strict=True):
        value["checkpoint_name"] = name
    reference = clone_state(state, tmp_path / "reference.sqlite3")
    monkeypatch.setattr(state_module, "utc_now", lambda: "fixed")
    try:
        with reference.transaction():
            for value in values:
                reference.complete_object(**value)
        state.complete_objects(values)
        assert rows(state, "checkpoints") == rows(reference, "checkpoints")
        assert rows(state, "findings") == rows(reference, "findings")
    finally:
        reference.close()


class InvalidString:
    def __str__(self):
        raise ValueError("invalid checkpoint conversion")


@pytest.mark.parametrize("failure", ["cycle", "conversion", "surrogate_value", "surrogate_name", "binding_name"])
def test_overwritten_invalid_checkpoint_still_rolls_back_everything(state, failure):
    values = completions(state.claim_objects(objects(2)))
    if failure == "cycle":
        cyclic = []
        cyclic.append(cyclic)
        values[0]["checkpoint_value"] = cyclic
        expected = RecursionError
    elif failure == "conversion":
        values[0]["checkpoint_value"] = InvalidString()
        expected = ValueError
    elif failure == "surrogate_value":
        values[0]["checkpoint_value"] = {"value": "\ud800"}
        expected = UnicodeEncodeError
    elif failure == "surrogate_name":
        values[0]["checkpoint_name"] = values[1]["checkpoint_name"] = "\ud800"
        expected = UnicodeEncodeError
    else:
        values[0]["checkpoint_name"] = ["invalid"]
        expected = StateError
    before = rows(state, "objects")
    with pytest.raises(expected):
        state.complete_objects(values)
    assert rows(state, "objects") == before
    assert rows(state, "findings") == []
    assert rows(state, "checkpoints") == []
    assert_integrity(state)


def test_overwritten_checkpoint_still_normalizes_each_value(state, tmp_path):
    values = completions(state.claim_objects(objects(2)))
    seen = []

    class Observed:
        def __str__(self):
            seen.append("converted")
            return "первое значение"

    values[0]["checkpoint_value"] = Observed()
    values[1]["checkpoint_value"] = {"path": tmp_path / "document", "values": ("пароль", 42)}
    state.complete_objects(values)
    assert seen == ["converted"]
    assert state.get_checkpoint("target:synthetic") == {
        "path": {"kind": "local", "path": str((tmp_path / "document").resolve())},
        "values": ["пароль", 42],
    }


def test_overwritten_checkpoint_cannot_hide_sqlite_length_limit_failure(state):
    if not hasattr(state.connection, "setlimit"):
        pytest.skip("SQLite connection length limits require Python 3.11+")
    values = completions(state.claim_objects(objects(2)))
    for value in values:
        value["findings"] = ()
    values[0]["checkpoint_value"] = "x" * 4096
    before = rows(state, "objects")
    former_limit = state.connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024)
    try:
        with pytest.raises(StateError, match="too big"):
            state.complete_objects(values)
    finally:
        state.connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, former_limit)
    assert rows(state, "objects") == before
    assert rows(state, "checkpoints") == []
    assert_integrity(state)


def test_connection_without_limit_api_retains_immediate_checkpoint_validation(state, monkeypatch):
    values = completions(state.claim_objects(objects(3)))
    original = state.connection

    class LegacyConnection:
        def __getattr__(self, name):
            if name == "getlimit":
                raise AttributeError(name)
            return getattr(original, name)

    monkeypatch.setattr(state, "connection", LegacyConnection())
    statements = []
    original.set_trace_callback(statements.append)
    state.complete_objects(values)
    original.set_trace_callback(None)
    assert sum("INSERT INTO checkpoints" in sql for sql in statements) == 3
    assert state.get_checkpoint("target:synthetic") == values[-1]["checkpoint_value"]


def test_checkpoint_flush_failure_rolls_back_findings_and_prior_checkpoint_writes(state, monkeypatch):
    values = completions(state.claim_objects(objects(3)))
    values[1]["checkpoint_name"] = "other"
    before = rows(state, "objects")
    original = state._write_checkpoint
    calls = 0

    def failing(*args):
        nonlocal calls
        calls += 1
        original(*args)
        if calls == 2:
            raise StateError("injected checkpoint failure")

    monkeypatch.setattr(state, "_write_checkpoint", failing)
    with pytest.raises(StateError, match="injected checkpoint failure"):
        state.complete_objects(values)
    assert rows(state, "objects") == before
    assert rows(state, "findings") == []
    assert rows(state, "checkpoints") == []
    monkeypatch.setattr(state, "_write_checkpoint", original)
    state.complete_objects(values)
    assert state.get_checkpoint("target:synthetic") == values[-1]["checkpoint_value"]


def test_finding_tags_are_serialized_once_without_changing_identity(state, monkeypatch):
    decision = state.claim_object(object_key="file|tags", kind="file")
    finding = FindingRecord("fixture", "Секрет!2026", tags=("credentials", "русский"))
    state.complete_object(decision.object_id, "processed", findings=(finding,))
    first = state.findings_for(decision.object_id)[0]
    original = json.dumps
    calls = []

    def counted(value, **kwargs):
        calls.append(value)
        return original(value, **kwargs)

    monkeypatch.setattr(state_module.json, "dumps", counted)
    state.complete_objects(({"object_id": decision.object_id, "status": "processed", "findings": (finding,)},))
    repeated = state.findings_for(decision.object_id)[0]
    assert repeated["finding_id"] == first["finding_id"]
    assert repeated["tags_json"] == first["tags_json"]
    assert repeated["value"] == "Секрет!2026"
    assert calls == [["credentials", "русский"]]


def test_parallel_batches_keep_counter_and_checkpoint_accumulators_separate(state):
    shared = ScanState.attach(state.path, state.run_id, thread_safe=True)
    barrier = threading.Barrier(4)
    errors = []

    def work(worker):
        try:
            barrier.wait()
            values = [dict(value, object_key=f"worker:{worker}|{value['object_key']}") for value in objects()]
            completed = completions(shared.claim_objects(values))
            for value in completed:
                value["checkpoint_name"] = f"target:{worker}"
            shared.complete_objects(completed)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(worker,)) for worker in range(4)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert not any(thread.is_alive() for thread in threads)
        assert errors == []
        snapshot = shared.progress_snapshot()
        assert snapshot["counters"] == {"objects_discovered": 256, "files_discovered": 256}
        assert snapshot["objects"]["file"]["processed"] == 256
        assert snapshot["findings"] == 256
        assert len(rows(shared, "checkpoints")) == 4
        for worker in range(4):
            assert shared.get_checkpoint(f"target:{worker}")["path"] == "63.txt"
        assert_integrity(shared)
    finally:
        shared.close()


def test_empty_batches_do_not_start_transactions(state):
    statements = []
    state.connection.set_trace_callback(statements.append)
    assert state.claim_objects(()) == ()
    assert state.complete_objects(()) is None
    state.connection.set_trace_callback(None)
    assert statements == []


def test_single_completion_checkpoint_remains_immediately_readable(state):
    decision = state.claim_object(object_key="file|single", kind="file")
    with state.transaction():
        state.complete_object(decision.object_id, "processed", checkpoint_name="one", checkpoint_value=Path("/tmp"))
        assert state.get_checkpoint("one") == {"kind": "local", "path": str(Path("/tmp").resolve())}
