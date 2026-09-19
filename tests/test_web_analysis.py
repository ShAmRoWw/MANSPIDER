"""Content-analysis UI reads exact observations without upgrading legacy scans."""

import hashlib

import pytest

from man_spider.state import FindingRecord, ScanState
from man_spider.web_data import ViewerError, ViewerStore


@pytest.fixture
def observed_state(tmp_path):
    state = ScanState.create(tmp_path / "analysis.sqlite3", {"semantic": {}}, "test")
    for index, analysis in enumerate(("unknown", "not_analyzed", "partial", "analyzed")):
        obj = state.register_object(object_key=f"file-{index}", kind="file", path=f"{analysis}.txt", size=32)
        state.complete_object(
            obj.object_id, "processed", analysis_status=analysis,
            analysis_reason=f"fixture_{analysis}", analysis_read=analysis in {"partial", "analyzed"},
            findings=[FindingRecord(rule_id="rule:fixture", value="ExampleOnly123!")],
        )
    directory = state.register_object(object_key="directory", kind="directory", path="container")
    state.complete_object(directory.object_id, "processed")
    yield state
    state.close()


def get_store(state):
    store = ViewerStore([], files=[state.path])
    return store, store.scans()["scans"][0]["id"]


def test_summary_counts_unique_files_in_every_analysis_state(observed_state):
    store, scan_id = get_store(observed_state)
    summary = store.summary(scan_id)
    assert summary["analysis_counts"] == {"unknown": 1, "not_analyzed": 1, "partial": 1, "analyzed": 1}
    assert summary["analysis_counts_available"] is True
    assert summary["objects"] == {"directory": {"processed": 1}, "file": {"processed": 4}}
    assert summary["analysis_counts"] == observed_state.progress_snapshot()["analysis_counts"]


@pytest.mark.parametrize("method", ["objects", "findings"])
@pytest.mark.parametrize("analysis", ["unknown", "not_analyzed", "partial", "analyzed"])
def test_analysis_filters_and_annotations(observed_state, method, analysis):
    store, scan_id = get_store(observed_state)
    result = getattr(store, method)(scan_id, analysis_status=analysis)
    assert len(result["items"]) == 1
    row = result["items"][0]
    assert row["path"] == f"{analysis}.txt"
    assert row["analysis_status"] == analysis
    assert row["analysis_reason"] == f"fixture_{analysis}"
    assert bool(row["analysis_read"]) == (analysis in {"partial", "analyzed"})


@pytest.mark.parametrize("method", ["objects", "findings"])
@pytest.mark.parametrize("value", ["", "unknown", "not_analyzed", "partial", "analyzed"])
def test_real_schema7_is_readable_without_columns_or_migration(observed_state, method, value):
    state = observed_state
    for column in ("analysis_status", "analysis_reason", "analysis_read"):
        state.connection.execute(f"ALTER TABLE objects DROP COLUMN {column}")
    state.connection.execute("UPDATE runs SET schema_version=7")
    state.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = hashlib.sha256(state.path.read_bytes()).hexdigest()
    store, scan_id = get_store(state)
    summary = store.summary(scan_id)
    assert summary["analysis_counts_available"] is False
    assert summary["analysis_counts"] == {"unknown": 4, "not_analyzed": 0, "partial": 0, "analyzed": 0}
    results = getattr(store, method)(scan_id, analysis_status=value)
    if value in {"", "unknown"}:
        assert len(results["items"]) == 4
        assert all(row["analysis_status"] == "unknown" and row["analysis_read"] is None for row in results["items"])
    else:
        assert results["items"] == []
    assert state.run_row()["schema_version"] == 7
    assert "analysis_status" not in {r["name"] for r in state.connection.execute("PRAGMA table_info(objects)")}
    assert hashlib.sha256(state.path.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("method", ["objects", "findings"])
@pytest.mark.parametrize("value", ["processed", "ANALYZED", "' OR 1=1 --", None, 1])
def test_invalid_analysis_filter_fails_closed(observed_state, method, value):
    store, scan_id = get_store(observed_state)
    with pytest.raises(ViewerError):
        getattr(store, method)(scan_id, analysis_status=value)


def test_live_resume_observation_replaces_counts_without_double_count(observed_state):
    store, scan_id = get_store(observed_state)
    before = store.summary(scan_id)
    assert before["analysis_counts"]["partial"] == 1
    row = observed_state.connection.execute("SELECT object_id FROM objects WHERE analysis_status='partial'").fetchone()
    observed_state.begin_object(row["object_id"])
    store._summaries.clear()
    during = store.summary(scan_id)
    assert during["analysis_counts"]["partial"] == 0
    assert during["analysis_counts"]["unknown"] == 2
    observed_state.complete_object(row["object_id"], "processed", analysis_status="analyzed", analysis_read=True)
    store._summaries.clear()
    after = store.summary(scan_id)
    assert after["analysis_counts"] == {"unknown": 1, "not_analyzed": 1, "partial": 0, "analyzed": 2}
    assert sum(after["analysis_counts"].values()) == 4


def test_analysis_filter_is_file_only_when_other_kinds_requested(observed_state):
    store, scan_id = get_store(observed_state)
    assert store.objects(scan_id, kind="directory", analysis_status="unknown")["items"] == []
    assert len(store.objects(scan_id, kind="", analysis_status="unknown")["items"]) == 1


def test_json_export_keeps_exact_object_analysis_annotations(observed_state):
    from man_spider.output import build_json_report

    report = build_json_report(observed_state)
    assert report["progress"]["analysis_counts"] == {"unknown": 1, "not_analyzed": 1, "partial": 1, "analyzed": 1}
    assert {row["analysis_status"] for row in report["findings"]} == {"unknown", "not_analyzed", "partial", "analyzed"}
    for row in report["findings"]:
        assert row["value"] == "ExampleOnly123!"
        assert row["analysis_reason"] == f"fixture_{row['analysis_status']}"
        assert row["analysis_read"] == (row["analysis_status"] in {"partial", "analyzed"})
