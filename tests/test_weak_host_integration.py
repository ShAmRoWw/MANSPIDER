"""Bounded cross-component checks for lossless weak-host improvements."""

import hashlib
import json
import sqlite3
import subprocess
import sys

from man_spider.state import ScanState
from man_spider.web_data import ViewerStore


def logical_rows(path):
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        run_id = connection.execute("SELECT run_id FROM runs").fetchone()[0]
        state = ScanState(path, connection, run_id)
        return [dict(row) for row in state.report_findings()]
    finally:
        connection.close()


def test_cli_full_context_json_viewer_review_and_resume_remain_lossless(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    source = scope / "dense.txt"
    assignments = [f'password="WeakHostFixture{i:03d}Only!" ' for i in range(32)]
    prefix = " ".join(assignments)
    marker = "ContextOnlyMarkerThatIsNotASecretValue"
    content = prefix + "x" * (65536 - len(prefix) - len(marker) - 1) + " " + marker
    assert len(content) == 65536
    source.write_text(content, encoding="utf-8")
    original = hashlib.sha256(source.read_bytes()).hexdigest()
    original_mtime = source.stat().st_mtime_ns
    state_path = tmp_path / "session.sqlite3"
    report_path = tmp_path / "report.json"
    common = [
        sys.executable, "-m", "man_spider.manspider", str(scope),
        "--yes", "--no-resume-prompt", "--builtin-rules",
        "-t", "1", "--max-sessions-per-host", "1",
    ]
    first = subprocess.run(
        [*common, "--state-file", str(state_path), "--json-file", str(report_path)],
        capture_output=True, text=True, timeout=45, check=False,
    )
    assert first.returncode == 0, first.stdout + first.stderr
    rows = logical_rows(state_path)
    full_context_rows = [row for row in rows if row["context"] == content]
    assert len(full_context_rows) >= len(assignments)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["run_status"] == "complete"
    assert [
        (row["rule_id"], row["value"], row["context"], row["match_start"], row["match_end"])
        for row in rows
    ] == [
        (row["rule"], row["value"], row["context"], row["match_start"], row["match_end"])
        for row in report["findings"]
    ]

    # The marker occurs only in full context, not in a matched secret value.
    # This exercises normalized-context search, not just finding.value search.
    store = ViewerStore([], files=[state_path])
    scan_id = store.scans()["scans"][0]["id"]
    page = store.findings(scan_id, q=marker)
    assert len(page["items"]) == 1
    selected = full_context_rows[0]
    evidence = store.evidence(scan_id, selected["finding_id"], field="context")
    assert evidence == {"text": content, "total": len(content), "next_offset": None}
    store.set_finding_review(scan_id, selected["finding_id"], True)
    reviewed = store.object_findings(scan_id, selected["object_id"], review_status="reviewed")
    assert [row["finding_id"] for row in reviewed["items"]] == [selected["finding_id"]]

    with sqlite3.connect(state_path.as_uri() + "?mode=ro", uri=True) as connection:
        before_attempts = connection.execute(
            "SELECT object_id,attempts FROM objects WHERE kind='file' ORDER BY object_id"
        ).fetchall()
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    resumed = subprocess.run(
        [*common, "--resume", str(state_path)],
        capture_output=True, text=True, timeout=45, check=False,
    )
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    assert logical_rows(state_path) == rows
    with sqlite3.connect(state_path.as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute(
            "SELECT object_id,attempts FROM objects WHERE kind='file' ORDER BY object_id"
        ).fetchall() == before_attempts
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    reopened = ViewerStore([], files=[state_path])
    assert reopened.scans()["scans"][0]["id"] == scan_id
    reviewed = reopened.object_findings(scan_id, selected["object_id"], review_status="reviewed")
    assert [row["finding_id"] for row in reviewed["items"]] == [selected["finding_id"]]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original
    assert source.stat().st_mtime_ns == original_mtime
