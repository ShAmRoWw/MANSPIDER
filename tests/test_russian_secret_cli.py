"""Owned Russian occurrences survive SQLite/report/resume without source writes."""

import json
import sqlite3
import subprocess
import sys

import pytest

from man_spider.lib.parser.localized_credentials import inspect_russian_json_credentials
from man_spider.lib.parser.legacy_cyrillic import inspect_russian_legacy_credentials
from man_spider.state import FindingRecord, ScanState


PASSWORD = "СложныйРусскийПароль!"
SOURCES = {
    "russian-json-credential-value": (
        "настройки.json",
        json.dumps([{"Пароль": PASSWORD}, {"Пароль": PASSWORD}]).encode(),
    ),
    "russian-legacy-credential-value": (
        "настройки.txt",
        f'пароль="{PASSWORD}"\nпароль="{PASSWORD}"\n'.encode("cp866"),
    ),
}
INSPECTORS = {
    "russian-json-credential-value": inspect_russian_json_credentials,
    "russian-legacy-credential-value": inspect_russian_legacy_credentials,
}


@pytest.mark.parametrize("detector", INSPECTORS)
def test_reordered_findings_keep_owner_identity_and_resume(tmp_path, detector):
    name, data = SOURCES[detector]
    findings = INSPECTORS[detector](data)
    assert sum(value == PASSWORD for value, *_ in findings) == 2
    records = [
        FindingRecord(
            "rule:" + detector,
            value,
            start,
            end,
            context,
            representation="inspect:" + detector,
            rule_pack_id="manspider.default",
            rule_pack_version="2.7.0",
        )
        for value, start, end, context in findings
    ]
    config = {"scope": str(tmp_path), "fixture": detector}
    state_path = tmp_path / "scan.sqlite3"
    state = ScanState.create(state_path, config, "2.0.0")
    registration = {"object_key": "file|" + name, "kind": "file", "path": name, "size": len(data), "mtime": 100}
    decision = state.register_object(**registration)
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "processed", findings=records)
    before = [dict(row) for row in state.findings_for(decision.object_id)]
    assert len(before) == len(records)
    state.set_run_status("interrupted")
    state.close()
    state = ScanState.resume(state_path, config, "2.0.0")
    decision = state.register_object(**registration)
    assert not decision.should_process
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "processed", findings=reversed(records))
    after = [dict(row) for row in state.findings_for(decision.object_id)]
    assert {(r["finding_id"], r["value"], r["context"]) for r in before} == {
        (r["finding_id"], r["value"], r["context"]) for r in after
    }
    assert state.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    state.close()


def test_default_cli_exact_json_export_and_idempotent_resume(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    original = {}
    for name, data in SOURCES.values():
        path = scope / name
        path.write_bytes(data)
        original[path] = (data, path.stat().st_mtime_ns)
    state_path = tmp_path / "scan.sqlite3"
    report_path = tmp_path / "report.json"
    common = [
        sys.executable,
        "-m",
        "man_spider.manspider",
        str(scope),
        "--yes",
        "--builtin-rules",
        "--json-file",
        str(report_path),
    ]
    rows_before = None
    for state_option in ("--state-file", "--resume", "--resume"):
        result = subprocess.run([*common, state_option, str(state_path)], capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        with sqlite3.connect(state_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = [
                dict(r)
                for r in connection.execute(
                    "SELECT * FROM findings WHERE representation LIKE 'inspect:russian-%' ORDER BY finding_id"
                )
            ]
            assert all(
                r["attempts"] == 1 for r in connection.execute("SELECT attempts FROM objects WHERE kind='file'")
            )
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert sum(r["value"] == PASSWORD for r in rows) == 4
        assert all(r["rule_pack_version"] == "2.7.0" for r in rows)
        report = json.loads(report_path.read_text())
        native = [f for f in report["findings"] if f["representation"].startswith("inspect:russian-")]
        assert {(f["value"], f["context"]) for f in native} == {(r["value"], r["context"]) for r in rows}
        if rows_before is not None:
            assert rows == rows_before
        rows_before = rows
    assert set(scope.iterdir()) == set(original)
    assert {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in original} == original
