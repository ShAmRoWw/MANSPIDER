import json
import os
import sqlite3
import stat
import subprocess
import sys

import pytest

from man_spider.cli import parse_options
from man_spider.evidence_storage import configure_evidence_reader, context_join, context_sql
from man_spider.output import build_json_report
from man_spider.state import SCHEMA_VERSION, ScanState, normalized_scan_configuration


def test_realtime_human_log_sqlite_and_json_share_full_findings(tmp_path):
    home = tmp_path / "home"
    scope = tmp_path / "scope"
    scope.mkdir()
    secret_file = scope / "secrets.txt"
    secret_file.write_text(
        "prefix ALPHA_SECRET=alpha-value suffix\nBETA_SECRET=second-value\n",
        encoding="utf-8",
    )
    state_path = tmp_path / "scan.sqlite3"
    json_path = tmp_path / "report.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "man_spider.manspider",
            "--yes",
            str(scope),
            "-c",
            r"(?:ALPHA|BETA)_SECRET=[a-z-]+",
            "--state-file",
            str(state_path),
            "--json-file",
            str(json_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={**os.environ, "HOME": str(home)},
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(json_path.read_text(encoding="utf-8"))
    metrics_path = state_path.with_suffix(".smb-metrics.json")
    metrics_report = json.loads(metrics_path.read_text(encoding="utf-8"))
    json_findings = [
        (row["path"], row["rule"], row["representation"], row["value"], row["context"]) for row in report["findings"]
    ]
    connection = sqlite3.connect(state_path)
    connection.row_factory = sqlite3.Row
    configure_evidence_reader(connection)
    try:
        sqlite_findings = [
            (str(secret_file), row["rule_id"], row["representation"], row["value"], row["context"])
            for row in connection.execute(
                f"SELECT f.rule_id, f.representation, f.value, {context_sql(SCHEMA_VERSION)} AS context "
                f"FROM findings f {context_join(SCHEMA_VERSION)} ORDER BY f.match_start"
            )
        ]
        internal_ids = [row[0] for row in connection.execute("SELECT finding_id FROM findings")]
    finally:
        connection.close()

    expected_values = ["ALPHA_SECRET=alpha-value", "BETA_SECRET=second-value"]
    assert json_findings == sqlite_findings
    assert [row[3] for row in json_findings] == expected_values
    assert report["progress"]["findings"] == 2
    assert report["run_status"] == "complete"
    assert metrics_report["mode"] == "passive-observation"
    assert metrics_report["automatic_throttling"] is False
    assert metrics_report["totals"]["hosts"] == 0
    assert stat.S_IMODE(metrics_path.stat().st_mode) == 0o664

    log_files = list(state_path.parent.glob(f"{state_path.stem}.run_*.log"))
    assert len(log_files) == 1
    text_log = log_files[0].read_text(encoding="utf-8")
    assert stat.S_IMODE(log_files[0].stat().st_mode) == 0o664
    console_findings = [line for line in completed.stdout.splitlines() if f'{secret_file}: rule="' in line]
    logged_findings = [line for line in text_log.splitlines() if f'{secret_file}: rule="' in line]
    assert len(console_findings) == len(logged_findings) == 2
    for value in expected_values:
        assert any(value in line for line in console_findings)
        assert any(value in line for line in logged_findings)
    for line in console_findings + logged_findings:
        assert '; severity=medium; confidence=medium; match=' in line
        assert all(field not in line for field in ("representation=", "source=", "schema=", "pack=", "tags=", "category="))
    assert "match=prefix ALPHA_SECRET=alpha-value suffix" in completed.stdout
    assert "match=prefix ALPHA_SECRET=alpha-value suffix" in text_log
    assert f"{secret_file}: context=" not in completed.stdout + text_log
    assert "\x1b" not in completed.stdout + text_log
    assert completed.stdout.index("match=prefix ALPHA_SECRET=alpha-value") < completed.stdout.index("Scan state: complete")
    assert "Progress: run=complete" in completed.stdout
    assert f"Passive SMB metrics report: {metrics_path}" in completed.stdout
    assert all(internal_id not in completed.stdout for internal_id in internal_ids)
    assert all(internal_id not in text_log for internal_id in internal_ids)


def test_explicit_json_contains_every_full_finding_and_no_progress_text(tmp_path):
    original_parent_mode = stat.S_IMODE(tmp_path.stat().st_mode)
    scope = tmp_path / "scope"
    scope.mkdir()
    secret_file = scope / "secrets.txt"
    secret_file.write_text(
        "API_SECRET=first-value\nAPI_SECRET=second-value\n",
        encoding="utf-8",
    )
    state_path = tmp_path / "scan.sqlite3"
    json_path = tmp_path / "report.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "man_spider.manspider",
            "--yes",
            str(scope),
            "-c",
            r"API_SECRET=[a-z-]+",
            "--state-file",
            str(state_path),
            "--json-file",
            str(json_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["run_status"] == "complete"
    assert [finding["value"] for finding in report["findings"]] == [
        "API_SECRET=first-value",
        "API_SECRET=second-value",
    ]
    assert [finding["context"] for finding in report["findings"]] == [
        "API_SECRET=first-value",
        "API_SECRET=second-value",
    ]
    assert all(finding["path"] == str(secret_file) for finding in report["findings"])
    assert {finding["representation"] for finding in report["findings"]} == {"text"}
    assert {finding["rule_provenance"]["source"] for finding in report["findings"]} == {"cli"}
    assert {finding["rule_provenance"]["schema_version"] for finding in report["findings"]} == {None}
    assert {finding["rule_provenance"]["pack"] for finding in report["findings"]} == {None}
    assert all("review" not in finding for finding in report["findings"])
    assert report["progress"]["findings"] == 2
    assert "Progress:" not in json_path.read_text(encoding="utf-8")
    assert stat.S_IMODE(json_path.stat().st_mode) == 0o664
    assert stat.S_IMODE(tmp_path.stat().st_mode) == original_parent_mode


def test_resume_may_atomically_replace_its_explicit_json_report(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "secret.txt").write_text("SECRET", encoding="utf-8")
    state_path = tmp_path / "scan.sqlite3"
    json_path = tmp_path / "report.json"
    first = subprocess.run(
        [
            sys.executable,
            "-m",
            "man_spider.manspider",
            "--yes",
            str(scope),
            "-c",
            "SECRET",
            "--state-file",
            str(state_path),
            "--json-file",
            str(json_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert first.returncode == 0, first.stdout + first.stderr
    json_path.write_text("replace me", encoding="utf-8")

    resumed = subprocess.run(
        [
            sys.executable,
            "-m",
            "man_spider.manspider",
            "--yes",
            str(scope),
            "-c",
            "SECRET",
            "--resume",
            str(state_path),
            "--json-file",
            str(json_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    assert json.loads(json_path.read_text(encoding="utf-8"))["findings"][0]["value"] == "SECRET"


def test_json_share_paths_do_not_repeat_the_share_name(tmp_path):
    options = parse_options([str(tmp_path), "-f", "secret"])
    state = ScanState.create(
        tmp_path / "share-path.sqlite3",
        normalized_scan_configuration(options),
        "2.0.0",
    )
    state.record_exclusion(
        object_key="share|server|admin",
        kind="share",
        target="server",
        share="ADMIN$",
        path="ADMIN$",
        reason="default exclusion",
    )

    assert build_json_report(state)["exclusions"][0]["path"] == r"server\ADMIN$"
    state.close()


@pytest.mark.parametrize("quiet", [False, True])
def test_short_context_tracks_each_occurrence_without_changing_stored_evidence(tmp_path, quiet):
    home = tmp_path / "home"
    scope = tmp_path / "scope"
    scope.mkdir()
    content_line = (
        "L" * 90 + " FIRST_BEFORE SECRET FIRST_AFTER " + "." * 150
        + " SECOND_BEFORE SECRET SECOND_AFTER " + "R" * 90
    )
    source = scope / "repeated.txt"
    original = ("unrelated header\n" + content_line + "\n").encode("utf-8")
    source.write_bytes(original)
    state_path = tmp_path / "scan.sqlite3"
    json_path = tmp_path / "report.json"
    completed = subprocess.run(
        [
            sys.executable, "-m", "man_spider.manspider", "--yes", str(scope),
            "-c", "SECRET", "--state-file", str(state_path),
            "--json-file", str(json_path), *(["-q"] if quiet else []),
        ],
        capture_output=True, text=True, timeout=30, check=False,
        env={**os.environ, "HOME": str(home)},
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    findings = json.loads(json_path.read_text(encoding="utf-8"))["findings"]
    assert len(findings) == 2
    assert [row["value"] for row in findings] == ["SECRET", "SECRET"]
    assert [row["context"] for row in findings] == [content_line, content_line]
    assert source.read_bytes() == original
    text_log = next(state_path.parent.glob(f"{state_path.stem}.run_*.log")).read_text(encoding="utf-8")
    console_lines = [line for line in completed.stdout.splitlines() if f'{source}: rule="' in line]
    logged_lines = [line for line in text_log.splitlines() if f'{source}: rule="' in line]
    assert len(console_lines) == 1
    assert len(logged_lines) == 2
    # Multiple occurrences of one rule do not become fictitious extra rules.
    assert "(ещё " not in console_lines[0]
    if quiet:
        assert console_lines[0].endswith("match=SECRET … SECRET")
        assert all(line.endswith("match=SECRET") for line in logged_lines)
    else:
        assert "FIRST_BEFORE SECRET FIRST_AFTER" in console_lines[0]
        assert "SECOND_BEFORE SECRET SECOND_AFTER" in console_lines[0]
        assert " … " in console_lines[0]
        assert "FIRST_BEFORE SECRET FIRST_AFTER" in logged_lines[0]
        assert "SECOND_BEFORE" not in logged_lines[0]
        assert "SECOND_BEFORE SECRET SECOND_AFTER" in logged_lines[1]
        assert "FIRST_BEFORE" not in logged_lines[1]
        assert all("match=…" in line and line.endswith("…") for line in console_lines + logged_lines)
