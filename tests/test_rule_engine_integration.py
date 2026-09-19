import json
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

from man_spider.evidence_storage import configure_evidence_reader, context_join, context_sql
from man_spider.state import SCHEMA_VERSION
from tests.optional_fixtures import require_private_directory

TESTDATA = Path(__file__).parent.parent / "testdata"


def write_pack(path, rules, *, version="1"):
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "pack": {"id": "manspider.integration", "version": version},
                "rules": rules,
            }
        ),
        encoding="utf-8",
    )


def run_manspider(arguments, *, timeout=60):
    return subprocess.run(
        [sys.executable, "-m", "man_spider.manspider", "--yes", *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def rows(path, query):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    configure_evidence_reader(connection)
    try:
        return connection.execute(query).fetchall()
    finally:
        connection.close()


def filename_match(filename):
    return {
        "condition": "all",
        "predicates": [{"field": "filename", "operator": "exact", "value": filename}],
    }


def test_native_representations_flow_through_cli_state_and_json(tmp_path):
    require_private_directory("testdata")
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "plain.txt").write_text("TEXT_RULE_SECRET", encoding="utf-8")
    (scope / "binary.bin").write_bytes(b"\x00STRINGS_RULE_SECRET\x00RAW_\xff_SECRET\x00")
    shutil.copy2(TESTDATA / "test.png", scope / "image.png")
    shutil.copy2(TESTDATA / "test.docx", scope / "document.docx")
    shutil.copy2(TESTDATA / "test.pdf", scope / "document.pdf")

    rule_path = tmp_path / "rules.json"
    state_path = tmp_path / "scan.sqlite3"
    json_path = tmp_path / "scan.json"
    write_pack(
        rule_path,
        [
            {
                "id": "binary-representations",
                "match": filename_match("binary.bin"),
                "actions": [
                    {
                        "type": "scan",
                        "representation": "strings",
                        "condition": "all",
                        "predicates": [{"operator": "contains", "value": "STRINGS_RULE_SECRET"}],
                    },
                    {
                        "type": "scan",
                        "representation": "raw",
                        "condition": "all",
                        "predicates": [{"operator": "contains", "value": "RAW_ÿ_SECRET", "case_sensitive": True}],
                    },
                ],
            },
            {
                "id": "image-ocr",
                "match": filename_match("image.png"),
                "actions": [{"type": "scan", "representation": "ocr", "pattern": "Password123"}],
            },
            {
                "id": "docx-structured",
                "match": filename_match("document.docx"),
                "actions": [{"type": "scan", "representation": "structured", "pattern": "Password123"}],
            },
            {
                "id": "pdf-structured",
                "match": filename_match("document.pdf"),
                "actions": [{"type": "scan", "representation": "structured", "pattern": "Password123"}],
            },
            {
                "id": "plain-text",
                "match": filename_match("plain.txt"),
                "actions": [
                    {
                        "type": "scan",
                        "representation": "text",
                        "condition": "all",
                        "predicates": [{"operator": "exact", "value": "TEXT_RULE_SECRET"}],
                    }
                ],
            },
        ],
    )

    completed = run_manspider(
        [
            scope,
            "--rules",
            rule_path,
            "--read-formats",
            "bin",
            "png",
            "--state-file",
            state_path,
            "--json-file",
            json_path,
        ]
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    objects = rows(state_path, "SELECT path, status, attempts FROM objects WHERE kind='file' ORDER BY path")
    assert len(objects) == 5
    assert {row["status"] for row in objects} == {"processed"}
    assert {row["attempts"] for row in objects} == {1}

    findings = rows(
        state_path,
        f"""
        SELECT f.rule_id, f.representation, f.rule_pack_id, f.rule_pack_version, f.value,
               {context_sql(SCHEMA_VERSION)} AS context
        FROM findings f {context_join(SCHEMA_VERSION)} ORDER BY f.finding_id
        """,
    )
    assert {row["representation"] for row in findings} == {"text", "strings", "raw", "ocr", "structured"}
    assert {(row["representation"], row["value"]) for row in findings} == {
        ("text", "TEXT_RULE_SECRET"),
        ("strings", "STRINGS_RULE_SECRET"),
        ("raw", "RAW_ÿ_SECRET"),
        ("ocr", "Password123"),
        ("structured", "Password123"),
    }
    assert {row["rule_pack_id"] for row in findings} == {"manspider.integration"}
    assert {row["rule_pack_version"] for row in findings} == {"1"}

    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["run_status"] == "complete"
    assert {(item["representation"], item["value"]) for item in report["findings"]} == {
        (row["representation"], row["value"]) for row in findings
    }
    assert all(
        item["rule_provenance"]["pack"] == {"id": "manspider.integration", "version": "1"}
        for item in report["findings"]
    )

    configuration = json.loads(rows(state_path, "SELECT config_json FROM runs")[0]["config_json"])
    assert configuration["execution"]["rule_representation_plan"] == {
        "ocr": ["image-ocr"],
        "raw": ["binary-representations"],
        "strings": ["binary-representations"],
        "structured": ["docx-structured", "pdf-structured"],
        "text": ["plain-text"],
    }

def test_rule_resume_reuses_findings_and_rejects_changed_representation_plan(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    candidate = scope / "resume.bin"
    candidate.write_bytes(b"\x00RESUME_SECRET\x00")
    rule_path = tmp_path / "rules.json"
    state_path = tmp_path / "scan.sqlite3"

    def rules(representation):
        return [
            {
                "id": "resume-secret",
                "match": filename_match(candidate.name),
                "actions": [
                    {
                        "type": "scan",
                        "representation": representation,
                        "pattern": "RESUME_SECRET",
                        "flags": [],
                    }
                ],
            }
        ]

    write_pack(rule_path, rules("raw"))
    common = [scope, "--rules", rule_path, "--read-formats", "bin"]
    first = run_manspider([*common, "--state-file", state_path])
    assert first.returncode == 0, first.stdout + first.stderr
    original_findings = rows(state_path, "SELECT finding_id, value FROM findings ORDER BY finding_id")
    assert [(row["value"]) for row in original_findings] == ["RESUME_SECRET"]

    resumed = run_manspider([*common, "--resume", state_path])
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    reused_findings = rows(state_path, "SELECT finding_id, value FROM findings ORDER BY finding_id")
    assert [tuple(row) for row in reused_findings] == [tuple(row) for row in original_findings]
    object_row = rows(state_path, "SELECT status, attempts FROM objects WHERE kind='file'")[0]
    assert (object_row["status"], object_row["attempts"]) == ("processed", 1)
    counters = {row["name"]: row["value"] for row in rows(state_path, "SELECT name, value FROM counters")}
    assert counters["resume_reused"] == 1

    write_pack(rule_path, rules("strings"))
    mismatched = run_manspider([*common, "--resume", state_path])
    assert mismatched.returncode == 5
    assert "Resume configuration does not match the stored scope, filters, rules, or policy" in mismatched.stdout
    assert [tuple(row) for row in rows(state_path, "SELECT finding_id, value FROM findings")] == [
        tuple(row) for row in original_findings
    ]


def test_real_ocr_failure_retains_raw_finding_and_completes_with_errors(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    corrupt = scope / "corrupt.png"
    corrupt.write_bytes(b"RAW_SURVIVES_OCR_ERROR\x00not-a-real-image")
    rule_path = tmp_path / "rules.json"
    state_path = tmp_path / "scan.sqlite3"
    json_path = tmp_path / "scan.json"
    write_pack(
        rule_path,
        [
            {
                "id": "corrupt-image",
                "match": filename_match(corrupt.name),
                "actions": [
                    {"type": "scan", "representation": "raw", "pattern": "RAW_SURVIVES_OCR_ERROR"},
                    {"type": "scan", "representation": "ocr", "pattern": "OCR_WILL_NOT_RUN"},
                ],
            }
        ],
    )

    completed = run_manspider(
        [
            scope,
            "--rules",
            rule_path,
            "--read-formats",
            "png",
            "--state-file",
            state_path,
            "--json-file",
            json_path,
        ]
    )

    assert completed.returncode == 2, completed.stdout + completed.stderr
    object_row = rows(state_path, "SELECT status, reason FROM objects WHERE kind='file'")[0]
    assert object_row["status"] == "error"
    assert "representation=ocr; rules=rule:corrupt-image" in object_row["reason"]
    findings = rows(state_path, "SELECT rule_id, representation, value FROM findings")
    assert [(row["rule_id"], row["representation"], row["value"]) for row in findings] == [
        ("rule:corrupt-image", "raw", "RAW_SURVIVES_OCR_ERROR")
    ]
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["run_status"] == "complete_with_errors"
    assert [(item["representation"], item["value"]) for item in report["findings"]] == [
        ("raw", "RAW_SURVIVES_OCR_ERROR")
    ]


def test_explicitly_enabled_archive_flows_through_cli_state_and_json(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    archive_path = scope / "secrets.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "nested/secrets.txt",
            "ARCHIVE_PIPELINE_SECRET\n" + ("x" * 200_000) + "\nARCHIVE_PIPELINE_SECRET",
        )

    rule_path = tmp_path / "rules.json"
    state_path = tmp_path / "scan.sqlite3"
    json_path = tmp_path / "scan.json"
    write_pack(
        rule_path,
        [
            {
                "id": "archive-content",
                "match": filename_match(archive_path.name),
                "actions": [
                    {
                        "type": "scan",
                        "representation": "structured",
                        "pattern": "ARCHIVE_PIPELINE_SECRET",
                    }
                ],
            }
        ],
    )

    completed = run_manspider(
        [
            scope,
            "--rules",
            rule_path,
            "--read-formats",
            "zip",
            "--state-file",
            state_path,
            "--json-file",
            json_path,
        ]
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    object_row = rows(state_path, "SELECT status, attempts FROM objects WHERE kind='file'")[0]
    assert (object_row["status"], object_row["attempts"]) == ("processed", 1)
    findings = rows(
        state_path,
        "SELECT representation, value, match_start FROM findings ORDER BY match_start",
    )
    assert [(row["representation"], row["value"]) for row in findings] == [
        ("structured", "ARCHIVE_PIPELINE_SECRET"),
        ("structured", "ARCHIVE_PIPELINE_SECRET"),
    ]
    assert findings[-1]["match_start"] > 200_000
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["run_status"] == "complete"
    assert [(item["representation"], item["value"], item["match_start"]) for item in report["findings"]] == [
        (row["representation"], row["value"], row["match_start"]) for row in findings
    ]
