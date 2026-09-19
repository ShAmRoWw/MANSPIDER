"""Independent private-key inspection evidence must survive real persistence."""

from dataclasses import asdict, fields, replace
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from man_spider.lib.parser import FileParser
from man_spider.lib.spiderling import Spiderling
from man_spider.rules import load_rule_files
from man_spider.state import FindingRecord, ScanState, local_object_key


PASSWORD = "AuditUnlockOnly!"
PRIVATE_KEY = "inspect:private-key-material"
PREVIOUS_CONTEXT_REPRESENTATIONS = {
    "inspect:kubernetes-secret-json",
    "inspect:group-policy-preference-password",
    "inspect:active-directory-ldif-secrets",
    "inspect:active-directory-json-secrets",
    "inspect:russian-json-credential-value",
    "inspect:russian-legacy-credential-value",
}


@pytest.fixture(scope="module")
def encrypted_pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASSWORD.encode()),
    )


def write_pack(path, *, reverse=False):
    actions = [
        {"type": "inspect", "detector": "private-key-material"},
        {"type": "inspect", "detector": "private-key-material", "passwords": [PASSWORD]},
    ]
    if reverse:
        actions.reverse()
    path.write_text(
        json.dumps({
            "schema_version": 3,
            "pack": {"id": "manspider.key-identity-test", "version": "1"},
            "rules": [{"id": "same-key-two-inspections", "actions": actions}],
        }),
        encoding="utf-8",
    )


def parsed_records(pack_path, payload):
    parser = FileParser([], quiet=True, blocked_extensions=[], rules=load_rule_files([pack_path]))
    parsed = parser.parse_file("encrypted.pem", data=payload)
    assert parsed.error is None
    assert len(parsed.findings) == 2
    accepted_fields = {field.name for field in fields(FindingRecord)}
    records = tuple(
        FindingRecord(**{name: value for name, value in asdict(finding).items() if name in accepted_fields})
        for finding in Spiderling.unique_findings(parsed.findings)
    )
    assert len(records) == 2
    assert len({(finding.value, finding.start, finding.end) for finding in records}) == 1
    assert len({finding.context for finding in records}) == 2
    assert any("private key parsed;" in finding.context for finding in records)
    assert any("PEM header present" in finding.context for finding in records)
    return records


def previous_identity(run_id, object_key, finding):
    """Freeze the pre-fix identity contract; do not call implementation helpers."""

    identity = "\x1f".join((
        run_id,
        object_key,
        finding.rule_id,
        finding.representation,
        finding.rule_source,
        str(finding.rule_schema_version),
        str(finding.rule_pack_id),
        str(finding.rule_pack_version),
        finding.severity,
        finding.confidence,
        finding.category,
        json.dumps(list(finding.tags), ensure_ascii=False, separators=(",", ":")),
        str(finding.start),
        str(finding.end),
        finding.value,
    ))
    if finding.representation in PREVIOUS_CONTEXT_REPRESENTATIONS:
        identity += "\x1f" + (finding.context or "")
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def test_real_parser_evidence_survives_state_reprocessing_and_action_reordering(tmp_path, encrypted_pem):
    pack_path = tmp_path / "rules.json"
    write_pack(pack_path)
    records = parsed_records(pack_path, encrypted_pem)
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "test")
    try:
        decision = state.claim_object(object_key="local|encrypted.pem", kind="file", path="encrypted.pem")
        state.complete_object(decision.object_id, "processed", findings=records)
        first_rows = state.findings_for(decision.object_id)
        identities = {row["finding_id"] for row in first_rows}
        evidence = {(row["value"], row["context"]) for row in first_rows}
        assert len(identities) == 2
        assert evidence == {(finding.value, finding.context) for finding in records}

        write_pack(pack_path, reverse=True)
        reordered = parsed_records(pack_path, encrypted_pem)
        assert [item.context for item in reordered] == [item.context for item in reversed(records)]
        state.begin_object(decision.object_id)
        state.complete_object(decision.object_id, "processed", findings=reordered)
        assert {row["finding_id"] for row in state.findings_for(decision.object_id)} == identities
        assert {(row["value"], row["context"]) for row in state.findings_for(decision.object_id)} == evidence
        assert state.object_row(decision.object_id)["status"] == "processed"
        assert state.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        state.close()


@pytest.mark.parametrize("representation", ["text", "raw", "structured", "metadata", *sorted(PREVIOUS_CONTEXT_REPRESENTATIONS)])
def test_other_finding_identity_contract_is_unchanged(tmp_path, representation):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "test")
    try:
        key = "local|controls.txt"
        decision = state.register_object(object_key=key, kind="file", path="controls.txt")
        first = FindingRecord(
            "rule:first", "SameSecret!", 0, 11, "source context one", representation=representation,
            rule_source="custom.json", rule_schema_version=3, rule_pack_id="custom", rule_pack_version="1",
            severity="high", confidence="medium", category="credential.password", tags=("test", "ключ"),
        )
        findings = [first, replace(first, start=20, end=31), replace(first, rule_id="rule:second")]
        if representation in PREVIOUS_CONTEXT_REPRESENTATIONS:
            findings.append(replace(first, context="source context two"))
        expected_ids = {previous_identity(state.run_id, key, finding) for finding in findings}
        state.complete_object(decision.object_id, "processed", findings=findings)
        assert {row["finding_id"] for row in state.findings_for(decision.object_id)} == expected_ids
        state.complete_object(decision.object_id, "processed", findings=reversed(findings))
        assert {row["finding_id"] for row in state.findings_for(decision.object_id)} == expected_ids
    finally:
        state.close()


def test_resume_does_not_migrate_legacy_key_rows_but_reprocessing_replaces_them(tmp_path, encrypted_pem):
    pack_path = tmp_path / "rules.json"
    write_pack(pack_path)
    records = parsed_records(pack_path, encrypted_pem)
    state_path = tmp_path / "scan.sqlite3"
    state = ScanState.create(state_path, {}, "before")
    try:
        legacy_objects = []
        for name in ("retained.pem", "reprocessed.pem"):
            key = local_object_key(tmp_path / name)
            decision = state.register_object(object_key=key, kind="file", path=name)
            state.complete_object(decision.object_id, "processed", findings=records[:1])
            old_id = previous_identity(state.run_id, key, records[0])
            # Build a genuine old-style persisted row, not an implementation
            # monkeypatch. Opening the new code must not rewrite this row.
            state.connection.execute("UPDATE findings SET finding_id=? WHERE object_id=?", (old_id, decision.object_id))
            legacy_objects.append((decision.object_id, old_id))
        before = [dict(row) for row in state.connection.execute("SELECT * FROM findings ORDER BY object_id")]
    finally:
        state.close()

    state = ScanState.resume(state_path, {}, "after")
    try:
        assert [dict(row) for row in state.connection.execute("SELECT * FROM findings ORDER BY object_id")] == before
        retained_id, retained_finding_id = legacy_objects[0]
        reprocessed_id, replaced_finding_id = legacy_objects[1]
        state.begin_object(reprocessed_id)
        state.complete_object(reprocessed_id, "processed", findings=records)
        assert [dict(row) for row in state.findings_for(retained_id)] == [
            {key: value for key, value in before[0].items() if key != "context_id"}
        ]
        assert state.findings_for(retained_id)[0]["finding_id"] == retained_finding_id
        rows = state.findings_for(reprocessed_id)
        assert len(rows) == 2
        assert replaced_finding_id not in {row["finding_id"] for row in rows}
        assert {(row["value"], row["context"]) for row in rows} == {(item.value, item.context) for item in records}
    finally:
        state.close()


def test_local_cli_completes_two_inspectors_without_modifying_key(tmp_path, encrypted_pem):
    scope = tmp_path / "scope"
    scope.mkdir()
    source = scope / "encrypted.pem"
    source.write_bytes(encrypted_pem)
    before = (hashlib.sha256(source.read_bytes()).hexdigest(), source.stat().st_mtime_ns)
    rule_path = tmp_path / "rules.json"
    state_path = tmp_path / "scan.sqlite3"
    write_pack(rule_path)
    result = subprocess.run(
        [
            sys.executable, "-m", "man_spider.manspider", str(scope), "--yes", "--rules", str(rule_path),
            "--state-file", str(state_path), "--loot-dir", str(tmp_path / "loot"),
            "--no-unclassified-report", "--no-smb-metrics",
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "UNIQUE constraint failed" not in result.stdout + result.stderr
    connection = sqlite3.connect(f"file:{state_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        assert connection.execute("SELECT status FROM runs").fetchone()[0] == "complete"
        objects = connection.execute("SELECT path, status FROM objects WHERE kind='file'").fetchall()
        assert [(row["path"], row["status"]) for row in objects] == [(str(source), "processed")]
        rows = connection.execute("SELECT * FROM findings").fetchall()
        assert len(rows) == 2
        assert len({row["finding_id"] for row in rows}) == 2
        assert len({(row["value"], row["match_start"], row["match_end"]) for row in rows}) == 1
        assert any("private key parsed;" in row["context"] for row in rows)
        assert any("PEM header present" in row["context"] for row in rows)
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        connection.close()
    assert before == (hashlib.sha256(source.read_bytes()).hexdigest(), source.stat().st_mtime_ns)
