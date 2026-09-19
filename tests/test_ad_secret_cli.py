"""Real local CLI persistence and resume identity for native AD secret evidence."""

import base64
import json
import sqlite3
import subprocess
import sys

import pytest

from man_spider.lib.parser.ad_directory_export import (
    inspect_active_directory_json_secrets,
    inspect_active_directory_ldif_secrets,
)
from man_spider.lib.parser.group_policy import inspect_group_policy_preference_password
from man_spider.state import FindingRecord, ScanState
from tests.rule_pack_2_6_ad_structured_cases import OPAQUE_FIXTURE
from tests.rule_pack_2_6_gpp_cases import GPP_CPASSWORD, GPP_PASSWORD


DIRECTORY_PASSWORD = "$uperSecret!DirectoryFixture"
OPAQUE_BASE64 = base64.b64encode(OPAQUE_FIXTURE).decode("ascii")
NATIVE_INSPECTORS = {
    "group-policy-preference-password": inspect_group_policy_preference_password,
    "active-directory-ldif-secrets": inspect_active_directory_ldif_secrets,
    "active-directory-json-secrets": inspect_active_directory_json_secrets,
}


def native_sources():
    gpp = (
        '<Groups><User name="FirstFixture"><Properties userName="EXAMPLE\\first" '
        f'cpassword="{GPP_CPASSWORD}" /></User><User name="SecondFixture">'
        f'<Properties userName="EXAMPLE\\second" cpassword="{GPP_CPASSWORD}" /></User></Groups>'
    )
    ldif = (
        f"dn: CN=FirstFixture,DC=example,DC=test\nms-Mcs-AdmPwd: {DIRECTORY_PASSWORD}\n\n"
        f"dn: CN=SecondFixture,DC=example,DC=test\nms-Mcs-AdmPwd: {DIRECTORY_PASSWORD}\n"
        f"msDS-ManagedPassword:: {OPAQUE_BASE64}\n"
    )
    document = json.dumps(
        [
            {"dn": "CN=FirstFixture", "ms-Mcs-AdmPwd": DIRECTORY_PASSWORD},
            {"dn": "CN=SecondFixture", "ms-Mcs-AdmPwd": DIRECTORY_PASSWORD},
            {"msLAPS-EncryptedPasswordHistory": [OPAQUE_BASE64, list(OPAQUE_FIXTURE)]},
        ]
    )
    return {
        "group-policy-preference-password": ("Groups.xml", gpp),
        "active-directory-ldif-secrets": ("directory.ldf", ldif),
        "active-directory-json-secrets": ("directory.json.bak", document),
    }


def read_rows(path, query):
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(query)]


@pytest.mark.parametrize("detector", NATIVE_INSPECTORS)
def test_native_state_identity_preserves_ownership_and_resume(tmp_path, detector):
    filename, source = native_sources()[detector]
    data = source.encode("utf-8")
    extracted = NATIVE_INSPECTORS[detector](data)
    assert len(extracted) >= 2
    expected_secret = GPP_PASSWORD if detector == "group-policy-preference-password" else DIRECTORY_PASSWORD
    assert sum(value == expected_secret for value, *_ in extracted) == 2
    records = [
        FindingRecord(
            "rule:" + detector,
            value,
            start,
            end,
            context,
            representation="inspect:" + detector,
            rule_pack_id="manspider.default",
            rule_pack_version="2.6.0",
        )
        for value, start, end, context in extracted
    ]
    configuration = {"scope": str(tmp_path), "fixture": detector}
    state_path = tmp_path / "scan.sqlite3"
    state = ScanState.create(state_path, configuration, "2.0.0")
    registration = {
        "object_key": "file|" + filename,
        "kind": "file",
        "path": filename,
        "size": len(data),
        "mtime": 100,
    }
    decision = state.register_object(**registration)
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "processed", findings=records)
    initial = [dict(row) for row in state.findings_for(decision.object_id)]
    initial_ids = {row["finding_id"] for row in initial}
    assert len(initial_ids) == len(records)
    state.set_run_status("interrupted")
    state.close()

    resumed = ScanState.resume(state_path, configuration, "2.0.0")
    unchanged = resumed.register_object(**registration)
    assert unchanged.should_process is False
    assert {row["finding_id"] for row in resumed.findings_for(unchanged.object_id)} == initial_ids
    # A retry/reprocessing path uses the same semantic evidence even if its
    # enumeration order changes; it must neither merge ownership nor add rows.
    resumed.begin_object(unchanged.object_id)
    resumed.complete_object(unchanged.object_id, "processed", findings=reversed(records))
    after = [dict(row) for row in resumed.findings_for(unchanged.object_id)]
    assert {row["finding_id"] for row in after} == initial_ids
    assert {(row["value"], row["context"]) for row in after} == {(row["value"], row["context"]) for row in initial}
    assert resumed.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    resumed.close()


def test_builtin_ad_native_values_survive_cli_json_state_and_repeated_resume(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    original = {}
    for filename, source in native_sources().values():
        path = scope / filename
        path.write_text(source, encoding="utf-8")
        original[path] = (path.read_bytes(), path.stat().st_mtime_ns)
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

    def run(state_option):
        result = subprocess.run(
            [*common, state_option, str(state_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    run("--state-file")
    query = (
        "SELECT * FROM findings WHERE representation IN ("
        + ",".join("'inspect:" + detector + "'" for detector in NATIVE_INSPECTORS)
        + ") ORDER BY finding_id"
    )
    rows = read_rows(state_path, query)
    assert len(rows) == 9
    assert all(row["rule_pack_id"] == "manspider.default" and row["rule_pack_version"] == "2.7.0" for row in rows)
    gpp = [row for row in rows if row["representation"] == "inspect:group-policy-preference-password"]
    assert [row["value"] for row in gpp] == [GPP_PASSWORD, GPP_PASSWORD]
    gpp_contexts = [json.loads(row["context"]) for row in gpp]
    assert {context["owner_name"] for context in gpp_contexts} == {"FirstFixture", "SecondFixture"}
    assert len({context["pointer"] for context in gpp_contexts}) == 2
    assert all(
        context["source_value"] == GPP_CPASSWORD and context["decoded_password"] == GPP_PASSWORD
        for context in gpp_contexts
    )
    ldif = [row for row in rows if row["representation"] == "inspect:active-directory-ldif-secrets"]
    assert {row["value"] for row in ldif} == {DIRECTORY_PASSWORD, OPAQUE_BASE64}
    assert {json.loads(row["context"])["record_dn"] for row in ldif if row["value"] == DIRECTORY_PASSWORD} == {
        "CN=FirstFixture,DC=example,DC=test",
        "CN=SecondFixture,DC=example,DC=test",
    }
    structured = [row for row in rows if row["representation"] == "inspect:active-directory-json-secrets"]
    assert len(structured) == 4
    opaque_contexts = [json.loads(row["context"]) for row in structured if row["value"] == OPAQUE_BASE64]
    assert {context["pointer"] for context in opaque_contexts} == {
        "/2/msLAPS-EncryptedPasswordHistory/0",
        "/2/msLAPS-EncryptedPasswordHistory/1",
    }
    array = next(context for context in opaque_contexts if context["encoding"] == "byte-array")
    assert array["source_value"] == list(OPAQUE_FIXTURE)
    assert array["decoded_base64"] == OPAQUE_BASE64
    assert array["decoded_utf8"] is None

    def assert_report_matches_state():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        native = [
            finding
            for finding in report["findings"]
            if finding["representation"] in {"inspect:" + name for name in NATIVE_INSPECTORS}
        ]
        assert {(finding["value"], finding["context"]) for finding in native} == {
            (row["value"], row["context"]) for row in rows
        }

    assert_report_matches_state()
    for _ in range(2):
        run("--resume")
        assert read_rows(state_path, query) == rows
        assert_report_matches_state()
    assert read_rows(state_path, "SELECT status FROM runs") == [{"status": "complete"}]
    assert all(row["attempts"] == 1 for row in read_rows(state_path, "SELECT attempts FROM objects WHERE kind='file'"))
    assert read_rows(state_path, "PRAGMA integrity_check") == [{"integrity_check": "ok"}]
    assert set(scope.iterdir()) == set(original)
    assert {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in original} == original
