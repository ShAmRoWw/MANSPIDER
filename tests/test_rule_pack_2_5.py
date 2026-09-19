"""End-to-end, ownership, and routing regressions for the audited 2.5 pack."""

from pathlib import PurePosixPath

import pytest

from man_spider.lib.parser import FileParser
from man_spider.rules import load_builtin_rules
from tests.rule_pack_2_5_content_cases import CONTENT_CASES, NEGATIVE_CASES
from tests.rule_pack_2_5_content_cases import METADATA_CASES as CLIENT_METADATA_CASES
from tests.rule_pack_2_5_content_cases import METADATA_NEGATIVE_CASES as CLIENT_METADATA_NEGATIVE_CASES
from tests.rule_pack_2_5_document_fixtures import DOCUMENT_ACCESS_KEY, DOCUMENT_PASSWORD, document_payloads
from tests.rule_pack_2_5_existing_cases import CLASSIFICATION_EXPECTATIONS
from tests.rule_pack_2_5_existing_cases import NEGATIVE_CASES as EXISTING_NEGATIVE_CASES
from tests.rule_pack_2_5_existing_cases import POSITIVE_CASES as EXISTING_CASES
from tests.rule_pack_2_5_metadata_cases import METADATA_CASES
from tests.rule_pack_2_5_metadata_cases import NEGATIVE_CASES as METADATA_NEGATIVE_CASES
from tests.rule_pack_2_5_root_cases import CONTENT_CASES as ROOT_CONTENT_CASES
from tests.rule_pack_2_5_root_cases import NEGATIVE_CASES as ROOT_NEGATIVE_CASES
from tests.rule_pack_2_5_structured_cases import STRUCTURED_INSPECTOR_CASES


RULES = load_builtin_rules()
PARSER = FileParser([], quiet=True, rules=RULES)
POSITIVE = list(CONTENT_CASES) + list(EXISTING_CASES) + list(ROOT_CONTENT_CASES)
NEGATIVE = list(NEGATIVE_CASES) + list(EXISTING_NEGATIVE_CASES) + list(ROOT_NEGATIVE_CASES)


def route_for(path, content=""):
    candidate = PurePosixPath(path.replace("\\", "/"))
    return PARSER.route_rules(
        {
            "share": "Fixtures",
            "directory": str(candidate.parent),
            "path": path,
            "filename": candidate.name,
            "extension": "".join(candidate.suffixes).lower(),
            "size": len(content.encode("utf-8")),
            "mtime": 0,
        }
    )


@pytest.mark.parametrize(("path", "content", "rule_id"), POSITIVE)
def test_complete_positive_matrix_reaches_real_extraction(tmp_path, path, content, rule_id):
    route = route_for(path, content)
    assert f"rule:{rule_id}" in route.matched_rule_ids
    result = PARSER.parse_file(tmp_path / path, data=content.encode(), rule_route=route)
    assert result.error is None
    findings = [finding for finding in result.findings if finding.rule_id == f"rule:{rule_id}"]
    assert findings
    assert all(f.value in content for f in findings)


@pytest.mark.parametrize(("path", "content", "rule_id"), NEGATIVE)
def test_negative_matrix_does_not_claim_this_secret(path, content, rule_id):
    assert f"rule:{rule_id}" not in {rule.rule_id for rule, _ in PARSER.match(content, route_for(path, content))}


@pytest.mark.parametrize(("path", "content", "rule_id"), list(CONTENT_CASES) + list(ROOT_CONTENT_CASES))
def test_new_regex_detectors_retain_every_occurrence(path, content, rule_id):
    def values(text):
        return [
            match.group(0)
            for rule, match in PARSER.match(text, route_for(path, text))
            if rule.rule_id == f"rule:{rule_id}"
        ]

    original = values(content)
    assert original
    assert values(content + "\n" + content) == original + original


@pytest.mark.parametrize(("path", "rule_id"), list(METADATA_CASES) + list(CLIENT_METADATA_CASES))
def test_metadata_candidates_are_precisely_routed(path, rule_id):
    assert f"rule:{rule_id}" in route_for(path).metadata_rule_ids


@pytest.mark.parametrize(("path", "rule_id"), list(METADATA_NEGATIVE_CASES) + list(CLIENT_METADATA_NEGATIVE_CASES))
def test_metadata_near_misses_are_not_misclassified(path, rule_id):
    assert f"rule:{rule_id}" not in route_for(path).metadata_rule_ids


@pytest.mark.parametrize(("path", "content", "rule_id"), STRUCTURED_INSPECTOR_CASES)
def test_actual_builtin_structural_inspector_uses_one_source_read(tmp_path, path, content, rule_id):
    calls = []
    result = PARSER.parse_file(
        tmp_path / path,
        rule_route=route_for(path, content),
        data_loader=lambda: calls.append(True) or content.encode("utf-8"),
    )
    assert calls == [True]
    assert result.error is None
    findings = [f for f in result.findings if f.rule_id == f"rule:{rule_id}"]
    assert findings
    assert all(f.representation == "inspect:kubernetes-secret-json" for f in findings)
    assert all(f.rule_pack_id == "manspider.default" and f.rule_pack_version == "2.7.0" for f in findings)


def test_evidence_strength_is_not_inflated_for_identifiers_and_candidates():
    by_id = {rule["id"]: rule for rule in RULES}
    for rule_id, expected in CLASSIFICATION_EXPECTATIONS.items():
        assert all(by_id[rule_id][key] == value for key, value in expected.items())
    assert by_id["unix-account-database"]["severity"] in {"info", "low"}
    assert by_id["credential-artifact-copy-name"]["severity"] == "low"
    assert not route_for("id_rsa.pub").inspector_rules


@pytest.mark.parametrize(
    "path",
    [
        "client.jsonc",
        "client.json5",
        "production.tfbackend",
        "site.pubxml.user",
        "Azure.publishsettings",
        "login.jaas",
        "directory.ldif",
        "users.acl",
        "wifi.nmconnection",
        ".htpasswd",
        ".authinfo",
        ".Renviron",
        ".Rprofile",
        ".Rhistory",
        ".curlrc",
        "_curlrc",
        ".wgetrc",
        ".databrickscfg",
        ".smbcredentials",
        "users/.oci/config",
        "etc/nix/netrc",
        "data/serf/local.keyring",
        "data/serf/remote.keyring",
        "etc/NetworkManager/system-connections/Office",
        "etc/credstore/db-password",
        "run/credstore/db-password",
        "usr/lib/credstore/db-password",
        "etc/ansible/hosts",
        "ansible/inventories/production/hosts",
    ],
)
@pytest.mark.parametrize("backup", ["", ".bak"])
def test_expanded_shared_gate_reaches_general_detectors(tmp_path, path, backup):
    path += backup
    text = '{"password":"FormatFixtureSecret!","AccessKeyId":"AKIAABCDEFGHIJKLMNOP"}'
    result = PARSER.parse_file(tmp_path / path, data=text.encode(), rule_route=route_for(path, text))
    assert result.error is None
    assert {"rule:assigned-secret", "rule:aws-access-key-id"} <= {f.rule_id for f in result.findings}


@pytest.mark.parametrize(
    "path",
    [
        "etc/credstore.encrypted/opaque",
        "arbitrary/hosts",
        "unrelated/config",
        "photo.jpg",
        "archive.zip.bak",
        "opaque.bin",
    ],
)
def test_contextual_gate_does_not_force_arbitrary_or_opaque_reads(path):
    # .zip.bak may route a generic .bak rule, but format policy blocks the read.
    assert not route_for(path).content_rules or not PARSER.match_magic(path)


@pytest.mark.parametrize("extension", [".odt", ".ods", ".epub", ".ppt"])
@pytest.mark.parametrize("backup", ["", ".bak", ".old.2", ".20260905", "~"])
def test_new_document_routes_use_real_formats_for_path_and_memory(tmp_path, extension, backup):
    candidate = tmp_path / f"document{extension}{backup}"
    data = document_payloads()[extension]
    candidate.write_bytes(data)
    route = route_for(candidate.name)
    for result in (
        PARSER.parse_file(candidate, rule_route=route),
        PARSER.parse_file(candidate, data=data, rule_route=route),
    ):
        assert result.error is None
        assert DOCUMENT_ACCESS_KEY in {f.value for f in result.findings}
        assert DOCUMENT_PASSWORD in {f.value for f in result.findings}
