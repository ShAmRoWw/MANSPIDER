"""Independent lexical AD expansion checks before and after builtin integration."""

from pathlib import Path, PurePosixPath

import pytest

from man_spider.lib.parser import FileParser
from man_spider.rules import load_rule_files
from tests.rule_pack_2_6_ad_content_cases import CONTENT_CASES, NEGATIVE_CASES, SOURCES
from tests.rule_pack_2_6_gpp_cases import GPP_CPASSWORD
from tests.optional_fixtures import require_private_directory


require_private_directory("testdata", module=True)
FRAGMENT = Path(__file__).resolve().parents[1] / "testdata/rule-pack-2.6-ad-content.json"
RULES = load_rule_files([FRAGMENT])
PARSER = FileParser([], quiet=True, rules=RULES)


def route_for(path, content):
    candidate = PurePosixPath(path.replace("\\", "/"))
    return PARSER.route_rules(
        {
            "path": path,
            "filename": candidate.name,
            "directory": str(candidate.parent),
            "extension": "".join(candidate.suffixes).lower(),
            "size": len(content.encode("utf-8")),
        }
    )


def values(path, content, rule_id):
    return [
        match.group(0)
        for rule, match in PARSER.match(content, route_for(path, content))
        if rule.rule_id == f"rule:{rule_id}"
    ]


@pytest.mark.parametrize(("path", "content", "rule_id"), CONTENT_CASES)
def test_fragment_routes_to_real_unmasked_extraction(tmp_path, path, content, rule_id):
    route = route_for(path, content)
    assert f"rule:{rule_id}" in route.matched_rule_ids
    result = PARSER.parse_file(tmp_path / path, data=content.encode("utf-8"), rule_route=route)
    assert result.error is None
    findings = [finding for finding in result.findings if finding.rule_id == f"rule:{rule_id}"]
    assert findings
    assert all(finding.value in content for finding in findings)
    assert all(finding.rule_pack_id == "manspider.default" for finding in findings)
    assert all(finding.rule_pack_version == "2.6.0" for finding in findings)


@pytest.mark.parametrize(("path", "content", "rule_id"), CONTENT_CASES)
def test_fragment_preserves_all_distinct_occurrences(path, content, rule_id):
    original = values(path, content, rule_id)
    assert original
    assert values(path, content + "\n" + content, rule_id) == original + original


@pytest.mark.parametrize(("path", "content", "rule_id"), NEGATIVE_CASES)
def test_fragment_rejects_public_metadata_placeholders_and_unowned_values(path, content, rule_id):
    assert not values(path, content, rule_id)


def test_every_new_rule_has_both_cases_and_a_primary_source():
    identifiers = {rule["id"] for rule in RULES}
    assert identifiers == {case[2] for case in CONTENT_CASES}
    assert identifiers <= {case[2] for case in NEGATIVE_CASES}
    assert identifiers == {source[0] for source in SOURCES}
    assert all(rule["severity"] != "critical" for rule in RULES)


@pytest.mark.parametrize(
    ("path", "content", "rule_id"),
    [
        ("users.ldf", "ms-Mcs-AdmPwd: " + "A" * 1024, "ad-legacy-laps-password"),
        ("users.ldf", "msDS-ManagedPassword:: " + "QUJD" * 16386, "ad-gmsa-managed-password-attribute"),
        ("users.ldf", "unicodePwd:: " + "QUJD" * 16386, "ad-directory-unicode-password-attribute"),
        (
            "users.ldf",
            'msLAPS-Password: {"p":"' + "A" * 1024 + '"}',
            "ad-laps-password-json",
        ),
        (
            "asrep.hash",
            "$krb5asrep$23$alice@EXAMPLE.TEST:" + "ab" * 16 + "$" + "ab" * 20480,
            "kerberos-asrep-hash",
        ),
        (
            "tickets.hashes",
            "$krb5tgs$18$alice$EXAMPLE.TEST$" + "ab" * 12 + "$" + "ab" * 20481,
            "kerberos-tgs-hash",
        ),
        (
            "credential.clixml",
            '<SS N="Password">' + "ab" * 65537 + "</SS>",
            "powershell-clixml-secure-string",
        ),
        (
            "users.ldf",
            "description: " + "A" * 1024 + " password=BeyondBoundFixture!",
            "ad-directory-credential-note",
        ),
    ],
)
def test_overlong_tokens_do_not_become_truncated_secret_findings(path, content, rule_id):
    assert not values(path, content, rule_id)


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("users.ldf", "A" * 1048576),
        ("users.ldf", ("msDS-ManagedPassword:: " + "QUJD" * 16386 + "!\n") * 16),
        (
            "laps.json",
            ("msLAPS-Password: {" + ",".join('"n":"' + "A" * 512 + '"' for _ in range(16)) + "}\n") * 128,
        ),
        ("users.ldf", ('description: "password=' + "A" * 128 + " " + "a " * 250 + "\n") * 1600),
        ("users.ldf", ("description: password=***; " * 42 + "\n") * 960),
        ("credential.clixml", ('<SS N="Password">' + "ab" * 65537 + "</SS>\n") * 8),
        (
            "tickets.hashes",
            ("$krb5tgs$18$alice$EXAMPLE.TEST$" + "ab" * 12 + "$" + "ab" * 20480 + "a\n") * 24,
        ),
    ],
)
def test_megabyte_adversarial_near_matches_do_not_produce_partial_evidence(path, content):
    # Deliberately no wall-clock assertion: the standalone review records
    # timings, while correctness must be stable on slower CI hosts as well.
    assert not list(PARSER.match(content, route_for(path, content)))


@pytest.mark.parametrize("path", ["SAM", "Windows/System32/config/SAM", "IFM/registry/SAM", "ntds"])
def test_bare_binary_hive_names_are_not_typed_text_dump_extensions(path):
    assert not route_for(path, "").content_rules


@pytest.mark.parametrize(
    "path", ["dump.sam", "dump.ntds", "dump.ntds.kerberos", "dump.ntds.cleartext", "dump.sam.bak"]
)
def test_named_text_dump_suffixes_remain_readable(path):
    assert route_for(path, "").content_rules


@pytest.mark.parametrize("backup", ["", ".bak.old", ".old.2", ".20260905", "~"])
@pytest.mark.parametrize(
    ("extension", "content", "rule_id"),
    [
        ("ldif", "ms-Mcs-AdmPwd: InspectorBackupFixture!", "active-directory-ldif-secrets"),
        ("ldf", "ms-Mcs-AdmPwd: InspectorBackupFixture!", "active-directory-ldif-secrets"),
        ("json", '{"ms-Mcs-AdmPwd":"InspectorBackupFixture!"}', "active-directory-json-secrets"),
        (
            "xml",
            f'<Groups><User><Properties cpassword="{GPP_CPASSWORD}" /></User></Groups>',
            "group-policy-preference-password",
        ),
    ],
)
def test_new_native_inspector_gates_preserve_real_backup_dispatch(tmp_path, backup, extension, content, rule_id):
    parser = FileParser([], quiet=True, rules=load_rule_files([FRAGMENT.with_name("rule-pack-2.6-ad-root.json")]))
    path = tmp_path / ("candidate." + extension + backup)
    route = parser.route_rules(
        {"filename": path.name, "path": str(path), "extension": "".join(path.suffixes), "size": len(content)}
    )
    assert f"rule:{rule_id}" in {inspector.rule_id for inspector in route.inspector_rules}
    result = parser.parse_file(path, data=content.encode("utf-8"), rule_route=route)
    assert result.error is None
    assert any(finding.rule_id == f"rule:{rule_id}" for finding in result.findings)
