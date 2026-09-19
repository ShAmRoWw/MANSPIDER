"""Builtin AD integration: routing, real extraction, and explicit evidence limits."""

import json
from pathlib import Path, PurePosixPath

import pytest

from man_spider.lib.parser import FileParser
from man_spider.rules import load_builtin_rules
from tests.rule_pack_2_6_ad_content_cases import CONTENT_CASES, NEGATIVE_CASES
from tests.rule_pack_2_6_ad_metadata_cases import METADATA_CASES
from tests.rule_pack_2_6_ad_metadata_cases import NEGATIVE_CASES as METADATA_NEGATIVE_CASES
from tests.rule_pack_2_6_ad_structured_cases import STRUCTURED_INSPECTOR_CASES as AD_CASES
from tests.rule_pack_2_6_gpp_cases import STRUCTURED_INSPECTOR_CASES as GPP_CASES
from tests.optional_fixtures import require_private_directory


RULES = load_builtin_rules()
PARSER = FileParser([], quiet=True, rules=RULES)
STRUCTURED_CASES = list(AD_CASES) + list(GPP_CASES)


def route_for(path, data=b""):
    candidate = PurePosixPath(path.replace("\\", "/"))
    return PARSER.route_rules(
        {
            "share": "Fixtures",
            "directory": str(candidate.parent),
            "path": path,
            "filename": candidate.name,
            "extension": "".join(candidate.suffixes).lower(),
            "size": len(data),
            "mtime": 0,
        }
    )


@pytest.mark.parametrize(("path", "content", "rule_id"), CONTENT_CASES)
def test_builtin_content_matrix_reaches_real_unmasked_extraction(tmp_path, path, content, rule_id):
    data = content.encode("utf-8")
    result = PARSER.parse_file(tmp_path / path, data=data, rule_route=route_for(path, data))
    assert result.error is None
    found = [f for f in result.findings if f.rule_id == f"rule:{rule_id}"]
    assert found
    assert all(f.value in content and f.rule_pack_version == "2.7.0" for f in found)


@pytest.mark.parametrize(("path", "content", "rule_id"), NEGATIVE_CASES)
def test_builtin_content_negative_matrix_preserves_detector_ownership(path, content, rule_id):
    assert f"rule:{rule_id}" not in {r.rule_id for r, _ in PARSER.match(content, route_for(path))}


@pytest.mark.parametrize(("path", "rule_id"), METADATA_CASES)
@pytest.mark.parametrize("windows", [False, True])
def test_ad_metadata_routes_both_path_styles(path, rule_id, windows):
    path = path.replace("/", "\\") if windows else path.replace("\\", "/")
    assert f"rule:{rule_id}" in route_for(path).metadata_rule_ids


@pytest.mark.parametrize(("path", "rule_id"), METADATA_NEGATIVE_CASES)
def test_ad_metadata_near_misses_are_not_secret_proof(path, rule_id):
    assert f"rule:{rule_id}" not in route_for(path).metadata_rule_ids


@pytest.mark.parametrize("share", ["NETLOGON", "SYSVOL", "netlogon"])
@pytest.mark.parametrize("filename", ["MapDrives.cmd", "Install.ps1.bak", "psscripts.ini", "Legacy.jse"])
def test_smb_domain_scripts_use_separate_share_field(share, filename):
    # Real SMB metadata is share-relative; it does not include an UNC prefix.
    route = PARSER.route_rules({"share": share, "path": "\\setup\\" + filename, "filename": filename})
    assert "rule:domain-policy-script-file" in route.metadata_rule_ids


@pytest.mark.parametrize(
    ("share", "filename"),
    [
        ("Public", "MapDrives.cmd"),
        ("MYNETLOGON", "Install.ps1"),
        ("NETLOGON", "guide.pdf"),
        ("SYSVOL", "logo.png"),
        ("SYSVOL", "ordinary.ini"),
    ],
)
def test_share_routing_does_not_classify_every_domain_share_file_as_script(share, filename):
    route = PARSER.route_rules({"share": share, "path": "\\setup\\" + filename, "filename": filename})
    assert "rule:domain-policy-script-file" not in route.metadata_rule_ids


@pytest.mark.parametrize(("path", "content", "rule_id"), STRUCTURED_CASES)
@pytest.mark.parametrize("backup", ["", ".bak", ".old.2", "~"])
def test_native_inspections_share_one_read_and_keep_full_provenance(tmp_path, path, content, rule_id, backup):
    # Strip fixture backup first so the tested chain stays within two layers.
    for suffix in (".bak", ".old"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
    path += backup
    data = content.encode("utf-8")
    calls = []
    result = PARSER.parse_file(
        tmp_path / path,
        rule_route=route_for(path, data),
        data_loader=lambda: calls.append(True) or data,
    )
    assert calls == [True]
    assert result.error is None
    found = [f for f in result.findings if f.rule_id == f"rule:{rule_id}"]
    assert found
    assert all(f.representation == f"inspect:{rule_id}" for f in found)
    assert all(f.rule_pack_version == "2.7.0" for f in found)
    assert all(json.loads(f.context)["value_kind"] for f in found)


@pytest.mark.parametrize("path", ["credential.clixml", "etc/samba/smbpasswd", "smbpasswd.bak"])
def test_shared_gate_additions_preserve_general_secret_search(tmp_path, path):
    data = b"password=SharedAdFixture!\nAKIAABCDEFGHIJKLMNOP\n"
    result = PARSER.parse_file(tmp_path / path, data=data, rule_route=route_for(path, data))
    assert result.error is None
    assert {"rule:assigned-secret", "rule:aws-access-key-id"} <= {f.rule_id for f in result.findings}


def test_ldf_is_only_added_to_ad_specific_read_gates():
    route = route_for("export.ldf")
    assert "rule:active-directory-ldif-secrets" in {r.rule_id for r in route.inspector_rules}
    assert "rule:assigned-secret" not in {r.rule_id for r in route.content_rules}
    assert "rule:aws-access-key-id" not in {r.rule_id for r in route.content_rules}
    assert route.content_rules  # AD lexical candidates still inspect decoded text.


@pytest.mark.parametrize(
    "path",
    [
        "Windows/System32/config/SAM",
        "Windows/System32/config/SYSTEM",
        "Windows/System32/config/SECURITY",
        "SAM",
        "Windows/System32/config/SAM.hiv",
        "IFM/Active Directory/ntds.dit",
        "var/lib/samba/private/sam.ldb",
        "var/lib/samba/private/secrets.tdb",
        "var/lib/samba/private/passdb.tdb",
        "Windows/System32/CertLog/Example CA.edb",
        "ProgramData/Microsoft/Crypto/RSA/MachineKeys/container-id",
        "tickets/admin.kirbi",
        "startup.bek",
        "recovery.kpg",
        "Windows/System32/GroupPolicy/Machine/Registry.pol",
    ],
)
def test_new_opaque_artifacts_are_metadata_candidates_without_forced_reads(path):
    route = route_for(path)
    assert route.metadata_rule_ids
    assert not route.content_rules
    assert not route.inspector_rules


def test_fragment_inventory_is_exactly_present_and_predecessor_ids_are_retained():
    require_private_directory("testdata")
    root = Path(__file__).resolve().parents[1]
    current = {rule["id"]: rule for rule in RULES}
    new_ids = set()
    for name in ("metadata", "content", "root"):
        fragment = json.loads((root / f"testdata/rule-pack-2.6-ad-{name}.json").read_text())
        for rule in fragment["rules"]:
            assert rule["id"] in current
            assert current[rule["id"]]["category"] == rule["category"]
            new_ids.add(rule["id"])
    assert len(new_ids) == 39
    later_ids = {"russian-access-identifier-assignment", "russian-json-credential-value", "russian-legacy-credential-value"}
    assert later_ids <= current.keys()
    assert len(current.keys() - new_ids - later_ids) == 209
    assert all(current[rule_id]["severity"] != "critical" for rule_id in new_ids)
