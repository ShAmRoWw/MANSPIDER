"""Integrated default routing and extraction for the Russian coverage expansion."""

import json
from pathlib import PurePosixPath

import pytest

from man_spider.lib.parser import FileParser
from man_spider.rules import load_builtin_rules
from tests.rule_pack_2_7_ru_content_cases import CONTENT_CASES, NEGATIVE_CASES
from tests.rule_pack_2_7_ru_generic_cases import CONTENT_CASES as GENERIC_CASES
from tests.rule_pack_2_7_ru_metadata_cases import (
    METADATA_CASES,
    NEGATIVE_CASES as METADATA_NEGATIVE,
    TEXT_GATE_POSITIVE_CASES,
    TEXT_GATE_NEGATIVE_CASES,
)
from tests.rule_pack_2_7_ru_root_cases import STRUCTURED_INSPECTOR_CASES


RULES = load_builtin_rules()
PARSER = FileParser([], quiet=True, rules=RULES)


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


@pytest.mark.parametrize(("path", "content", "rule_id"), list(CONTENT_CASES) + list(GENERIC_CASES))
def test_default_rules_reach_real_unmasked_extraction(tmp_path, path, content, rule_id):
    if rule_id == "editor-session-binary-secret":
        # This representation is exercised separately by its binary fixtures.
        return
    data = content.encode()
    result = PARSER.parse_file(tmp_path / path, data=data, rule_route=route_for(path, data))
    assert result.error is None
    found = [f for f in result.findings if f.rule_id == "rule:" + rule_id]
    assert found
    assert all(f.value in content and f.rule_pack_version == "2.7.0" for f in found)


@pytest.mark.parametrize(("path", "content", "rule_id"), NEGATIVE_CASES)
def test_negative_assignments_remain_negative_in_merged_pack(path, content, rule_id):
    assert "rule:" + rule_id not in {r.rule_id for r, _ in PARSER.match(content, route_for(path))}


@pytest.mark.parametrize(("path", "rule_id"), METADATA_CASES)
@pytest.mark.parametrize("windows", [False, True])
def test_russian_metadata_both_path_styles(path, rule_id, windows):
    path = path.replace("/", "\\") if windows else path.replace("\\", "/")
    assert "rule:" + rule_id in route_for(path).metadata_rule_ids


@pytest.mark.parametrize(("path", "rule_id"), METADATA_NEGATIVE)
def test_russian_metadata_negative_ownership(path, rule_id):
    assert "rule:" + rule_id not in route_for(path).metadata_rule_ids


@pytest.mark.parametrize("filename", TEXT_GATE_POSITIVE_CASES)
def test_extensionless_russian_names_receive_general_secret_scan(tmp_path, filename):
    data = 'пароль="РусскийПароль!"\npassword="MixedРусский!"\nAKIAABCDEFGHIJKLMNOP\n'.encode()
    calls = []
    result = PARSER.parse_file(
        tmp_path / filename, data_loader=lambda: calls.append(1) or data, rule_route=route_for(filename, data)
    )
    assert calls == [1]
    assert result.error is None
    assert {"rule:russian-secret-assignment", "rule:assigned-secret", "rule:aws-access-key-id"} <= {
        f.rule_id for f in result.findings
    }


@pytest.mark.parametrize("filename", TEXT_GATE_NEGATIVE_CASES)
def test_russian_names_do_not_force_arbitrary_binary_reads(filename):
    route = route_for(filename)
    assert not route.content_rules
    assert not route.inspector_rules


@pytest.mark.parametrize(("path", "content", "rule_id"), STRUCTURED_INSPECTOR_CASES)
@pytest.mark.parametrize("backup", ["", ".bak", ".old.2", "~"])
def test_native_inspection_shared_read_and_provenance(tmp_path, path, content, rule_id, backup):
    data = content if isinstance(content, bytes) else content.encode()
    path += backup
    calls = []
    result = PARSER.parse_file(
        tmp_path / path, data_loader=lambda: calls.append(1) or data, rule_route=route_for(path, data)
    )
    assert calls == [1]
    assert result.error is None
    found = [f for f in result.findings if f.rule_id == "rule:" + rule_id]
    assert any(f.value == "СложныйРусскийПароль!" for f in found)
    assert all(f.representation == "inspect:" + rule_id and json.loads(f.context)["value_kind"] for f in found)


@pytest.mark.parametrize("label", ["пароль", "логин", "секрет", "токен", "ключ"])
def test_original_five_assignment_branches_keep_full_pairs(label):
    content = f'{label}="LegacyFixture!"'
    found = list(PARSER.match(content, route_for("notes.txt")))
    expected = "russian-access-identifier-assignment" if label in {"логин", "ключ"} else "russian-secret-assignment"
    assert any(rule.rule_id == "rule:" + expected and match.group() == content for rule, match in found)


def test_native_parse_error_keeps_independent_raw_findings(tmp_path):
    data = '{"Пароль":"Секрет!", "access":"AKIAABCDEFGHIJKLMNOP",'.encode()
    result = PARSER.parse_file(tmp_path / "broken.json", data=data, rule_route=route_for("broken.json", data))
    assert result.error and "russian-json-credential-value" in result.error
    assert "rule:aws-access-key-id" in {f.rule_id for f in result.findings}
    assert "rule:russian-json-credential-value" not in {f.rule_id for f in result.findings}


@pytest.mark.parametrize("suffix", [".py", ".sh", ".http", ".rest", ".json5", ".jsonc", ".ipynb", ".sublime_session", ".jaas", ".clixml"])
def test_legacy_codec_candidates_cover_known_plaintext_source_and_configuration(tmp_path, suffix):
    path = "параметры" + suffix
    data = 'Пароль="РусскийСекрет!"\n'.encode("cp1251")
    result = PARSER.parse_file(tmp_path / path, data=data, rule_route=route_for(path, data))
    assert result.error is None
    assert any(f.rule_id == "rule:russian-legacy-credential-value" and f.value == "РусскийСекрет!" for f in result.findings)


@pytest.mark.parametrize("suffix", [".pdf", ".rtf", ".doc", ".docx", ".xlsx", ".pptx", ".eml", ".msg", ".odt", ".ods", ".epub", ".ppt"])
def test_structured_container_bytes_are_not_treated_as_legacy_plaintext(suffix):
    assert "rule:russian-legacy-credential-value" not in {r.rule_id for r in route_for("параметры" + suffix).inspector_rules}
