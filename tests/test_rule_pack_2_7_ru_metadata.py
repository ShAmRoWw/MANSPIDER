"""Independent Russian metadata additions and monotonic legacy selection."""

import json
import re
from pathlib import Path, PurePosixPath

import pytest

from man_spider.lib.parser import FileParser
from man_spider.rules import BUILTIN_RULES_PATH, load_rule_files
from tests.optional_fixtures import require_private_directory
from tests.rule_pack_2_7_ru_metadata_cases import (
    EXTENSIONLESS_TEXT_FILENAME_PATTERNS,
    METADATA_CASES,
    NEGATIVE_CASES,
    TEXT_GATE_NEGATIVE_CASES,
    TEXT_GATE_POSITIVE_CASES,
)


require_private_directory("testdata", module=True)
FRAGMENT = Path(__file__).resolve().parents[1] / "testdata/rule-pack-2.7-ru-metadata-overrides.json"
RAW_RULES = json.loads(FRAGMENT.read_text())["rules"]
PARSER = FileParser([], quiet=True, rules=load_rule_files([FRAGMENT]))


def route(path):
    candidate = PurePosixPath(path.replace("\\", "/"))
    return PARSER.route_rules(
        {
            "share": "Общие документы",
            "path": path,
            "filename": candidate.name,
            "directory": str(candidate.parent),
            "extension": "".join(candidate.suffixes).lower(),
            "size": 1024,
        }
    )


@pytest.mark.parametrize(("path", "rule_id"), METADATA_CASES)
@pytest.mark.parametrize("windows", [False, True])
def test_russian_candidates_route_both_path_styles(path, rule_id, windows):
    path = path.replace("/", "\\") if windows else path.replace("\\", "/")
    result = route(path)
    assert f"rule:{rule_id}" in result.metadata_rule_ids
    assert not result.requires_content


@pytest.mark.parametrize(("path", "rule_id"), NEGATIVE_CASES)
def test_near_misses_do_not_make_specific_credential_candidates(path, rule_id):
    assert f"rule:{rule_id}" not in route(path).metadata_rule_ids


@pytest.mark.parametrize("filename", TEXT_GATE_POSITIVE_CASES)
def test_targeted_text_gate_accepts_extensionless_aliases(filename):
    assert any(re.search(pattern, filename, re.IGNORECASE) for pattern in EXTENSIONLESS_TEXT_FILENAME_PATTERNS)


@pytest.mark.parametrize("filename", TEXT_GATE_NEGATIVE_CASES)
def test_targeted_text_gate_does_not_treat_arbitrary_binary_suffixes_as_extensionless(filename):
    assert not any(re.search(pattern, filename, re.IGNORECASE) for pattern in EXTENSIONLESS_TEXT_FILENAME_PATTERNS)


def test_all_overrides_are_report_only_and_preserve_every_existing_predicate_and_exclude():
    baseline = {rule["id"]: rule for rule in json.loads(BUILTIN_RULES_PATH.read_text())["rules"]}
    assert len(RAW_RULES) == len({rule["id"] for rule in RAW_RULES}) == 8
    for rule in RAW_RULES:
        original = baseline[rule["id"]]
        assert rule["actions"] == original["actions"] == [{"type": "report"}]
        assert rule["match"]["condition"] == original["match"]["condition"] == "any"
        assert all(predicate in rule["match"]["predicates"] for predicate in original["match"]["predicates"])
        assert rule.get("exclude") == original.get("exclude")
        assert (rule["severity"], rule["confidence"]) == (original["severity"], original["confidence"])
    assert {rule["id"] for rule in RAW_RULES} == {rule_id for _, rule_id in METADATA_CASES}
    assert {rule["id"] for rule in RAW_RULES} <= {rule_id for _, rule_id in NEGATIVE_CASES}


def test_long_or_multiline_human_label_is_not_a_truncated_configuration_name():
    for name in ("пароли_" + "я" * 1024, "пароли\nсерверов", "учётные_данные\n_серверов"):
        assert "rule:sensitive-configuration-file" not in route(name).metadata_rule_ids
