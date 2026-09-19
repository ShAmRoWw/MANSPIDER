"""Standalone Russian rule overrides: evidence, ownership, legacy and bounds."""

import re
from pathlib import Path, PurePosixPath

import pytest

from man_spider.lib.parser import FileParser
from man_spider.rules import load_rule_files
from tests.rule_pack_2_6_ad_content_cases import CONTENT_CASES as AD_LEGACY_POSITIVE
from tests.rule_pack_2_6_ad_content_cases import NEGATIVE_CASES as AD_LEGACY_NEGATIVE
from tests.rule_pack_2_7_ru_content_cases import (
    CONTENT_CASES,
    IDENTIFIER_LABEL_PATTERN,
    NEGATIVE_CASES,
    STRICT_SECRET_LABEL_PATTERN,
)
from tests.test_builtin_rule_pack import LEGACY_CONTENT_CASES
from tests.optional_fixtures import require_private_directory


require_private_directory("testdata", module=True)
ROOT = Path(__file__).resolve().parents[1]
RULES = load_rule_files(
    [ROOT / "testdata/rule-pack-2.7-ru-content-overrides.json", ROOT / "testdata/rule-pack-2.7-ru-content.json"]
)
PARSER = FileParser([], quiet=True, rules=RULES)
IDS = {rule["id"] for rule in RULES}
AD_NOTE = "ad-directory-credential-note"
LEGACY_POSITIVE = [case for case in AD_LEGACY_POSITIVE if case[2] == AD_NOTE]
LEGACY_NEGATIVE = [case for case in AD_LEGACY_NEGATIVE if case[2] == AD_NOTE]
LEGACY_POSITIVE += [("legacy.txt", value, rule_id) for _, value, rule_id in LEGACY_CONTENT_CASES if rule_id in IDS]


def route_for(path, content):
    candidate = PurePosixPath(path.replace("\\", "/"))
    return PARSER.route_rules(
        {
            "path": path,
            "filename": candidate.name,
            "directory": str(candidate.parent),
            "extension": "".join(candidate.suffixes),
            "size": len(content.encode("utf-8")),
        }
    )


def values(path, content, rule_id):
    return [
        match.group(0)
        for rule, match in PARSER.match(content, route_for(path, content))
        if rule.rule_id == f"rule:{rule_id}"
    ]


@pytest.mark.parametrize(("path", "content", "rule_id"), CONTENT_CASES + LEGACY_POSITIVE)
def test_positive_cases_reach_unmasked_real_extraction(tmp_path, path, content, rule_id):
    route = route_for(path, content)
    assert f"rule:{rule_id}" in route.matched_rule_ids
    result = PARSER.parse_file(tmp_path / path, data=content.encode("utf-8"), rule_route=route)
    assert result.error is None
    findings = [finding for finding in result.findings if finding.rule_id == f"rule:{rule_id}"]
    assert findings
    assert all(finding.value in content for finding in findings)
    assert all(finding.rule_pack_version == "2.7.0" for finding in findings)


@pytest.mark.parametrize(("path", "content", "rule_id"), NEGATIVE_CASES + LEGACY_NEGATIVE)
def test_public_placeholders_and_unowned_fields_do_not_become_secret_findings(path, content, rule_id):
    assert not values(path, content, rule_id)


@pytest.mark.parametrize(("path", "content", "rule_id"), CONTENT_CASES)
def test_every_occurrence_is_retained_in_source_order(path, content, rule_id):
    original = values(path, content, rule_id)
    assert original
    assert values(path, content + "\n" + content, rule_id) == original + original


@pytest.mark.parametrize(
    ("path", "content", "rule_id"),
    [
        case
        for case in CONTENT_CASES
        if case[2] == "russian-secret-assignment" and not case[1].startswith("{") and not case[1].endswith(".")
    ],
)
def test_literal_spaces_and_punctuation_are_not_truncated(path, content, rule_id):
    assert values(path, content, rule_id) == [content]


@pytest.mark.parametrize("label", ["пароль", "логин", "секрет", "токен", "ключ"])
def test_complete_legacy_assignment_pairs_remain_visible_with_correct_classification(label):
    source = f'{label}="LegacyРусскийFixture!"'
    findings = list(PARSER.match(source, route_for("legacy.txt", source)))
    assert any("LegacyРусскийFixture!" in match.group(0) for _, match in findings)
    expected = "russian-access-identifier-assignment" if label in {"логин", "ключ"} else "russian-secret-assignment"
    assert values("legacy.txt", source, expected) == [source]
    if label in {"логин", "ключ"}:
        assert not values("legacy.txt", source, "russian-secret-assignment")


@pytest.mark.parametrize(
    "label",
    [
        "ПарольАдминистратора",
        "пароль_БД",
        "DB_пароль",
        "пароль учётной записи",
        "пароль учетной записи",
        "API-ключ",
        "токен доступа",
        "парольная фраза",
        "Пароль к серверу",
        "код восстановления",
    ],
)
def test_exported_strict_native_aliases_match_complete_names(label):
    assert re.fullmatch(STRICT_SECRET_LABEL_PATTERN, label, re.IGNORECASE)


@pytest.mark.parametrize(
    "label", ["логин", "имя пользователя", "ключ", "публичный ключ", "ID_токен", "политика_пароль", "ДлинаПароля"]
)
def test_exported_strict_aliases_do_not_promote_identifiers_or_policy_fields(label):
    assert not re.fullmatch(STRICT_SECRET_LABEL_PATTERN, label, re.IGNORECASE)
    if label in {"логин", "имя пользователя", "ключ"}:
        assert re.fullmatch(IDENTIFIER_LABEL_PATTERN, label, re.IGNORECASE)


def test_review_signal_classification_remains_explicit():
    by_id = {rule["id"]: rule for rule in RULES}
    for rule_id in IDS - {"russian-secret-assignment", AD_NOTE}:
        assert by_id[rule_id]["severity"] in {"info", "low"}
        assert by_id[rule_id]["confidence"] == "low"
    assert by_id[AD_NOTE]["confidence"] == "low"


@pytest.mark.parametrize(
    ("content", "rule_id"),
    [
        ('Пароль="' + "А" * 513 + '"', "russian-secret-assignment"),
        ("Пароль=" + "А" * 513, "russian-secret-assignment"),
        ("парол" + "ь" * 97, "russian-credential-language-signal"),
        ("логин" + "а" * 65, "russian-credential-language-signal"),
        ("строка" + " " * 1000 + "подключения", "russian-data-connection-language-signal"),
        ("закрытый" + " " * 1000 + "ключ", "russian-cryptography-language-signal"),
        ("Пароль: " + " " * 1000 + "НеДолженДостигаться!", "russian-secret-assignment"),
    ],
)
def test_bounds_do_not_create_truncated_or_far_borrowed_values(content, rule_id):
    assert not values("пользователи.txt", content, rule_id)
