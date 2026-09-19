"""Isolated routing/matching regression for the 2.7 generic Unicode overrides."""

import json
import multiprocessing
from pathlib import Path, PurePosixPath

import pytest

from man_spider.lib.parser import FileParser
from man_spider.rules import load_builtin_rules, load_rule_files
from tests.rule_pack_2_5_content_cases import CONTENT_CASES as PREVIOUS_CONTENT
from tests.rule_pack_2_5_content_cases import NEGATIVE_CASES as PREVIOUS_NEGATIVE
from tests.rule_pack_2_5_existing_cases import NEGATIVE_CASES as PREVIOUS_EXISTING_NEGATIVE
from tests.rule_pack_2_5_existing_cases import POSITIVE_CASES as PREVIOUS_EXISTING
from tests.rule_pack_2_7_ru_generic_cases import (
    CONTENT_CASES,
    NEGATIVE_CASES,
    PHRASE,
    UNCHANGED_UNICODE_CASES,
)
from tests.test_builtin_rule_pack import CONTENT_CASES as ORIGINAL_CONTENT
from tests.optional_fixtures import require_private_directory


require_private_directory("testdata", module=True)
FRAGMENT = Path(__file__).resolve().parents[1] / "testdata/rule-pack-2.7-ru-generic-overrides.json"
OVERRIDES = load_rule_files([FRAGMENT])
IDS = {rule["id"] for rule in OVERRIDES}
BASE = {rule["id"]: rule for rule in load_builtin_rules()}
MERGED = dict(BASE)
MERGED.update({rule["id"]: rule for rule in OVERRIDES})
PARSER = FileParser([], quiet=True, rules=list(MERGED.values()))
REGRESSION_POSITIVE = [case for case in (*ORIGINAL_CONTENT, *PREVIOUS_CONTENT, *PREVIOUS_EXISTING) if case[2] in IDS]
REGRESSION_NEGATIVE = [case for case in (*PREVIOUS_NEGATIVE, *PREVIOUS_EXISTING_NEGATIVE) if case[2] in IDS]


def route_for(path, content):
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


def matches(path, content, rule_id):
    representation = "strings" if rule_id == "editor-session-binary-secret" else "text"
    return [
        match
        for rule, match in PARSER.match(content, route_for(path, content), representation=representation)
        if rule.rule_id == f"rule:{rule_id}"
    ]


@pytest.mark.parametrize(("path", "content", "rule_id"), CONTENT_CASES + UNCHANGED_UNICODE_CASES)
def test_russian_secret_value_and_localized_context(path, content, rule_id):
    assert f"rule:{rule_id}" in route_for(path, content).matched_rule_ids
    found = matches(path, content, rule_id)
    assert found
    assert all(content[match.start():match.end()] == match.group(0) for match in found)


@pytest.mark.parametrize(("path", "content", "rule_id"), NEGATIVE_CASES + tuple(REGRESSION_NEGATIVE))
def test_public_labels_placeholders_and_cross_ownership_are_not_secrets(path, content, rule_id):
    assert not matches(path, content, rule_id)


@pytest.mark.parametrize(("path", "content", "rule_id"), REGRESSION_POSITIVE)
def test_preexisting_positive_coverage_survives_unicode_extension(path, content, rule_id):
    assert matches(path, content, rule_id)


@pytest.mark.parametrize(("path", "content", "rule_id"), CONTENT_CASES)
def test_all_occurrences_and_unmasked_source_spans_survive(path, content, rule_id):
    original = [match.group(0) for match in matches(path, content, rule_id)]
    doubled = [match.group(0) for match in matches(path, content + "\n" + content, rule_id)]
    assert original
    assert doubled == original + original


@pytest.mark.parametrize(("path", "content", "rule_id"), [case for case in CONTENT_CASES if case[2] != "editor-session-binary-secret"])
def test_text_extraction_uses_same_unmasked_values(tmp_path, path, content, rule_id):
    result = PARSER.parse_file(tmp_path / path, data=content.encode("utf-8"), rule_route=route_for(path, content))
    assert result.error is None
    actual = [finding.value for finding in result.findings if finding.rule_id == f"rule:{rule_id}"]
    assert actual == [match.group(0) for match in matches(path, content, rule_id)]


def test_quoted_connection_password_is_not_truncated_at_a_space_or_semicolon():
    content = f'connectionString = "Server=lab;Password=\'{PHRASE}\';"'
    assert PHRASE in matches("app.ini", content, "generic-connection-string-password")[0].group(0)


def test_fragment_changes_only_assigned_generic_rules_not_classification_or_gates():
    assert len(OVERRIDES) == 10
    assert not IDS.intersection(
        {
            "russian-credential-language-signal",
            "russian-cryptography-language-signal",
            "russian-data-connection-language-signal",
            "russian-secret-assignment",
            "ad-directory-credential-note",
        }
    )
    for rule in OVERRIDES:
        for field in ("severity", "confidence", "category", "tags"):
            assert rule[field] == BASE[rule["id"]][field]
        assert rule["rule_pack_version"] == "2.7.0"
    payload = json.loads(FRAGMENT.read_text(encoding="utf-8"))
    assert payload["pack"] == {"id": "manspider.default", "version": "2.7.0"}


@pytest.mark.parametrize(
    ("path", "content", "rule_id"),
    [
        ("app.txt", "AKIA" + "Я" * 16, "aws-access-key-id"),
        ("app.txt", "ghp_" + "Я" * 36, "github-access-token"),
        ("app.txt", "glpat-" + "Я" * 20, "gitlab-access-token"),
        ("app.txt", "AIza" + "Я" * 35, "google-api-key"),
        ("app.txt", "xoxb-" + "Я" * 32, "slack-access-token"),
        ("app.txt", "eyJ" + "Я" * 20 + ".eyJ" + "Я" * 20 + "." + "Я" * 20, "jwt-token"),
        ("app.txt", "Authorization: Bearer " + "Я" * 32, "http-bearer-authorization"),
        ("app.txt", "Authorization: Basic " + "Я" * 32, "http-basic-authorization"),
        ("app.conf", "PrivateKey = " + "Я" * 43 + "=", "wireguard-private-key"),
        ("app.txt", "-----НАЧАЛО ЗАКРЫТОГО КЛЮЧА-----", "private-key-block"),
        (".erlang.cookie", "ПарольКластера!", "erlang-cookie-value"),
    ],
)
def test_specified_token_hash_and_protocol_alphabets_are_not_translated(path, content, rule_id):
    assert not matches(path, content, rule_id)


def _adversarial_worker():
    parser = FileParser([], quiet=True, rules=OVERRIDES)
    corpus = (
        ('{"ключ":"Пароль","значение":' + '"' * 80 + "} " + "ПарольБД=" + "я" * 80 + "\n") * 4000
        + ("<учёт:Пароль>" + "я" * 256 + "</другой:Пароль>\n") * 2000
        + ("org.apache.kafka.common.security.plain.PlainLoginModule required " + 'user_Алиса="' + "я" * 128 + "\n") * 2000
    )
    assert len(corpus.encode("utf-8")) >= 1024 * 1024
    for rule in parser.rule_content_filters.values():
        for predicate in rule.predicates:
            tuple(predicate.expression.finditer(corpus))


def test_localized_regexes_have_bounded_adversarial_runtime():
    # A subprocess isolates runaway regressions; this is a generous safety cap,
    # not a hardware-sensitive performance claim or a network benchmark.
    # Structured extractors can already have native worker threads here; spawn
    # avoids inheriting their locks or thread state through fork().
    process = multiprocessing.get_context("spawn").Process(target=_adversarial_worker)
    process.start()
    process.join(timeout=15)
    if process.is_alive():
        process.terminate()
        process.join(timeout=2)
        pytest.fail("localized generic rules exceeded the bounded local near-miss budget")
    assert process.exitcode == 0
