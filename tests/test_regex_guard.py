"""Negative guards must never suppress original regex evidence or diagnostics."""

import importlib
import itertools
import pickle
import random
import re
from dataclasses import replace

import pytest

from man_spider.lib.parser import FileParser
from man_spider.lib.parser.parser import ContentPredicate, ContentRule
from man_spider.lib.parser.regex_guard import build_regex_guard
from man_spider.rules import load_builtin_rules
from tests.test_builtin_rule_pack import CONTENT_CASES, LEGACY_CONTENT_CASES
from tests.rule_pack_2_7_ru_content_cases import CONTENT_CASES as RU_CASES, NEGATIVE_CASES as RU_NEGATIVE


guard_module = importlib.import_module("man_spider.lib.parser.regex_guard")


def original_evidence(rule, content):
    evaluated = []
    for predicate in rule.predicates:
        matches = tuple(predicate.expression.finditer(content))
        satisfied = not matches if predicate.negate else bool(matches)
        evaluated.append((predicate, matches, satisfied))
    matched = any(item[2] for item in evaluated) if rule.condition == "any" else all(item[2] for item in evaluated)
    if not matched:
        return ()
    return tuple(
        (predicate, match)
        for predicate, matches, satisfied in evaluated
        if satisfied
        for match in ((None,) if predicate.negate else matches)
    )


def evidence(items):
    return [(predicate.value, None if match is None else (match.span(), match.group(0))) for predicate, match in items]


@pytest.mark.parametrize("pattern,flags,absent,present", [
    (r"(?<!\w)(?:AKIA|ASIA)[A-Z0-9]{16}", 0, "ordinary notes", "AKIA" + "A" * 16),
    (r"\bпароль\w*", re.I, "ordinary notes", "ПАРОЛЬ_БД"),
    (r"(?i:password)=(?-i:Secret)", 0, "password=secret", "PASSWORD=Secret"),
    (r"(?=TOKEN)\w+", 0, "ordinary notes", "TOKEN"),
    (r"(?<=TOKEN)\w+", 0, "ordinary notes", "TOKENvalue"),
    (r"(?:one|two){2,3}", 0, "ordinary notes", "onetwo"),
    (r"[Ж-Я]+", re.I, "ordinary notes", "жюя"),
    (r"[\u0400\u0410]+", re.I, "ordinary notes", "ѐа"),
])
def test_guard_only_rejects_impossible_input(pattern, flags, absent, present):
    expression = re.compile(pattern, flags)
    guard = build_regex_guard(expression)
    assert guard is not None
    assert expression.search(absent) is None
    assert expression.search(present) is not None
    assert not guard.impossible(present)
    # PIN alternative or ignorecase-only short expressions may deliberately
    # have no restrictive literal guard, but must never lose the match.


@pytest.mark.parametrize("pattern,content", [
    ("(?i)İ", "i"), ("(?i)ı", "I"), ("(?i)ſ", "s"), ("(?i)K", "K"),
    ("(?i:[İ-ı])", "i"), ("(?i:[ſ])", "S"), ("(?i:[K])", "k"),
    ("(?i)пароль|PIN", "PIN"), ("(?i:пароль)?PIN", "PIN"),
    ("(?i:пароль)*PIN", "PIN"), ("(?i:пароль){0,2}PIN", "PIN"),
    ("(?!(?:пароль))PIN", "PIN"), ("(?<!пароль)PIN", "PIN"),
    ("(?i:пароль)|", ""), ("(?:(?i:пароль)|)PIN", "PIN"),
    (r"(?P<key>\w+)(?P=key)", "token token".replace(" ", "")),
    (r"(a)?(?(1)пароль|PIN)", "PIN"),
    (r"(?a:(?i:K))|PIN", "PIN"),
    (r"(?x) TOKEN \# value # a Cyrillic comment: пароль", "TOKEN#value"),
    (r"[^\u0400-\u052f]+", "ASCII"),
])
def test_optional_branches_casefold_references_and_comments_do_not_lose_matches(pattern, content):
    expression = re.compile(pattern)
    assert expression.search(content) is not None
    guard = build_regex_guard(expression)
    assert guard is None or not guard.impossible(content)


def test_guard_falls_back_when_private_parser_is_unavailable_or_fails(monkeypatch):
    expression = re.compile("(?<!x)TOKEN")
    monkeypatch.setattr(guard_module, "_regex_parser", None)
    assert build_regex_guard(expression) is None
    monkeypatch.setattr(guard_module, "_regex_parser", type("Broken", (), {"parse": lambda *args: 1 / 0})())
    assert build_regex_guard(expression) is None


def test_guard_budgets_and_bytes_patterns_fall_back():
    assert build_regex_guard(re.compile(b"TOKEN")) is None
    assert build_regex_guard(re.compile("x" * (guard_module._MAX_PATTERN_LENGTH + 1))) is None
    assert build_regex_guard(re.compile("x" * (guard_module._MAX_NODES + 1))) is None
    guard = build_regex_guard(re.compile("x" * 500))
    assert guard is not None
    assert max(map(len, guard.alternatives)) <= guard_module._MAX_LITERAL_LENGTH
    assert not guard.impossible("x" * 500)


@pytest.mark.parametrize("condition", ["all", "any"])
@pytest.mark.parametrize("negations", tuple(itertools.product((False, True), repeat=3)))
def test_all_any_negation_preserves_every_predicate_and_empty_evidence(condition, negations):
    patterns = ("TOKEN", "(?i:пароль)", "(?i:PIN)")
    rule = ContentRule("custom", tuple(
        ContentPredicate("regex", pattern, negate, re.compile(pattern))
        for pattern, negate in zip(patterns, negations)
    ), condition=condition)
    for content in ("", "plain", "TOKEN TOKEN", "пароль", "PIN", "TOKEN ПАРОЛЬ PIN TOKEN"):
        assert evidence(FileParser._evaluate_content_rule(rule, content)) == evidence(original_evidence(rule, content))


def test_guard_is_rebuilt_for_custom_override_and_survives_pickle():
    first = ContentPredicate("regex", "TOKEN", False, re.compile("TOKEN"))
    second = replace(first, value="OTHER", expression=re.compile("OTHER"))
    assert first.guard != second.guard
    assert not second.guard.impossible("OTHER")
    assert pickle.loads(pickle.dumps(second)) == second
    parser = FileParser(["(?-i:TOKEN)"], quiet=True, blocked_extensions=[])
    restored = pickle.loads(pickle.dumps(parser))
    assert [(rule.rule_id, match.span()) for rule, match in restored.match("TOKEN TOKEN")] == [
        (rule.rule_id, match.span()) for rule, match in parser.match("TOKEN TOKEN")
    ]


def test_generic_guard_does_not_depend_on_rule_id():
    rules = [
        {"id": "aws-access-key-id", "pattern": "UNRELATED", "flags": []},
        {"id": "russian-secret-assignment", "pattern": "ASCII_VALUE", "flags": []},
    ]
    parser = FileParser([], quiet=True, blocked_extensions=[], rules=rules)
    assert {rule.rule_id for rule, _match in parser.match("UNRELATED ASCII_VALUE")} == {
        "rule:aws-access-key-id", "rule:russian-secret-assignment",
    }


def test_parser_factored_branch_prefix_retains_useful_negative_guard():
    expression = re.compile(r"(?:(?<!\w)(?:gh[opusr]_[A-Za-z0-9]{36}|github_pat_\w{20})|ghp_\w{36})")
    guard = build_regex_guard(expression)
    assert guard is not None
    assert guard.impossible("ordinary notes")
    for content in ("ghp_" + "A" * 36, "gho_" + "B" * 36, "github_pat_" + "C" * 20):
        assert expression.search(content) is not None
        assert not guard.impossible(content)


@pytest.mark.parametrize("pattern,content", [
    ("gh(?:|ithub)", "gh"), ("g(?:h|ithub)", "gh"), ("g(?:h(?:x|)|ithub)", "gh"),
    ("g(?:(?=h)h|ithub)", "gh"), ("(?i:g)(?-i:h|ithub)", "Gh"),
    ("g(?i:h|ithub)", "gH"), ("g(?:Ж|PIN)", "gPIN"),
])
def test_factored_prefix_with_optional_asserted_and_scoped_alternatives(pattern, content):
    expression = re.compile(pattern)
    assert expression.search(content)
    guard = build_regex_guard(expression)
    assert guard is None or not guard.impossible(content)


def test_str_subclass_overrides_cannot_hide_underlying_regex_matches():
    class UnusualText(str):
        def isascii(self):
            return True

        def __contains__(self, other):
            return False

    content = UnusualText("TOKEN пароль TOKEN")
    for pattern in ("TOKEN", "(?i:пароль)"):
        rule = ContentRule("custom", (ContentPredicate("regex", pattern, False, re.compile(pattern)),))
        assert evidence(FileParser._evaluate_content_rule(rule, content)) == evidence(original_evidence(rule, content))


def test_empty_branch_and_depth_work_budgets_fall_back(monkeypatch):
    expression = re.compile("(?:" + "|" * 30 + ")TOKEN")
    monkeypatch.setattr(guard_module, "_MAX_NODES", 10)
    assert build_regex_guard(expression) is None
    monkeypatch.setattr(guard_module, "_MAX_NODES", 4096)
    monkeypatch.setattr(guard_module, "_MAX_DEPTH", 2)
    assert build_regex_guard(re.compile("(?=(?=(?=TOKEN)))TOKEN")) is None


@pytest.mark.parametrize("pattern,content", [
    ("(?>gh|github)_TOKEN", "gh_TOKEN"), ("(?:TOKEN)++", "TOKEN"),
    ("(?:пароль)*+PIN", "PIN"), ("(?>пароль|PIN)", "PIN"),
])
def test_atomic_and_possessive_syntax_uses_conservative_conditions(pattern, content):
    import sys

    if sys.version_info < (3, 11):
        pytest.skip("atomic groups and possessive quantifiers require Python 3.11")
    expression = re.compile(pattern)
    assert expression.search(content)
    guard = build_regex_guard(expression)
    assert guard is None or not guard.impossible(content)


def test_builtin_and_legacy_corpus_has_exact_original_predicate_evidence():
    parser = FileParser([], quiet=True, blocked_extensions=[], rules=load_builtin_rules())
    rules = {rule.rule_id.removeprefix("rule:"): rule for rule in parser.content_filters}
    cases = (*CONTENT_CASES, *LEGACY_CONTENT_CASES, *RU_CASES, *RU_NEGATIVE)
    for _path, content, rule_id in cases:
        # Some legacy fixtures refer to detectors under another canonical ID;
        # exercise every content predicate to retain overlapping evidence too.
        for rule in rules.values():
            assert evidence(parser._evaluate_content_rule(rule, content)) == evidence(original_evidence(rule, content)), (
                rule.rule_id, rule_id, content,
            )


def test_generated_regex_grammar_and_unicode_inputs_have_no_false_negative_guard():
    randomizer = random.Random(20260906)
    atoms = ("AB", "TOKEN", "пароль", "[А-Я]", "(?i:İ)", "(?i:пароль)", ".", r"\w", r"\b", "")
    patterns = set(atoms)
    for _ in range(160):
        first, second = randomizer.choices(atoms, k=2)
        patterns.update((f"(?:{first}|{second})", f"(?:{first})?(?:{second})", f"(?:{first})+(?:{second})"))
    inputs = ["", "TOKEN", "AB", "пароль", "ПАРОЛЬ", "i", "I", "İ", "ı", "ſ", "S", "K", "K", "\n"]
    inputs.extend("".join(randomizer.choices(inputs[:13], k=5)) for _ in range(80))
    for pattern in patterns:
        expression = re.compile(pattern)
        guard = build_regex_guard(expression)
        if guard is None:
            continue
        for content in inputs:
            if expression.search(content) is not None:
                assert not guard.impossible(content), (pattern, content, guard)
