"""Offline evidence-preservation tests for console-only same-line grouping."""

from dataclasses import asdict, replace

import pytest

from man_spider.lib.finding_log import grouped_console_overrides
from man_spider.lib.parser import FileParser
from man_spider.state import FindingRecord


LOCATION = r"\\server\share\folder\config.ini"


def finding(context="before SECRET after", value="SECRET", *, rule="rule:password", line_start=100, **changes):
    offset = context.index(value) if value else 0
    fields = {
        "rule_id": rule,
        "value": value,
        "start": line_start + offset,
        "end": line_start + offset + len(value),
        "context": context,
        "context_offset": offset,
        "representation": "text",
        "severity": "high",
        "confidence": "medium",
    }
    fields.update(changes)
    return FindingRecord(**fields)


def grouped(records, *, leader=0, show_context=True, location=LOCATION):
    overrides = grouped_console_overrides(location, records, show_context=show_context)
    assert set(overrides) == set(range(len(records)))
    assert all(overrides[index] is None for index in overrides if index != leader)
    message, highlights, severity = overrides[leader]
    assert all(0 <= start < end <= len(message) for start, end, _ in highlights)
    assert all(highlights[index][1] <= highlights[index + 1][0] for index in range(len(highlights) - 1))
    assert highlights[0][2] == "severity"
    assert message[highlights[0][0] : highlights[0][1]] == severity
    assert all(role == "match" for _, _, role in highlights[1:])
    return message, highlights, severity


def match_parts(message, highlights):
    return [message[start:end] for start, end, role in highlights if role == "match"]


def test_same_line_three_rules_show_only_most_severe_and_sorted_other_names():
    records = (
        finding(rule="rule:z-keyword", severity="low", confidence="high"),
        finding(rule="rule:primary", severity="critical", confidence="low"),
        finding(rule="rule:a-candidate", severity="high", confidence="high"),
    )
    original = [asdict(item) for item in records]

    message, highlights, severity = grouped(records, leader=1)

    assert message == (
        LOCATION + ': rule="rule:primary"; severity=critical; confidence=low; '
        "match=before SECRET after (ещё 2 правила: rule:a-candidate, rule:z-keyword)"
    )
    assert severity == "critical"
    assert match_parts(message, highlights) == ["SECRET"]
    assert [asdict(item) for item in records] == original


@pytest.mark.parametrize(
    ("first", "second", "leader"),
    [
        ({"severity": "info"}, {"severity": "low"}, 1),
        ({"severity": "low"}, {"severity": "medium"}, 1),
        ({"severity": "medium"}, {"severity": "high"}, 1),
        ({"severity": "high"}, {"severity": "critical"}, 1),
        ({"severity": "critical", "confidence": "low"}, {"severity": "high", "confidence": "high"}, 0),
        ({"confidence": "low"}, {"confidence": "medium"}, 1),
        ({"confidence": "medium"}, {"confidence": "high"}, 1),
        ({"rule": "rule:z"}, {"rule": "rule:a"}, 1),
        ({"rule": "rule:same"}, {"rule": "rule:same"}, 0),
    ],
)
def test_leader_order_is_severity_then_confidence_then_name_then_first_occurrence(first, second, leader):
    records = (finding(**first), finding(**second))

    message, _, severity = grouped(records, leader=leader)

    assert f'rule="{records[leader].rule_id}";' in message
    assert f"confidence={records[leader].confidence};" in message
    assert severity == records[leader].severity


def test_identical_text_at_different_file_offsets_is_not_grouped():
    records = (finding(line_start=10), finding(rule="rule:other", line_start=100))

    assert grouped_console_overrides(LOCATION, records) == {}


def test_mixed_groups_keep_distinct_identical_lines_and_singletons():
    records = (
        finding(line_start=10, rule="rule:a"),
        finding(line_start=100, rule="rule:c"),
        finding(line_start=10, rule="rule:b"),
        finding(line_start=100, rule="rule:d"),
        finding(line_start=200, rule="rule:e"),
    )

    overrides = grouped_console_overrides(LOCATION, records)

    assert set(overrides) == {0, 1, 2, 3}
    assert overrides[0] is not None and overrides[1] is not None
    assert overrides[2] is None and overrides[3] is None
    assert "rule:b" in overrides[0][0] and "rule:d" not in overrides[0][0]
    assert "rule:d" in overrides[1][0] and "rule:b" not in overrides[1][0]


@pytest.mark.parametrize("representation", ["raw", "strings", "ocr", "structured"])
def test_same_text_and_offsets_in_different_representations_remain_separate(representation):
    records = (finding(), finding(rule="rule:other", representation=representation))

    assert grouped_console_overrides(LOCATION, records) == {}


@pytest.mark.parametrize("representation", ["text", "raw", "strings", "ocr", "structured"])
def test_literal_single_line_evidence_can_group_within_every_supported_representation(representation):
    records = (
        finding(rule="rule:a", representation=representation),
        finding(rule="rule:b", representation=representation),
    )

    message, highlights, _ = grouped(records)

    assert match_parts(message, highlights) == ["SECRET"]
    assert message.endswith(" (ещё 1 правило: rule:b)")


def test_different_context_at_same_inferred_line_start_is_not_grouped():
    records = (finding(), finding("before SECRET changed", rule="rule:other"))

    assert grouped_console_overrides(LOCATION, records) == {}


def test_conflicting_equal_length_context_prevents_whole_candidate_bucket_grouping():
    records = (
        finding(rule="rule:a"),
        finding(rule="rule:b"),
        finding("before SECRET other", rule="rule:c"),
    )

    assert len(records[0].context) == len(records[2].context)
    assert grouped_console_overrides(LOCATION, records) == {}


@pytest.mark.parametrize(
    "changes",
    [
        {"start": None},
        {"start": -1},
        {"start": "107"},
        {"start": True},
        {"start": 1, "end": 7},
        {"end": None},
        {"end": True},
        {"end": 107},
        {"end": 999},
        {"context_offset": None},
        {"context_offset": -1},
        {"context_offset": 0},
        {"context_offset": 999},
        {"context_offset": "7"},
        {"context_offset": True},
        {"context": None},
        {"context": ""},
        {"value": "DIFFERENT"},
        {"value": "", "end": 107},
        {"representation": "metadata"},
        {"representation": "unknown"},
        {"representation": "inspect:decoded-secret"},
        {"severity": "unknown"},
        {"confidence": "unknown"},
        {"start": 0, "end": 0, "context_offset": None, "value": "not regex:password"},
    ],
)
def test_invalid_or_nonliteral_evidence_is_not_silently_folded_into_group(changes):
    first = finding(rule="rule:a")
    second = finding(rule="rule:b")
    invalid = replace(finding(rule="rule:c"), **changes)

    overrides = grouped_console_overrides(LOCATION, (first, second, invalid))

    assert set(overrides) == {0, 1}
    assert overrides[0] is not None
    assert overrides[1] is None


@pytest.mark.parametrize("line_break", ["\n", "\r", "\r\n", "\v", "\f", "\x85", "\u2028", "\u2029"])
def test_multiline_context_is_never_grouped(line_break):
    context = "before" + line_break + "SECRET after"
    records = (finding(context, rule="rule:a"), finding(context, rule="rule:b"))

    assert grouped_console_overrides(LOCATION, records) == {}


def test_multiline_matched_value_is_never_grouped():
    value = "BEGIN SECRET\nKEY MATERIAL\nEND SECRET"
    context = "before " + value + " after"
    records = (finding(context, value, rule="rule:a"), finding(context, value, rule="rule:b"))

    assert grouped_console_overrides(LOCATION, records) == {}


def test_distant_different_secrets_are_both_retained_without_repeating_long_line():
    first_value = "SECRET_ONE_" + "a" * 150
    second_value = "SECRET_TWO_" + "b" * 150
    context = "L" * 100 + first_value + "M" * 400 + second_value + "R" * 100
    records = (
        finding(context, first_value, rule="rule:a", severity="critical"),
        finding(context, second_value, rule="rule:b", severity="low"),
    )

    message, highlights, _ = grouped(records)

    assert match_parts(message, highlights) == [first_value, second_value]
    assert message.count(first_value) == message.count(second_value) == 1
    assert " … " in message
    assert "L" * 61 not in message
    assert "M" * 61 not in message
    assert "R" * 61 not in message
    assert context not in message


def test_nearby_match_contexts_merge_without_duplicating_surrounding_text():
    context = "prefix SECRET_ONE middle SECRET_TWO suffix"
    records = (
        finding(context, "SECRET_ONE", rule="rule:a"),
        finding(context, "SECRET_TWO", rule="rule:b"),
    )

    message, highlights, _ = grouped(records)

    assert "match=" + context + " (ещё 1 правило: rule:b)" in message
    assert match_parts(message, highlights) == ["SECRET_ONE", "SECRET_TWO"]
    assert message.count("prefix") == message.count("middle") == message.count("suffix") == 1


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (("ABCDEF", "CDE"), ["ABCDEF"]),
        (("ABCD", "CDEF"), ["ABCDEF"]),
        (("ABC", "DEF"), ["ABCDEF"]),
        (("ABCDEF", "ABCDEF"), ["ABCDEF"]),
    ],
)
def test_overlap_nested_identical_and_adjacent_spans_have_one_complete_highlight(values, expected):
    context = "before ABCDEF after"
    records = tuple(finding(context, value, rule=f"rule:{index}") for index, value in enumerate(values))

    message, highlights, _ = grouped(records)

    assert match_parts(message, highlights) == expected
    assert message.count("ABCDEF") == 1


def test_additional_count_uses_unique_other_rule_names_not_occurrences():
    context = "FIRST SECOND THIRD"
    records = (
        finding(context, "FIRST", rule="rule:a", severity="critical"),
        finding(context, "SECOND", rule="rule:b"),
        finding(context, "THIRD", rule="rule:b"),
        finding(context, "THIRD", rule="rule:a"),
    )

    message, highlights, _ = grouped(records)

    assert message.endswith(" (ещё 1 правило: rule:b)")
    assert match_parts(message, highlights) == ["FIRST", "SECOND", "THIRD"]


def test_multiple_matches_from_same_rule_do_not_claim_additional_rules():
    context = "FIRST SECOND"
    records = (finding(context, "FIRST"), finding(context, "SECOND"))

    message, highlights, _ = grouped(records)

    assert "ещё" not in message
    assert match_parts(message, highlights) == ["FIRST", "SECOND"]


@pytest.mark.parametrize(
    ("count", "word"), [(1, "правило"), (2, "правила"), (4, "правила"), (5, "правил"), (11, "правил"), (12, "правил"), (21, "правило")]
)
def test_additional_rule_count_has_correct_russian_plural(count, word):
    records = tuple(finding(rule=f"rule:{index:02}") for index in range(count + 1))

    message, _, _ = grouped(records)

    assert f" (ещё {count} {word}: " in message
    assert message.endswith(", ".join(f"rule:{index:02}" for index in range(1, count + 1)) + ")")


def test_quiet_mode_keeps_every_match_and_no_nonmatched_context():
    context = "prefix FIRST middle SECOND suffix"
    records = (finding(context, "FIRST", rule="rule:a"), finding(context, "SECOND", rule="rule:b"))

    message, highlights, _ = grouped(records, show_context=False)

    assert message.endswith("match=FIRST … SECOND (ещё 1 правило: rule:b)")
    assert match_parts(message, highlights) == ["FIRST", "SECOND"]
    assert all(word not in message for word in ("prefix", "middle", "suffix"))


@pytest.mark.parametrize("control", ["\t", "\x00", "\x1b", "\u202e", "\u2066"])
def test_control_escaping_keeps_all_match_spans_correct_and_original_evidence_unchanged(control):
    context = "before A" + control + "SECRET middle OTHER after"
    first_value = "A" + control + "SECRET"
    records = (
        finding(context, first_value, rule="rule:a"),
        finding(context, "OTHER", rule="rule:b" + control + "name"),
    )
    original = [asdict(item) for item in records]
    escaped = {"\t": r"\t", "\x00": r"\x00", "\x1b": r"\x1b", "\u202e": r"\u202e", "\u2066": r"\u2066"}[control]

    message, highlights, _ = grouped(records, location=LOCATION + control + "tail")

    assert control not in message
    assert match_parts(message, highlights) == ["A" + escaped + "SECRET", "OTHER"]
    assert "rule:b" + escaped + "name" in message
    assert [asdict(item) for item in records] == original


def test_real_parser_offsets_group_within_line_but_keep_repeated_lines_separate():
    parser = FileParser(["SECRET", "SECRET password"], quiet=True, blocked_extensions=[])
    result = parser.parse_file("config.txt", data=b"header\nSECRET password\nSECRET password\nfooter")
    assert result.error is None
    assert len(result.findings) == 4

    overrides = grouped_console_overrides(LOCATION, result.findings)

    assert len(overrides) == 4
    leaders = [item for item in overrides.values() if item is not None]
    assert len(leaders) == 2
    assert all(match_parts(message, highlights) == ["SECRET password"] for message, highlights, _ in leaders)


def test_empty_and_singleton_calls_need_no_override():
    assert grouped_console_overrides(LOCATION, ()) == {}
    assert grouped_console_overrides(LOCATION, (finding(),)) == {}


def test_grouping_never_combines_separate_file_calls():
    records = (finding(rule="rule:a"), finding(rule="rule:b"))

    first, _, _ = grouped(records, location="/scope/one.ini")
    second, _, _ = grouped(records, location="/scope/two.ini")

    assert first.startswith("/scope/one.ini:")
    assert second.startswith("/scope/two.ini:")
