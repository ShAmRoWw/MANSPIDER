"""Malformed configuration must fail before scan setup, without changing valid rules."""

from copy import deepcopy
import json
import os
import subprocess
import sys

import pytest

from man_spider.cli import ConfigurationError, parse_options
from man_spider.lib.util import human_to_int
from man_spider.rules import (
    RuleConfigurationError,
    RuleEngine,
    load_builtin_rules,
    load_rule_files,
    normalize_rule_objects,
)


VALID_SIZES = [
    ("8M", 8 * 1024**2),
    ("8MB", 8 * 1024**2),
    ("8MiB", 8 * 1024**2),
    ("1.5M", 1572864),
    (" 8m ", 8 * 1024**2),
    ("8192", 8192),
    (".5M", 524288),
    ("1.M", 1024**2),
    ("1 M", 1024**2),
    ("+8M", 8 * 1024**2),
    ("1B", 1),
    (".5KiB", 512),
    ("0.5M", 524288),
    ("1.9B", 1),
    ("1.5G", 1610612736),
    ("2TiB", 2 * 1024**4),
]
INVALID_SIZES = [
    "-8M", "8M123", "8Mbytes", "8MM", "1e3", "8,5M", "", ".M",
    "8..5M", "8M!", "1 2M", "8 MB extra", "0x10", "NaN", "inf", "8IB",
]
NON_STRING_ENUMS = [[], {}, None, True, 12]
OVERFLOW_REGEX = "a{4294967296}"


def write_pack(path, rules, *, schema_version=3):
    path.write_text(json.dumps({"schema_version": schema_version, "rules": rules}), encoding="utf-8")
    return path


def predicate_rule(predicate, *, location="match"):
    rule = {"id": "configuration-probe", "match": {}, "actions": [{"type": "report"}]}
    rule[location] = {"predicates": [predicate]}
    return rule


def invalid_enum_rule(location, value):
    if location in ("field", "operator"):
        predicate = {"field": "filename", "operator": "exact", "value": "sample.txt"}
        predicate[location] = value
        return predicate_rule(predicate)
    if location == "content-operator":
        action = {"type": "scan", "predicates": [{"operator": value, "value": "secret"}]}
    elif location == "type":
        action = {"type": value}
    elif location == "representation":
        action = {"type": "scan", "representation": value, "pattern": "secret"}
    else:
        action = {"type": "inspect", "detector": value}
    return {"id": "configuration-probe", "match": {}, "actions": [action]}


@pytest.mark.parametrize(("value", "expected"), VALID_SIZES)
def test_valid_filesize_forms_preserve_byte_limit(value, expected, tmp_path):
    assert human_to_int(value) == expected
    options = parse_options([str(tmp_path), "-f", "sample", "--max-filesize=" + value])
    assert options.max_filesize == expected


@pytest.mark.parametrize("value", INVALID_SIZES)
def test_malformed_filesize_is_rejected_instead_of_reinterpreted(value, tmp_path, capsys):
    with pytest.raises(ValueError, match="Invalid filesize"):
        human_to_int(value)
    with pytest.raises(SystemExit) as exc:
        parse_options([str(tmp_path), "-f", "sample", "--max-filesize=" + value])
    assert exc.value.code == 2
    diagnostic = capsys.readouterr().err
    assert "--max-filesize" in diagnostic
    assert "Invalid filesize" in diagnostic
    assert "decimal point, not a comma" in diagnostic


@pytest.mark.parametrize(
    "value",
    ["9" * 400, "9" * 10000 + "M", "9" * 300 + "T"],
    ids=["integer-overflow", "long-integer-overflow", "unit-multiplication-overflow"],
)
def test_unrepresentable_size_has_normal_validation_error(value, tmp_path, capsys):
    with pytest.raises(ValueError, match="size is too large"):
        human_to_int(value)
    with pytest.raises(SystemExit) as exc:
        parse_options([str(tmp_path), "-f", "sample", "--max-filesize=" + value])
    assert exc.value.code == 2
    assert "size is too large" in capsys.readouterr().err


@pytest.mark.parametrize("value", [None, [], {}, True, 1.5])
def test_non_string_non_integer_filesize_is_a_value_error(value):
    with pytest.raises(ValueError, match="Invalid filesize"):
        human_to_int(value)


@pytest.mark.parametrize("value", ["0", "0B", "0.1B", ".5"])
def test_fractional_byte_truncation_cannot_disable_size_limit(value, tmp_path):
    assert human_to_int(value) == 0
    with pytest.raises(ConfigurationError, match="--max-filesize must be greater than zero"):
        parse_options([str(tmp_path), "-f", "sample", "--max-filesize=" + value])


def test_default_size_and_integer_api_remain_unchanged(tmp_path):
    assert human_to_int(1024) == 1024
    assert parse_options([str(tmp_path), "-f", "sample"]).max_filesize == 10 * 1024**2


@pytest.mark.parametrize("location", ["field", "operator", "content-operator", "type", "representation", "detector"])
@pytest.mark.parametrize("value", NON_STRING_ENUMS)
def test_non_string_rule_enums_raise_configuration_errors(location, value, tmp_path):
    rule = invalid_enum_rule(location, value)
    path = write_pack(tmp_path / "rules.json", [rule])
    with pytest.raises(RuleConfigurationError, match="unsupported"):
        load_rule_files([path])
    with pytest.raises(RuleConfigurationError, match="unsupported"):
        normalize_rule_objects([rule])
    # The API also accepts already normalized objects. Its preprocessing must
    # not attempt a set lookup on an invalid field before strict validation.
    with pytest.raises(RuleConfigurationError, match="unsupported"):
        RuleEngine([dict(rule, schema_version=3)])


@pytest.mark.parametrize("value", NON_STRING_ENUMS)
def test_invalid_field_in_canonical_exclusion_is_checked_before_membership(value):
    rule = predicate_rule({"field": value, "operator": "exact", "value": "sample"}, location="exclude")
    with pytest.raises(RuleConfigurationError, match="unsupported field"):
        normalize_rule_objects([dict(rule, schema_version=3)])


@pytest.mark.parametrize("field", ["size", "mtime"])
@pytest.mark.parametrize("operator", ["eq", "gt", "gte", "lt", "lte", "between-low", "between-high"])
@pytest.mark.parametrize("number", [float("nan"), float("inf"), -float("inf")])
@pytest.mark.parametrize("location", ["match", "exclude"])
def test_nonfinite_numeric_rule_bounds_are_rejected(field, operator, number, location, tmp_path):
    value = number
    if operator.startswith("between"):
        value = [number, 10] if operator == "between-low" else [0, number]
        operator = "between"
    rule = predicate_rule({"field": field, "operator": operator, "value": value}, location=location)
    path = write_pack(tmp_path / "rules.json", [rule])
    with pytest.raises(RuleConfigurationError, match="finite"):
        load_rule_files([path])
    with pytest.raises(RuleConfigurationError, match="finite"):
        normalize_rule_objects([dict(rule, schema_version=3)])


@pytest.mark.parametrize("field", ["size", "mtime"])
@pytest.mark.parametrize("operator", ["eq", "gt", "gte", "lt", "lte", "between"])
@pytest.mark.parametrize("number", [0, 10, 10.5, 10**400])
def test_finite_numeric_bounds_including_huge_exact_integers_preserve_values(field, operator, number, tmp_path):
    value = [0, number] if operator == "between" else number
    rule = predicate_rule({"field": field, "operator": operator, "value": value})
    path = write_pack(tmp_path / "rules.json", [rule])
    loaded = load_rule_files([path])
    assert loaded[0]["match"]["predicates"][0]["value"] == value
    engine = RuleEngine(loaded)
    assert engine.route({field: number}).matched == (operator not in {"gt", "lt"})


@pytest.mark.parametrize("field", ["size", "mtime"])
@pytest.mark.parametrize("value", [True, False, [False, 10], [0, True]])
def test_boolean_rule_bounds_remain_invalid(field, value):
    operator = "between" if isinstance(value, list) else "eq"
    rule = predicate_rule({"field": field, "operator": operator, "value": value})
    with pytest.raises(RuleConfigurationError):
        normalize_rule_objects([rule])


@pytest.mark.parametrize("location", ["legacy", "scan-pattern", "content-predicate", "match", "exclude"])
def test_regex_repeat_overflow_is_a_rule_configuration_error(location, tmp_path):
    if location == "legacy":
        rule = {"id": "configuration-probe", "pattern": OVERFLOW_REGEX}
    elif location == "scan-pattern":
        rule = {"id": "configuration-probe", "actions": [{"type": "scan", "pattern": OVERFLOW_REGEX}]}
    elif location == "content-predicate":
        rule = {"id": "configuration-probe", "actions": [{
            "type": "scan", "predicates": [{"operator": "regex", "value": OVERFLOW_REGEX}],
        }]}
    else:
        rule = predicate_rule({"field": "filename", "operator": "regex", "value": OVERFLOW_REGEX}, location=location)
    path = write_pack(tmp_path / "rules.json", [rule], schema_version=1 if location == "legacy" else 3)
    with pytest.raises(RuleConfigurationError, match="invalid regex"):
        load_rule_files([path])
    with pytest.raises(RuleConfigurationError, match="invalid regex"):
        normalize_rule_objects([rule])


@pytest.mark.parametrize("option", ["--filenames", "--content"])
def test_regex_repeat_overflow_is_a_cli_configuration_error(option, tmp_path):
    with pytest.raises(ConfigurationError, match="Invalid regex for " + option):
        parse_options([str(tmp_path), option, OVERFLOW_REGEX])


@pytest.mark.parametrize("case", ["size", "field", "infinite-number", "rule-regex", "filename-regex", "content-regex"])
def test_real_cli_rejects_bad_configuration_before_state_creation(case, tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    state = tmp_path / "scan.sqlite3"
    if case == "size":
        arguments = ["-f", "sample", "--max-filesize=8,5M"]
        message = "decimal point, not a comma"
    elif case in {"filename-regex", "content-regex"}:
        option = "--filenames" if case == "filename-regex" else "--content"
        arguments, message = [option, OVERFLOW_REGEX], "Invalid regex"
    else:
        if case == "field":
            rule, message = invalid_enum_rule("field", []), "unsupported field"
        elif case == "infinite-number":
            rule = predicate_rule({"field": "size", "operator": "gte", "value": "JSON_EXPONENT"})
            message = "finite"
        else:
            rule, message = {"id": "overflow", "pattern": OVERFLOW_REGEX}, "invalid regex"
        path = write_pack(tmp_path / "rules.json", [rule])
        if case == "infinite-number":
            # Exercise actual numeric exponent overflow in JSON, not only its
            # permissive Infinity/NaN spellings or an in-memory float.
            path.write_text(path.read_text(encoding="utf-8").replace('"JSON_EXPONENT"', "1e999"), encoding="utf-8")
        arguments = ["--rules", str(path)]
    result = subprocess.run(
        [sys.executable, "-m", "man_spider.manspider", str(scope), "--yes", "--no-resume-prompt",
         "--state-file", str(state), *arguments],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "XDG_STATE_HOME": str(tmp_path / "automatic-state")},
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert message in result.stderr
    assert "Traceback" not in result.stdout + result.stderr
    assert not state.exists()
    assert list(scope.iterdir()) == []


def test_builtin_definitions_are_unchanged_by_strict_normalization():
    rules = load_builtin_rules()
    original = deepcopy(rules)
    assert normalize_rule_objects(rules) == original
    assert list(RuleEngine(rules).rules) == original
    assert rules == original
