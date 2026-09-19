"""Rule input limits fail before state/preflight, while valid rules stay exact."""

from copy import deepcopy
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

from man_spider.cli import ConfigurationError, parse_options
from man_spider.lib.parser import FileParser
import man_spider.rules as rules_module
from man_spider.rules import (
    RuleConfigurationError,
    RuleEngine,
    compose_rules,
    load_builtin_rules,
    load_rule_files,
    normalize_rule_objects,
)
from man_spider.state import configuration_fingerprint


DEEP_REGEX = '(' * 700 + 'TOKEN' + ')' * 700
SURROGATES = ('\ud800', '\udfff')
STRING_LOCATIONS = ('id', 'description', 'match', 'exclude', 'pattern', 'content-value', 'password')


def rule_with_string(location, value):
    rule = {'id': 'boundary', 'match': {}, 'actions': [{'type': 'report'}]}
    if location in ('id', 'description'):
        rule[location] = value
    elif location in ('match', 'exclude'):
        rule[location] = {'predicates': [{'field': 'filename', 'operator': 'contains', 'value': value}]}
    elif location == 'pattern':
        rule['actions'] = [{'type': 'scan', 'representation': 'raw', 'pattern': value}]
    elif location == 'content-value':
        rule['actions'] = [{'type': 'scan', 'predicates': [{'operator': 'contains', 'value': value}]}]
    elif location == 'password':
        rule['actions'] = [{'type': 'inspect', 'detector': 'private-key-material', 'passwords': [value]}]
    else:
        raise AssertionError(location)
    return rule


def write_pack(path, rules, **metadata):
    path.write_text(json.dumps({'schema_version': 3, 'rules': rules, **metadata}), encoding='utf-8')
    return path


@pytest.mark.parametrize('location', STRING_LOCATIONS)
@pytest.mark.parametrize('surrogate', SURROGATES)
def test_active_unpaired_surrogate_is_rejected_by_file_and_memory_boundaries(tmp_path, location, surrogate):
    rule = rule_with_string(location, surrogate)
    original = deepcopy(rule)
    path = write_pack(tmp_path / 'rules.json', [rule])
    before = path.read_bytes()
    for load in (
        lambda: load_rule_files([path]),
        lambda: normalize_rule_objects([rule]),
        lambda: normalize_rule_objects([dict(rule, schema_version=3)]),
        lambda: RuleEngine([rule]),
    ):
        with pytest.raises(RuleConfigurationError, match='unpaired Unicode surrogate') as failure:
            load()
        # The error itself must remain printable, including when the ID is bad.
        str(failure.value).encode('utf-8')
    assert path.read_bytes() == before
    assert rule == original


@pytest.mark.parametrize('field', ('id', 'version'))
@pytest.mark.parametrize('surrogate', SURROGATES)
def test_active_pack_provenance_is_validated(tmp_path, field, surrogate):
    pack = dict(id='example', version='1')
    pack[field] = surrogate
    path = write_pack(tmp_path / 'rules.json', [rule_with_string('description', 'valid')], pack=pack)
    with pytest.raises(RuleConfigurationError, match='unpaired Unicode surrogate'):
        load_rule_files([path])


@pytest.mark.parametrize('field', ('rule_source', 'rule_pack_id', 'rule_pack_version'))
@pytest.mark.parametrize('surrogate', SURROGATES)
def test_normalized_in_memory_provenance_is_validated(field, surrogate):
    rule = normalize_rule_objects([rule_with_string('description', 'valid')])[0]
    rule[field] = surrogate
    with pytest.raises(RuleConfigurationError, match='unpaired Unicode surrogate'):
        normalize_rule_objects([rule])
    with pytest.raises(RuleConfigurationError, match='unpaired Unicode surrogate'):
        FileParser([], quiet=True, blocked_extensions=[], rules=[rule])


@pytest.mark.parametrize('location', STRING_LOCATIONS)
@pytest.mark.parametrize('value', ('пароль', '🔒', 'e\u0301', '\\ud800'))
def test_valid_unicode_and_literal_regex_escapes_are_not_rewritten(tmp_path, location, value):
    rule = rule_with_string(location, value)
    path = write_pack(tmp_path / 'rules.json', [rule])
    before = path.read_bytes()
    loaded = load_rule_files([path])
    assert normalize_rule_objects(loaded) == loaded
    assert list(RuleEngine(loaded).rules) == loaded
    assert path.read_bytes() == before
    assert value in json.dumps(loaded, ensure_ascii=False).replace('\\\\', '\\')
    configuration_fingerprint({'rules': loaded})


def test_json_surrogate_pair_becomes_a_supported_astral_character(tmp_path):
    path = write_pack(tmp_path / 'emoji.json', [rule_with_string('id', '🔒')])
    assert b'\\ud83d\\udd12' in path.read_bytes()
    assert load_rule_files([path])[0]['id'] == '🔒'


@pytest.mark.parametrize('field', ('id', 'description', 'pattern'))
def test_legacy_rule_strings_use_the_same_unicode_boundary(tmp_path, field):
    rule = {'id': 'legacy', 'pattern': 'TOKEN', field: '\ud800'}
    path = tmp_path / 'legacy.json'
    path.write_text(json.dumps([rule]), encoding='utf-8')
    with pytest.raises(RuleConfigurationError, match='unpaired Unicode surrogate'):
        load_rule_files([path])
    with pytest.raises(RuleConfigurationError, match='unpaired Unicode surrogate'):
        normalize_rule_objects([rule])


@pytest.mark.parametrize('schema', (1, 2, 3))
def test_disabled_raw_rules_keep_ignoring_unused_invalid_fields(tmp_path, schema):
    disabled = {'id': '\ud800', 'enabled': False, 'unknown-unused': {'value': '\udfff'}, 'pattern': DEEP_REGEX}
    path = tmp_path / 'disabled.json'
    path.write_text(json.dumps({'schema_version': schema, 'rules': [disabled]}), encoding='utf-8')
    assert load_rule_files([path]) == []
    assert normalize_rule_objects([disabled]) == []


def test_deep_regex_is_a_configuration_error_in_legacy_match_exclude_and_actions(tmp_path):
    cases = [
        ({'id': 'legacy', 'pattern': DEEP_REGEX}, 1),
        ({'id': 'pattern', 'actions': [{'type': 'scan', 'pattern': DEEP_REGEX}]}, 3),
        ({'id': 'grouped', 'actions': [{'type': 'scan', 'predicates': [{'operator': 'regex', 'value': DEEP_REGEX}]}]}, 3),
    ]
    for location in ('match', 'exclude'):
        cases.append(({'id': location, location: {'predicates': [{'field': 'filename', 'operator': 'regex', 'value': DEEP_REGEX}]}, 'actions': [{'type': 'report'}]}, 3))
    for index, (rule, schema) in enumerate(cases):
        path = tmp_path / f'deep-{index}.json'
        path.write_text(json.dumps({'schema_version': schema, 'rules': [rule]}), encoding='utf-8')
        for load in (lambda: load_rule_files([path]), lambda: normalize_rule_objects([rule])):
            with pytest.raises(RuleConfigurationError, match='invalid regex') as failure:
                load()
            assert isinstance(failure.value.__cause__, RecursionError)


@pytest.mark.parametrize('option', ('--filenames', '--content'))
def test_cli_regex_depth_has_normal_configuration_error(tmp_path, option):
    with pytest.raises(ConfigurationError, match='Invalid regex for ' + option) as failure:
        parse_options([str(tmp_path), option, DEEP_REGEX])
    assert isinstance(failure.value.__cause__, RecursionError)


def long_integer_pack(digits):
    return '{"schema_version":3,"rules":[{"id":"boundary","match":{"predicates":[{"field":"size","operator":"lte","value":' + '9' * digits + '}]},"actions":[{"type":"report"}]}]}'


def test_json_integer_conversion_limit_is_translated_without_changing_limit(tmp_path):
    if not hasattr(sys, 'set_int_max_str_digits'):
        pytest.skip('Interpreter has no integer string conversion limit')
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(640)
        path = tmp_path / 'long-integer.json'
        path.write_text(long_integer_pack(641), encoding='utf-8')
        with pytest.raises(RuleConfigurationError, match='Invalid JSON rule file') as failure:
            load_rule_files([path])
        assert type(failure.value.__cause__) is ValueError
        assert sys.get_int_max_str_digits() == 640
        # Exact large integers remain exact; the fix must not parse them as floats.
        bound = 10 ** 400
        valid = rule_with_string('description', 'large exact integer')
        valid['match'] = {'predicates': [{'field': 'size', 'operator': 'lte', 'value': bound}]}
        loaded = load_rule_files([write_pack(tmp_path / 'valid.json', [valid])])
        actual = loaded[0]['match']['predicates'][0]['value']
        assert type(actual) is int and actual == bound
        engine = RuleEngine(loaded)
        assert engine.route({'size': bound}).matched
        assert not engine.route({'size': bound + 1}).matched
    finally:
        sys.set_int_max_str_digits(previous)


def test_overrides_use_the_same_unicode_boundary(tmp_path):
    base = write_pack(tmp_path / 'base.json', [rule_with_string('description', 'base')])
    bad_override = write_pack(tmp_path / 'bad.json', [rule_with_string('description', '\ud800')])
    with pytest.raises(ConfigurationError, match='unpaired Unicode surrogate'):
        parse_options([str(tmp_path), '--rules', str(base), '--rule-overrides', str(bad_override)])
    valid_override = write_pack(tmp_path / 'valid.json', [rule_with_string('description', '🔒')])
    options = parse_options([str(tmp_path), '--rules', str(base), '--rule-overrides', str(valid_override)])
    assert options.rules == compose_rules([load_rule_files([base])], overrides=load_rule_files([valid_override]))
    assert options.rules[0]['description'] == '🔒'


def invalid_cli_arguments(case, tmp_path):
    if case in ('filename-depth', 'content-depth'):
        return ['--filenames' if case == 'filename-depth' else '--content', DEEP_REGEX], 'Invalid regex'
    path = tmp_path / 'invalid.json'
    if case == 'integer-limit':
        path.write_text(long_integer_pack(641), encoding='utf-8')
        message = 'Invalid JSON rule file'
    else:
        if case == 'rule-depth':
            rule, message = rule_with_string('pattern', DEEP_REGEX), 'invalid regex'
        else:
            rule, message = rule_with_string('id' if case == 'surrogate-id' else 'description', '\ud800'), 'unpaired Unicode surrogate'
        write_pack(path, [rule])
    arguments = ['--rules', str(path)]
    if case == 'surrogate-override':
        base = write_pack(tmp_path / 'base.json', [rule_with_string('description', 'base')])
        arguments = ['--rules', str(base), '--rule-overrides', str(path)]
    return arguments, message


CLI_CASES = ('surrogate-id', 'surrogate-description', 'surrogate-override', 'rule-depth', 'filename-depth', 'content-depth', 'integer-limit')


@pytest.mark.parametrize('case', CLI_CASES[:-1])
def test_invalid_rules_stop_before_logging_state_worker_and_preflight(tmp_path, monkeypatch, capsys, case):
    scanner = importlib.import_module('man_spider.manspider')
    arguments, message = invalid_cli_arguments(case, tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail('Invalid configuration reached scan setup')

    monkeypatch.setattr(scanner, 'require_safe_standard_streams', lambda: None)
    monkeypatch.setattr(scanner, 'prepare_logging', forbidden)
    monkeypatch.setattr(scanner, 'credential_preflight', forbidden)
    monkeypatch.setattr(scanner.ScanState, 'create', forbidden)
    monkeypatch.setattr(scanner.multiprocessing, 'Process', forbidden)
    state = tmp_path / 'scan.sqlite3'
    with pytest.raises(SystemExit) as failure:
        scanner.main([str(tmp_path), '--state-file', str(state), '--yes', '--no-resume-prompt', *arguments])
    assert failure.value.code == 2
    assert message in capsys.readouterr().err
    assert not state.exists()


@pytest.mark.parametrize('case', CLI_CASES)
def test_real_cli_input_boundaries_leave_no_state_or_preflight(tmp_path, case):
    if case == 'integer-limit' and not hasattr(sys, 'set_int_max_str_digits'):
        pytest.skip('Interpreter has no integer string conversion limit')
    scope = tmp_path / 'scope'
    scope.mkdir()
    candidate = scope / 'original.txt'
    candidate.write_bytes(b'ORIGINAL-CONTROL\n')
    before = hashlib.sha256(candidate.read_bytes()).hexdigest()
    arguments, message = invalid_cli_arguments(case, tmp_path)
    state = tmp_path / 'scan.sqlite3'
    completed = subprocess.run(
        [sys.executable, '-m', 'man_spider.manspider', str(scope), '--state-file', str(state), '--yes', '--no-resume-prompt', *arguments],
        capture_output=True, text=True, timeout=30, check=False,
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, 'XDG_STATE_HOME': str(tmp_path / 'automatic-state'), 'PYTHONINTMAXSTRDIGITS': '640'},
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 2, output
    assert message in completed.stderr
    assert 'Traceback' not in output
    assert 'Preparing credential preflight' not in output
    assert not state.exists()
    assert not (tmp_path / 'automatic-state').exists()
    assert not list(tmp_path.glob('*.run_*.log'))
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == before


def test_validation_preserves_builtin_definitions_fingerprints_and_is_not_on_route(monkeypatch):
    validator = rules_module._validate_rule_unicode
    with monkeypatch.context() as baseline:
        baseline.setattr(rules_module, '_validate_rule_unicode', lambda _rule: None)
        old_definitions = load_builtin_rules()
    loaded = load_builtin_rules()
    assert len(loaded) == 251
    assert loaded == old_definitions
    assert normalize_rule_objects(loaded) == loaded
    assert configuration_fingerprint({'rules': loaded}) == configuration_fingerprint({'rules': old_definitions})
    calls = []

    def counted(rule):
        calls.append(rule['id'])
        validator(rule)

    monkeypatch.setattr(rules_module, '_validate_rule_unicode', counted)
    engine = RuleEngine(loaded)
    assert len(calls) == 251
    for index in range(10):
        engine.route({'filename': 'settings.json', 'extension': '.json', 'path': str(index), 'size': index, 'mtime': 100})
    assert len(calls) == 251


def test_small_valid_nested_regex_still_emits_original_occurrences():
    pattern = '(' * 5 + 'TOKEN' + ')' * 5
    parser = FileParser([], quiet=True, blocked_extensions=[], rules=[rule_with_string('pattern', pattern)])
    matches = list(parser.match('TOKEN token', representation='raw'))
    assert [(match.group(), match.span()) for _rule, match in matches] == [('TOKEN', (0, 5)), ('token', (6, 11))]
    assert re.compile(pattern, re.I).pattern == pattern
