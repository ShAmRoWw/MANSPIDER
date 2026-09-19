"""Untrusted presentation fields never become terminal controls or log lines."""

import ast
import builtins
import io
import logging
from pathlib import Path
import re
import socket
from types import SimpleNamespace

import pytest
from impacket.smb import SharedFile

from man_spider.filters import ScopeMatcher
from man_spider.lib.errors import FileChangedDuringRead, FileListError
from man_spider.lib.file import RemoteFile
from man_spider.lib.finding_log import display_text, display_traceback, finding_log_message
from man_spider.lib.logger import ColoredFormatter
from man_spider.lib.network_recovery import NetworkRecovery
from man_spider.lib.smb import SMBClient
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.state import FindingRecord


PAYLOADS = ('ordinary', 'Кириллица😀', 'line\nFORGED', 'screen\x1b[2J', 'report\u202e', 'carriage\rRETURN', 'nul\x00tail')
CONTROLS = re.compile(r'[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ud800-\udfff]')


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def fail(*_args, **_kwargs):
        raise AssertionError('Log presentation tests must not contact a server')
    monkeypatch.setattr(socket.socket, 'connect', fail)
    monkeypatch.setattr(socket.socket, 'connect_ex', fail)
    monkeypatch.setattr(socket, 'create_connection', fail)


def capture(monkeypatch, name, action, level=logging.INFO):
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(ColoredFormatter('%(levelname)s %(message)s', use_color=False))
    logger = logging.getLogger(name)
    with monkeypatch.context() as patch:
        patch.setattr(logger, 'handlers', [handler])
        patch.setattr(logger, 'propagate', False)
        patch.setattr(logger, 'level', level)
        logger.manager._clear_cache()
        try:
            action()
        finally:
            logger.manager._clear_cache()
    return output.getvalue()


def make_worker(*, filename=None, error=None):
    worker = Spiderling.__new__(Spiderling)
    worker.target = Target('192.0.2.25')
    worker.parent = SimpleNamespace(
        maxdepth=15, state_path=None, state_run_id=None,
        scope_matcher=ScopeMatcher(excluded_extensions=('.txt',)),
    )
    requests, exclusions, completions = [], [], []
    def ls(share, path):
        requests.append((share, path))
        if error is not None:
            raise error
        return [SharedFile(0, 0, 0, 0, 12, 12, 0, '', filename)]
    worker.smb_client = SimpleNamespace(ls=ls)
    worker.prepare_container = lambda **_kwargs: None
    worker.complete_container = lambda *args, **kwargs: completions.append((args, kwargs))
    worker.record_exclusion = lambda **kwargs: exclusions.append(kwargs)
    return worker, requests, exclusions, completions


@pytest.mark.parametrize('payload', PAYLOADS[:-1])
def test_listing_and_hsm_escape_display_but_preserve_raw_metadata(monkeypatch, payload):
    filename, share = payload + '.txt', 'share-' + payload
    worker, requests, exclusions, _completions = make_worker(filename=filename)
    listing = capture(monkeypatch, 'manspider.spiderling', lambda: list(worker.list_files(share)))
    assert listing.startswith('INFO Excluded ')
    assert listing.count('\n') == 1
    assert CONTROLS.search(listing[:-1]) is None
    assert display_text(filename) in listing and display_text(share) in listing
    assert requests == [(share, '')]
    assert exclusions[0]['path'] == filename
    assert exclusions[0]['share'] == share
    recall = capture(monkeypatch, 'manspider.spiderling', lambda: worker.warn_recall_access('file', share, filename, 0x1000, 'read'))
    assert recall.startswith('WARNING OFFLINE/HSM ')
    assert recall.count('\n') == 1 and CONTROLS.search(recall[:-1]) is None
    assert display_text(filename) in recall and display_text(share) in recall
    # Existing evidence/console span handling is not changed by log escaping.
    finding = FindingRecord(rule_id='example', value=filename, context='metadata', representation='metadata')
    message, highlights = finding_log_message(filename, finding)
    assert CONTROLS.search(message) is None
    assert finding.value == filename
    start, end, role = highlights[-1]
    assert role == 'match' and message[start:end] == display_text(filename)


@pytest.mark.parametrize('payload', PAYLOADS)
def test_directory_error_escapes_log_only_and_keeps_failure_reason(monkeypatch, payload):
    reason = 'server error: ' + payload
    worker, requests, _exclusions, completions = make_worker(error=FileListError(reason))
    path = '\\folder-' + payload
    output = capture(monkeypatch, 'manspider.spiderling', lambda: list(worker.list_files('share', path)))
    assert output.startswith('WARNING Error listing ')
    assert output.count('\n') == 1 and CONTROLS.search(output[:-1]) is None
    assert display_text(reason) in output
    assert requests == [('share', path), ('share', path)]
    assert completions[-1][1]['reason'] == reason


@pytest.mark.parametrize('payload', PAYLOADS)
def test_smb_debug_error_keeps_original_exception_and_never_connects(monkeypatch, payload):
    client = SMBClient('server-' + payload, '', '', '', '')
    error = RuntimeError('response: ' + payload)
    returned = []
    output = capture(monkeypatch, 'manspider.smb', lambda: returned.append(client.handle_impacket_error(error, 'share-' + payload, payload + '.txt', display=True)), logging.DEBUG)
    assert returned == [error]
    assert str(error) == 'response: ' + payload
    assert output.count('\n') == 1 and CONTROLS.search(output[:-1]) is None
    assert display_text(payload) in output


def test_disabled_debug_does_not_compute_sanitization(monkeypatch):
    from man_spider.lib import smb as module
    client = SMBClient('server', '', '', '', '')
    def fail(_value):
        raise AssertionError('Disabled debug must not evaluate display fields')
    monkeypatch.setattr(module, 'display_text', fail)
    assert capture(monkeypatch, 'manspider.smb', lambda: client.handle_impacket_error(RuntimeError('x'), display=True)) == ''


@pytest.mark.parametrize('payload', PAYLOADS)
def test_retry_warning_preserves_actual_file_name_and_content(monkeypatch, tmp_path, payload):
    filename = payload + '.txt'
    remote = RemoteFile(filename, 'share', Target('server'), tmp_dir=tmp_path)
    calls = []
    def read(share, name, callback):
        calls.append((share, name))
        if len(calls) == 1:
            raise FileChangedDuringRead('incomplete')
        callback(b'unchanged payload')
        return (17, 12345, None)
    try:
        output = capture(monkeypatch, 'manspider.file', lambda: remote.get(SimpleNamespace(retrieve_file=read)))
        assert output.count('\n') == 1 and CONTROLS.search(output[:-1]) is None
        assert display_text(filename) in output
        assert calls == [('share', filename)] * 2
        assert remote.content_bytes() == b'unchanged payload'
    finally:
        remote.cleanup()


def test_recovery_warning_escapes_endpoint_without_extra_attempts(monkeypatch):
    now = [0.0]
    def sleep(delay):
        now[0] += delay + 1e-9
    endpoint = 'server\nFORGED\x1b[2J:445'
    recovery = NetworkRecovery(endpoint, clock=lambda: now[0], sleeper=sleep)
    recovery.failed()
    output = capture(monkeypatch, 'manspider.smb', lambda: recovery.wait(lambda: None))
    assert output.count('\n') == 1 and CONTROLS.search(output[:-1]) is None
    assert display_text(endpoint) in output
    assert recovery.endpoint == endpoint
    assert now[0] == pytest.approx(1.0)


@pytest.mark.parametrize('payload', PAYLOADS)
def test_traceback_preserves_structure_and_escapes_exception_and_filename(payload):
    # Python rejects NUL in code filenames, but exceptions may still contain it.
    filename = 'synthetic-' + payload.replace('\x00', '-nul-') + '.py'
    namespace = {'failure': RuntimeError(payload)}
    try:
        exec(compile('raise failure', filename, 'exec'), namespace)
    except RuntimeError as error:
        if hasattr(error, 'add_note'):
            error.add_note(payload)
        output = display_traceback()
        assert str(error) == payload
    assert 'Traceback (most recent call last):\n' in output
    assert display_text(filename) in output
    assert f'RuntimeError: {display_text(payload)}\n' in output
    assert CONTROLS.search(output.replace('\n', '')) is None


def test_traceback_handles_chain_suppression_groups_and_missing_current_error():
    assert display_traceback() == 'NoneType: None\n'
    first = ValueError('first\nFORGED')
    second = RuntimeError('second\x1b[2J')
    second.__cause__ = first
    output = display_traceback(second)
    assert 'direct cause' in output and 'first\\nFORGED' in output and 'second\\x1b[2J' in output
    second.__cause__ = None
    second.__context__ = first
    second.__suppress_context__ = True
    assert 'first' not in display_traceback(second)
    second.__suppress_context__ = False
    assert 'During handling' in display_traceback(second)
    first.__context__ = second
    assert 'already displayed' in display_traceback(second)
    if hasattr(builtins, 'ExceptionGroup'):
        output = display_traceback(builtins.ExceptionGroup('group\nFORGED', [second, ValueError('child\u202e')]))
        assert 'Exception group item 1:' in output and 'Exception group item 2:' in output
        assert CONTROLS.search(output.replace('\n', '')) is None


@pytest.mark.parametrize('filename', ['spiderling.py', 'smb.py', 'file.py', 'spider.py'])
def test_traversal_log_interpolations_require_explicit_field_sanitization(filename):
    tree = ast.parse((Path('man_spider/lib') / filename).read_text())
    count = 0
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) and call.func.value.id == 'log' and call.args and isinstance(call.args[0], ast.JoinedStr)):
            continue
        for field in call.args[0].values:
            if not isinstance(field, ast.FormattedValue):
                continue
            count += 1
            value = field.value
            if field.format_spec is not None:
                # Only existing numeric counters use formatting outside display_text.
                assert ast.unparse(value) in {'len(frontier)', 'len(rows)', 'len(files)', 'self.max_failed_logons'}
            else:
                assert isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == 'display_text', (filename, call.lineno)
    assert count > 0
