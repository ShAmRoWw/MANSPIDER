"""Supervisor signal lifetime and cleanup, without processes or SMB traffic."""
import os
import signal
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import man_spider.manspider as cli
from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.state import StateError


SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP) if os.name == 'posix' else (signal.SIGINT,)


@pytest.mark.parametrize('first_signal', SIGNALS)
def test_first_signal_protects_every_following_shutdown_signal(first_signal):
    before = {sig: signal.getsignal(sig) for sig in SIGNALS}
    with cli._SupervisorInterrupts() as guard:
        with pytest.raises(KeyboardInterrupt):
            signal.raise_signal(first_signal)
        assert guard.requested
        assert not guard.stopping
        with pytest.raises(KeyboardInterrupt):
            guard.checkpoint()
        guard.begin_cleanup()
        assert guard.stopping
        for _ in range(50):
            for sig in SIGNALS:
                signal.raise_signal(sig)
        guard.checkpoint()
    assert {sig: signal.getsignal(sig) for sig in SIGNALS} == before


@pytest.mark.parametrize('first_signal', SIGNALS)
def test_actual_signal_suppressed_in_destructor_remains_pending_until_supervisor_cleanup(monkeypatch, first_signal):
    unraisable = []
    monkeypatch.setattr(sys, 'unraisablehook', lambda event: unraisable.append(event.exc_type.__name__))
    before = {sig: signal.getsignal(sig) for sig in SIGNALS}

    class InterruptingDestructor:
        def __del__(self):
            signal.raise_signal(first_signal)

    with cli._SupervisorInterrupts() as guard:
        victim = InterruptingDestructor()
        del victim
        assert unraisable == ['KeyboardInterrupt']
        assert guard.requested and not guard.stopping
        for _ in range(50):
            for sig in SIGNALS:
                signal.raise_signal(sig)
        with pytest.raises(KeyboardInterrupt):
            guard.checkpoint()
        guard.begin_cleanup()
        guard.checkpoint()
        for sig in SIGNALS:
            signal.raise_signal(sig)
    assert {sig: signal.getsignal(sig) for sig in SIGNALS} == before


@pytest.mark.parametrize('outcome', ['success', 'interrupt', 'state_error', 'safety_error'])
def test_library_main_restores_caller_handlers_and_mask(monkeypatch, outcome):
    originals = {sig: signal.getsignal(sig) for sig in SIGNALS}
    def caller(*_):
        pass
    expected = {sig: caller for sig in SIGNALS}
    for sig, handler in expected.items():
        signal.signal(sig, handler)
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set()) if os.name == 'posix' else None
    failure = {'interrupt': KeyboardInterrupt, 'state_error': StateError, 'safety_error': ReadOnlySMBViolation}

    def implementation(argv, guard):
        assert argv == ['fixture']
        if outcome != 'success':
            raise failure[outcome]()
        return 0

    monkeypatch.setattr(cli, '_main', implementation)
    try:
        if outcome in ('state_error', 'safety_error'):
            with pytest.raises(failure[outcome]):
                cli.main(['fixture'])
        else:
            assert cli.main(['fixture']) == (130 if outcome == 'interrupt' else 0)
        assert {sig: signal.getsignal(sig) for sig in SIGNALS} == expected
        if original_mask is not None:
            assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask
    finally:
        for sig, handler in originals.items():
            signal.signal(sig, handler)


def test_custom_non_cancelling_sigint_handler_retains_its_behavior():
    calls = []
    original = signal.signal(signal.SIGINT, lambda sig, _frame: calls.append(sig))
    try:
        with cli._SupervisorInterrupts() as guard:
            signal.raise_signal(signal.SIGINT)
            signal.raise_signal(signal.SIGINT)
            assert not guard.stopping
        assert calls == [signal.SIGINT, signal.SIGINT]
    finally:
        signal.signal(signal.SIGINT, original)


def test_explicitly_ignored_sigint_is_not_reenabled():
    original = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        with cli._SupervisorInterrupts():
            assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
            signal.raise_signal(signal.SIGINT)
        assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGINT, original)


def fake_supervisor(monkeypatch, tmp_path, *, cancel, burst_stage, failure_stage=None, failure_type=OSError):
    events = []
    options = SimpleNamespace(verbose=False, state_path=tmp_path / 'unused.sqlite3', json_path=None)

    def stage(name):
        events.append(name)
        if name == burst_stage:
            for _ in range(20):
                for sig in SIGNALS:
                    signal.raise_signal(sig)
        if name == failure_stage:
            raise failure_type('genuine cleanup failure')

    class Endpoint:
        def __init__(self, name):
            self.name = name
            self.closed = 0

        def poll(self, _timeout):
            return True

        def recv(self):
            return 'fixture approval'

        def send(self, _value):
            pass

        def close(self):
            self.closed += 1
            stage(self.name + ('-initial' if self.name == 'child-pipe' and self.closed == 1 else ''))

    class Process:
        pid = 7654321
        exitcode = None
        alive = False
        normal_wait_entered = False

        def start(self):
            self.alive = True

        def is_alive(self):
            return self.alive

        def join(self, timeout=None):
            if not self.normal_wait_entered:
                self.normal_wait_entered = True
                assert timeout == 0.5, 'normal supervisor wait must reach its cancellation checkpoint periodically'
            if cancel and timeout == 0.5:
                signal.raise_signal(signal.SIGINT)
            self.alive = False
            self.exitcode = 130 if cancel else 0
            stage('child-join')

        def terminate(self):
            raise AssertionError('normal cancellation should not need forced termination')

        kill = terminate

    parent, child = Endpoint('parent-pipe'), Endpoint('child-pipe')
    attached = SimpleNamespace(path=options.state_path, run_id='fixture', close=lambda: stage('state-close'))
    monkeypatch.setattr(cli, 'log', Mock())
    monkeypatch.setattr(cli, 'require_safe_standard_streams', lambda: None)
    monkeypatch.setattr(cli, 'parse_options', lambda *_, **__: options)
    monkeypatch.setattr(cli, 'offer_automatic_resume', lambda _: None)
    monkeypatch.setattr(cli, 'validate_options', lambda _: None)
    monkeypatch.setattr(cli, 'prepare_logging', lambda _: tmp_path / 'invocation.log')
    monkeypatch.setattr(cli.multiprocessing, 'Pipe', lambda **_: (parent, child))
    monkeypatch.setattr(cli.multiprocessing, 'Process', lambda **_: Process())
    monkeypatch.setattr(cli, '_start_worker_process', lambda process: process.start())
    monkeypatch.setattr(cli, 'start_listener', lambda: True)
    monkeypatch.setattr(cli, 'stop_listener', lambda _: stage('listener-close'))
    monkeypatch.setattr(cli, 'confirm_scan', lambda *_: True)
    monkeypatch.setattr(cli.os, 'kill', lambda *_: stage('send-child-signal'))
    monkeypatch.setattr(cli.ScanState, 'interrupt_latest', lambda *_, **__: (stage('state-mark'), True)[1])
    monkeypatch.setattr(cli.ScanState, 'attach_latest', lambda *_: attached)
    monkeypatch.setattr(cli, '_emit_terminal_output', lambda *_: stage('state-report'))
    return events


@pytest.mark.parametrize('stage', ['child-join', 'state-mark', 'state-report', 'state-close', 'parent-pipe', 'child-pipe', 'listener-close'])
def test_supervisor_bursts_cannot_skip_state_or_final_releases(monkeypatch, tmp_path, stage):
    events = fake_supervisor(monkeypatch, tmp_path, cancel=True, burst_stage=stage)
    assert cli.main(['fixture']) == 130
    assert events[-3:] == ['parent-pipe', 'child-pipe', 'listener-close']
    assert all(name in events for name in ['state-mark', 'state-report', 'state-close'])


@pytest.mark.parametrize('stage', ['parent-pipe', 'child-pipe', 'listener-close'])
def test_first_interrupt_during_finished_scan_cleanup_does_not_abort_cleanup(monkeypatch, tmp_path, stage):
    events = fake_supervisor(monkeypatch, tmp_path, cancel=False, burst_stage=stage)
    assert cli.main(['fixture']) == 0
    assert events[-3:] == ['parent-pipe', 'child-pipe', 'listener-close']


@pytest.mark.parametrize('failure_type', [StateError, ReadOnlySMBViolation, OSError])
def test_real_cleanup_error_survives_later_interrupt_burst(monkeypatch, tmp_path, failure_type):
    events = fake_supervisor(monkeypatch, tmp_path, cancel=True, burst_stage='listener-close',
                             failure_stage='parent-pipe', failure_type=failure_type)
    with pytest.raises(failure_type, match='genuine cleanup failure'):
        cli.main(['fixture'])
    assert events[-3:] == ['parent-pipe', 'child-pipe', 'listener-close']


def test_cli_keeps_shutdown_handler_after_return_for_interpreter_finalizers(monkeypatch):
    original = {sig: signal.getsignal(sig) for sig in SIGNALS}
    monkeypatch.setattr(cli, '_main', lambda *_: 130)
    try:
        assert cli.cli() == 130
        for _ in range(50):
            for sig in SIGNALS:
                signal.raise_signal(sig)
    finally:
        for sig, handler in original.items():
            signal.signal(sig, handler)
