"""Cancellation at real worker boundaries, with no network or SMB server."""
import multiprocessing
import os
from pathlib import Path
import queue
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

import man_spider.lib.spiderling as workers
from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib.spider import MANSPIDER
from man_spider.state import StateError


class _UnpickleGate:
    def __init__(self, ready, release, stderr_path):
        self.ready, self.release, self.stderr_path = ready, release, stderr_path

    def __reduce__(self):
        return _restore_unpickle_gate, (self.ready, self.release, self.stderr_path)


def _restore_unpickle_gate(ready, release, stderr_path):
    # This runs inside multiprocessing.spawn._main -> pickle.load, before its
    # Process has even become current_process and before any product entry.
    with open(stderr_path, 'w', encoding='utf-8') as stream:
        os.dup2(stream.fileno(), 2)
    ready.set()
    if not release.wait(5):
        raise RuntimeError('test did not release unpickling')
    return 'fixture'


@pytest.mark.skipif(os.name != 'posix', reason='POSIX inherited signal masks')
@pytest.mark.parametrize('entry', ['scan', 'target', 'share'])
def test_sigint_during_actual_spawn_unpickle_is_deferred_until_protected_entry(tmp_path, entry):
    from man_spider.manspider import _run_scan

    context = multiprocessing.get_context('spawn')
    ready, release, stopped = (context.Event() for _ in range(3))
    errors = context.Queue()
    stderr_path = tmp_path / 'early-spawn-stderr.txt'
    gate = _UnpickleGate(ready, release, str(stderr_path))
    if entry == 'scan':
        target, arguments = _run_scan, (gate, [])
    elif entry == 'target':
        target, arguments = workers._run_target_worker_process, (gate, SimpleNamespace(log_queue=None))
    else:
        target, arguments = workers._run_share_worker_process, (
            gate, SimpleNamespace(log_queue=None, share_worker_slots=context.BoundedSemaphore(1)),
            None, {}, None, stopped, errors)
    process = context.Process(target=target, args=arguments)
    before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    workers._start_worker_process(process)
    try:
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == before
        assert not hasattr(process, '_manspider_startup_sigmask')
        assert ready.wait(5)
        os.kill(process.pid, signal.SIGINT)
        time.sleep(0.05)
        assert process.is_alive(), 'SIGINT escaped during pickle.load'
        release.set()
        process.join(timeout=5)
        assert process.exitcode == 130
        assert stderr_path.read_text() == ''
        if entry == 'share':
            assert stopped.is_set()
            assert errors.get(timeout=1) == ('KeyboardInterrupt', '')
    finally:
        release.set()
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        errors.close()
        errors.join_thread()


def _report_initial_child_mask(results):
    workers._install_worker_interrupt_handler()
    results.put((signal.pthread_sigmask(signal.SIG_BLOCK, set()),
                 hasattr(multiprocessing.current_process(), '_manspider_startup_sigmask')))


@pytest.mark.skipif(os.name != 'posix', reason='POSIX inherited signal masks')
@pytest.mark.parametrize('blocked_interrupt', [True, False])
def test_start_restores_exact_parent_and_child_masks_without_unblocking_callers_signal(blocked_interrupt):
    context = multiprocessing.get_context('spawn')
    results = context.Queue()
    original = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    desired = original | {signal.SIGUSR1}
    if blocked_interrupt:
        desired.add(signal.SIGINT)
    else:
        desired.discard(signal.SIGINT)
    signal.pthread_sigmask(signal.SIG_SETMASK, desired)
    process = context.Process(target=_report_initial_child_mask, args=(results,))
    try:
        workers._start_worker_process(process)
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == desired
        assert results.get(timeout=5) == (desired, False)
        process.join(timeout=5)
        assert process.exitcode == 0
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, original)
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        results.close()
        results.join_thread()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX inherited signal masks')
@pytest.mark.parametrize('pending_interrupt', [True, False])
@pytest.mark.parametrize('start_error', [True, False])
def test_start_cleanup_restores_mask_and_attribute_even_with_pending_signal_or_start_error(pending_interrupt, start_error):
    original = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    previous_handler = signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
    before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    actual = StateError('real start failure')

    def start():
        assert signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, set())
        if pending_interrupt:
            signal.pthread_kill(threading.get_ident(), signal.SIGINT)
        if start_error:
            raise actual

    process = SimpleNamespace(start=start)
    try:
        if pending_interrupt or start_error:
            with pytest.raises(StateError if start_error else KeyboardInterrupt) as captured:
                workers._start_worker_process(process)
            if start_error:
                assert captured.value is actual
        else:
            workers._start_worker_process(process)
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == before
        assert not hasattr(process, '_manspider_startup_sigmask')
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, original)
        signal.signal(signal.SIGINT, previous_handler)


class _Slots:
    def __init__(self, stage=None):
        self.stage = stage
        self.releases = 0

    def acquire(self, **_kwargs):
        if self.stage == 'semaphore':
            raise KeyboardInterrupt
        return True

    def release(self):
        self.releases += 1
        if self.stage == 'release':
            raise KeyboardInterrupt


@pytest.mark.parametrize('stage', ['logging', 'semaphore', 'create', 'consume', 'cleanup', 'release'])
def test_share_entry_cancellation_is_explicit_and_releases_owned_slots(monkeypatch, stage):
    slots = _Slots(stage)
    stopped = threading.Event()
    errors = queue.Queue()
    closed = []

    def at(step):
        if stage == step:
            raise KeyboardInterrupt

    def close():
        closed.append(True)
        at('cleanup')

    def create(*_args):
        at('create')
        return SimpleNamespace(_consume_share_queue=lambda *_: at('consume'), _close_share_worker=close)

    monkeypatch.setattr(workers, 'configure_worker_logging', lambda _: at('logging'))
    monkeypatch.setattr(workers.Spiderling, '_create_share_worker', create)
    parent = SimpleNamespace(log_queue=None, share_worker_slots=slots)
    with pytest.raises(SystemExit) as captured:
        workers._run_share_worker_process('fixture', parent, None, {}, None, stopped, errors)
    assert captured.value.code == 130
    assert stopped.is_set()
    assert errors.get_nowait() == ('KeyboardInterrupt', '')
    assert slots.releases == (stage not in ('logging', 'semaphore'))
    assert bool(closed) == (stage in ('consume', 'cleanup', 'release'))


@pytest.mark.parametrize('stop_after_acquire', [True, False])
def test_share_entry_never_discards_release_failure_after_skipped_work(monkeypatch, stop_after_acquire):
    stopped, errors = threading.Event(), queue.Queue()
    actual = StateError('release failed after skipped work')

    class Slots:
        def acquire(self, **_kwargs):
            if stop_after_acquire:
                stopped.set()
            return True

        def release(self):
            raise actual

    monkeypatch.setattr(workers, 'configure_worker_logging', lambda _: None)
    monkeypatch.setattr(workers.Spiderling, '_create_share_worker', lambda *_: None)
    with pytest.raises(StateError) as captured:
        workers._run_share_worker_process('fixture', SimpleNamespace(log_queue=None, share_worker_slots=Slots()),
                                          None, {}, None, stopped, errors)
    assert captured.value is actual
    assert errors.get_nowait() == ('StateError', str(actual))


@pytest.mark.parametrize('real_error', [StateError, ReadOnlySMBViolation, RuntimeError])
@pytest.mark.parametrize('first_interrupt', [True, False])
def test_share_cleanup_keeps_real_failure_over_cancellation(monkeypatch, real_error, first_interrupt):
    actual = real_error('genuine failure')
    first, cleanup = (KeyboardInterrupt(), actual) if first_interrupt else (actual, KeyboardInterrupt())
    slots, stopped, errors, safety = _Slots(), threading.Event(), queue.Queue(), []

    def fail(error):
        raise error

    worker = SimpleNamespace(_consume_share_queue=lambda *_: fail(first), _close_share_worker=lambda: fail(cleanup))
    monkeypatch.setattr(workers, 'configure_worker_logging', lambda _: None)
    monkeypatch.setattr(workers.Spiderling, '_create_share_worker', lambda *_: worker)
    monkeypatch.setattr(workers, '_report_read_only_failure', lambda *args: safety.append(args[-1]))
    with pytest.raises(real_error) as captured:
        workers._run_share_worker_process('fixture', SimpleNamespace(log_queue=None, share_worker_slots=slots),
                                          None, {}, None, stopped, errors)
    assert captured.value is actual
    assert errors.get_nowait() == (real_error.__name__, 'genuine failure')
    assert slots.releases == 1
    assert safety == ([actual] if real_error is ReadOnlySMBViolation else [])


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, StateError, ReadOnlySMBViolation, RuntimeError])
def test_target_entry_covers_setup_without_hiding_real_errors(monkeypatch, error_type):
    failure = error_type()

    def fail(*_args):
        raise failure

    monkeypatch.setattr(workers, 'Spiderling', fail)
    if error_type is KeyboardInterrupt:
        with pytest.raises(SystemExit) as captured:
            workers._run_target_worker_process('fixture', None)
        assert captured.value.code == 130
    else:
        with pytest.raises(error_type) as captured:
            workers._run_target_worker_process('fixture', None)
        assert captured.value is failure


@pytest.mark.parametrize('real_error', [StateError, ReadOnlySMBViolation])
@pytest.mark.parametrize('first_interrupt', [True, False])
def test_target_cleanup_preserves_real_failure_over_cancellation(monkeypatch, tmp_path, real_error, first_interrupt):
    actual = real_error('genuine target failure')
    first, cleanup = (KeyboardInterrupt(), actual) if first_interrupt else (actual, KeyboardInterrupt())
    messages = queue.Queue()

    def fail(error):
        raise error

    monkeypatch.setattr(workers, 'configure_worker_logging', lambda _: None)
    monkeypatch.setattr(workers.Spiderling, 'go', lambda _: fail(first))
    monkeypatch.setattr(workers.Spiderling, 'flush_unclassified_observations', lambda _: fail(cleanup))
    with pytest.raises(real_error) as captured:
        workers._run_target_worker_process(tmp_path, SimpleNamespace(log_queue=None, spiderling_queue=messages))
    assert captured.value is actual
    emitted = list(messages.queue)
    assert not any(message.type == 'p' and message.content.get('target_complete') for message in emitted)
    if real_error is ReadOnlySMBViolation:
        assert any(message.type == 's' for message in emitted)


@pytest.mark.parametrize('entry', ['target', 'share'])
@pytest.mark.parametrize('first_interrupt', [True, False])
@pytest.mark.parametrize('real_error', [StateError, ReadOnlySMBViolation])
@pytest.mark.parametrize('flush_stage', ['unclassified', 'state'])
@pytest.mark.parametrize('close_stage', ['smb', 'state'])
def test_multiple_cleanup_failures_preserve_real_error_across_all_stages(
        monkeypatch, tmp_path, entry, first_interrupt, real_error, flush_stage, close_stage):
    actual = real_error('intermediate cleanup failure')
    early, late = (KeyboardInterrupt(), actual) if first_interrupt else (actual, KeyboardInterrupt())
    visited = []

    def step(name, error=None):
        visited.append(name)
        if error is not None:
            raise error

    monkeypatch.setattr(workers, 'configure_worker_logging', lambda _: None)
    monkeypatch.setattr(workers.Spiderling, 'flush_unclassified_observations',
                        lambda _: step('flush-unclassified', early if flush_stage == 'unclassified' else None))
    monkeypatch.setattr(workers.Spiderling, 'flush_state_completions',
                        lambda _: step('flush-state', early if flush_stage == 'state' else None))

    def setup(worker):
        worker.smb_client = SimpleNamespace(close=lambda: step('close-smb', late if close_stage == 'smb' else None))
        worker.scan_state = SimpleNamespace(close=lambda: step('close-state', late if close_stage == 'state' else None))
        worker._owns_scan_state = True

    if entry == 'target':
        monkeypatch.setattr(workers.Spiderling, 'go', setup)
        monkeypatch.setattr(workers.Spiderling, 'complete_container', lambda *_args, **_kwargs: None)
        def invoke():
            workers._run_target_worker_process(
                tmp_path, SimpleNamespace(log_queue=None, spiderling_queue=queue.Queue()))
    else:
        worker = workers.Spiderling.__new__(workers.Spiderling)
        setup(worker)
        invoke = worker._close_share_worker
    with pytest.raises(real_error) as captured:
        invoke()
    assert captured.value is actual
    assert visited == ['flush-unclassified', 'flush-state', 'close-smb', 'close-state']


def test_late_cleanup_safety_failure_has_priority_over_earlier_state_error():
    actual = ReadOnlySMBViolation('late safety failure')
    def fail(error):
        raise error
    with pytest.raises(ReadOnlySMBViolation) as captured:
        workers._run_worker_cleanup(lambda: fail(StateError('state failed')), lambda: fail(actual))
    assert captured.value is actual


@pytest.mark.parametrize('exitcode', [130, -signal.SIGINT])
def test_live_parent_does_not_treat_interrupted_target_as_success(exitcode):
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.spiderling_queue = None
    child = SimpleNamespace(pid=123, exitcode=exitcode, join=lambda: None)
    scanner.spiderling_pool = [child]
    with pytest.raises(KeyboardInterrupt):
        scanner.ensure_worker_succeeded(child)


def test_safety_queue_message_has_priority_over_child_interrupt_exit():
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.spiderling_queue = object()
    actual = ReadOnlySMBViolation('genuine queued safety failure')

    def fail(**_kwargs):
        raise actual

    scanner.check_spiderling_queue = fail
    with pytest.raises(ReadOnlySMBViolation) as captured:
        scanner.ensure_worker_succeeded(SimpleNamespace(pid=123, exitcode=130, join=lambda: None))
    assert captured.value is actual


@pytest.mark.parametrize('failure_type', ['StateError', 'ReadOnlySMBViolation', 'RuntimeError', None])
def test_share_coordinator_retains_worker_cleanup_failure_after_its_own_interrupt(failure_type):
    errors, stopped = queue.Queue(), threading.Event()
    child = SimpleNamespace(name='fixture-worker', exitcode=None, start=lambda: None)
    context = SimpleNamespace(JoinableQueue=queue.Queue, Event=lambda: stopped, Queue=lambda: errors,
                              Process=lambda **_kwargs: child)
    worker = workers.Spiderling.__new__(workers.Spiderling)
    worker.parent = SimpleNamespace(share_process_context=context)
    worker.target, worker.target_object_id = 'fixture', None
    worker._session_configuration = dict
    worker._consume_share_queue = lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())

    def stop(_children):
        child.exitcode = 1 if failure_type else 130
        errors.put((failure_type or 'KeyboardInterrupt', 'cleanup evidence'))

    worker._stop_share_workers = stop
    expected = ReadOnlySMBViolation if failure_type == 'ReadOnlySMBViolation' else StateError if failure_type else KeyboardInterrupt
    with pytest.raises(expected) as captured:
        worker._run_parallel_share_work(['fixture'], 2)
    if failure_type:
        assert 'cleanup evidence' in str(captured.value)
    assert stopped.is_set()


@pytest.mark.parametrize('exitcode,expected', [(1, StateError), (130, KeyboardInterrupt),
                                             (-signal.SIGTERM, KeyboardInterrupt), (-signal.SIGKILL, KeyboardInterrupt)])
def test_share_cancellation_does_not_hide_unreported_worker_failure(exitcode, expected):
    with pytest.raises(expected):
        workers.Spiderling._raise_share_worker_failures(
            [SimpleNamespace(name='fixture', exitcode=exitcode)], queue.Queue(), interrupted=True)


@pytest.mark.parametrize('failure_type', [StateError, ReadOnlySMBViolation, None])
def test_scanner_preserves_child_failure_reported_during_interrupted_stop(failure_type):
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.external_log_listener = True
    scanner.prepare_temp_dir = lambda: None
    scanner.cleanup_temp_dir = lambda: None
    scanner.initialize_progress_tracking = lambda: None
    scanner._start = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
    scanner.spiderling_queue = SimpleNamespace(close=lambda: None, join_thread=lambda: None)
    child = SimpleNamespace(pid=123, exitcode=None)
    scanner.spiderling_pool = [child]

    def stop():
        child.exitcode = 1 if failure_type else 130

    def messages(**_kwargs):
        if failure_type is ReadOnlySMBViolation:
            raise ReadOnlySMBViolation('actual unsafe operation')

    scanner.stop_workers = stop
    scanner.check_spiderling_queue = messages
    with pytest.raises(failure_type or KeyboardInterrupt):
        scanner.start()


@pytest.mark.parametrize('entry', ['target', 'share'])
@pytest.mark.parametrize('exitcode', [1, -signal.SIGTERM])
def test_forced_stop_never_reads_potentially_corrupt_queue_but_keeps_abnormal_exit(entry, exitcode):
    child = SimpleNamespace(pid=123, name='fixture', exitcode=exitcode)

    def unsafe_read(*_args, **_kwargs):
        pytest.fail('must not read a queue whose producer was forcibly killed')

    if entry == 'target':
        scanner = MANSPIDER.__new__(MANSPIDER)
        scanner.external_log_listener = True
        scanner.prepare_temp_dir = lambda: None
        scanner.cleanup_temp_dir = lambda: None
        scanner.initialize_progress_tracking = lambda: None
        scanner._start = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
        scanner.spiderling_queue = SimpleNamespace(close=lambda: None, join_thread=lambda: None)
        scanner.spiderling_pool = [child]
        scanner.stop_workers = lambda: True
        scanner.check_spiderling_queue = unsafe_read
        invoke = scanner.start
    else:
        def invoke():
            workers.Spiderling._raise_share_worker_failures(
                [child], SimpleNamespace(get_nowait=unsafe_read), interrupted=True, read_queue=False)
    with pytest.raises(StateError if exitcode == 1 else KeyboardInterrupt):
        invoke()


@pytest.mark.parametrize('force', [True, False])
def test_share_stop_reports_whether_queue_writer_required_forced_shutdown(force):
    class Child:
        pid = None
        alive = True
        def is_alive(self):
            return self.alive
        def join(self, **_kwargs):
            if not force:
                self.alive = False
        def terminate(self):
            self.alive = False
    child = Child()
    assert workers.Spiderling._stop_share_workers([child]) is force
    assert not child.alive


@pytest.mark.parametrize('abandon', [True, False])
def test_only_abandoned_owned_work_queue_skips_feeder_join(abandon):
    actions = []
    process_queue = SimpleNamespace(cancel_join_thread=lambda: actions.append('cancel'),
                                    close=lambda: actions.append('close'), join_thread=lambda: actions.append('join'))
    workers.Spiderling._close_process_queue(process_queue, abandon=abandon)
    assert actions == (['cancel', 'close'] if abandon else ['close', 'join'])


def _abandon_real_full_work_queue():
    pending = multiprocessing.get_context('spawn').JoinableQueue()
    pending.put(b'x' * (512 * 1024))
    workers.Spiderling._close_process_queue(pending, abandon=True)


def test_real_abandoned_work_queue_with_no_consumers_does_not_hang_process_exit():
    process = multiprocessing.get_context('spawn').Process(target=_abandon_real_full_work_queue)
    process.start()
    try:
        process.join(timeout=5)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=5)


class _ReadySlots:
    def __init__(self, semaphore, ready):
        self.semaphore, self.ready = semaphore, ready

    def acquire(self, **kwargs):
        self.ready.set()
        return self.semaphore.acquire(**kwargs)

    def release(self):
        return self.semaphore.release()


def _real_share_signal_entry(stage, ready, cleanup_ready, cleaned, semaphore, errors, stopped, stderr_path):
    # Keep fd 2 redirected through multiprocessing's own bootstrap exception
    # printer, not merely while the target's context manager is active.
    with open(stderr_path, 'w', encoding='utf-8') as stream:
        os.dup2(stream.fileno(), 2)

    def wait_for_signal():
        ready.set()
        time.sleep(30)

    def logging(_queue):
        if stage == 'logging':
            wait_for_signal()

    class Worker:
        def _consume_share_queue(self, *_args):
            if stage in ('consume', 'repeat'):
                wait_for_signal()

        def _close_share_worker(self):
            try:
                if stage == 'cleanup':
                    wait_for_signal()
                elif stage == 'repeat':
                    cleanup_ready.set()
                    time.sleep(0.2)
            finally:
                cleaned.set()

    def create(*_args):
        if stage == 'create':
            wait_for_signal()
        return Worker()

    workers.configure_worker_logging = logging
    workers.Spiderling._create_share_worker = create
    slots = _ReadySlots(semaphore, ready) if stage == 'semaphore' else semaphore
    workers._run_share_worker_process('fixture', SimpleNamespace(log_queue=None, share_worker_slots=slots),
                                      None, {}, None, stopped, errors)


@pytest.mark.skipif(os.name != 'posix', reason='POSIX signal delivery')
@pytest.mark.parametrize('stage', ['logging', 'semaphore', 'create', 'consume', 'cleanup', 'repeat'])
def test_real_spawn_worker_sigint_is_quiet_in_setup_wait_and_cleanup(tmp_path, stage):
    context = multiprocessing.get_context('spawn')
    ready, cleanup_ready, cleaned, stopped = (context.Event() for _ in range(4))
    semaphore, errors = context.BoundedSemaphore(1), context.Queue()
    if stage == 'semaphore':
        semaphore.acquire()
    stderr_path = tmp_path / 'worker-stderr.txt'
    process = context.Process(target=_real_share_signal_entry,
                              args=(stage, ready, cleanup_ready, cleaned, semaphore, errors, stopped, str(stderr_path)))
    process.start()
    try:
        assert ready.wait(5), 'worker did not reach its selected interruption point'
        os.kill(process.pid, signal.SIGINT)
        if stage == 'repeat':
            assert cleanup_ready.wait(5)
            os.kill(process.pid, signal.SIGINT)
        process.join(timeout=5)
        assert process.exitcode == 130
        assert stopped.is_set()
        assert errors.get(timeout=1) == ('KeyboardInterrupt', '')
        assert stderr_path.read_text() == ''
        assert cleaned.is_set() == (stage in ('consume', 'cleanup', 'repeat'))
        if stage == 'semaphore':
            semaphore.release()
        assert semaphore.acquire(timeout=1)
        semaphore.release()
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        errors.close()
        errors.join_thread()


def _slow_local_worker_entry(target, arguments):
    original = workers.Spiderling.process_file

    def slow_file(worker, file):
        original(worker, file)
        worker.flush_state_completions()
        time.sleep(0.04)

    workers.Spiderling.process_file = slow_file
    pid_path = os.environ.get('MANSPIDER_TEST_WORKER_PID')
    if pid_path:
        Path(pid_path).write_text(str(os.getpid()))
    target(*arguments)


class _SlowSpawnContext:
    @staticmethod
    def Process(*, target, args, **kwargs):
        return multiprocessing.get_context('spawn').Process(target=_slow_local_worker_entry,
                                                            args=(target, args), **kwargs)


class _SlowLocalScanner(MANSPIDER):
    def __init__(self, options):
        super().__init__(options)
        self.process_context = _SlowSpawnContext()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process-group Ctrl+C')
@pytest.mark.parametrize('signal_scope', ['group', 'worker'])
def test_real_local_cli_ctrl_c_is_quiet_and_resume_preserves_completed_files(tmp_path, signal_scope):
    source = tmp_path / 'source'
    source.mkdir()
    for index in range(40):
        (source / f'fixture-{index:02d}.txt').write_text('synthetic fixture\n')
    database = tmp_path / 'interrupted.sqlite3'
    pid_path = tmp_path / 'worker.pid'
    script = """
import sys
sys.path.insert(0, sys.argv[1])
import test_worker_interrupts as fixtures
import man_spider.manspider as module
module.MANSPIDER = fixtures._SlowLocalScanner
raise SystemExit(module.main([sys.argv[2], '-e', 'txt', '--yes', '--state-file', sys.argv[3]]))
"""
    process = subprocess.Popen([sys.executable, '-c', script, str(Path(__file__).parent), str(source), str(database)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
                               env={**os.environ, 'MANSPIDER_TEST_WORKER_PID': str(pid_path)})
    try:
        deadline = time.monotonic() + 10
        observed = 0
        while time.monotonic() < deadline:
            if database.exists():
                try:
                    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
                        observed = connection.execute("SELECT COUNT(*) FROM objects WHERE kind='file' AND status='processed'").fetchone()[0]
                except sqlite3.Error:
                    pass
                if observed >= 2:
                    break
            time.sleep(0.02)
        assert 2 <= observed < 40
        if signal_scope == 'group':
            os.killpg(process.pid, signal.SIGINT)
        else:
            os.kill(int(pid_path.read_text()), signal.SIGINT)
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 130, stdout + stderr
        assert 'Traceback' not in stdout + stderr
        assert 'KeyboardInterrupt' not in stdout + stderr
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
        assert connection.execute('SELECT status FROM runs').fetchone()[0] == 'interrupted'
        completed = dict(connection.execute("SELECT object_key,attempts FROM objects WHERE kind='file' AND status='processed'"))
    resumed = subprocess.run([sys.executable, '-m', 'man_spider.manspider', str(source), '-e', 'txt', '--yes',
                              '--resume', str(database)], capture_output=True, text=True, timeout=15)
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    assert 'Traceback' not in resumed.stdout + resumed.stderr
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
        assert connection.execute('SELECT status FROM runs').fetchone()[0] == 'complete'
        assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        current = dict(connection.execute("SELECT object_key,attempts FROM objects WHERE kind='file' AND status='processed'"))
        assert len(current) == 40
        assert {key: current[key] for key in completed} == completed
