"""Interrupts delivered through other threads during actual process startup."""
import multiprocessing
import os
from pathlib import Path
import signal
import threading
import time
from types import SimpleNamespace

import pytest

import man_spider.lib.spiderling as workers
from man_spider.state import StateError


pytestmark = pytest.mark.skipif(
    os.name != "posix" or not hasattr(signal, "pthread_sigmask"),
    reason="POSIX per-thread signal masks and actual spawn",
)


class _UnpickleGate:
    def __init__(self, root):
        self.root = str(root)

    def __reduce__(self):
        return _restore_gate, (self.root,)


def _restore_gate(root_text):
    root = Path(root_text)
    with (root / "stderr").open("w", encoding="utf-8") as stream:
        os.dup2(stream.fileno(), 2)
    (root / "ready").touch()
    _wait_until(lambda: (root / "release").exists())
    return "local-startup-fixture"


def _wait_until(condition):
    deadline = time.monotonic() + 5
    while not condition():
        if time.monotonic() >= deadline:
            raise AssertionError("startup fixture did not reach its expected gate")
        time.sleep(0.005)


@pytest.fixture
def unmasked_receiver():
    ready, stopped = threading.Event(), threading.Event()

    def receive():
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
        ready.set()
        stopped.wait()

    thread = threading.Thread(target=receive)
    thread.start()
    assert ready.wait(5)
    try:
        yield thread
    finally:
        stopped.set()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.parametrize("interrupt_count", [1, 50])
def test_actual_spawn_registers_child_before_thread_delivered_interrupt_and_keeps_semaphores(
    monkeypatch, tmp_path, unmasked_receiver, interrupt_count,
):
    context = multiprocessing.get_context("spawn")
    slots, stopped, errors = context.BoundedSemaphore(1), context.Event(), context.Queue()
    parent = SimpleNamespace(log_queue=None, share_worker_slots=slots)
    process = context.Process(
        target=workers._run_share_worker_process,
        args=(_UnpickleGate(tmp_path), parent, None, {}, None, stopped, errors),
    )
    original_popen = type(process)._Popen
    raw_children = []
    previous_handler = signal.signal(signal.SIGINT, signal.default_int_handler)
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
    expected_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

    def interrupted_popen(process_object):
        popen = original_popen(process_object)
        raw_children.append(popen)
        _wait_until(lambda: (tmp_path / "ready").exists())
        assert signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, set())
        for _ in range(interrupt_count):
            # The receiver models an already-running Queue feeder. CPython
            # dispatches its received signal in our masked main thread.
            signal.pthread_kill(unmasked_receiver.ident, signal.SIGINT)
            os.kill(popen.pid, signal.SIGINT)
            time.sleep(0.001)
        assert process.pid is None, "gate must precede Process._popen registration"
        return popen

    monkeypatch.setattr(type(process), "_Popen", staticmethod(interrupted_popen))
    try:
        with pytest.raises(KeyboardInterrupt):
            workers._start_worker_process(process)
        assert process.pid == raw_children[0].pid
        assert process.is_alive()
        assert process in multiprocessing.active_children()
        assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == expected_mask
        assert not hasattr(process, "_manspider_startup_sigmask")
        # Owners remain reachable while the registered child is unpickling.
        # Its pending SIGINT must reach the protected product entrypoint.
        (tmp_path / "release").touch()
        process.join(timeout=5)
        assert process.exitcode == 130
        assert (tmp_path / "stderr").read_text(encoding="utf-8") == ""
        assert stopped.is_set()
        assert errors.get(timeout=1) == ("KeyboardInterrupt", "")
        assert slots.acquire(block=False)
        slots.release()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        signal.signal(signal.SIGINT, previous_handler)
        (tmp_path / "release").touch()
        # Also reap an unregistered raw child if this test detects regression.
        for popen in raw_children:
            if popen.poll() is None:
                os.kill(popen.pid, signal.SIGKILL)
                popen.wait(timeout=5)
        errors.close()
        errors.join_thread()


@pytest.mark.parametrize("start_error", [False, True])
@pytest.mark.parametrize("blocked_by_caller", [False, True])
def test_custom_handler_and_exact_mask_restored_after_thread_delivery(
    unmasked_receiver, start_error, blocked_by_caller,
):
    actual = StateError("actual process-start failure")
    events = []

    def custom_handler(signum, _frame):
        events.append(("handler", signum))

    previous_handler = signal.signal(signal.SIGINT, custom_handler)
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    desired = original_mask | {signal.SIGUSR1}
    if blocked_by_caller:
        desired.add(signal.SIGINT)
    else:
        desired.discard(signal.SIGINT)
    signal.pthread_sigmask(signal.SIG_SETMASK, desired)
    previous_attribute = object()

    def start():
        signal.pthread_kill(unmasked_receiver.ident, signal.SIGINT)
        time.sleep(0.03)
        assert events == []
        events.append("start-finished")
        if start_error:
            raise actual

    process = SimpleNamespace(start=start, _manspider_startup_sigmask=previous_attribute)
    try:
        if start_error:
            with pytest.raises(StateError) as captured:
                workers._start_worker_process(process)
            assert captured.value is actual
        else:
            workers._start_worker_process(process)
        assert events == ["start-finished", ("handler", signal.SIGINT)]
        assert signal.getsignal(signal.SIGINT) is custom_handler
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == desired
        assert process._manspider_startup_sigmask is previous_attribute
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        signal.signal(signal.SIGINT, previous_handler)


@pytest.mark.parametrize("handler_error", [KeyboardInterrupt, RuntimeError])
def test_real_start_error_is_not_hidden_by_deferred_handler_error(unmasked_receiver, handler_error):
    actual = StateError("real start failure takes priority")

    def interrupt_handler(_signum, _frame):
        raise handler_error("deferred signal")

    previous_handler = signal.signal(signal.SIGINT, interrupt_handler)

    def start():
        signal.pthread_kill(unmasked_receiver.ident, signal.SIGINT)
        time.sleep(0.03)
        raise actual

    try:
        with pytest.raises(StateError) as captured:
            workers._start_worker_process(SimpleNamespace(start=start))
        assert captured.value is actual
        assert signal.getsignal(signal.SIGINT) is interrupt_handler
    finally:
        signal.signal(signal.SIGINT, previous_handler)


def test_explicitly_ignored_signal_stays_ignored(unmasked_receiver):
    previous_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    completed = []

    def start():
        assert signal.getsignal(signal.SIGINT) is signal.SIG_IGN
        signal.pthread_kill(unmasked_receiver.ident, signal.SIGINT)
        time.sleep(0.02)
        completed.append(True)

    try:
        workers._start_worker_process(SimpleNamespace(start=start))
        assert completed == [True]
        assert signal.getsignal(signal.SIGINT) is signal.SIG_IGN
    finally:
        signal.signal(signal.SIGINT, previous_handler)


def test_non_main_thread_rejected_before_process_start_without_changing_signal_state():
    results = []
    started = []
    previous_handler = signal.getsignal(signal.SIGINT)

    def invoke():
        before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        try:
            workers._start_worker_process(SimpleNamespace(start=lambda: started.append(True)))
        except RuntimeError as exc:
            results.append(str(exc))
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == before

    thread = threading.Thread(target=invoke)
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert started == []
    assert results == ["MANSPIDER worker processes must be started from the main thread"]
    assert signal.getsignal(signal.SIGINT) is previous_handler
