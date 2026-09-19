"""Idle admission is distinct from cancellation; all process tests are SMB-free."""

from contextlib import suppress
import multiprocessing
import os
import queue
import signal
import threading
from types import SimpleNamespace

import pytest

import man_spider.lib.spiderling as workers
from man_spider.state import StateError


class _CapturedSpawnContext:
    """Record only this test coordinator's children for bounded cleanup."""

    def __init__(self):
        self.events = []
        self.children = []

    def __getstate__(self):
        # The configuration crosses spawn; live Process objects must not.
        return {}

    def __setstate__(self, _state):
        self.__init__()

    @staticmethod
    def JoinableQueue():
        return multiprocessing.get_context("spawn").JoinableQueue()

    @staticmethod
    def Queue():
        return multiprocessing.get_context("spawn").Queue()

    def Event(self):
        event = multiprocessing.get_context("spawn").Event()
        self.events.append(event)
        return event

    def Process(self, **kwargs):
        child = multiprocessing.get_context("spawn").Process(**kwargs)
        self.children.append(child)
        return child


def _run_exhausted_coordinator(report):
    # A private process group lets the test reap the whole owned tree even if
    # a future regression defeats both the product and the local watchdog.
    os.setsid()
    context = _CapturedSpawnContext()
    slots = multiprocessing.get_context("spawn").BoundedSemaphore(0)
    coordinator = workers.Spiderling.__new__(workers.Spiderling)
    coordinator.parent = SimpleNamespace(
        log_queue=None, share_worker_slots=slots, share_process_context=context,
    )
    coordinator.target = "no-network-fixture"
    coordinator.target_object_id = None
    # Missing auth fields also fail before any SMB constructor if admission
    # were accidentally allowed despite the exhausted semaphore.
    coordinator._session_configuration = dict
    completed = []
    coordinator._dispatch_share_work = completed.append
    forced = threading.Event()

    def unblock_regression():
        forced.set()
        for event in context.events:
            event.set()
        for child in context.children:
            if child.is_alive():
                child.join(timeout=0.5)
            if child.is_alive():
                child.kill()
                child.join(timeout=0.5)

    watchdog = threading.Timer(4, unblock_regression)
    watchdog.daemon = True
    watchdog.start()
    try:
        coordinator._run_parallel_share_work(tuple(range(12)), 3)
        report.send({
            "completed": completed,
            "forced": forced.is_set(),
            "child_exits": [child.exitcode for child in context.children],
            "extra_token_available": slots.acquire(block=False),
        })
    finally:
        watchdog.cancel()
        watchdog.join()
        for child in context.children:
            if child.is_alive():
                child.kill()
                child.join(timeout=1)
        report.close()


@pytest.mark.skipif(os.name != "posix", reason="bounded owned process-group cleanup")
def test_real_spawn_scheduler_completes_when_all_global_slots_are_reserved():
    context = multiprocessing.get_context("spawn")
    report, child_report = context.Pipe(duplex=False)
    process = context.Process(target=_run_exhausted_coordinator, args=(child_report,))
    process.start()
    child_report.close()
    try:
        process.join(timeout=10)
        assert process.exitcode == 0, "coordinator did not finish after queue exhaustion"
        assert report.poll(1)
        result = report.recv()
        assert result == {
            "completed": list(range(12)),
            "forced": False,
            "child_exits": [0, 0],
            "extra_token_available": False,
        }
    finally:
        if process.is_alive():
            with suppress(ProcessLookupError):
                if os.getpgid(process.pid) == process.pid:
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            process.join(timeout=2)
        report.close()


class _ObservedSlots:
    def __init__(self, semaphore, ready, admission_closed, close_on_acquire):
        self.semaphore = semaphore
        self.ready = ready
        self.admission_closed = admission_closed
        self.close_on_acquire = close_on_acquire

    def acquire(self, **kwargs):
        self.ready.set()
        acquired = self.semaphore.acquire(**kwargs)
        if acquired and self.close_on_acquire:
            self.admission_closed.set()
        return acquired

    def release(self):
        self.semaphore.release()


def _run_share_admission_probe(
    stage, semaphore, admission_closed, stopped, errors, work_queue,
    acquired_ready, task_ready, created, cleaned, completed,
):
    workers.configure_worker_logging = lambda _: None

    class ClaimedWorkQueue:
        def get(self):
            item = work_queue.get()
            if item is not None:
                task_ready.set()
                assert admission_closed.wait(5), "test did not close admission"
                if stage == "cancel_active":
                    # Admission closure must not cancel owned work itself.
                    # The test sends an actual SIGINT at this separate gate.
                    assert stopped.wait(5), "test did not interrupt active work"
            return item

        def task_done(self):
            work_queue.task_done()

    class ActiveWorker:
        def _dispatch_share_work(self, _item):
            completed.set()

        def _consume_share_queue(self, _queue, stop):
            workers.Spiderling._consume_share_queue(self, ClaimedWorkQueue(), stop)

        def _close_share_worker(self):
            cleaned.set()

    def create(*_args):
        created.set()
        return ActiveWorker()

    workers.Spiderling._create_share_worker = create
    slots = _ObservedSlots(semaphore, acquired_ready, admission_closed, stage == "close_on_acquire")
    workers._run_share_worker_process(
        "fixture", SimpleNamespace(log_queue=None, share_worker_slots=slots),
        None, {}, work_queue, stopped, errors, admission_closed,
    )


@pytest.mark.parametrize("stage", ["already_closed", "waiting", "close_on_acquire", "claimed_work"])
def test_real_spawn_admission_closure_preserves_tokens_and_claimed_work(stage):
    context = multiprocessing.get_context("spawn")
    admission, stopped, acquired_ready, task_ready, created, cleaned, completed = (
        context.Event() for _ in range(7)
    )
    semaphore, errors, work = context.BoundedSemaphore(1), context.Queue(), context.JoinableQueue()
    if stage == "already_closed":
        admission.set()
    if stage == "waiting":
        semaphore.acquire()
    work.put("claimed")
    work.put(None)
    process = context.Process(target=_run_share_admission_probe, args=(
        stage, semaphore, admission, stopped, errors, work,
        acquired_ready, task_ready, created, cleaned, completed,
    ))
    process.start()
    try:
        if stage == "waiting":
            assert acquired_ready.wait(5)
            admission.set()
        elif stage == "claimed_work":
            assert task_ready.wait(5)
            admission.set()
        process.join(timeout=5)
        assert process.exitcode == 0
        assert not stopped.is_set()
        assert created.is_set() == (stage == "claimed_work")
        assert cleaned.is_set() == (stage == "claimed_work")
        assert completed.is_set() == (stage == "claimed_work")
        with pytest.raises(queue.Empty):
            errors.get_nowait()
        if stage == "waiting":
            semaphore.release()
        assert semaphore.acquire(timeout=1)
        assert not semaphore.acquire(block=False), "global token was released twice"
        semaphore.release()
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=2)
        workers.Spiderling._close_process_queue(work, abandon=True)
        workers.Spiderling._close_process_queue(errors)


@pytest.mark.skipif(os.name != "posix", reason="actual SIGINT delivery")
@pytest.mark.parametrize("stage", ["cancel_waiting", "cancel_active"])
def test_real_spawn_cancellation_with_admission_event_keeps_cleanup(stage):
    context = multiprocessing.get_context("spawn")
    admission, stopped, acquired_ready, task_ready, created, cleaned, completed = (
        context.Event() for _ in range(7)
    )
    semaphore, errors, work = context.BoundedSemaphore(1), context.Queue(), context.JoinableQueue()
    if stage == "cancel_waiting":
        semaphore.acquire()
    work.put("claimed")
    work.put(None)
    process = context.Process(target=_run_share_admission_probe, args=(
        stage, semaphore, admission, stopped, errors, work,
        acquired_ready, task_ready, created, cleaned, completed,
    ))
    process.start()
    try:
        if stage == "cancel_waiting":
            assert acquired_ready.wait(5)
        else:
            assert task_ready.wait(5)
            admission.set()
        os.kill(process.pid, signal.SIGINT)
        process.join(timeout=5)
        assert process.exitcode == 130
        assert stopped.is_set()
        assert errors.get(timeout=1) == ("KeyboardInterrupt", "")
        assert cleaned.is_set() == (stage == "cancel_active")
        assert not completed.is_set()
        if stage == "cancel_waiting":
            semaphore.release()
        assert semaphore.acquire(timeout=1)
        assert not semaphore.acquire(block=False)
        semaphore.release()
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=2)
        workers.Spiderling._close_process_queue(work, abandon=True)
        workers.Spiderling._close_process_queue(errors)


def test_admission_closure_does_not_hide_slot_release_failure(monkeypatch):
    admission, stopped, errors = threading.Event(), threading.Event(), queue.Queue()
    failure = StateError("owned slot release failed")

    class Slots:
        def acquire(self, **_kwargs):
            admission.set()
            return True

        def release(self):
            raise failure

    monkeypatch.setattr(workers, "configure_worker_logging", lambda _: None)
    monkeypatch.setattr(
        workers.Spiderling, "_create_share_worker",
        lambda *_: pytest.fail("closed admission must not create an SMB session"),
    )
    with pytest.raises(StateError) as captured:
        workers._run_share_worker_process(
            "fixture", SimpleNamespace(log_queue=None, share_worker_slots=Slots()),
            None, {}, None, stopped, errors, admission,
        )
    assert captured.value is failure
    assert stopped.is_set()
    assert errors.get_nowait() == ("StateError", str(failure))
