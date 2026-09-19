"""Small real-process regressions for cancellation and process-family ownership.

Signals affect only disposable local fixture processes. No SMB connections or
customer files are involved; CLI/state/reporting and shutdown remain production
code. The adversarial worker bodies deliberately model dependency failures.
"""

import errno
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not Path("/proc").is_dir(),
    reason="Linux process-family inventory and actual POSIX signal delivery",
)
REPOSITORY = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("change", [None, "started", "session", "gone"])
def test_pidfd_signal_rechecks_identity_before_sending_and_closes_descriptor(monkeypatch, change):
    from man_spider.lib import process_lifecycle as lifecycle

    identity = lifecycle.ProcessIdentity(54321, 123, 54321, 54321, 987654, "S")
    current = identity
    if change == "started":
        current = lifecycle.ProcessIdentity(54321, 123, 54321, 54321, 987655, "S")
    elif change == "session":
        current = lifecycle.ProcessIdentity(54321, 123, 54321, 11111, 987654, "S")
    elif change == "gone":
        current = None
    events = []
    monkeypatch.setattr(
        lifecycle,
        "os",
        SimpleNamespace(
            pidfd_open=lambda pid: (events.append(("open", pid)), 77)[1],
            close=lambda fd: events.append(("close", fd)),
            kill=lambda *_: pytest.fail("pidfd-capable path must not signal a bare numeric PID"),
        ),
    )
    monkeypatch.setattr(
        lifecycle,
        "signal",
        SimpleNamespace(
            pidfd_send_signal=lambda fd, signum: events.append(("signal", fd, signum)),
        ),
    )
    monkeypatch.setattr(lifecycle, "_identity", lambda _pid: current)
    lifecycle._send(identity, signal.SIGTERM)
    expected = [("open", identity.pid)]
    if change is None:
        expected.append(("signal", 77, signal.SIGTERM))
    expected.append(("close", 77))
    assert events == expected


def test_owned_family_excludes_caller_session_older_processes_and_zombies(monkeypatch):
    from man_spider.lib import process_lifecycle as lifecycle

    records = {
        100: lifecycle.ProcessIdentity(100, 50, 100, 100, 1000, "S"),
        101: lifecycle.ProcessIdentity(101, 100, 100, 100, 1001, "S"),
        102: lifecycle.ProcessIdentity(102, 100, 100, 100, 1002, "Z"),
        103: lifecycle.ProcessIdentity(103, 50, 50, 50, 1003, "S"),
        104: lifecycle.ProcessIdentity(104, 1, 100, 100, 999, "S"),
        105: lifecycle.ProcessIdentity(105, 1, 105, 100, 1004, "S"),
    }
    family = lifecycle.OwnedScanFamily()
    family.leader = records[100]
    monkeypatch.setattr(lifecycle, "_PROC", SimpleNamespace(iterdir=lambda: [Path(str(pid)) for pid in records]))
    monkeypatch.setattr(lifecycle, "_identity", records.get)
    assert {member.pid for member in family.members()} == {100, 101, 105}
    assert {member.pid for member in family.members(exclude_leader=True)} == {101, 105}


@pytest.mark.parametrize("still_owned", [True, False])
def test_pidfd_enosys_fallback_rechecks_identity_before_numeric_signal(monkeypatch, still_owned):
    from man_spider.lib import process_lifecycle as lifecycle

    identity = lifecycle.ProcessIdentity(54321, 123, 54321, 54321, 987654, "S")
    current = identity if still_owned else lifecycle.ProcessIdentity(54321, 1, 555, 555, 987655, "S")
    events = []

    def unsupported(pid):
        events.append(("open", pid))
        raise OSError(errno.ENOSYS, "synthetic old kernel")

    monkeypatch.setattr(
        lifecycle,
        "os",
        SimpleNamespace(
            pidfd_open=unsupported,
            close=lambda _fd: pytest.fail("failed pidfd_open did not create a descriptor"),
            kill=lambda pid, signum: events.append(("kill", pid, signum)),
        ),
    )
    monkeypatch.setattr(
        lifecycle,
        "signal",
        SimpleNamespace(
            pidfd_send_signal=lambda *_: pytest.fail("no pidfd exists on this synthetic kernel"),
        ),
    )
    monkeypatch.setattr(lifecycle, "_identity", lambda _pid: current)
    lifecycle._send(identity, signal.SIGTERM)
    expected = [("open", identity.pid)]
    if still_owned:
        expected.append(("kill", identity.pid, signal.SIGTERM))
    assert events == expected


@pytest.mark.parametrize("error_number", [errno.EPERM, errno.EINVAL, errno.EMFILE])
def test_pidfd_failure_other_than_enosys_is_not_downgraded_to_numeric_signal(monkeypatch, error_number):
    from man_spider.lib import process_lifecycle as lifecycle

    identity = lifecycle.ProcessIdentity(54321, 123, 54321, 54321, 987654, "S")

    def failed(_pid):
        raise OSError(error_number, "synthetic unexpected pidfd failure")

    monkeypatch.setattr(
        lifecycle,
        "os",
        SimpleNamespace(
            pidfd_open=failed,
            close=lambda _fd: pytest.fail("failed pidfd_open did not create a descriptor"),
            kill=lambda *_: pytest.fail("unexpected pidfd failure must not bypass the pidfd path"),
        ),
    )
    with pytest.raises(OSError) as caught:
        lifecycle._send(identity, signal.SIGTERM)
    assert caught.value.errno == error_number


def _dead_leader_ready_child(connection):
    from man_spider.lib.process_lifecycle import enter_scan_process_group

    ready = enter_scan_process_group()
    child = os.fork()
    if child == 0:
        connection.close()
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        while True:
            signal.pause()
    connection.send((ready, child))
    connection.close()
    os._exit(0)


def test_trusted_ready_after_actual_leader_reaping_still_owns_and_stops_orphan():
    from man_spider.lib import process_lifecycle as lifecycle

    context = multiprocessing.get_context("fork")
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(target=_dead_leader_ready_child, args=(sending,))
    process.start()
    sending.close()
    family = lifecycle.OwnedScanFamily()
    orphan = None
    try:
        assert receiving.poll(5)
        ready, orphan_pid = receiving.recv()
        process.join(timeout=5)
        assert process.exitcode == 0
        assert lifecycle._identity(process.pid) is None, "leader must actually be reaped before ready acceptance"
        assert family.accept(ready, process)
        members = family.members()
        assert {member.pid for member in members} == {orphan_pid}
        orphan = members[0]
        assert family.stop(grace=0.05, terminate_grace=0.5, kill_grace=0.5)
        assert family.members() == []
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        if orphan is not None:
            lifecycle._send(orphan, signal.SIGKILL)
        receiving.close()


@pytest.mark.parametrize("pid,started", [(99, 1000), (True, 1000), (100, True), (100, -1)])
def test_dead_leader_ready_rejects_wrong_pid_or_noncanonical_identity(monkeypatch, pid, started):
    from man_spider.lib import process_lifecycle as lifecycle

    family = lifecycle.OwnedScanFamily()
    monkeypatch.setattr(lifecycle, "_identity", lambda _pid: None)
    with pytest.raises(lifecycle.ProcessCleanupError):
        family.accept((lifecycle.SESSION_MESSAGE, pid, started), SimpleNamespace(pid=100))
    assert family.leader is None


def _identity(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rfind(")") + 2 :].split()
        return {
            "pid": pid,
            "state": fields[0],
            "pgid": int(fields[2]),
            "sid": int(fields[3]),
            "starttime": int(fields[19]),
        }
    except (OSError, ValueError, IndexError):
        return None


def _alive(identity):
    current = _identity(identity["pid"])
    return bool(current and current["starttime"] == identity["starttime"] and current["state"] not in ("Z", "X"))


def _record(directory, name, value):
    (Path(directory) / name).write_text(json.dumps(value), encoding="utf-8")


def _read(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _wait_record(path, process=None, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = _read(path)
        if value is not None:
            return value
        if process is not None and process.poll() is not None:
            break
        time.sleep(0.01)
    pytest.fail(f"Fixture did not publish {path.name}")


def _swallowed_signal_child(connection):
    from man_spider.lib import cancellation
    from man_spider.lib.spiderling import (
        _ignore_worker_interrupts,
        _install_worker_interrupt_handler,
    )

    _install_worker_interrupt_handler()
    unraisable = []
    sys.unraisablehook = lambda event: unraisable.append(event.exc_type.__name__)

    class InterruptingDestructor:
        def __del__(self):
            os.kill(os.getpid(), signal.SIGINT)

    victim = InterruptingDestructor()
    del victim
    observed = {"unraisable": unraisable, "checkpoint_cancelled": False}
    try:
        cancellation.check_worker_cancellation()
    except KeyboardInterrupt:
        observed["checkpoint_cancelled"] = True
        _ignore_worker_interrupts()
    for _ in range(10):
        os.kill(os.getpid(), signal.SIGINT)
    cancellation.check_worker_cancellation()
    observed["cleanup_survived_burst"] = True
    connection.send(observed)
    connection.close()


def test_actual_sigint_swallowed_by_destructor_remains_latched_for_checkpoint():
    context = multiprocessing.get_context("spawn")
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(target=_swallowed_signal_child, args=(sending,))
    process.start()
    sending.close()
    try:
        assert receiving.poll(8), "worker lost cancellation or failed before publishing evidence"
        result = receiving.recv()
        process.join(timeout=5)
        assert process.exitcode == 0
        assert result == {
            "unraisable": ["KeyboardInterrupt"],
            "checkpoint_cancelled": True,
            "cleanup_survived_burst": True,
        }
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        receiving.close()


def _cleanup_sigterm_child(connection):
    from man_spider.lib.spiderling import (
        _ignore_worker_interrupts,
        _install_worker_interrupt_handler,
    )

    _install_worker_interrupt_handler()
    _ignore_worker_interrupts()
    os.kill(os.getpid(), signal.SIGINT)
    connection.send({"term_is_default": signal.getsignal(signal.SIGTERM) == signal.SIG_DFL})
    try:
        while True:
            signal.pause()
    except KeyboardInterrupt:
        # The old fork-inherited supervisor handler incorrectly reaches here.
        connection.send({"cleanup_interrupted_by_python_handler": True})
        raise SystemExit(42)


def test_fork_cleanup_sigterm_does_not_inherit_supervisor_keyboardinterrupt():
    import man_spider.manspider as cli

    context = multiprocessing.get_context("fork")
    receiving, sending = context.Pipe(duplex=False)
    with cli._SupervisorInterrupts():
        process = context.Process(target=_cleanup_sigterm_child, args=(sending,))
        process.start()
    sending.close()
    try:
        assert receiving.poll(5)
        assert receiving.recv() == {"term_is_default": True}
        os.kill(process.pid, signal.SIGTERM)
        process.join(timeout=5)
        assert process.exitcode == -signal.SIGTERM
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        receiving.close()


def _rogue_worker(directory, scenario):
    from man_spider.lib.spiderling import _install_worker_interrupt_handler

    # Process startup intentionally inherits a blocked SIGINT. Enter through
    # the real worker initializer before replacing only the adversarial body.
    _install_worker_interrupt_handler()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    def spawn_after_cancellation(_signum, _frame):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        child = os.fork()
        if child == 0:
            _record(directory, "late-child.json", _identity(os.getpid()))
            while True:
                signal.pause()

    signal.signal(
        signal.SIGINT,
        spawn_after_cancellation if scenario == "late-child" else signal.SIG_IGN,
    )
    _record(directory, "worker.json", _identity(os.getpid()))
    while True:
        signal.pause()


def _fault_target_worker(target, parent, directory):
    import man_spider.lib.spiderling as workers

    original = workers.Spiderling.process_file
    triggered = False
    unraisable = []
    sys.unraisablehook = lambda event: unraisable.append(event.exc_type.__name__)

    class InterruptingDestructor:
        def __del__(self):
            os.kill(os.getpid(), signal.SIGINT)

    def process_file(worker, file):
        nonlocal triggered
        if not triggered:
            triggered = True
            victim = InterruptingDestructor()
            del victim
            _record(directory, "destructor.json", {"unraisable": unraisable})
        return original(worker, file)

    workers.Spiderling.process_file = process_file
    _record(directory, "worker.json", _identity(os.getpid()))
    workers._run_target_worker_process(target, parent)


def _drive_cli(directory, scenario, arguments):
    """Inject adversarial work only, keeping actual CLI shutdown and state I/O."""

    import man_spider.manspider as cli
    from man_spider.lib.errors import ReadOnlySMBViolation
    from man_spider.lib.spider import MANSPIDER
    from man_spider.lib.spiderling import _start_worker_process
    from man_spider.state import StateError

    def observe_finalization(stage):
        living = []
        for name in ("worker.json", "late-child.json"):
            identity = _read(Path(directory) / name)
            if identity and _alive(identity):
                living.append(identity)
        _record(
            directory,
            f"finalization-{os.getpid()}-{time.monotonic_ns()}.json",
            {"stage": stage, "live_writers": living},
        )

    real_json_report = cli.write_json_report
    real_set_run_status = cli.ScanState.set_run_status
    real_finish = cli.ScanState.finish

    def write_json_report(*args, **kwargs):
        observe_finalization("json")
        return real_json_report(*args, **kwargs)

    def set_run_status(state, status, *args, **kwargs):
        if status in ("interrupted", "complete", "complete_with_errors"):
            observe_finalization("status:" + status)
        return real_set_run_status(state, status, *args, **kwargs)

    def finish(state, *args, **kwargs):
        observe_finalization("finish")
        return real_finish(state, *args, **kwargs)

    cli.write_json_report = write_json_report
    cli.ScanState.set_run_status = set_run_status
    cli.ScanState.finish = finish

    class FixtureScanner(MANSPIDER):
        def stop_workers(self):
            failure = sys.exception()
            if scenario.endswith("-cancel") and isinstance(failure, (ReadOnlySMBViolation, StateError)):
                _record(
                    directory,
                    "failure-pending.json",
                    {
                        "type": type(failure).__name__,
                        "stage": "actual exception caught; worker cleanup entered",
                    },
                )
            return super().stop_workers()

        def _start(self):
            _record(directory, "coordinator.json", _identity(os.getpid()))
            if scenario == "swallowed":
                child = self.process_context.Process(
                    target=_fault_target_worker,
                    args=(self.targets[0], self.worker_context(), directory),
                )
            else:
                child_scenario = "late-child" if "-priority" in scenario else scenario
                child = self.process_context.Process(target=_rogue_worker, args=(directory, child_scenario))
            self.spiderling_pool[0] = child
            _start_worker_process(child)
            deadline = time.monotonic() + 8
            while _read(Path(directory) / "worker.json") is None:
                if time.monotonic() >= deadline:
                    raise RuntimeError("fixture child startup timed out")
                time.sleep(0.01)
            if scenario == "abrupt-coordinator":
                os._exit(23)
            if scenario.startswith("safety-priority"):
                raise ReadOnlySMBViolation("synthetic safety evidence before cancellation")
            if scenario.startswith("state-priority"):
                raise StateError("synthetic state evidence before cancellation")
            if scenario == "swallowed":
                child.join()
                self.ensure_worker_succeeded(child)
                return
            while True:
                signal.pause()

    # This sibling belongs to the inherited CLI group, not the scanner family.
    # Incorrect killpg(os.getpgrp(), ...) kills it and fails the assertion below.
    sentinel = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _record(directory, "sentinel.json", _identity(sentinel.pid))
    cli.MANSPIDER = FixtureScanner
    result = 99
    try:
        result = cli.main(arguments)
        _record(directory, "returned.json", {"exitcode": result, "sentinel_alive": sentinel.poll() is None})
    finally:
        if sentinel.poll() is None:
            sentinel.terminate()
        sentinel.wait(timeout=5)
    raise SystemExit(result)


def _rejected_resume_driver(directory, arguments):
    """Hold only the reporting boundary after a real incompatible resume."""

    import man_spider.manspider as cli

    real_output = cli._emit_terminal_output_best_effort

    def output(state, state_path, run_id, options, **kwargs):
        if run_id is None:
            _record(directory, "coordinator.json", _identity(os.getpid()))
            _record(directory, "rejection-ready.json", {"caught_real_resume_error": True})
            time.sleep(0.2)
        return real_output(state, state_path, run_id, options, **kwargs)

    cli._emit_terminal_output_best_effort = output
    raise SystemExit(cli.main(arguments))


def _interrupt_after_completed_leaf(target, parent):
    import man_spider.lib.spiderling as workers

    directory = Path(target).parent
    original_leave = workers.Spiderling.leave_local_directory
    signalled = False

    def leave(worker, path):
        nonlocal signalled
        result = original_leave(worker, path)
        if not signalled and Path(path) != Path(target):
            signalled = True
            objects = [
                dict(row)
                for row in worker.open_state().connection.execute(
                    "SELECT object_key,kind,path,status,attempts FROM objects ORDER BY object_id"
                )
            ]
            _record(directory, "leaf-boundary.json", {"completed_leaf": str(path), "objects": objects})
            # A real interrupt exactly between a finished leaf and discovery
            # of its next sibling; do not mutate manifest status for the test.
            os.kill(os.getpid(), signal.SIGINT)
        return result

    _record(directory, "worker.json", _identity(os.getpid()))
    _record(directory, "coordinator.json", _identity(os.getppid()))
    workers.Spiderling.leave_local_directory = leave
    workers._run_target_worker_process(target, parent)


def _leaf_boundary_driver(arguments):
    import man_spider.manspider as cli
    import man_spider.lib.spider as spider

    spider._run_target_worker_process = _interrupt_after_completed_leaf
    raise SystemExit(cli.main(arguments))


def test_resume_after_completed_local_leaf_discovers_every_unvisited_sibling(tmp_path):
    source = tmp_path / "source"
    for group in range(3):
        directory = source / f"department-{group}"
        directory.mkdir(parents=True)
        for index in range(2):
            (directory / f"secret-{index}.txt").write_text(f"password=SyntheticBoundaryValue{group}{index}\n")
    initial = {str(path): (path.read_bytes(), path.stat().st_mtime_ns) for path in source.rglob("*.txt")}
    database = tmp_path / "scan.sqlite3"
    common = [str(source), "-e", "txt", "-c", "password", "-t", "1", "--yes", "--json"]
    script = (
        "import json, sys; sys.path.insert(0, sys.argv[1]); "
        "import test_cancellation_lifecycle as fixture; fixture._leaf_boundary_driver(json.loads(sys.argv[2]))"
    )
    with (tmp_path / "interrupted.log").open("w") as stream:
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(Path(__file__).parent),
                json.dumps([*common, "--state-file", str(database)]),
            ],
            cwd=REPOSITORY,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            process.wait(timeout=15)
            assert process.returncode == 130, (tmp_path / "interrupted.log").read_text()
            boundary = _read(tmp_path / "leaf-boundary.json")
            assert boundary is not None
        finally:
            _cleanup_owned_fixture(process, tmp_path)
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone()[0] == "interrupted"
        completed = dict(
            connection.execute("SELECT object_key,attempts FROM objects WHERE kind='file' AND status='processed'")
        )
        assert len(completed) == 2
        with sqlite3.connect(tmp_path / "interrupted-copy.sqlite3") as copy:
            connection.backup(copy)
    resumed = subprocess.run(
        [sys.executable, "-m", "man_spider.manspider", *common, "--resume", str(database)],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        timeout=15,
        start_new_session=True,
    )
    (tmp_path / "resumed.log").write_text(resumed.stdout + resumed.stderr)
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT status FROM runs").fetchone()[0] == "complete"
        current = dict(
            connection.execute("SELECT object_key,attempts FROM objects WHERE kind='file' AND status='processed'")
        )
        assert len(current) == 6, {"boundary": boundary, "final_files": current}
        assert {key: current[key] for key in completed} == completed
        assert connection.execute("SELECT count(*) FROM findings").fetchone()[0] == 6
        assert (
            connection.execute("SELECT count(*) FROM objects WHERE status IN ('pending','in_progress')").fetchone()[0]
            == 0
        )
    assert {str(path): (path.read_bytes(), path.stat().st_mtime_ns) for path in source.rglob("*.txt")} == initial


@pytest.mark.parametrize("initial_status", ["running", "interrupted"])
@pytest.mark.parametrize("interrupt_during_rejection", [False, True])
def test_rejected_legacy_resume_keeps_previous_database_and_json_even_during_ctrl_c(
    tmp_path,
    initial_status,
    interrupt_during_rejection,
):
    from man_spider.cli import parse_options
    from man_spider.output import write_json_report
    from man_spider.policy import apply_scope_policy, estimate_scope
    from man_spider.state import FindingRecord, ScanState, normalized_scan_configuration

    source = tmp_path / "source"
    source.mkdir()
    database = tmp_path / "legacy.sqlite3"
    report = tmp_path / "legacy.json"
    common = [str(source), "-e", "txt", "--dirnames", "finance/reports", "--yes", "--json-file", str(report)]
    options = parse_options([*common, "--state-file", str(database)])
    apply_scope_policy(options, estimate_scope(options))
    configuration = normalized_scan_configuration(options)
    configuration["semantic"]["scope"]["directories"] = ["finance/reports"]
    state = ScanState.create(database, configuration, "synthetic-legacy")
    decision = state.claim_object(object_key="retained-legacy-object", kind="file", path="secret.txt")
    state.complete_object(decision.object_id, "processed", findings=[FindingRecord("fixture", "RetainedValue")])
    state.set_run_status(initial_status, reason="original diagnostic must remain unchanged")
    write_json_report(state, report, overwrite=False)
    state.close()
    before_database, before_json = database.read_bytes(), report.read_bytes()
    arguments = [*common, "--resume", str(database)]
    script = (
        "import json, sys; sys.path.insert(0, sys.argv[1]); "
        "import test_cancellation_lifecycle as fixture; "
        "fixture._rejected_resume_driver(sys.argv[2], json.loads(sys.argv[3]))"
    )
    with (tmp_path / "rejected.log").open("w") as stream:
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(Path(__file__).parent), str(tmp_path), json.dumps(arguments)],
            cwd=REPOSITORY,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            ready = _wait_record(tmp_path / "rejection-ready.json", process)
            assert ready == {"caught_real_resume_error": True}
            if interrupt_during_rejection:
                process.send_signal(signal.SIGINT)
            process.wait(timeout=10)
            assert process.returncode == 5, (tmp_path / "rejected.log").read_text()
            assert database.read_bytes() == before_database
            assert report.read_bytes() == before_json
        finally:
            _cleanup_owned_fixture(process, tmp_path)


def _cleanup_owned_fixture(process, directory):
    """Never use a guessed/shared group; PID reuse is checked before cleanup."""

    for name in ("late-child.json", "worker.json", "coordinator.json", "sentinel.json"):
        identity = _read(directory / name)
        if identity and _alive(identity):
            try:
                os.kill(identity["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
    # This group was created by Popen exclusively for this fixture and its
    # sibling. Production may have moved scanner descendants into another one.
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


@pytest.mark.parametrize(
    "scenario",
    [
        "swallowed",
        "late-child",
        "abrupt-coordinator",
        "safety-priority",
        "state-priority",
        "safety-priority-cancel",
        "state-priority-cancel",
    ],
)
def test_cli_stops_entire_owned_family_before_return_and_report(tmp_path, scenario):
    source = tmp_path / "source"
    source.mkdir()
    for index in range(12):
        (source / f"fixture-{index:02d}.txt").write_text("password=SyntheticLocalOnly#2026\n")
    database = tmp_path / "state.sqlite3"
    report = tmp_path / "state.json"
    arguments = [
        str(source),
        "-e",
        "txt",
        "-c",
        "password",
        "-t",
        "1",
        "--yes",
        "--state-file",
        str(database),
        "--json-file",
        str(report),
    ]
    script = (
        "import json, sys; sys.path.insert(0, sys.argv[1]); "
        "import test_cancellation_lifecycle as fixture; "
        "fixture._drive_cli(sys.argv[2], sys.argv[3], json.loads(sys.argv[4]))"
    )
    log_path = tmp_path / "cli.log"
    with log_path.open("w") as stream:
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(Path(__file__).parent), str(tmp_path), scenario, json.dumps(arguments)],
            cwd=REPOSITORY,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            coordinator = _wait_record(tmp_path / "coordinator.json", process)
            worker = _wait_record(tmp_path / "worker.json", process)
            sentinel = _wait_record(tmp_path / "sentinel.json", process)
            assert coordinator["pgid"] == coordinator["pid"]
            assert worker["pgid"] == coordinator["pgid"]
            assert sentinel["pgid"] == process.pid != coordinator["pgid"]
            if scenario == "late-child":
                process.send_signal(signal.SIGINT)
            elif scenario.endswith("-cancel"):
                pending = _wait_record(tmp_path / "failure-pending.json", process)
                expected_failure = "ReadOnlySMBViolation" if scenario.startswith("safety") else "StateError"
                assert pending["type"] == expected_failure
                process.send_signal(signal.SIGINT)
            process.wait(timeout=35)
            output = log_path.read_text()
            returned = _read(tmp_path / "returned.json")
            assert returned is not None, output[-10000:]
            assert returned["sentinel_alive"], "shutdown signalled a non-scan sibling"
            assert returned["exitcode"] == process.returncode
            if scenario == "abrupt-coordinator":
                assert process.returncode != 0
            else:
                expected_exit = 8 if scenario.startswith("safety") else 5 if scenario.startswith("state") else 130
                assert process.returncode == expected_exit, output[-10000:]
            identities = [coordinator, worker]
            if scenario == "late-child" or "-priority" in scenario:
                late_child = _read(tmp_path / "late-child.json")
                assert late_child is not None, "worker never exercised a late descendant spawn"
                assert late_child["pgid"] == coordinator["pgid"]
                identities.append(late_child)
            assert not [identity for identity in identities if _alive(identity)], output[-10000:]
            finalizations = [_read(path) for path in tmp_path.glob("finalization-*.json")]
            assert finalizations, "fixture observed no terminal state/report operations"
            assert all(not event["live_writers"] for event in finalizations), finalizations
            with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
                assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                assert connection.execute("SELECT status FROM runs").fetchone()[0] == "interrupted"
                count = connection.execute(
                    "SELECT COUNT(*) FROM objects WHERE kind='file' AND status='processed'"
                ).fetchone()[0]
            if scenario == "swallowed":
                assert _read(tmp_path / "destructor.json") == {"unraisable": ["KeyboardInterrupt"]}
                assert count < 12, "swallowed cancellation allowed the worker to finish its entire scan"
            snapshot = report.read_bytes()
            assert json.loads(snapshot)["run_status"] == "interrupted"
            time.sleep(0.1)
            assert report.read_bytes() == snapshot
        finally:
            _cleanup_owned_fixture(process, tmp_path)
