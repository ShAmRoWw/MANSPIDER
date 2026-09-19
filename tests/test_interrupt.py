import json
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from man_spider.lib.file import RemoteFile
from man_spider.lib.spider import MANSPIDER
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.state import StateError


def test_file_parser_keyboard_interrupt_propagates(tmp_path):
    class InterruptingParser:
        def parse_file(self, *_args, **_kwargs):
            raise KeyboardInterrupt

    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(parser=InterruptingParser())
    candidate = tmp_path / "interrupted.txt"
    candidate.write_text("fixture", encoding="utf-8")

    with pytest.raises(KeyboardInterrupt):
        worker.parse_file(candidate)


def test_file_parser_persistent_state_failure_propagates(tmp_path):
    class FailingStateParser:
        def parse_file(self, *_args, **_kwargs):
            raise StateError("SQLite fixture failed")

    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(parser=FailingStateParser())
    candidate = tmp_path / "state-failed.txt"
    candidate.write_text("fixture", encoding="utf-8")

    with pytest.raises(StateError, match="SQLite fixture failed"):
        worker.parse_file(candidate)


def test_file_parser_keyboard_interrupt_removes_remote_temporary_file(tmp_path):
    class InterruptingParser:
        def parse_file(self, *_args, **_kwargs):
            raise KeyboardInterrupt

    remote = RemoteFile("interrupted.txt", "share", Target("server"), tmp_dir=tmp_path)
    remote.tmp_filename = tmp_path / "downloaded.txt"
    remote.tmp_filename.write_text("partial download")
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(parser=InterruptingParser())

    with pytest.raises(KeyboardInterrupt):
        worker.parse_file(remote)

    assert remote._tmp_filename is None
    assert not (tmp_path / "downloaded.txt").exists()


def test_file_parser_error_removes_remote_temporary_file(tmp_path):
    class FailingParser:
        def parse_file(self, *_args, **_kwargs):
            raise ValueError("parser failed")

    remote = RemoteFile("failed.txt", "share", Target("server"), tmp_dir=tmp_path)
    remote.tmp_filename = tmp_path / "downloaded.txt"
    remote.tmp_filename.write_text("downloaded content")
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(parser=FailingParser())
    completed = []
    worker.complete_file = lambda file, status, reason=None: completed.append((file, status, reason))

    worker.parse_file(remote)

    assert completed == [(remote, "error", "parser failed")]
    assert remote._tmp_filename is None
    assert not (tmp_path / "downloaded.txt").exists()


def test_scanner_stops_all_workers_and_removes_run_temp_dir_when_parent_is_interrupted(monkeypatch, tmp_path):
    class Worker:
        def __init__(self):
            self.alive = True
            self.exitcode = None
            self.pid = 12345
            self.terminated = 0
            self.killed = 0
            self.joins = []

        def is_alive(self):
            return self.alive

        def terminate(self):
            self.terminated += 1

        def kill(self):
            self.killed += 1
            self.alive = False

        def join(self, timeout=None):
            self.joins.append(timeout)
            self.alive = False

    class Queue:
        closed = False
        joined = False

        def close(self):
            self.closed = True

        def join_thread(self):
            self.joined = True

    worker = Worker()
    queue = Queue()
    sent_signals = []
    temporary_root = tmp_path / "manspider-run"
    temporary_root.mkdir()
    (temporary_root / "partial.txt").write_text("partial")
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.external_log_listener = True
    scanner.spiderling_pool = [worker]
    scanner.spiderling_queue = queue
    scanner.check_spiderling_queue = lambda **_kwargs: None
    scanner.tmp_dir = temporary_root
    identity = temporary_root.stat(follow_symlinks=False)
    scanner._owned_tmp_dir = temporary_root
    scanner._owned_tmp_identity = (identity.st_dev, identity.st_ino)
    scanner._start = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
    monkeypatch.setattr(
        "man_spider.lib.spider.os.kill",
        lambda pid, sent_signal: sent_signals.append((pid, sent_signal)),
    )

    with pytest.raises(KeyboardInterrupt):
        scanner.start()

    assert sent_signals == [(worker.pid, signal.SIGINT)]
    assert worker.terminated == 0
    assert worker.killed == 0
    assert len(worker.joins) == 1
    assert 0 < worker.joins[0] <= 5
    assert queue.closed is True
    assert queue.joined is True
    assert not temporary_root.exists()


def test_scanner_creates_temporary_directory_only_for_start(monkeypatch, tmp_path):
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.tmp_dir = None
    scanner._owned_tmp_dir = None
    scanner._owned_tmp_identity = None
    temporary_root = tmp_path / "run"
    temporary_root.mkdir()
    identity = temporary_root.stat()
    monkeypatch.setattr(
        "man_spider.lib.spider.create_private_local_directory",
        lambda *_args, **_kwargs: (temporary_root, (identity.st_dev, identity.st_ino)),
    )

    scanner.prepare_temp_dir()

    assert scanner.tmp_dir == tmp_path / "run"
    assert scanner._owned_tmp_dir == tmp_path / "run"
    assert scanner.tmp_dir.is_dir()
    scanner.cleanup_temp_dir()
    assert scanner.tmp_dir is None
    assert not (tmp_path / "run").exists()


def test_scanner_cleanup_ignores_an_accidentally_reassigned_tmp_dir(monkeypatch, tmp_path):
    owned = tmp_path / "owned"
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "important.txt").write_text("PRESERVE")
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.tmp_dir = None
    scanner._owned_tmp_dir = None
    scanner._owned_tmp_identity = None
    owned.mkdir()
    identity = owned.stat()
    monkeypatch.setattr(
        "man_spider.lib.spider.create_private_local_directory",
        lambda *_args, **_kwargs: (owned, (identity.st_dev, identity.st_ino)),
    )

    scanner.prepare_temp_dir()
    scanner.tmp_dir = victim
    scanner.cleanup_temp_dir()

    assert not owned.exists()
    assert (victim / "important.txt").read_text() == "PRESERVE"


def test_scanner_cleanup_refuses_a_replaced_temp_root(monkeypatch, tmp_path):
    owned = tmp_path / "owned"
    displaced = tmp_path / "displaced"
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "important.txt").write_text("PRESERVE")
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.tmp_dir = None
    scanner._owned_tmp_dir = None
    scanner._owned_tmp_identity = None
    owned.mkdir()
    identity = owned.stat()
    monkeypatch.setattr(
        "man_spider.lib.spider.create_private_local_directory",
        lambda *_args, **_kwargs: (owned, (identity.st_dev, identity.st_ino)),
    )

    scanner.prepare_temp_dir()
    owned.rename(displaced)
    owned.symlink_to(victim, target_is_directory=True)
    scanner.cleanup_temp_dir()

    assert owned.is_symlink()
    assert displaced.is_dir()
    assert (victim / "important.txt").read_text() == "PRESERVE"


def test_scanner_cleanup_refuses_to_cross_a_nested_network_mount(monkeypatch, tmp_path):
    import man_spider.path_safety as path_safety_module

    owned = tmp_path / "owned"
    nested_mount = owned / "network-mount"
    nested_mount.mkdir(parents=True)
    protected = nested_mount / "customer.txt"
    protected.write_text("PRESERVE")
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.tmp_dir = owned
    scanner._owned_tmp_dir = owned
    identity = owned.stat(follow_symlinks=False)
    scanner._owned_tmp_identity = (identity.st_dev, identity.st_ino)

    def filesystem_type(path):
        resolved = Path(path).resolve(strict=False)
        return "cifs" if resolved == nested_mount or resolved.is_relative_to(nested_mount) else "ext4"

    monkeypatch.setattr(path_safety_module, "filesystem_type", filesystem_type)
    scanner.cleanup_temp_dir()

    assert protected.read_text() == "PRESERVE"
    assert owned.is_dir()


def test_abnormal_worker_exit_stops_other_workers_and_becomes_state_error():
    class Process:
        def __init__(self, pid, *, alive, exitcode):
            self.pid = pid
            self.alive = alive
            self.exitcode = exitcode
            self.terminated = 0
            self.joins = []

        def is_alive(self):
            return self.alive

        def join(self, timeout=None):
            self.joins.append(timeout)
            if self.terminated:
                self.alive = False

        def terminate(self):
            self.terminated += 1

    failed = Process(101, alive=False, exitcode=7)
    running = Process(102, alive=True, exitcode=None)
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.spiderling_pool = [failed, running]

    with pytest.raises(StateError, match="process 101 exited with code 7"):
        scanner.ensure_worker_succeeded(failed)

    assert running.terminated == 1
    assert running.joins == [5]


@pytest.mark.parametrize("interrupt_signal", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_cli_supervisor_marks_a_terminated_child_run_interrupted(tmp_path, interrupt_signal):
    state_path = tmp_path / "interrupt.sqlite3"
    json_path = tmp_path / "interrupt.json"
    script = r"""
import sys
import time
import man_spider.manspider as module

class SlowSpider:
    def __init__(self, options):
        self.options = options
    def start(self):
        time.sleep(30)

module.MANSPIDER = SlowSpider
raise SystemExit(module.main([
    sys.argv[1], "-f", "secret", "--yes", "--state-file", sys.argv[2], "--json-file", sys.argv[3]
]))
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path), str(state_path), str(json_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        status = None
        while time.monotonic() < deadline:
            if state_path.is_file():
                try:
                    connection = sqlite3.connect(state_path)
                    row = connection.execute("SELECT status FROM runs").fetchone()
                    connection.close()
                    status = row[0] if row else None
                except sqlite3.Error:
                    status = None
                if status == "running":
                    break
            time.sleep(0.02)
        assert status == "running"

        process.send_signal(interrupt_signal)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 130, (stdout, stderr)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    connection = sqlite3.connect(state_path)
    row = connection.execute("SELECT status, error_reason FROM runs").fetchone()
    connection.close()
    assert row == ("interrupted", "Interrupted by user")
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["run_status"] == "interrupted"
    assert report["error_reason"] == "Interrupted by user"


@pytest.mark.skipif(sys.platform == "win32", reason="hard-crash signal semantics are POSIX-specific")
def test_hard_crash_releases_state_lease_and_resume_restarts_in_progress_object(tmp_path):
    state_path = tmp_path / "crash.sqlite3"
    first_script = r"""
import sys
import time
import man_spider.manspider as module
from man_spider.cli import parse_options
from man_spider.state import ScanState

class CrashSpider:
    def __init__(self, options):
        self.options = options
    def start(self):
        state = ScanState.attach(self.options.state_path, self.options.state_run_id)
        try:
            state.claim_object(
                object_key="file|hard-crash",
                kind="file",
                path="secret.txt",
                size=12,
                mtime=100,
                retry_limit=2,
            )
        finally:
            state.close()
        time.sleep(30)

module.MANSPIDER = CrashSpider
options = parse_options([sys.argv[1], "-f", "secret", "--yes", "--state-file", sys.argv[2]])
raise SystemExit(module.go(options, command=["manspider", sys.argv[1]]))
"""
    process = subprocess.Popen(
        [sys.executable, "-c", first_script, str(tmp_path), str(state_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        observed = None
        while time.monotonic() < deadline:
            if state_path.is_file():
                try:
                    connection = sqlite3.connect(state_path)
                    observed = connection.execute(
                        "SELECT status, attempts FROM objects WHERE object_key='file|hard-crash'"
                    ).fetchone()
                    connection.close()
                except sqlite3.Error:
                    observed = None
                if observed == ("in_progress", 1):
                    break
            time.sleep(0.02)
        assert observed == ("in_progress", 1)

        contender_script = r"""
import sys
from man_spider.cli import parse_options
from man_spider.manspider import go

options = parse_options([sys.argv[1], "-f", "secret", "--yes", "--resume", sys.argv[2]])
raise SystemExit(go(options, command=["manspider", sys.argv[1]]))
"""
        contender = subprocess.run(
            [sys.executable, "-c", contender_script, str(tmp_path), str(state_path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        assert contender.returncode == 5, contender.stdout + contender.stderr

        process.kill()
        process.communicate(timeout=5)
        assert process.returncode is not None and process.returncode < 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    resume_script = r"""
import sys
import man_spider.manspider as module
from man_spider.cli import parse_options
from man_spider.state import FindingRecord, ScanState

class ResumeSpider:
    def __init__(self, options):
        self.options = options
    def start(self):
        state = ScanState.attach(self.options.state_path, self.options.state_run_id)
        try:
            decision = state.claim_object(
                object_key="file|hard-crash",
                kind="file",
                path="secret.txt",
                size=12,
                mtime=100,
                retry_limit=2,
            )
            if not decision.should_process or decision.prior_status != "in_progress":
                raise RuntimeError(f"unexpected resume decision: {decision}")
            state.complete_object(
                decision.object_id,
                "processed",
                findings=[FindingRecord("fixture", "SECRET_VALUE", 0, 12, "SECRET_VALUE")],
            )
        finally:
            state.close()

module.MANSPIDER = ResumeSpider
options = parse_options([sys.argv[1], "-f", "secret", "--yes", "--resume", sys.argv[2]])
raise SystemExit(module.go(options, command=["manspider", sys.argv[1]]))
"""
    resumed = subprocess.run(
        [sys.executable, "-c", resume_script, str(tmp_path), str(state_path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr

    connection = sqlite3.connect(state_path)
    run_status = connection.execute("SELECT status FROM runs").fetchone()[0]
    object_row = connection.execute(
        "SELECT status, attempts FROM objects WHERE object_key='file|hard-crash'"
    ).fetchone()
    findings = connection.execute("SELECT value FROM findings").fetchall()
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    connection.close()
    assert run_status == "complete"
    assert object_row == ("processed", 2)
    assert findings == [("SECRET_VALUE",)]
    assert integrity == "ok"
