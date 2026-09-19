"""Real CLI/terminal cancellation, including repeated Ctrl+C during cleanup.

Only a small local synthetic corpus is scanned. No scanner or signal handler is
patched; the PTY keeper acts like a shell that outlives its foreground command.
"""
import errno
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import sys
import time

import pytest

from man_spider.state import ScanLease


pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or not Path('/proc').is_dir(),
    reason='Linux process-group inventory and real terminal signals',
)
REPOSITORY = Path(__file__).resolve().parents[1]
FILE_COUNT = 512
CONTENT = ('Synthetic local cancellation fixture. password=NotARealCredential#2026\n'
           + 'Harmless synthetic plain data for read-only cancellation verification.\n' * 32)


@pytest.fixture
def local_scan(tmp_path):
    source = tmp_path / 'source'
    for index in range(FILE_COUNT):
        directory = source / f'dir-{index // 32:02d}'
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f'fixture-{index:04d}.txt').write_text(CONTENT)
    database = tmp_path / 'state.sqlite3'
    arguments = [str(source), '-e', 'txt', '-c', 'password', '--yes']
    return source, database, arguments


def _command(arguments, database, *, resume=False):
    # Exercise the installed console entrypoint when running in a development
    # installation. The PTY cases independently exercise python -m below.
    installed = Path(sys.executable).with_name('manspider')
    prefix = [str(installed)] if installed.is_file() else [sys.executable, '-m', 'man_spider.manspider']
    return [*prefix, *arguments,
            '--resume' if resume else '--state-file', str(database)]


def _group_processes(group):
    result = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / 'stat').read_text()
            fields = text[text.rfind(')') + 2:].split()
            if int(fields[2]) == group:
                result.append((int(entry.name), fields[0]))
        except (OSError, ValueError, IndexError):
            pass
    return result


def _wait_for_empty_group(group):
    deadline = time.monotonic() + 5
    remaining = _group_processes(group)
    while remaining and time.monotonic() < deadline:
        time.sleep(0.02)
        remaining = _group_processes(group)
    assert not remaining, f'CLI left descendants behind before test cleanup: {remaining}'


def _cleanup_group(group):
    # Called only after checking the live result, so SIGKILL cannot manufacture
    # a passing "no descendants" result. The group belongs to this test alone.
    if any(state != 'Z' for _pid, state in _group_processes(group)):
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _state(database):
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=0.2) as db:
        return {
            'status': db.execute('SELECT status FROM runs').fetchone()[0],
            'integrity': db.execute('PRAGMA integrity_check').fetchone()[0],
            'processed': dict(db.execute(
                "SELECT object_key,attempts FROM objects WHERE kind='file' AND status='processed'")),
            'nonterminal': db.execute(
                "SELECT COUNT(*) FROM objects WHERE status IN ('pending','in_progress')").fetchone()[0],
        }


def _wait_for_progress(database, poll, pump=lambda: None):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        pump()
        assert poll() is None, 'CLI exited before the cancellation point'
        if database.exists():
            try:
                with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=0.1) as db:
                    count = db.execute(
                        "SELECT COUNT(*) FROM objects WHERE kind='file' AND status='processed'").fetchone()[0]
                if 8 <= count < FILE_COUNT:
                    return count
            except sqlite3.Error:
                pass
        time.sleep(0.005)
    pytest.fail('CLI did not persist partial file progress before cancellation')


def _assert_quiet(output):
    for unexpected in ('Traceback (most recent call last)', 'KeyboardInterrupt', 'BrokenPipeError',
                       'Exception ignored in atexit callback', 'leaked semaphore objects',
                       'Cannot finish scan while manifest objects are non-terminal'):
        assert unexpected not in output, output[-15000:]


def _assert_interrupted_and_resume(local_scan, output, tmp_path):
    source, database, arguments = local_scan
    _assert_quiet(output)
    assert 'Scan state: interrupted;' in output, output[-15000:]
    interrupted = _state(database)
    assert interrupted['status'] == 'interrupted'
    assert interrupted['integrity'] == 'ok'
    assert 0 < len(interrupted['processed']) < FILE_COUNT
    assert ScanLease.available(database), 'CLI leaked its scan-state lease'
    resume_log = tmp_path / 'resume.log'
    with resume_log.open('w') as stream:
        resume = subprocess.Popen(_command(arguments, database, resume=True), cwd=REPOSITORY,
                                  stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            returncode = resume.wait(timeout=30)
            _wait_for_empty_group(resume.pid)
        finally:
            _cleanup_group(resume.pid)
            resume.wait(timeout=5)
    resume_output = resume_log.read_text()
    assert returncode == 0, resume_output[-15000:]
    _assert_quiet(resume_output)
    final = _state(database)
    assert final['status'] == 'complete'
    assert final['integrity'] == 'ok'
    assert final['nonterminal'] == 0
    assert len(final['processed']) == FILE_COUNT
    assert {key: final['processed'][key] for key in interrupted['processed']} == interrupted['processed']
    assert ScanLease.available(database)
    remaining_files = list(source.rglob('*.txt'))
    assert len(remaining_files) == FILE_COUNT
    assert all(path.read_text() == CONTENT for path in remaining_files)


@pytest.mark.parametrize('scope', ['group', 'parent'])
@pytest.mark.parametrize('count,spacing', [(10, 0.02), (50, 0.005)])
def test_real_cli_repeated_sigint_is_quiet_and_resumable(local_scan, tmp_path, scope, count, spacing):
    _source, database, arguments = local_scan
    log_path = tmp_path / 'interrupted.log'
    with log_path.open('w') as stream:
        process = subprocess.Popen(_command(arguments, database), cwd=REPOSITORY,
                                   stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            _wait_for_progress(database, process.poll)
            for _ in range(count):
                try:
                    if scope == 'group':
                        os.killpg(process.pid, signal.SIGINT)
                    else:
                        os.kill(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    break
                time.sleep(spacing)
            returncode = process.wait(timeout=20)
            _wait_for_empty_group(process.pid)
        finally:
            _cleanup_group(process.pid)
            process.wait(timeout=5)
    output = log_path.read_text()
    assert returncode == 130, f'Unexpected exit {returncode}:\n{output[-15000:]}'
    _assert_interrupted_and_resume(local_scan, output, tmp_path)


_PTY_KEEPER = r'''
import fcntl, json, os, signal, sys, termios
slave = int(sys.argv[1])
fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
settings = termios.tcgetattr(slave)
settings[3] |= termios.ISIG | termios.ICANON
settings[6][termios.VINTR] = b'\x03'
termios.tcsetattr(slave, termios.TCSANOW, settings)
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
gate_read, gate_write = os.pipe()
child = os.fork()
if child == 0:
    os.close(gate_write)
    os.setpgid(0, 0)
    os.read(gate_read, 1)
    os.close(gate_read)
    for descriptor in (0, 1, 2):
        os.dup2(slave, descriptor)
    if slave > 2:
        os.close(slave)
    os.execv(sys.executable, [sys.executable, '-m', 'man_spider.manspider', *sys.argv[2:]])
os.close(gate_read)
reaped = False
try:
    os.setpgid(child, child)
    os.tcsetpgrp(slave, child)
    os.write(gate_write, b'1')
    os.close(gate_write)
    print(json.dumps({'pid': child, 'session': os.getsid(child)}), flush=True)
    _, status = os.waitpid(child, 0)
    reaped = True
    print(json.dumps({'returncode': os.waitstatus_to_exitcode(status)}), flush=True)
    # Keep the terminal session leader alive until the test checks CLI cleanup.
    # Its exit must not inject an unrelated SIGHUP during Ctrl+C cleanup.
    sys.stdin.read(1)
finally:
    # Only an unexpected keeper setup/protocol failure reaches this branch.
    # Without a reported CLI exit the test fails, rather than treating forced
    # cleanup as a successful interruption.
    if not reaped:
        try:
            os.killpg(child, signal.SIGKILL)
        except ProcessLookupError:
            os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
'''


class _TerminalCLI:
    def __init__(self, arguments, tmp_path):
        import pty

        self.master, slave = pty.openpty()
        self.output = bytearray()
        self.returncode = None
        self.pid = None
        self.keeper_stderr = (tmp_path / 'terminal-keeper.log').open('w')
        self.keeper = subprocess.Popen(
            [sys.executable, '-c', _PTY_KEEPER, str(slave), *arguments],
            cwd=REPOSITORY, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.keeper_stderr, pass_fds=(slave,), start_new_session=True, text=True,
        )
        os.close(slave)
        os.set_blocking(self.master, False)
        try:
            assert select.select([self.keeper.stdout], [], [], 10)[0], 'PTY keeper failed to start'
            ready = json.loads(self.keeper.stdout.readline())
            self.pid = ready['pid']
            assert ready['session'] == self.keeper.pid != self.pid
        except BaseException:
            self.close()
            raise

    def pump(self):
        while True:
            try:
                data = os.read(self.master, 65536)
            except BlockingIOError:
                break
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            self.output.extend(data)

    def poll(self):
        self.pump()
        if self.returncode is None and select.select([self.keeper.stdout], [], [], 0)[0]:
            line = self.keeper.stdout.readline()
            assert line, 'PTY keeper disappeared before reporting CLI exit'
            self.returncode = json.loads(line)['returncode']
        return self.returncode

    def wait(self):
        deadline = time.monotonic() + 20
        while self.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert self.returncode is not None, 'CLI hung after terminal Ctrl+C'
        self.pump()
        return self.returncode

    def close(self):
        if self.pid is not None:
            _cleanup_group(self.pid)
        if self.keeper.poll() is None:
            try:
                self.keeper.communicate(input='x', timeout=5)
            except subprocess.TimeoutExpired:
                self.keeper.kill()
                self.keeper.communicate(timeout=5)
        self.keeper_stderr.close()
        os.close(self.master)


@pytest.mark.parametrize('count', [1, 50])
def test_real_terminal_ctrl_c_is_quiet_and_resumable(local_scan, tmp_path, count):
    _source, database, arguments = local_scan
    terminal = _TerminalCLI([*arguments, '--state-file', str(database)], tmp_path)
    try:
        _wait_for_progress(database, terminal.poll, terminal.pump)
        for _ in range(count):
            # Actual VINTR bytes; the terminal driver generates foreground-
            # group SIGINT. Do not replace this with os.kill/killpg.
            os.write(terminal.master, b'\x03')
            terminal.pump()
            time.sleep(0.005)
        returncode = terminal.wait()
        assert terminal.keeper.poll() is None, 'Terminal keeper must outlive CLI cleanup'
        _wait_for_empty_group(terminal.pid)
        output = terminal.output.decode(errors='replace')
        (tmp_path / 'terminal.log').write_text(output)
        assert returncode == 130, f'Unexpected exit {returncode}:\n{output[-15000:]}'
    finally:
        terminal.close()
    _assert_interrupted_and_resume(local_scan, output, tmp_path)
