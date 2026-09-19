"""Small real-CLI checks for per-invocation text logs alongside scan state."""

import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SECRET_PATTERN = r"SESSION_SECRET=[A-Za-z0-9!]+"


def _environment(tmp_path):
    environment = {
        **os.environ,
        "HOME": str(tmp_path / "home"),
        "NO_COLOR": "1",
        "PYTHONUNBUFFERED": "1",
    }
    environment.pop("XDG_STATE_HOME", None)
    environment.pop("MANSPIDER_STATE_DIR", None)
    return environment


def _fixture(tmp_path, name):
    scope = tmp_path / name
    scope.mkdir()
    source = scope / "credentials.txt"
    secret = f"SESSION_SECRET={name}Fixture123!"
    source.write_text(f"prefix {secret} suffix\n", encoding="utf-8")
    before = _source_identity(source)
    return scope, source, secret, before


def _source_identity(source):
    metadata = source.stat()
    # A read can affect atime, but must never replace or alter the source.
    return (
        source.read_bytes(), metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _arguments(scope, *extra):
    return [
        sys.executable, "-m", "man_spider.manspider", str(scope),
        "--yes", "--threads", "1", "--no-resume-prompt", "-c", SECRET_PATTERN,
        "--no-smb-metrics", "--no-unclassified-report", *map(str, extra),
    ]


def _start(scope, environment, *extra):
    return subprocess.Popen(
        _arguments(scope, *extra),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        cwd=PROJECT_ROOT, env=environment, start_new_session=True,
    )


def _finish(process):
    stdout, stderr = process.communicate(timeout=30)
    assert process.returncode == 0, stdout + stderr
    assert "Traceback" not in stdout + stderr
    return stdout, stderr


def _cleanup(process):
    if process.poll() is None:
        # The separate process group belongs exclusively to this test invocation.
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


def _scan(scope, environment, *extra):
    process = _start(scope, environment, *extra)
    try:
        return _finish(process)
    finally:
        _cleanup(process)


def _logs(state_path):
    return set(state_path.parent.glob(f"{state_path.stem}.run_*.log"))


def _assert_log(state_path, log_path, stdout):
    assert log_path.parent == state_path.parent
    assert re.fullmatch(
        re.escape(state_path.stem) + r"\.run_\d{8}_\d{6}_\d{6}_[0-9a-f]{8}\.log",
        log_path.name,
    )
    content = log_path.read_text(encoding="utf-8")
    assert f"Text log: {log_path}" in stdout
    assert f"Text log: {log_path}" in content
    assert stdout.index(f"Text log: {log_path}") < stdout.index("Main scan explicitly approved by --yes")
    assert "\x1b" not in content
    assert "Scan state: complete" in content
    return content


def _state_rows(state_path):
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert connection.execute("SELECT status FROM runs").fetchall() == [("complete",)]
        return connection.execute(
            "SELECT path, status, attempts FROM objects WHERE kind='file' ORDER BY path"
        ).fetchall()


def test_consecutive_automatic_scans_keep_distinct_logs_beside_each_session(tmp_path):
    environment = _environment(tmp_path)
    scans = Path(environment["HOME"]) / ".local" / "state" / "manspider" / "scans"
    legacy_log = Path(environment["HOME"]) / ".manspider" / "logs" / "manspider_09-14-2026.log"
    legacy_log.parent.mkdir(parents=True)
    legacy_log.write_bytes(b"Historical daily log must survive unchanged.\n")
    legacy_before = _source_identity(legacy_log)
    fixtures = [_fixture(tmp_path, "FirstCorpus"), _fixture(tmp_path, "SecondCorpus")]
    previous_states = set()
    log_snapshots = {}
    for scope, source, secret, before in fixtures:
        stdout, _stderr = _scan(scope, environment)
        states = set(scans.glob("*.sqlite3"))
        created = states - previous_states
        assert len(created) == 1
        state_path = created.pop()
        log_files = _logs(state_path)
        assert len(log_files) == 1
        log_path = log_files.pop()
        content = _assert_log(state_path, log_path, stdout)
        assert secret in content
        assert str(source) in content
        assert _state_rows(state_path) == [(str(source), "processed", 1)]
        for previous_log, identity in log_snapshots.items():
            assert _source_identity(previous_log) == identity
        log_snapshots[log_path] = _source_identity(log_path)
        previous_states = states
        assert _source_identity(source) == before

    assert len(log_snapshots) == 2
    for (_scope, _source, secret, _before), content in zip(
        fixtures, (path.read_text(encoding="utf-8") for path in log_snapshots), strict=True
    ):
        other_secrets = {fixture[2] for fixture in fixtures} - {secret}
        assert all(other_secret not in content for other_secret in other_secrets)
    assert _source_identity(legacy_log) == legacy_before
    assert set(legacy_log.parent.iterdir()) == {legacy_log}


def test_parallel_independent_scans_do_not_mix_text_logs(tmp_path):
    environment = _environment(tmp_path)
    fixtures = [_fixture(tmp_path, "ParallelAlpha"), _fixture(tmp_path, "ParallelBeta")]
    states = [tmp_path / "sessions" / f"parallel-{index}.sqlite3" for index in range(2)]
    processes = []
    try:
        # Both commands are launched before waiting for either to finish.
        for fixture, state_path in zip(fixtures, states, strict=True):
            processes.append(_start(fixture[0], environment, "--state-file", state_path))
        outputs = [_finish(process) for process in processes]
    finally:
        for process in processes:
            _cleanup(process)

    all_logs = set()
    for index, ((scope, source, secret, before), state_path, (stdout, _stderr)) in enumerate(
        zip(fixtures, states, outputs, strict=True)
    ):
        log_files = _logs(state_path)
        assert len(log_files) == 1
        log_path = log_files.pop()
        assert log_path not in all_logs
        all_logs.add(log_path)
        content = _assert_log(state_path, log_path, stdout)
        other_scope, _other_source, other_secret, _other_before = fixtures[1 - index]
        assert str(scope) in content and secret in content
        assert str(other_scope) not in content and other_secret not in content
        assert _state_rows(state_path) == [(str(source), "processed", 1)]
        assert _source_identity(source) == before
    assert len(all_logs) == 2
    assert not (Path(environment["HOME"]) / ".manspider" / "logs").exists()


def test_each_resume_creates_a_new_log_without_touching_previous_logs(tmp_path):
    resume_count = 2
    environment = _environment(tmp_path)
    scope, source, secret, before = _fixture(tmp_path, "ResumeCorpus")
    state_path = tmp_path / "sessions" / "resumable.sqlite3"
    stdout, _stderr = _scan(scope, environment, "--state-file", state_path)
    first_logs = _logs(state_path)
    assert len(first_logs) == 1
    initial_path = first_logs.pop()
    assert secret in _assert_log(state_path, initial_path, stdout)
    initial_rows = _state_rows(state_path)
    assert initial_rows == [(str(source), "processed", 1)]
    snapshots = {initial_path: _source_identity(initial_path)}

    for _ in range(resume_count):
        stdout, _stderr = _scan(scope, environment, "--resume", state_path)
        new_logs = _logs(state_path) - snapshots.keys()
        assert len(new_logs) == 1
        new_path = new_logs.pop()
        content = _assert_log(state_path, new_path, stdout)
        assert f'{source}: rule="' not in content
        assert secret not in content
        assert "Resumed scan state:" in content
        assert _state_rows(state_path) == initial_rows
        for old_path, identity in snapshots.items():
            assert _source_identity(old_path) == identity
        snapshots[new_path] = _source_identity(new_path)

    assert len(_logs(state_path)) == resume_count + 1
    assert _source_identity(source) == before
