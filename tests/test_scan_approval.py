"""Operator approval gates scanning; all fixtures are tiny and strictly local."""

import errno
import io
import json
import os
import pty
import select
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import man_spider.approval as approval
import man_spider.manspider as manspider_module
from man_spider.cli import parse_options
from man_spider.policy import apply_scope_policy, estimate_scope
from man_spider.state import FindingRecord, ScanState, configuration_fingerprint, normalized_scan_configuration


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


def capture_summary(monkeypatch):
    messages = []
    monkeypatch.setattr(approval, "log_scan_summary", messages.append)
    return messages


@pytest.mark.parametrize("answer", ["y\n", "YES\n", " yes \n", "д\n", "Да\n", "ДА\n"])
def test_confirmation_accepts_explicit_english_and_russian_approval(monkeypatch, capsys, answer):
    messages = capture_summary(monkeypatch)

    assert approval.confirm_scan(SimpleNamespace(yes=False), "fixture summary", stdin=TerminalInput(answer))

    assert messages[0] == "fixture summary"
    assert messages.count("fixture summary") == 1
    assert capsys.readouterr().out


@pytest.mark.parametrize("answer", ["\n", "n\n", "NO\n", "нет\n", ""])
def test_default_empty_negative_and_eof_answers_never_approve(monkeypatch, answer):
    messages = capture_summary(monkeypatch)

    assert not approval.confirm_scan(SimpleNamespace(yes=False), "fixture summary", stdin=TerminalInput(answer))

    assert messages == ["fixture summary"]


def test_summary_is_displayed_and_prompt_flushed_before_reading(monkeypatch):
    events = []

    class Output(io.StringIO):
        def write(self, text):
            events.append(("write", text))
            return super().write(text)

        def flush(self):
            events.append(("flush", None))

    class Input(TerminalInput):
        def readline(self, *args):
            assert events[0] == ("summary", "fixture summary")
            assert events[-1][0] == "flush"
            events.append(("read", None))
            return super().readline(*args)

    monkeypatch.setattr(approval, "log_scan_summary", lambda text: events.append(("summary", text)))
    monkeypatch.setattr(sys, "stdout", Output())

    assert approval.confirm_scan(SimpleNamespace(yes=False), "fixture summary", stdin=Input("yes\n"))
    assert sum(event[0] == "read" for event in events) == 1


def test_unknown_answer_retries_without_reprinting_summary(monkeypatch):
    messages = capture_summary(monkeypatch)
    answers = TerminalInput("perhaps\nyes please\ntrue\nyes\n")

    assert approval.confirm_scan(SimpleNamespace(yes=False), "fixture summary", stdin=answers)

    assert messages[0] == "fixture summary"
    assert messages.count("fixture summary") == 1
    assert answers.tell() == len(answers.getvalue())


@pytest.mark.parametrize("isatty_result", [False, OSError("terminal unavailable"), AttributeError("no tty")])
def test_noninteractive_input_cannot_implicitly_approve(monkeypatch, isatty_result):
    messages = capture_summary(monkeypatch)

    class Noninteractive:
        def isatty(self):
            if isinstance(isatty_result, Exception):
                raise isatty_result
            return isatty_result

        def readline(self):
            pytest.fail("A noninteractive stream must not be used as operator approval")

    assert not approval.confirm_scan(SimpleNamespace(yes=False), "fixture summary", stdin=Noninteractive())
    assert messages[0] == "fixture summary"
    assert messages.count("fixture summary") == 1


def test_explicit_yes_still_displays_summary_without_reading_input(monkeypatch):
    messages = capture_summary(monkeypatch)

    class UnreadableInput:
        def isatty(self):
            pytest.fail("Explicit --yes must not require an interactive terminal")

        def readline(self):
            pytest.fail("Explicit --yes must not wait for input")

    assert approval.confirm_scan(SimpleNamespace(yes=True), "fixture summary", stdin=UnreadableInput())
    assert messages[0] == "fixture summary"
    assert messages.count("fixture summary") == 1


def test_keyboard_interrupt_is_not_treated_as_approval(monkeypatch):
    capture_summary(monkeypatch)

    class InterruptedInput(TerminalInput):
        def readline(self, *args):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        approval.confirm_scan(SimpleNamespace(yes=False), "fixture summary", stdin=InterruptedInput())


def make_options(tmp_path, *, resume=False, builtin=False):
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    arguments = [
        str(source),
        "--resume" if resume else "--state-file",
        str(tmp_path / "scan.sqlite3"),
        "--loot-dir",
        str(tmp_path / "loot"),
        "--no-unclassified-report",
        "--no-smb-metrics",
        "--threads",
        "1",
        "--max-sessions-per-host",
        "1",
    ]
    arguments.extend(["--builtin-rules"] if builtin else ["-c", "ApprovalFixtureSecret"])
    return parse_options(arguments)


def read_state(path):
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        row = dict(connection.execute("SELECT * FROM runs").fetchone())
        objects = [dict(item) for item in connection.execute("SELECT * FROM objects")]
        findings = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    return row, objects, findings


def seed_resume(options):
    apply_scope_policy(options, estimate_scope(options))
    state = ScanState.create(options.state_path, normalized_scan_configuration(options), "2.0.0")
    try:
        completed = state.claim_object(object_key="fixture|finished", kind="file", path="finished.txt")
        state.complete_object(
            completed.object_id,
            "processed",
            findings=[
                FindingRecord(
                    rule_id="fixture-rule",
                    value="ApprovalFixtureSecret",
                    context="prefix ApprovalFixtureSecret suffix",
                    severity="high",
                    confidence="high",
                )
            ],
        )
        state.claim_object(object_key="fixture|unfinished", kind="file", path="secret.txt")
        state.set_run_status("interrupted", reason="fixture interruption")
        return state.run_id
    finally:
        state.close()


def forbid_scan(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("An unapproved scan must not start or rearm resume work")

    monkeypatch.setattr(manspider_module, "MANSPIDER", unexpected)
    monkeypatch.setattr(ScanState, "prepare_resume", unexpected)


@pytest.mark.parametrize("resume", [False, True], ids=["new", "resume"])
def test_declining_marks_run_interrupted_without_starting_or_rearming(monkeypatch, tmp_path, resume):
    original = make_options(tmp_path)
    run_id = seed_resume(original) if resume else None
    options = make_options(tmp_path, resume=resume)
    before = read_state(options.state_path)[1] if resume else []
    if resume:
        with sqlite3.connect(options.state_path) as connection:
            findings_before = connection.execute("SELECT * FROM findings").fetchall()
    events = []
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: events.append("preflight") or 0)
    forbid_scan(monkeypatch)

    def decline(summary):
        assert options.large_domain is False
        assert str(tmp_path / "source") in summary
        assert str(options.state_path) in summary
        assert "pending preliminary estimate" not in summary
        events.append("approval")
        return False

    result = manspider_module.go(options, command=["manspider", "fixture"], approval_request=decline)

    assert result == manspider_module.EXIT_SCAN_NOT_APPROVED == 7
    assert events == ["preflight", "approval"]
    row, objects, findings = read_state(options.state_path)
    assert row["status"] == "interrupted"
    assert row["error_reason"] == "Main scan was not approved by the operator"
    assert objects == before
    assert findings == (1 if resume else 0)
    if resume:
        assert row["run_id"] == run_id
        with sqlite3.connect(options.state_path) as connection:
            assert connection.execute("SELECT * FROM findings").fetchall() == findings_before


def test_successful_approval_runs_only_after_preflight_and_final_policy(monkeypatch, tmp_path):
    options = make_options(tmp_path)
    events = []
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: events.append("preflight") or 0)

    class ApprovedSpider:
        def __init__(self, received):
            assert received is options
            assert events == ["preflight", "approval"]
            events.append("constructor")

        def start(self):
            events.append("scan")

    def accept(summary):
        assert options.large_domain is False
        assert "effective_large_domain: False" in summary
        row, objects, _ = read_state(options.state_path)
        assert not objects
        stored = json.loads(row["config_json"])
        assert stored == normalized_scan_configuration(options)
        events.append("approval")
        return True

    monkeypatch.setattr(manspider_module, "MANSPIDER", ApprovedSpider)
    assert manspider_module.go(options, command=["manspider", "fixture"], approval_request=accept) == 0
    assert events == ["preflight", "approval", "constructor", "scan"]
    assert read_state(options.state_path)[0]["status"] == "complete"


def test_failed_preflight_does_not_offer_main_scan_approval(monkeypatch, tmp_path):
    options = make_options(tmp_path)
    monkeypatch.setattr(
        manspider_module, "credential_preflight", lambda _options: manspider_module.EXIT_CREDENTIALS_INVALID
    )
    forbid_scan(monkeypatch)

    def unexpected(summary):
        pytest.fail("Rejected credentials must stop before approval for main scanning")

    assert manspider_module.go(options, approval_request=unexpected) == manspider_module.EXIT_CREDENTIALS_INVALID
    assert read_state(options.state_path)[0]["status"] == "preflight_failed"


def test_cancelling_approval_preserves_resumability(monkeypatch, tmp_path):
    options = make_options(tmp_path)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)
    forbid_scan(monkeypatch)

    def interrupt(summary):
        raise KeyboardInterrupt

    assert manspider_module.go(options, approval_request=interrupt) == 130
    row, objects, _ = read_state(options.state_path)
    assert row["status"] == "interrupted"
    assert row["error_reason"] == "Interrupted by user"
    assert objects == []


def test_approval_summary_has_final_scope_filters_limits_and_output_locations(tmp_path):
    options = make_options(tmp_path)
    apply_scope_policy(options, estimate_scope(options))
    state = ScanState.create(options.state_path, normalized_scan_configuration(options), "2.0.0")
    try:
        summary = approval.format_scan_summary(options, state=state)
    finally:
        state.close()

    for value in (
        str(tmp_path / "source"),
        str(options.state_path),
        str(tmp_path / "loot"),
        "ApprovalFixtureSecret",
        "threads: 1",
        "max_sessions_per_host: 1",
        "maxdepth: 15",
        "effective_large_domain: False",
        "download_matches: False",
        "allow_external_dfs: False",
    ):
        assert value in summary
    assert "pending preliminary estimate" not in summary


def test_builtin_review_lists_every_enabled_rule_and_preserves_full_definitions(tmp_path):
    options = make_options(tmp_path, builtin=True)
    apply_scope_policy(options, estimate_scope(options))
    state = ScanState.create(options.state_path, normalized_scan_configuration(options), "2.0.0")
    try:
        summary = approval.format_scan_summary(options, state=state)
        stored = json.loads(state.run_row()["config_json"])
    finally:
        state.close()

    assert len(options.rules) >= 250
    assert all(rule["id"] in summary for rule in options.rules)
    assert stored["semantic"]["filters"]["rules"] == options.rules
    assert "SQLite config_json" in summary


def test_yes_is_not_semantic_and_prior_approval_is_not_inherited_on_resume(monkeypatch, tmp_path):
    options = make_options(tmp_path)
    assert options.yes is False
    apply_scope_policy(options, estimate_scope(options))
    interactive_configuration = normalized_scan_configuration(options)
    options.yes = True
    explicit_configuration = normalized_scan_configuration(options)
    assert configuration_fingerprint(interactive_configuration) == configuration_fingerprint(explicit_configuration)
    assert explicit_configuration["execution"]["explicit_scan_approval"] is True
    seed_resume(options)

    resumed = make_options(tmp_path, resume=True)
    assert resumed.yes is False
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)
    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))
    capture_summary(monkeypatch)
    forbid_scan(monkeypatch)

    assert manspider_module.go(resumed) == manspider_module.EXIT_SCAN_NOT_APPROVED
    row, _objects, findings = read_state(resumed.state_path)
    assert row["status"] == "interrupted"
    assert findings == 1
    assert json.loads(row["config_json"])["execution"]["explicit_scan_approval"] is False


def cli_fixture(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    fixture = source / "secret.txt"
    fixture.write_text("prefix ApprovalFixtureSecret suffix\n", encoding="utf-8")
    original = (fixture.read_bytes(), fixture.stat().st_mtime_ns)
    state_path = tmp_path / "scan.sqlite3"
    arguments = [
        sys.executable,
        "-m",
        "man_spider.manspider",
        str(source),
        "-c",
        "ApprovalFixtureSecret",
        "--threads",
        "1",
        "--max-sessions-per-host",
        "1",
        "--state-file",
        str(state_path),
        "--loot-dir",
        str(tmp_path / "loot"),
        "--no-unclassified-report",
        "--no-smb-metrics",
    ]
    return arguments, fixture, original, state_path


def stop_process_group(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


def run_interactive_cli(arguments, answer, state_path):
    """Drain the PTY continuously: the large configuration must not fill its buffer."""

    master, slave = pty.openpty()
    process = None
    chunks = []
    replied = False
    try:
        process = subprocess.Popen(
            arguments,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            start_new_session=True,
            cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, "NO_COLOR": "1"},
        )
        os.close(slave)
        slave = None
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.1)
            if readable:
                try:
                    chunk = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if not replied and b"[y/N]" in b"".join(chunks):
                    before_prompt = b"".join(chunks).split(b"[y/N]", 1)[0]
                    assert b"effective_large_domain: False" in before_prompt
                    assert b"Operational notes:" in before_prompt
                    assert (
                        b"Approval applies only to this invocation, including when resuming a saved session."
                        in before_prompt
                    )
                    # No target or file may be touched before the response.
                    _, objects, findings = read_state(state_path)
                    assert objects == []
                    assert findings == 0
                    if answer is None:
                        os.kill(process.pid, signal.SIGINT)
                    else:
                        os.write(master, answer)
                    replied = True
            elif process.poll() is not None:
                break
        else:
            pytest.fail("Interactive scan approval timed out:\n" + b"".join(chunks).decode(errors="replace"))
        process.wait(timeout=5)
        return process.returncode, b"".join(chunks).decode(errors="replace"), replied
    finally:
        if process is not None:
            stop_process_group(process)
        if slave is not None:
            os.close(slave)
        os.close(master)


@pytest.mark.skipif(os.name != "posix", reason="Exercises the real POSIX CLI supervisor and terminal")
@pytest.mark.parametrize(
    ("answer", "exit_code", "status"),
    [
        (b"yes\n", 0, "complete"),
        (b"no\n", 7, "interrupted"),
        (b"\x04", 7, "interrupted"),
        (None, 130, "interrupted"),
    ],
    ids=["approve", "decline", "terminal-eof", "ctrl-c"],
)
def test_real_cli_reads_operator_response_in_supervisor(tmp_path, answer, exit_code, status):
    arguments, fixture, original, state_path = cli_fixture(tmp_path)

    result, output, replied = run_interactive_cli(arguments, answer, state_path)

    assert replied, output
    assert result == exit_code, output
    row, objects, findings = read_state(state_path)
    assert row["status"] == status
    if exit_code == 0:
        assert findings == 1
        assert objects
        assert "ApprovalFixtureSecret" in output
    else:
        assert objects == []
        assert findings == 0
    assert (fixture.read_bytes(), fixture.stat().st_mtime_ns) == original


@pytest.mark.parametrize("preapproved", [False, True], ids=["piped-yes-rejected", "explicit-yes"])
def test_real_noninteractive_cli_requires_explicit_yes(tmp_path, preapproved):
    arguments, fixture, original, state_path = cli_fixture(tmp_path)
    if preapproved:
        arguments.append("--yes")
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "NO_COLOR": "1"},
    )
    try:
        output, _ = process.communicate(input=b"yes\n", timeout=25)
    finally:
        stop_process_group(process)

    assert process.returncode == (0 if preapproved else 7), output.decode(errors="replace")
    row, objects, findings = read_state(state_path)
    assert row["status"] == ("complete" if preapproved else "interrupted")
    assert findings == (1 if preapproved else 0)
    if not preapproved:
        assert objects == []
    assert str(fixture.parent).encode() in output
    assert b"effective_large_domain: False" in output
    assert (fixture.read_bytes(), fixture.stat().st_mtime_ns) == original
