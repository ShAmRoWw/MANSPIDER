"""Offline integration checks for display-only grouping of same-line findings."""

import io
import json
import logging
import os
import pickle
import re
import sqlite3
import subprocess
import sys
from logging.handlers import QueueHandler
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from man_spider.evidence_storage import configure_evidence_reader, context_join, context_sql
from man_spider.lib import logger as logger_module
from man_spider.lib import spiderling as spiderling_module
from man_spider.state import SCHEMA_VERSION, FindingRecord


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _record(*, suppressed=False):
    message = "original full finding; severity=medium; match=COMPLETE_SECRET"
    record = logging.LogRecord("manspider.grouping-test", logging.INFO, __file__, 1, message, (), None)
    record.finding_highlights = ((message.index("medium"), message.index("medium") + 6, "severity"),)
    record.finding_severity = "medium"
    grouped = "grouped finding; severity=critical; match=FIRST_SECRET … LAST_SECRET (ещё 2 правила: second, third)"
    record.console_message = grouped
    record.console_highlights = tuple(
        (grouped.index(value), grouped.index(value) + len(value), role)
        for value, role in (("critical", "severity"), ("FIRST_SECRET", "match"), ("LAST_SECRET", "match"))
    )
    record.console_severity = "critical"
    record.console_suppressed = suppressed
    return record


@pytest.mark.parametrize("console_first", [False, True])
@pytest.mark.parametrize("use_color", [False, True])
def test_queued_grouped_display_never_changes_original_file_record(monkeypatch, console_first, use_color):
    monkeypatch.delenv("NO_COLOR", raising=False)
    original = _record()
    # Exercise the worker preparation and the multiprocessing serialization
    # boundary; the real listener distributes this one record to both handlers.
    queued = pickle.loads(pickle.dumps(QueueHandler(None).prepare(original)))
    original_message = original.getMessage()
    original_highlights = original.finding_highlights
    console_stream = io.StringIO()
    file_stream = io.StringIO()
    console_handler = logger_module.ConsoleHandler(console_stream)
    console_handler.setFormatter(logger_module.ColoredFormatter("%(message)s", use_color=use_color))
    file_handler = logging.StreamHandler(file_stream)
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    handlers = (console_handler, file_handler) if console_first else (file_handler, console_handler)
    try:
        for handler in handlers:
            assert handler.handle(queued)
    finally:
        for handler in handlers:
            handler.close()

    displayed = console_stream.getvalue().rstrip("\n")
    assert ANSI.sub("", displayed) == queued.console_message
    assert ("\x1b" in displayed) is use_color
    if use_color:
        formatter = logger_module.ColoredFormatter
        assert formatter.severity_colors["critical"] + "critical\x1b[0m" in displayed
        assert formatter.match_color + "FIRST_SECRET\x1b[0m" in displayed
        assert formatter.match_color + "LAST_SECRET\x1b[0m" in displayed
    assert file_stream.getvalue() == original_message + "\n"
    assert "\x1b" not in file_stream.getvalue()
    assert queued.getMessage() == original_message
    assert queued.finding_highlights == original_highlights
    assert queued.finding_severity == original.finding_severity == "medium"
    assert original.getMessage() == original_message


@pytest.mark.parametrize("console_first", [False, True])
def test_suppressed_group_member_is_still_written_to_file(console_first):
    record = pickle.loads(pickle.dumps(QueueHandler(None).prepare(_record(suppressed=True))))
    console_stream = io.StringIO()
    file_stream = io.StringIO()
    console_handler = logger_module.ConsoleHandler(console_stream)
    file_handler = logging.StreamHandler(file_stream)
    handlers = (console_handler, file_handler) if console_first else (file_handler, console_handler)
    try:
        for handler in handlers:
            result = handler.handle(record)
            if handler is console_handler:
                assert result is False
    finally:
        for handler in handlers:
            handler.close()

    assert console_stream.getvalue() == ""
    assert file_stream.getvalue() == record.getMessage() + "\n"
    assert record.console_suppressed is True


def test_console_handler_keeps_ordinary_messages_and_format_arguments():
    stream = io.StringIO()
    handler = logger_module.ConsoleHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    record = logging.LogRecord("manspider", logging.WARNING, __file__, 1, "Cannot read %s", ("fixture",), None)
    try:
        assert handler.handle(record)
    finally:
        handler.close()

    assert stream.getvalue() == "WARNING Cannot read fixture\n"
    assert record.msg == "Cannot read %s"
    assert record.args == ("fixture",)


def test_grouping_failure_keeps_every_original_finding_visible(monkeypatch):
    worker = spiderling_module.Spiderling.__new__(spiderling_module.Spiderling)
    worker.parent = SimpleNamespace(quiet=False)
    records = (FindingRecord("first", "FIRST_SECRET"), FindingRecord("second", "SECOND_SECRET"))
    logger = Mock()
    monkeypatch.setattr(spiderling_module, "log", logger)

    def fail_grouping(*_args, **_kwargs):
        raise ValueError("fixture presentation error")

    monkeypatch.setattr(spiderling_module, "grouped_console_overrides", fail_grouping)
    worker.emit_findings("/scope/fixture.txt", records)

    logger.warning.assert_called_once()
    assert "displaying all findings separately" in logger.warning.call_args.args[0]
    assert logger.info.call_count == 2
    for call, finding in zip(logger.info.call_args_list, records, strict=True):
        assert finding.value in call.args[0]
        assert not any(key.startswith("console_") for key in call.kwargs["extra"])


def _source_identity(path):
    info = path.stat()
    # Reads may update atime; all other source metadata and bytes must survive.
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _scan(arguments, home):
    return subprocess.run(
        [sys.executable, "-m", "man_spider.manspider", "--yes", "-t", "1", *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={**os.environ, "HOME": str(home)},
    )


def _stored_findings(state_path):
    connection = sqlite3.connect(state_path)
    connection.row_factory = sqlite3.Row
    configure_evidence_reader(connection)
    try:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT f.finding_id, f.rule_id, f.severity, f.confidence, f.value, "
                f"{context_sql(SCHEMA_VERSION)} AS context, f.match_start, f.match_end "
                f"FROM findings f {context_join(SCHEMA_VERSION)} ORDER BY f.finding_id"
            )
        ]
    finally:
        connection.close()


def test_local_scan_groups_console_only_preserves_evidence_and_resume(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    source = scope / "credentials.txt"
    first_secret = "ALPHA_SECRET=FixtureAlphaOnly123!"
    last_secret = "OMEGA_SECRET=FixtureOmegaOnly456!"
    line = "before " + first_secret + " " + "padding " * 90 + last_secret + " after"
    payload = ((line + "\n") * 2).encode()
    source.write_bytes(payload)
    source.chmod(0o400)
    identity = _source_identity(source)
    rule_path = tmp_path / "rules.json"
    rule_path.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "pack": {"id": "manspider.console-grouping-fixture", "version": "1"},
                "rules": [
                    {
                        "id": rule_id,
                        "severity": severity,
                        "confidence": confidence,
                        "actions": [{"type": "scan", "representation": "text", "pattern": pattern, "flags": []}],
                    }
                    for rule_id, severity, confidence, pattern in (
                        ("primary-secret", "critical", "low", r"ALPHA_SECRET=[A-Za-z0-9!]+"),
                        ("broad-secret", "high", "high", r"(?:ALPHA|OMEGA)_SECRET=[A-Za-z0-9!]+"),
                        ("secret-keyword", "medium", "high", r"SECRET"),
                    )
                ],
            }
        ),
        encoding="utf-8",
    )
    home = tmp_path / "home"
    state_path = tmp_path / "scan.sqlite3"
    report_path = tmp_path / "report.json"
    common = [scope, "--rules", rule_path, "--json-file", report_path]

    first = _scan([*common, "--state-file", state_path], home)

    assert first.returncode == 0, first.stdout + first.stderr
    report = json.loads(report_path.read_text(encoding="utf-8"))
    stored = _stored_findings(state_path)
    assert report["run_status"] == "complete"
    assert report["progress"]["findings"] == len(report["findings"]) == len(stored) == 10
    assert sorted((item["rule"], item["value"], item["context"]) for item in report["findings"]) == sorted(
        (item["rule_id"], item["value"], item["context"]) for item in stored
    )
    assert {item["context"] for item in stored} == {line}
    assert len({item["match_start"] for item in stored}) == 8
    assert {item["value"] for item in stored} == {first_secret, last_secret, "SECRET"}
    console_rows = [row for row in first.stdout.splitlines() if f'{source}: rule="' in row]
    assert len(console_rows) == 2  # Identical text at different offsets is not one finding location.
    for row in console_rows:
        assert 'rule="rule:primary-secret"; severity=critical; confidence=low;' in row
        assert first_secret in row and last_secret in row
        assert "ещё 2 правила:" in row
        assert "broad-secret" in row and "secret-keyword" in row
        assert "…" in row
        assert row.count(first_secret) == row.count(last_secret) == 1
    assert "\x1b" not in first.stdout
    log_files = list(state_path.parent.glob(f"{state_path.stem}.run_*.log"))
    assert len(log_files) == 1
    initial_log = log_files[0].read_text(encoding="utf-8")
    logged_rows = [row for row in initial_log.splitlines() if f'{source}: rule="' in row]
    assert len(logged_rows) == 10
    assert sum('rule="rule:primary-secret";' in row for row in logged_rows) == 2
    assert sum('rule="rule:broad-secret";' in row for row in logged_rows) == 4
    assert sum('rule="rule:secret-keyword";' in row for row in logged_rows) == 4
    assert "ещё 2 правила:" not in initial_log
    assert "\x1b" not in initial_log
    assert source.read_bytes() == payload
    assert _source_identity(source) == identity

    resumed = _scan([*common, "--resume", state_path], home)

    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    assert f'{source}: rule="' not in resumed.stdout
    assert _stored_findings(state_path) == stored
    resumed_report = json.loads(report_path.read_text(encoding="utf-8"))
    assert resumed_report["findings"] == report["findings"]
    assert resumed_report["progress"]["findings"] == 10
    assert log_files[0].read_text(encoding="utf-8") == initial_log
    resumed_logs = set(state_path.parent.glob(f"{state_path.stem}.run_*.log")) - set(log_files)
    assert len(resumed_logs) == 1
    assert f'{source}: rule="' not in resumed_logs.pop().read_text(encoding="utf-8")
    assert source.read_bytes() == payload
    assert _source_identity(source) == identity
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status, attempts FROM objects WHERE kind='file'").fetchall() == [
            ("processed", 1)
        ]
