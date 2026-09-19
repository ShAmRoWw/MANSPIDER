"""Small offline tests for concise, safely highlighted finding messages."""

import logging
import re
from logging.handlers import QueueHandler
from types import SimpleNamespace

import pytest

from man_spider.lib import logger as logger_module
from man_spider.lib import spiderling as spiderling_module
from man_spider.lib.file import RemoteFile
from man_spider.lib.finding_log import finding_log_message
from man_spider.lib.logger import ColoredFormatter
from man_spider.lib.parser import FileParser
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.state import FindingRecord


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def finding(**changes):
    fields = {
        "rule_id": "rule:config-password",
        "value": "secret-value",
        "context": "before secret-value after",
        "representation": "text",
        "severity": "high",
        "confidence": "high",
        "rule_source": "builtin",
        "rule_pack_id": "manspider.builtin",
        "rule_pack_version": "test",
        "category": "credentials",
        "tags": ("password", "config"),
    }
    fields.update(changes)
    return FindingRecord(**fields)


def highlighted_parts(message, spans):
    return [(role, message[start:end]) for start, end, role in spans]


def log_record(message, spans, *, severity="high"):
    record = logging.LogRecord("manspider.spiderling", logging.INFO, __file__, 1, message, (), None)
    record.finding_highlights = spans
    record.finding_severity = severity
    return record


def test_finding_message_has_only_the_five_requested_fields():
    message, spans = finding_log_message(r"\\server\share\folder\config.ini", finding())

    assert message == (
        r'\\server\share\folder\config.ini: rule="rule:config-password"; '
        "severity=high; confidence=high; match=before secret-value after"
    )
    assert highlighted_parts(message, spans) == [("severity", "high"), ("match", "secret-value")]
    assert "\x1b" not in message
    for redundant in ("representation=", "source=", "schema=", "pack=", "category=", "tags=", "value="):
        assert redundant not in message


def test_context_is_bounded_but_the_complete_matched_value_is_retained():
    value = "SECRET_" + "x" * 2_000
    record = finding(value=value, context="L" * 500 + value + "R" * 500)

    message, spans = finding_log_message("/scope/config.ini", record)

    assert value in message
    assert message.count("L") == 60
    assert message.count("R") == 61  # The value also contains the R in SECRET.
    assert highlighted_parts(message, spans)[-1] == ("match", value)
    assert record.value == value
    assert record.context == "L" * 500 + value + "R" * 500


def test_exact_context_offset_highlights_the_selected_repeated_occurrence():
    value = "SECRET"
    context = "SECRET at the beginning; " + "between " * 20 + "SECRET at the end"
    offset = context.rindex(value)

    message, spans = finding_log_message(
        "/scope/config.ini", finding(value=value, context=context, context_offset=offset)
    )

    assert "at the beginning" not in message
    assert "SECRET at the end" in message
    assert highlighted_parts(message, spans)[-1] == ("match", value)
    match_start, match_end, _role = spans[-1]
    assert message[match_end:] == " at the end"
    assert message[match_start:match_end] == value


def test_parser_preserves_distinct_context_offsets_for_repeated_matches():
    content = "first line\nSECRET one SECRET two\nlast line"
    parser = FileParser(["SECRET"], quiet=True, blocked_extensions=[])

    result = parser.parse_file("config.txt", data=content.encode())

    assert result.error is None
    assert len(result.findings) == 2
    first, second = result.findings
    assert first.context == second.context == "SECRET one SECRET two"
    assert first.context_offset == 0
    assert second.context_offset == len("SECRET one ")
    for item in result.findings:
        assert item.context[item.context_offset : item.context_offset + len(item.value)] == item.value


def test_inspector_value_without_literal_context_is_shown_with_short_explanation():
    value = "decoded-complete-secret"
    record = finding(value=value, context="decoded from config: " + "a" * 500)

    message, spans = finding_log_message("/scope/config.json", record)

    assert "match=decoded-complete-secret (context: decoded from config: " in message
    assert "a" * 121 not in message
    assert highlighted_parts(message, spans)[-1] == ("match", value)


def test_metadata_finding_retains_the_full_value_without_generic_context():
    value = r"server\share\folder\vault.kdbx"
    record = finding(
        value=value,
        context="matched rule metadata predicates; representation=metadata",
        representation="metadata",
    )

    message, spans = finding_log_message(r"\\server\share\folder\vault.kdbx", record)

    assert message.endswith("match=" + value)
    assert "matched rule metadata" not in message
    assert highlighted_parts(message, spans)[-1] == ("match", value)


def test_disabling_context_keeps_full_value_and_required_fields():
    message, spans = finding_log_message("/scope/config.ini", finding(), show_context=False)

    assert message.endswith("confidence=high; match=secret-value")
    assert "before" not in message
    assert "after" not in message
    assert highlighted_parts(message, spans)[-1] == ("match", "secret-value")


def test_multiline_match_remains_complete_in_one_visible_log_line():
    value = "-----BEGIN PRIVATE KEY-----\nFULL-KEY-MATERIAL\n-----END PRIVATE KEY-----"
    message, spans = finding_log_message("/scope/key.pem", finding(value=value, context="before " + value + " after"))

    assert "\n" not in message
    assert highlighted_parts(message, spans)[-1] == ("match", value.replace("\n", r"\n"))
    assert "match=before " in message
    assert message.endswith(" after")


def test_empty_matches_are_explicit_and_do_not_drop_the_finding():
    message, _spans = finding_log_message("/scope/config.ini", finding(value="", context=""))

    assert "match=(empty match)" in message
    assert 'rule="rule:config-password"' in message


@pytest.mark.parametrize(
    ("control", "escaped"),
    [
        ("\n", r"\n"),
        ("\r", r"\r"),
        ("\t", r"\t"),
        ("\x1b", r"\x1b"),
        ("\x00", r"\x00"),
        ("\u202e", r"\u202e"),
        ("\u2066", r"\u2066"),
    ],
)
def test_untrusted_control_characters_are_visible_and_cannot_forge_log_lines(control, escaped):
    value = "пароль" + control + "secret"
    record = finding(value=value, context="prefix " + value + " suffix", rule_id="rule:bad" + control + "name")

    message, spans = finding_log_message("/scope/bad" + control + "file", record)

    assert control not in message
    assert escaped in message
    assert "пароль" in message
    assert highlighted_parts(message, spans)[-1] == ("match", "пароль" + escaped + "secret")
    assert record.value == value  # Display safety must not redact or rewrite stored evidence.


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_formatter_colors_only_severity_and_exact_match_without_mutating_record(monkeypatch, severity):
    monkeypatch.delenv("NO_COLOR", raising=False)
    message, spans = finding_log_message("/scope/config.ini", finding(severity=severity))
    record = log_record(message, spans, severity=severity)
    formatter = ColoredFormatter("%(message)s", use_color=True)

    colored = formatter.format(record)

    assert ANSI.sub("", colored) == message
    assert colored.startswith('/scope/config.ini: rule="rule:config-password"; severity=')
    assert colored.count("\x1b[0m") == 2
    assert f"severity={ColoredFormatter.severity_colors[severity]}{severity}\x1b[0m" in colored
    assert f"match=before {ColoredFormatter.match_color}secret-value\x1b[0m after" in colored
    assert re.search(r"\x1b\[[0-9;]*m" + severity + r"\x1b\[0m", colored)
    assert re.search(r"\x1b\[[0-9;]*msecret-value\x1b\[0m", colored)
    assert "match=before \x1b[" in colored
    assert "\x1b[0m after" in colored
    assert record.getMessage() == message
    assert record.levelname == "INFO"
    assert logging.Formatter("%(message)s").format(record) == message


@pytest.mark.parametrize("no_color", ["0", "1"])
def test_nonempty_no_color_disables_terminal_escapes(monkeypatch, no_color):
    monkeypatch.setenv("NO_COLOR", no_color)
    message, spans = finding_log_message("/scope/config.ini", finding())

    result = ColoredFormatter("%(levelname)s %(message)s", use_color=True).format(log_record(message, spans))

    assert "\x1b" not in result
    assert message in result


def test_empty_no_color_does_not_disable_terminal_colors(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "")
    message, spans = finding_log_message("/scope/config.ini", finding())

    result = ColoredFormatter("%(message)s", use_color=True).format(log_record(message, spans))

    assert "\x1b" in result
    assert ANSI.sub("", result) == message


@pytest.mark.parametrize(
    ("is_tty", "term", "expected_color"), [(True, "xterm", True), (False, "xterm", False), (True, "dumb", False)]
)
def test_color_auto_detection_respects_terminal_and_redirection(monkeypatch, is_tty, term, expected_color):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", term)
    monkeypatch.setattr(logger_module, "stdout", SimpleNamespace(isatty=lambda: is_tty))
    message, spans = finding_log_message("/scope/config.ini", finding())

    result = ColoredFormatter("%(message)s").format(log_record(message, spans))

    assert ("\x1b" in result) is expected_color
    assert ANSI.sub("", result) == message


def test_queue_preparation_preserves_highlights_and_plain_file_output(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    message, spans = finding_log_message("/scope/config.ini", finding())
    original = log_record(message, spans)

    queued = QueueHandler(None).prepare(original)
    colored = ColoredFormatter("%(message)s", use_color=True).format(queued)
    saved = logging.Formatter("%(levelname)s %(message)s").format(queued)

    assert queued.finding_highlights == spans
    assert queued.finding_severity == "high"
    assert ANSI.sub("", colored) == message
    assert saved == "INFO " + message
    assert "\x1b" not in saved
    assert original.getMessage() == message


def test_explicit_color_off_does_not_color_a_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setattr(logger_module, "stdout", SimpleNamespace(isatty=lambda: True))
    message, spans = finding_log_message("/scope/config.ini", finding())

    result = ColoredFormatter("%(message)s", use_color=False).format(log_record(message, spans))

    assert result == message


@pytest.mark.parametrize("port", [445, 1445])
def test_worker_emits_one_compact_record_with_complete_unc_location(monkeypatch, tmp_path, port):
    calls = []
    monkeypatch.setattr(
        spiderling_module, "log", SimpleNamespace(info=lambda message, **kwargs: calls.append((message, kwargs)))
    )
    worker = object.__new__(Spiderling)
    worker.parent = SimpleNamespace(quiet=False)
    remote = RemoteFile(r"folder\config.ini", "share", Target("192.0.2.3", port), tmp_dir=tmp_path)

    worker.emit_findings(remote, (finding(),))

    assert len(calls) == 1
    message, kwargs = calls[0]
    host = "192.0.2.3" if port == 445 else "192.0.2.3:1445"
    assert message.startswith("\\\\" + host + r"\share\folder\config.ini: rule=")
    assert message.endswith("match=before secret-value after")
    assert kwargs["extra"]["finding_severity"] == "high"
    assert highlighted_parts(message, kwargs["extra"]["finding_highlights"])[-1] == ("match", "secret-value")


def test_worker_quiet_mode_suppresses_only_context_not_findings(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        spiderling_module, "log", SimpleNamespace(info=lambda message, **kwargs: calls.append((message, kwargs)))
    )
    worker = object.__new__(Spiderling)
    worker.parent = SimpleNamespace(quiet=True)

    worker.emit_findings(tmp_path / "config.ini", (finding(), finding(value="another-secret")))

    assert len(calls) == 2
    assert calls[0][0].endswith("match=secret-value")
    assert calls[1][0].endswith("match=another-secret")
    assert all(message.startswith(str(tmp_path / "config.ini")) for message, _kwargs in calls)
