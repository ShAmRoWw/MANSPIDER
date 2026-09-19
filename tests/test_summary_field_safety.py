"""Escaping at presentation boundaries leaves persisted configuration intact."""

from copy import deepcopy
import io
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from man_spider.approval import format_scan_summary
from man_spider.cli import format_configuration, parse_options
from man_spider.lib.finding_log import display_text
from man_spider.lib.util import Target
import man_spider.manspider as app
from man_spider.policy import apply_scope_policy, estimate_scope, format_scope_policy
from man_spider.preflight import AttemptOutcome, PreflightStatus
from man_spider.state import ResumableScan, normalized_scan_configuration


@pytest.mark.parametrize("control", ["\n", "\r", "\t", "\x1b[2J", "\u202e", "\x00"])
def test_configuration_and_approval_escape_fields_not_the_multiline_layout(tmp_path, control):
    options = parse_options([str(tmp_path), "-f", "secret"])
    apply_scope_policy(options, estimate_scope(options))
    payload = "before" + control + "after"
    options.username = options.password = options.domain = options.hash = payload
    options.filenames = [payload]
    options.rule_files = [payload]
    # NUL cannot be a filesystem name. Keep testing it in credentials, filter
    # and diagnostic fields without constructing an impossible local target.
    options.targets = [Path("/synthetic") / (payload if control != "\x00" else "ordinary")]
    options.state_path = options.json_path = options.loot_dir = payload
    options.smb_metrics_path = options.unclassified_report_path = payload
    options.scope_estimate["reason"] = payload
    options.blocked_content_extensions = [payload]
    before = deepcopy(normalized_scan_configuration(options))
    for text in (format_configuration(options), format_scope_policy(options), format_scan_summary(options)):
        assert payload not in text
        assert display_text(payload) in text
        assert "\n" in text  # Deliberate summary structure survives.
    assert normalized_scan_configuration(options) == before
    assert before["authentication"]["password"] == payload


def test_preflight_log_escapes_reason_without_changing_retained_attempt(monkeypatch, tmp_path):
    options = parse_options([str(tmp_path), "-f", "secret"])
    payload = "line\nFORGED\x1b[2J\u202e"
    target = Target("example.invalid")
    attempt = SimpleNamespace(target=target, outcome=AttemptOutcome.SUCCESS, reason=payload, share_count=None)
    result = SimpleNamespace(status=PreflightStatus.SUCCESS, attempts=[attempt], required_definitive_results=3)
    monkeypatch.setattr(app, "verify_credentials", lambda *_args, **_kwargs: result)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    monkeypatch.setattr(app.log, "handlers", [handler])
    monkeypatch.setattr(app.log, "level", logging.INFO)
    assert app.credential_preflight(options) == 0
    assert options.preflight_result is result
    assert attempt.reason == payload
    assert payload not in stream.getvalue()
    assert display_text(payload) in stream.getvalue()


def test_resume_menu_escapes_saved_fields_and_preserves_its_two_line_layout():
    payload = "before\nFORGED\x1b[2Jafter"
    candidate = ResumableScan(path=Path("/synthetic") / payload, run_id="fixture", status="interrupted",
                              created_at="2026-09-14T00:00:00+00:00", updated_at="unused", targets=(payload,))
    rendered = app._resume_candidate_line(1, candidate)
    assert rendered.count("\n") == 1
    assert "\x1b" not in rendered
    assert display_text(payload) in rendered
    assert candidate.targets == (payload,)
