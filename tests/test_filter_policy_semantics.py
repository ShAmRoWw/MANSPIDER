"""Explicit exclusions and directory separators, including pre-fix resume."""

from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

from man_spider.cli import parse_options
from man_spider.filters import ScopeMatcher, normalize_directory_filter
from man_spider.lib.parser.parser import FileParser
from man_spider.policy import apply_scope_policy, effective_content_blocks, estimate_scope, restore_scope_policy
from man_spider.state import FindingRecord, ResumeMismatchError, ScanState, normalized_scan_configuration


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Filter-policy checks must not contact a server")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.mark.parametrize("mode", ["auto", "read", "skip"])
@pytest.mark.parametrize("large", [False, True])
@pytest.mark.parametrize("extension", [".txt", ".zip", ".bin"])
def test_explicit_skip_has_priority_over_extension_selection(mode, large, extension):
    options = SimpleNamespace(non_text_policy=mode, extensions=[extension], read_formats=[], skip_formats=[extension])
    blocked = effective_content_blocks(options, large)
    assert extension in blocked
    options.skip_formats = []
    assert extension not in effective_content_blocks(options, large)


@pytest.mark.parametrize("name", ["secret.txt", "secret.txt.bak", "secret.txt.old.20260914"])
def test_explicit_skip_does_not_even_invoke_the_content_loader(tmp_path, name):
    options = parse_options([str(tmp_path), "-e", "txt", "-c", "Secret", "--skip-formats", "txt"])
    apply_scope_policy(options, estimate_scope(options))
    parser = FileParser(options.content, blocked_extensions=options.blocked_content_extensions)
    def forbidden():
        pytest.fail("Explicitly disabled content must not be opened")
    result = parser.parse_file(name, data_loader=forbidden, path_factory=forbidden)
    assert result.skipped_reason
    assert not result.findings
    assert result.analysis_read is False


@pytest.mark.parametrize("expression", ["finance/reports", "FINANCE/REPORTS", r"finance\reports", "reports"])
@pytest.mark.parametrize("directory", ["finance/reports", r"finance\reports", r"\finance\reports\2026"])
def test_directory_filters_share_path_separator_semantics(expression, directory):
    scope = ScopeMatcher(included_directories=[expression], excluded_directories=[expression])
    assert scope.directory_matches(directory)
    assert scope.directory_exclusion(directory)
    assert not scope.directory_matches("engineering/other")
    assert scope.directory_exclusion("engineering/other") is None


@pytest.mark.parametrize("expression", ["/", "//", "/finance/", " finance/reports ", ".", "", "[x]", "*"])
def test_filter_normalization_preserves_edges_and_literal_substring_meaning(expression):
    assert normalize_directory_filter(expression) == expression.lower().replace("/", "\\")


def options_for(tmp_path, *extra):
    options = parse_options([str(tmp_path), "-e", "txt", *extra])
    apply_scope_policy(options, estimate_scope(options))
    return options


def saved_state(tmp_path, configuration):
    state = ScanState.create(tmp_path / "scan.sqlite3", configuration, "audit-before")
    decision = state.claim_object(object_key="fixture|secret", kind="file", path="secret.txt")
    state.complete_object(decision.object_id, "processed", findings=[FindingRecord("fixture", "RetainedSecret")])
    state.set_run_status("interrupted")
    row = dict(state.run_row())
    findings = [tuple(item) for item in state.connection.execute("SELECT * FROM findings")]
    state.close()
    return tmp_path / "scan.sqlite3", row, findings


def test_new_slash_and_backslash_filters_resume_identically(tmp_path):
    forward = options_for(tmp_path, "--dirnames", "finance/reports", "--exclude-dirnames", "finance/private")
    backward = options_for(tmp_path, "--dirnames", r"finance\reports", "--exclude-dirnames", r"finance\private")
    assert forward.dirnames == backward.dirnames
    assert forward.exclude_dirnames == backward.exclude_dirnames
    configuration = normalized_scan_configuration(forward)
    path, row, findings = saved_state(tmp_path, configuration)
    resumed = ScanState.resume(path, normalized_scan_configuration(backward), "audit-after")
    try:
        assert resumed.run_id == row["run_id"]
        assert [tuple(item) for item in resumed.connection.execute("SELECT * FROM findings")] == findings
    finally:
        resumed.close()


@pytest.mark.parametrize("field", ["directories", "excluded_directories"])
@pytest.mark.parametrize("identical_requested", [False, True])
def test_old_forward_slash_filter_is_rejected_without_altering_state(tmp_path, field, identical_requested):
    current = normalized_scan_configuration(options_for(tmp_path))
    current["semantic"]["scope"][field] = [r"finance\reports"]
    legacy = deepcopy(current)
    legacy["semantic"]["scope"][field] = ["finance/reports"]
    path, row, findings = saved_state(tmp_path, legacy)
    with pytest.raises(ResumeMismatchError, match="start a new scan.*directory filters"):
        ScanState.resume(path, legacy if identical_requested else current, "audit-after")
    state = ScanState.attach(path, row["run_id"])
    try:
        assert dict(state.run_row()) == row
        assert [tuple(item) for item in state.connection.execute("SELECT * FROM findings")] == findings
    finally:
        state.close()


@pytest.mark.parametrize("blocked", [[], [".zip"], None])
def test_saved_explicit_skip_cannot_be_bypassed_by_policy_restoration(tmp_path, blocked):
    options = options_for(tmp_path, "--skip-formats", "txt")
    legacy = normalized_scan_configuration(options)
    legacy["semantic"]["policy"]["blocked_content_extensions"] = blocked
    path, row, findings = saved_state(tmp_path, legacy)
    # None means no effective policy was selected yet (e.g. preflight failed).
    # Such a run must still be resumable; the new policy is selected later.
    assert restore_scope_policy(options, legacy) is (blocked is not None)
    requested = normalized_scan_configuration(options) if blocked is not None else legacy
    if blocked is not None:
        with pytest.raises(ResumeMismatchError, match="--skip-formats.*start a new scan"):
            ScanState.resume(path, requested, "audit-after")
        state = ScanState.attach(path, row["run_id"])
        assert dict(state.run_row()) == row
    else:
        state = ScanState.resume(path, requested, "audit-after")
    try:
        assert [tuple(item) for item in state.connection.execute("SELECT * FROM findings")] == findings
    finally:
        state.close()


@pytest.mark.parametrize("extras", [[], ["--skip-formats", "zip"], ["--skip-formats", "txt"], ["--dirnames", "reports"]])
def test_unaffected_or_fixed_sessions_continue_without_migration(tmp_path, extras):
    options = options_for(tmp_path, *extras)
    configuration = normalized_scan_configuration(options)
    path, row, findings = saved_state(tmp_path, configuration)
    state = ScanState.resume(path, configuration, "audit-after")
    try:
        assert state.run_id == row["run_id"]
        assert [tuple(item) for item in state.connection.execute("SELECT * FROM findings")] == findings
    finally:
        state.close()


@pytest.mark.parametrize("legacy_kind", ["directory", "explicit_skip"])
def test_affected_resume_stops_before_preflight_or_worker_creation(tmp_path, monkeypatch, legacy_kind):
    import man_spider.manspider as app
    options = options_for(tmp_path, "--skip-formats", "txt")
    configuration = normalized_scan_configuration(options)
    if legacy_kind == "directory":
        configuration["semantic"]["scope"]["directories"] = ["finance/reports"]
    else:
        configuration["semantic"]["policy"]["blocked_content_extensions"] = []
    path, row, _ = saved_state(tmp_path, configuration)
    options.state_path = str(path)
    options.resume_mode = True
    def forbidden(*args, **kwargs):
        pytest.fail("Incompatible resume must stop before preflight or any scan")
    monkeypatch.setattr(app, "credential_preflight", forbidden)
    monkeypatch.setattr(app, "MANSPIDER", forbidden)
    assert app.go(options, command=["manspider", "local-fixture"]) == app.EXIT_STATE_ERROR
    state = ScanState.attach(path, row["run_id"])
    try:
        assert dict(state.run_row()) == row
    finally:
        state.close()


@pytest.mark.parametrize("extra,expected_files,expected_findings", [
    (["--dirnames", "finance/reports"], 1, 1),
    (["--exclude-dirnames", "finance/reports"], 0, 0),
    (["-c", "AuditFilterSecret", "--skip-formats", "txt"], 1, 0),
])
def test_small_real_local_cli_preserves_input_and_fixed_semantics(tmp_path, extra, expected_files, expected_findings):
    source = tmp_path / "source" / "finance" / "reports"
    source.mkdir(parents=True)
    file = source / "secret.txt"
    file.write_text("password=AuditFilterSecret!\n", encoding="utf-8")
    initial = (file.read_bytes(), file.stat().st_mtime_ns)
    state_path = tmp_path / "scan.sqlite3"
    command = [sys.executable, "-m", "man_spider.manspider", str(tmp_path / "source"),
               "-e", "txt", "--state-file", str(state_path), "--yes", "-t", "1",
               "--no-smb-metrics", "--no-unclassified-report", *extra]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20,
                            env={**os.environ, "NO_COLOR": "1"}, cwd=Path(__file__).resolve().parents[1])
    assert result.returncode == 0, result.stdout + result.stderr
    with sqlite3.connect(f"file:{state_path}?mode=ro", uri=True) as connection:
        files = connection.execute("SELECT status,analysis_status,analysis_read FROM objects WHERE kind='file'").fetchall()
        assert len(files) == expected_files
        assert connection.execute("SELECT count(*) FROM findings").fetchone()[0] == expected_findings
        if "--skip-formats" in extra:
            assert files == [("skipped", "not_analyzed", 0)]
        assert json.loads(connection.execute("SELECT config_json FROM runs").fetchone()[0])["semantic"]["scope"]
    assert (file.read_bytes(), file.stat().st_mtime_ns) == initial
