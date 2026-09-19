"""JSON output must never replace storage owned by the active scan session."""

import io
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from man_spider.cli import ConfigurationError, parse_options
from man_spider.manspider import _emit_terminal_output, offer_automatic_resume
from man_spider.output import JsonOutputError, write_json_report
from man_spider.session_paths import session_path_conflict
from man_spider.state import FindingRecord, ScanLease, ScanState, StateError, normalized_scan_configuration
from man_spider.web_review import review_path, set_review


RESERVED_SUFFIXES = (
    "", "-wal", "-shm", "-journal", ".lock", ".review", ".review-wal", ".review-shm", ".review-journal",
)


class TtyInput(io.StringIO):
    def isatty(self):
        return True


@pytest.mark.parametrize("suffix", RESERVED_SUFFIXES)
@pytest.mark.parametrize("resume", [False, True])
def test_cli_rejects_reserved_session_destinations_before_creating_files(tmp_path, suffix, resume):
    state_path = tmp_path / "scan.sqlite3"
    arguments = [
        str(tmp_path), "-f", "secret", "--resume" if resume else "--state-file", str(state_path),
        "--json-file", str(state_path) + suffix,
    ]
    with pytest.raises(ConfigurationError, match="same path|reserved"):
        parse_options(arguments, defer_existing_json_check=True)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("suffix", RESERVED_SUFFIXES)
@pytest.mark.parametrize("overwrite", [False, True])
def test_runtime_rejection_preserves_findings_review_and_live_lease(tmp_path, suffix, overwrite):
    state_path = tmp_path / "scan.sqlite3"
    state = ScanState.create(state_path, {}, "test")
    lease = ScanLease.acquire(state_path)
    try:
        decision = state.claim_object(object_key="local|/audit/secret.txt", kind="file", path="/audit/secret.txt")
        state.complete_object(
            decision.object_id, "processed", findings=[FindingRecord(rule_id="audit", value="SECRET")],
        )
        finding_id = state.connection.execute("SELECT finding_id FROM findings").fetchone()[0]
        set_review(state_path, state.run_id, finding_id, True, timeout=2)
        protected = [Path(str(state_path) + ending) for ending in RESERVED_SUFFIXES]
        before = {path: path.read_bytes() if path.exists() else None for path in protected}
        with pytest.raises(JsonOutputError, match="reserved"):
            write_json_report(state, Path(str(state_path) + suffix), overwrite=overwrite)
        after = {path: path.read_bytes() if path.exists() else None for path in protected}
        assert after == before
        assert state.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert state.connection.execute("SELECT value FROM findings").fetchone()[0] == "SECRET"
        with sqlite3.connect(f"file:{review_path(state_path)}?mode=ro", uri=True) as review:
            assert review.execute("SELECT finding_id FROM reviewed_findings").fetchall() == [(finding_id,)]
        with pytest.raises(StateError, match="already in use"):
            ScanLease.acquire(state_path)
    finally:
        lease.release()
        state.close()
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT value FROM findings").fetchone()[0] == "SECRET"


@pytest.mark.parametrize("suffix", RESERVED_SUFFIXES)
def test_automatic_resume_revalidates_json_against_selected_session(tmp_path, suffix):
    scope = tmp_path / "scope"
    scope.mkdir()
    scans = tmp_path / "scans"
    state_path = scans / "unfinished.sqlite3"
    initial = parse_options([str(scope), "-f", "secret", "--state-file", str(state_path)])
    state = ScanState.create(state_path, normalized_scan_configuration(initial), "test")
    state.set_run_status("interrupted")
    state.close()
    options = parse_options(
        [str(scope), "-f", "secret", "--json-file", str(state_path) + suffix],
        environ={"HOME": str(tmp_path / "home"), "MANSPIDER_STATE_DIR": str(scans)},
        defer_existing_json_check=True,
    )
    assert options.state_path != str(state_path)
    before = state_path.read_bytes()
    with pytest.raises(ConfigurationError, match="same path|reserved"):
        offer_automatic_resume(options, stdin=TtyInput("1\n"), stdout=io.StringIO())
    assert state_path.read_bytes() == before


@pytest.mark.parametrize("attached", [False, True])
def test_terminal_and_supervisor_shared_output_path_reject_reserved_names(tmp_path, attached):
    path = tmp_path / "scan.sqlite3"
    state = ScanState.create(path, {}, "test")
    run_id = state.run_id
    state.set_run_status("interrupted")
    if not attached:
        state.close()
    try:
        options = SimpleNamespace(json_path=str(path) + "-wal", resume_mode=True)
        with pytest.raises(JsonOutputError, match="reserved"):
            _emit_terminal_output(state if attached else None, path, run_id, options)
    finally:
        if attached:
            state.close()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone()[0] == "interrupted"
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_ordinary_json_and_resume_overwrite_remain_supported(tmp_path):
    path = tmp_path / "scan.sqlite3"
    destination = tmp_path / "scan.json"
    state = ScanState.create(path, {}, "test")
    try:
        write_json_report(state, destination, overwrite=False)
        with pytest.raises(JsonOutputError, match="already exists"):
            write_json_report(state, destination, overwrite=False)
        state.set_run_status("interrupted")
        write_json_report(state, destination, overwrite=True)
        assert json.loads(destination.read_text())['run_status'] == "interrupted"
    finally:
        state.close()


def test_reserved_names_are_specific_to_current_session_and_support_path_aliases(tmp_path):
    state = tmp_path / "scan.sqlite3"
    assert session_path_conflict(state, tmp_path / "subdir" / ".." / "scan.sqlite3-wal") is not None
    assert session_path_conflict(tmp_path / "subdir" / ".." / "scan.sqlite3", str(state) + ".review") is not None
    assert session_path_conflict(state, tmp_path / "other" / "scan.sqlite3-wal") is None
    assert session_path_conflict(state, tmp_path / "other.sqlite3-wal") is None
    assert session_path_conflict(state, tmp_path / "scan.sqlite3-wal.json") is None


def test_light_helper_does_not_import_runtime_or_sqlite():
    completed = subprocess.run(
        [sys.executable, "-c", "import sys; import man_spider.session_paths; "
         "assert 'man_spider.state' not in sys.modules; assert 'man_spider.lib' not in sys.modules; "
         "assert 'sqlite3' not in sys.modules"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
