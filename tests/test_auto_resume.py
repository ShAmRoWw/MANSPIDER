import io
import sqlite3
from pathlib import Path

import man_spider.manspider as manspider_module
import pytest

from man_spider.cli import ConfigurationError, parse_options, validate_options
from man_spider.manspider import go, offer_automatic_resume
from man_spider.state import ScanLease, ScanState, discover_resumable_scans, normalized_scan_configuration


class TtyInput(io.StringIO):
    def isatty(self):
        return True


def create_scan(path, scope, *, status="interrupted", created_at="2026-09-03T10:00:00+00:00"):
    options = parse_options([str(scope), "-f", "secret", "--state-file", str(path)])
    state = ScanState.create(path, normalized_scan_configuration(options), "2.0.0")
    if status != "running":
        state.set_run_status(status)
    state.close()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE runs SET created_at=?, updated_at=?",
            (created_at, created_at),
        )
    return options


def test_automatic_state_paths_use_xdg_state_home_and_are_unique(tmp_path):
    state_home = tmp_path / "xdg-state"
    environ = {"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(state_home)}

    first = parse_options(
        [str(tmp_path), "-f", "secret", "--loot-dir", str(tmp_path / "custom-loot")],
        environ=environ,
    )
    second = parse_options([str(tmp_path), "-f", "secret"], environ=environ)

    expected_directory = state_home / "manspider" / "scans"
    assert Path(first.state_path).parent == expected_directory
    assert Path(second.state_path).parent == expected_directory
    assert first.state_path != second.state_path
    assert first.state_path_explicit is False
    assert first.resume_mode is False
    assert not expected_directory.exists()


def test_automatic_state_path_falls_back_to_local_state_directory(tmp_path):
    options = parse_options([str(tmp_path), "-f", "secret"], environ={"HOME": str(tmp_path / "home")})

    assert Path(options.state_path).parent == tmp_path / "home" / ".local" / "state" / "manspider" / "scans"


def test_manspider_state_directory_environment_override_is_exact(tmp_path):
    configured = tmp_path / "central-state"
    options = parse_options(
        [str(tmp_path), "-f", "secret"],
        environ={"HOME": str(tmp_path / "home"), "MANSPIDER_STATE_DIR": str(configured)},
    )

    assert Path(options.state_path).parent == configured


def test_first_scan_creates_its_automatic_state_without_a_prompt(monkeypatch, tmp_path):
    class SuccessfulSpider:
        def __init__(self, options):
            self.options = options

        def start(self):
            return None

    state_home = tmp_path / "state"
    options = parse_options(
        [str(tmp_path), "-f", "secret", "--json", "--yes"],
        environ={"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(state_home)},
    )
    monkeypatch.setattr(manspider_module, "MANSPIDER", SuccessfulSpider)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    assert go(options, command=["manspider", str(tmp_path), "-f", "secret"]) == 0
    assert Path(options.state_path).is_file()
    assert Path(options.state_path).with_name(Path(options.state_path).name + ".lock").is_file()
    assert Path(options.json_path).is_file()
    assert Path(options.json_path).parent == Path(options.state_path).parent
    assert Path(options.unclassified_report_path).is_file()
    assert Path(options.unclassified_report_path).parent == Path(options.state_path).parent
    assert Path(options.unclassified_report_path).read_text(encoding="utf-8") == ""
    with sqlite3.connect(options.state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone()[0] == "complete"


def test_resumable_scan_discovery_is_newest_first_and_ignores_finished_corrupt_and_busy_states(tmp_path):
    scans = tmp_path / "scans"
    scope = tmp_path / "scope"
    scope.mkdir()
    old = scans / "old.sqlite3"
    stale_running = scans / "stale-running.sqlite3"
    newest = scans / "newest.sqlite3"
    complete = scans / "complete.sqlite3"
    busy = scans / "busy.sqlite3"
    create_scan(old, scope, created_at="2026-09-03T10:00:00+00:00")
    create_scan(stale_running, scope, status="running", created_at="2026-09-03T11:00:00+00:00")
    create_scan(newest, scope, created_at="2026-09-03T12:00:00+00:00")
    create_scan(complete, scope, status="complete", created_at="2026-09-03T13:00:00+00:00")
    create_scan(busy, scope, created_at="2026-09-03T14:00:00+00:00")
    (scans / "corrupt.sqlite3").write_bytes(b"not sqlite")

    lease = ScanLease.acquire(busy)
    try:
        candidates = discover_resumable_scans([scans])
    finally:
        lease.release()

    assert [candidate.path.name for candidate in candidates] == [
        "newest.sqlite3",
        "stale-running.sqlite3",
        "old.sqlite3",
    ]
    assert candidates[1].status == "running"
    assert candidates[0].targets == (str(scope),)


def test_interactive_selection_resumes_chosen_scan_and_moves_automatic_json_next_to_it(tmp_path):
    state_home = tmp_path / "state"
    scans = state_home / "manspider" / "scans"
    scope = tmp_path / "scope"
    scope.mkdir()
    older = scans / "older.sqlite3"
    newer = scans / "newer.sqlite3"
    create_scan(older, scope, created_at="2026-09-03T10:00:00+00:00")
    create_scan(newer, scope, created_at="2026-09-03T12:00:00+00:00")
    options = parse_options(
        [str(scope), "-f", "secret", "--json"],
        environ={"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(state_home)},
    )
    output = io.StringIO()

    selected = offer_automatic_resume(options, stdin=TtyInput("2\n"), stdout=output)

    assert selected is not None and selected.path == older.resolve()
    assert options.resume_mode is True
    assert options.resume_file == str(older.resolve())
    assert options.state_path == str(older.resolve())
    assert options.json_path == str(older.resolve().with_suffix(".json"))
    assert options.unclassified_report_path == str(older.resolve().with_suffix(".unclassified-files.jsonl"))
    rendered = output.getvalue()
    assert rendered.index("newer.sqlite3") < rendered.index("older.sqlite3")
    assert "Resuming scan state" in rendered


def test_empty_interactive_selection_starts_a_fresh_automatic_state(tmp_path):
    state_home = tmp_path / "state"
    scans = state_home / "manspider" / "scans"
    scope = tmp_path / "scope"
    scope.mkdir()
    create_scan(scans / "unfinished.sqlite3", scope)
    options = parse_options(
        [str(scope), "-f", "secret"],
        environ={"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(state_home)},
    )
    fresh_path = options.state_path
    output = io.StringIO()

    assert offer_automatic_resume(options, stdin=TtyInput("\n"), stdout=output) is None
    assert options.resume_mode is False
    assert options.state_path == fresh_path
    assert "Starting a new scan" in output.getvalue()


def test_existing_json_file_can_be_reused_only_after_automatic_resume_selection(tmp_path):
    state_home = tmp_path / "state"
    scans = state_home / "manspider" / "scans"
    scope = tmp_path / "scope"
    scope.mkdir()
    create_scan(scans / "unfinished.sqlite3", scope)
    json_path = tmp_path / "existing.json"
    json_path.write_text("preserve until resume", encoding="utf-8")
    arguments = [
        str(scope),
        "-f",
        "secret",
        "--json-file",
        str(json_path),
    ]
    environ = {"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(state_home)}

    with pytest.raises(ConfigurationError, match="already exists"):
        parse_options(arguments, environ=environ)

    options = parse_options(arguments, environ=environ, defer_existing_json_check=True)
    assert offer_automatic_resume(options, stdin=TtyInput("1\n"), stdout=io.StringIO()) is not None
    validate_options(options, environ=environ)
    assert options.resume_mode is True
    assert json_path.read_text(encoding="utf-8") == "preserve until resume"


def test_existing_json_file_is_rejected_after_user_chooses_a_new_scan(tmp_path):
    state_home = tmp_path / "state"
    scans = state_home / "manspider" / "scans"
    scope = tmp_path / "scope"
    scope.mkdir()
    create_scan(scans / "unfinished.sqlite3", scope)
    json_path = tmp_path / "existing.json"
    json_path.write_text("do not overwrite", encoding="utf-8")
    environ = {"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(state_home)}
    options = parse_options(
        [str(scope), "-f", "secret", "--json-file", str(json_path)],
        environ=environ,
        defer_existing_json_check=True,
    )

    assert offer_automatic_resume(options, stdin=TtyInput("0\n"), stdout=io.StringIO()) is None
    with pytest.raises(ConfigurationError, match="already exists"):
        validate_options(options, environ=environ)
    assert json_path.read_text(encoding="utf-8") == "do not overwrite"


def test_resume_prompt_never_blocks_noninteractive_or_explicit_state_runs(tmp_path):
    state_home = tmp_path / "state"
    scans = state_home / "manspider" / "scans"
    scope = tmp_path / "scope"
    scope.mkdir()
    create_scan(scans / "unfinished.sqlite3", scope)
    environ = {"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(state_home)}

    automatic = parse_options([str(scope), "-f", "secret"], environ=environ)
    assert offer_automatic_resume(automatic, stdin=io.StringIO("1\n"), stdout=io.StringIO()) is None
    assert automatic.resume_mode is False

    explicit = parse_options(
        [str(scope), "-f", "secret", "--state-file", str(tmp_path / "explicit.sqlite3")],
        environ=environ,
    )
    assert offer_automatic_resume(explicit, stdin=TtyInput("1\n"), stdout=io.StringIO()) is None
    assert explicit.resume_mode is False

    disabled = parse_options([str(scope), "-f", "secret", "--no-resume-prompt"], environ=environ)
    assert offer_automatic_resume(disabled, stdin=TtyInput("1\n"), stdout=io.StringIO()) is None


def test_automatically_selected_state_runs_through_the_existing_resume_contract(monkeypatch, tmp_path):
    class SuccessfulSpider:
        def __init__(self, options):
            self.options = options

        def start(self):
            return None

    state_home = tmp_path / "state"
    scans = state_home / "manspider" / "scans"
    scope = tmp_path / "scope"
    scope.mkdir()
    state_path = scans / "unfinished.sqlite3"
    create_scan(state_path, scope)
    options = parse_options(
        [str(scope), "-f", "secret", "--yes"],
        environ={"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(state_home)},
    )
    offer_automatic_resume(options, stdin=TtyInput("1\n"), stdout=io.StringIO())
    monkeypatch.setattr(manspider_module, "MANSPIDER", SuccessfulSpider)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    assert go(options, command=["manspider", str(scope), "-f", "secret"]) == 0
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone()[0] == "complete"
