import json
import sqlite3
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from man_spider.filters import ScopeMatcher
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.rules import RuleEngine
from man_spider.state import SCHEMA_VERSION, ScanState, StateError, UNCLASSIFIED_REASON_BITS
from man_spider.unclassified import default_unclassified_report_path, write_unclassified_report


def coverage_record(**overrides):
    record = {
        "object_key": "local|/scope/mystery.odd",
        "target": "/scope",
        "share": None,
        "path": "/scope/mystery.odd",
        "full_path": "/scope/mystery.odd",
        "filename": "mystery.odd",
        "extension": ".odd",
        "extension_recognized": False,
        "size": 12,
        "mtime": 100.5,
        "reasons": ("unrecognized_extension", "no_active_rule_match"),
        "matched_rule_ids": (),
        "content_status": "not_requested",
        "content_read": False,
        "processing_status": "skipped",
        "processing_reason": "no active rule matched file metadata",
    }
    record.update(overrides)
    return record


def test_rule_engine_recognizes_compound_suffixes_from_positive_extension_predicates():
    engine = RuleEngine(
        [
            {
                "id": "text-files",
                "match": {
                    "condition": "all",
                    "predicates": [
                        {"field": "extension", "operator": "endswith", "value": ".txt"},
                        {"field": "filename", "operator": "contains", "value": "secret"},
                    ],
                },
                "actions": [{"type": "report"}],
            }
        ]
    )

    assert engine.recognizes_extension(".backup.txt") is True
    assert engine.recognizes_extension(".odd") is False
    assert engine.recognizes_extension("") is False


def test_unclassified_observations_are_deduplicated_and_exported_atomically(tmp_path):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "2.0.0")
    state.upsert_unclassified_files((coverage_record(),))
    first_seen = state.report_unclassified_files()[0]["first_seen_at"]
    state.upsert_unclassified_files(
        (
            coverage_record(
                size=14,
                content_status="analyzed",
                content_read=True,
                processing_status="processed",
                processing_reason=None,
            ),
        )
    )

    destination = default_unclassified_report_path(state.path)
    written, count = write_unclassified_report(state, destination)
    report = json.loads(written.read_text(encoding="utf-8"))

    assert count == 1
    assert report["schema_version"] == 1
    assert report["run_id"] == state.run_id
    assert report["full_path"] == "/scope/mystery.odd"
    assert report["size_bytes"] == 14
    assert report["content_read"] is True
    assert report["reasons"] == ["unrecognized_extension", "no_active_rule_match"]
    assert stat.S_IMODE(written.stat().st_mode) == 0o664
    assert list(tmp_path.glob(f".{written.name}.*.tmp")) == []
    assert state.report_unclassified_files()[0]["first_seen_at"] == first_seen
    state.close()


def test_directory_completion_atomically_persists_unselected_coverage_batch(tmp_path):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "2.0.0")
    decision = state.claim_object(
        object_key="directory|local|/scope",
        kind="directory",
        target="/scope",
        path="/scope",
    )
    valid = coverage_record()
    invalid = coverage_record(
        object_key="local|/scope/invalid.odd",
        full_path="/scope/invalid.odd",
        path="/scope/invalid.odd",
        filename="invalid.odd",
        reasons=(),
    )

    with pytest.raises(StateError):
        state.complete_object(
            decision.object_id,
            "processed",
            unclassified_records=(valid, invalid),
        )

    assert state.object_row(decision.object_id)["status"] == "in_progress"
    assert state.unclassified_count() == 0

    state.complete_object(
        decision.object_id,
        "processed",
        unclassified_records=(valid,),
    )
    assert state.object_row(decision.object_id)["status"] == "processed"
    assert state.unclassified_count() == 1
    state.close()


def test_terminal_status_and_unclassified_observation_commit_or_roll_back_together(tmp_path):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "2.0.0")
    decision = state.claim_object(
        object_key="local|/scope/mystery.odd",
        kind="file",
        target="/scope",
        path="/scope/mystery.odd",
        size=12,
        mtime=100.5,
    )

    invalid_record = coverage_record(reasons=())
    with pytest.raises(StateError, match="require object_key, full_path, filename, and reasons"):
        state.complete_object(
            decision.object_id,
            "processed",
            unclassified_record=invalid_record,
        )

    assert state.object_row(decision.object_id)["status"] == "in_progress"
    assert state.unclassified_count() == 0

    statements = []
    state.connection.set_trace_callback(statements.append)
    try:
        state.complete_object(
            decision.object_id,
            "processed",
            unclassified_record=coverage_record(),
        )
    finally:
        state.connection.set_trace_callback(None)
    row = state.report_unclassified_files()[0]
    assert state.object_row(decision.object_id)["status"] == "processed"
    assert state.object_row(decision.object_id)["coverage_reason_mask"] == (
        UNCLASSIFIED_REASON_BITS["unrecognized_extension"] | UNCLASSIFIED_REASON_BITS["no_active_rule_match"]
    )
    assert state.connection.execute("SELECT COUNT(*) FROM unclassified_files").fetchone()[0] == 0
    assert sum(statement.lstrip().upper().startswith("UPDATE OBJECTS") for statement in statements) == 1
    assert not any(
        statement.lstrip().upper().startswith(("INSERT INTO UNCLASSIFIED_FILES", "UPDATE UNCLASSIFIED_FILES"))
        for statement in statements
    )
    assert row["processing_status"] == "processed"
    assert row["processing_reason"] is None
    state.close()


@pytest.mark.parametrize("target", [Target("ServerName", 1445), Target("2001:db8::1", 1445)])
def test_manifest_coverage_reconstructs_exact_unc_without_duplicated_path_columns(tmp_path, target):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "2.0.0")
    object_key = f"smb|{target.host.casefold()}|{target.port}|share|folder\\file.tar.odd"
    decision = state.claim_object(
        object_key=object_key,
        kind="file",
        target=str(target),
        share="Share",
        path=r"Folder\file.tar.odd",
        size=12,
        mtime=100.5,
    )
    state.complete_object(
        decision.object_id,
        "processed",
        unclassified_record=coverage_record(
            object_key=object_key,
            target=str(target),
            share="Share",
            path=r"Folder\file.tar.odd",
            full_path=rf"\\{target.host}\Share\Folder\file.tar.odd",
            filename="file.tar.odd",
            extension=".tar.odd",
        ),
    )

    row = state.report_unclassified_files()[0]
    assert row["full_path"] == rf"\\{target.host}\Share\Folder\file.tar.odd"
    assert row["filename"] == "file.tar.odd"
    assert row["extension"] == ".tar.odd"
    columns = {item["name"] for item in state.connection.execute("PRAGMA table_info(objects)").fetchall()}
    assert "coverage_full_path" not in columns
    assert "coverage_filename" not in columns
    state.close()


def test_schema_four_state_migrates_to_hybrid_unclassified_storage(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    state = ScanState.create(path, {}, "2.0.0")
    state.connection.execute("DROP TABLE unclassified_files")
    state.connection.execute("UPDATE runs SET schema_version=4")
    state.set_run_status("interrupted")
    state.close()

    resumed = ScanState.resume(path, {}, "2.0.0")

    assert resumed.run_row()["schema_version"] == SCHEMA_VERSION
    assert resumed.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert (
        resumed.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='unclassified_files'"
        ).fetchone()[0]
        == "unclassified_files"
    )
    resumed.close()


def test_schema_five_state_preserves_legacy_rows_during_hybrid_migration(tmp_path):
    path = tmp_path / "legacy-v5.sqlite3"
    state = ScanState.create(path, {}, "2.0.0")
    state.upsert_unclassified_files((coverage_record(),))
    coverage_columns = [
        row["name"]
        for row in state.connection.execute("PRAGMA table_info(objects)").fetchall()
        if row["name"].startswith("coverage_")
    ]
    for column in reversed(coverage_columns):
        state.connection.execute(f"ALTER TABLE objects DROP COLUMN {column}")
    state.connection.execute("UPDATE runs SET schema_version=5")
    state.set_run_status("interrupted")
    state.close()

    resumed = ScanState.resume(path, {}, "2.0.0")

    assert resumed.run_row()["schema_version"] == SCHEMA_VERSION
    assert resumed.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert {row["name"] for row in resumed.connection.execute("PRAGMA table_info(objects)").fetchall()} >= {
        "coverage_reason_mask",
        "coverage_content_status",
        "coverage_first_seen_at",
    }
    assert resumed.unclassified_count() == 1
    assert resumed.report_unclassified_files()[0]["filename"] == "mystery.odd"
    resumed.close()


def test_manifest_coverage_wins_over_legacy_row_and_deletion_clears_both(tmp_path):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "2.0.0")
    decision = state.claim_object(
        object_key="local|/scope/mystery.odd",
        kind="file",
        target="/scope",
        path="/scope/mystery.odd",
        size=14,
        mtime=101,
    )
    state.upsert_unclassified_files((coverage_record(size=12),))
    state.complete_object(
        decision.object_id,
        "processed",
        unclassified_record=coverage_record(
            size=14,
            mtime=101,
            reasons=("unrecognized_extension",),
            matched_rule_ids=("rule:filename-match",),
            content_status="analyzed",
            content_read=True,
        ),
    )

    rows = state.report_unclassified_files()
    assert len(rows) == state.unclassified_count() == 1
    assert rows[0]["size"] == 14
    assert json.loads(rows[0]["reasons_json"]) == ["unrecognized_extension"]
    assert json.loads(rows[0]["matched_rule_ids_json"]) == ["rule:filename-match"]
    assert state.connection.execute("SELECT COUNT(*) FROM unclassified_files").fetchone()[0] == 1

    state.delete_unclassified_files(("local|/scope/mystery.odd",))
    assert state.unclassified_count() == 0
    assert state.object_row(decision.object_id)["coverage_reason_mask"] == 0
    assert state.connection.execute("SELECT COUNT(*) FROM unclassified_files").fetchone()[0] == 0
    state.close()


def test_reused_manifest_observation_never_spills_into_side_table(tmp_path):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "2.0.0")
    decision = state.claim_object(
        object_key="local|/scope/mystery.odd",
        kind="file",
        target="/scope",
        path="/scope/mystery.odd",
        size=12,
        mtime=100,
    )
    state.complete_object(decision.object_id, "processed", unclassified_record=coverage_record())
    first_seen = state.report_unclassified_files()[0]["first_seen_at"]
    state.upsert_unclassified_files(
        (
            coverage_record(
                _manifest_object_id=decision.object_id,
                processing_status="processed",
                processing_reason="unchanged terminal object reused by resume",
                content_status="reused_without_content_read",
            ),
        )
    )

    row = state.report_unclassified_files()[0]
    assert row["first_seen_at"] == first_seen
    assert row["content_status"] == "reused_without_content_read"
    assert row["processing_reason"] == "unchanged terminal object reused by resume"
    assert state.connection.execute("SELECT COUNT(*) FROM unclassified_files").fetchone()[0] == 0
    state.close()


def test_listed_unknown_file_survives_unavailable_smb_size_metadata(tmp_path):
    class Entry:
        @staticmethod
        def get_longname():
            return "mystery.odd"

        @staticmethod
        def is_directory():
            return False

        @staticmethod
        def get_filesize():
            raise ValueError("invalid size")

    class Client:
        @staticmethod
        def ls(_share, _path):
            return (Entry(),)

        @staticmethod
        def handle_impacket_error(_error):
            return None

    unmatched_route = SimpleNamespace(matched=False, matched_rule_ids=())
    parser = SimpleNamespace(
        has_rules=True,
        has_cli_content_filters=False,
        content_filters=(),
        route_rules=lambda _metadata: unmatched_route,
        recognizes_extension=lambda _extension: False,
        requires_content=lambda _route: False,
    )
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "2.0.0")
    spiderling = Spiderling.__new__(Spiderling)
    spiderling.target = Target("server")
    spiderling.smb_client = Client()
    spiderling.parent = SimpleNamespace(
        state_path=str(state.path),
        state_run_id=state.run_id,
        unclassified_report_enabled=True,
        refresh_resume=False,
        object_retry_limit=2,
        maxdepth=10,
        max_filesize=1024,
        parser=parser,
        scope_matcher=ScopeMatcher(),
        file_extensions=(),
        blocked_content_extensions=(),
        tmp_dir=tmp_path,
        modified_after=None,
        modified_before=None,
    )
    spiderling.scan_state = state
    spiderling.fast_resume = False
    spiderling.resume_frontier = frozenset()
    spiderling.pending_state_completions = []
    spiderling.completed_files_since_progress = 0

    assert list(spiderling.list_files("share")) == []
    spiderling.flush_state_completions()

    record = state.report_unclassified_files()[0]
    assert record["full_path"] == r"\\server\share\mystery.odd"
    assert json.loads(record["reasons_json"]) == ["unrecognized_extension", "no_active_rule_match"]
    assert record["size"] is None
    assert record["content_status"] == "metadata_unavailable"
    assert record["content_read"] == 0
    assert record["processing_status"] == "error"
    assert record["processing_reason"] == "unable to read file size: ValueError: invalid size"
    state.close()


def test_local_scan_reports_rule_gaps_and_blocked_content_without_reading_them(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "covered.txt").write_text("metadata only", encoding="utf-8")
    (scope / "uncovered.txt").write_text("must not be content-read", encoding="utf-8")
    (scope / "mystery.weird").write_text("must not be content-read", encoding="utf-8")
    (scope / "covered.weird").write_text("metadata only", encoding="utf-8")
    (scope / "README").write_text("must not be content-read", encoding="utf-8")
    (scope / "archive.zip").write_bytes(b"not actually a zip SECRET")
    rule_file = tmp_path / "rules.json"
    rule_file.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "rules": [
                    {
                        "id": "covered-text",
                        "match": {
                            "condition": "all",
                            "predicates": [
                                {"field": "extension", "operator": "endswith", "value": ".txt"},
                                {"field": "filename", "operator": "exact", "value": "covered.txt"},
                            ],
                        },
                        "actions": [{"type": "report"}],
                    },
                    {
                        "id": "covered-unknown-name",
                        "match": {
                            "condition": "all",
                            "predicates": [{"field": "filename", "operator": "exact", "value": "covered.weird"}],
                        },
                        "actions": [{"type": "report"}],
                    },
                    {
                        "id": "zip-content",
                        "match": {
                            "condition": "all",
                            "predicates": [{"field": "extension", "operator": "endswith", "value": ".zip"}],
                        },
                        "actions": [{"type": "scan", "representation": "text", "pattern": "SECRET"}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    state_path = tmp_path / "scan.sqlite3"
    script = r"""
import sys
from man_spider.cli import parse_options
from man_spider.manspider import go

scope, rules, state = sys.argv[1:]
arguments = [scope, "--rules", rules, "--skip-formats", "zip", "--yes", "--state-file", state]
options = parse_options(arguments)
raise SystemExit(go(options, command=["manspider", *arguments]))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(scope), str(rule_file), str(state_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report_path = default_unclassified_report_path(state_path)
    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    by_name = {record["filename"]: record for record in records}
    assert set(by_name) == {
        "README",
        "archive.zip",
        "covered.weird",
        "mystery.weird",
        "uncovered.txt",
    }
    assert by_name["uncovered.txt"]["extension_recognized"] is True
    assert by_name["uncovered.txt"]["reasons"] == ["no_active_rule_match"]
    assert by_name["mystery.weird"]["reasons"] == [
        "unrecognized_extension",
        "no_active_rule_match",
    ]
    assert by_name["covered.weird"]["reasons"] == ["unrecognized_extension"]
    assert by_name["covered.weird"]["matched_rule_ids"] == ["rule:covered-unknown-name"]
    assert by_name["README"]["extensionless"] is True
    assert by_name["archive.zip"]["reasons"] == ["content_not_analyzed_format_policy"]
    assert by_name["archive.zip"]["content_read"] is False
    assert by_name["archive.zip"]["content_status"] == "blocked_by_format_policy"
    assert all(record["full_path"].startswith(str(scope.resolve())) for record in records)

    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM unclassified_files").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM objects WHERE coverage_reason_mask<>0").fetchone()[0] == 5
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_no_unclassified_report_disables_collection_and_sidecar(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "mystery.odd").write_text("metadata only", encoding="utf-8")
    state_path = tmp_path / "scan.sqlite3"
    script = r"""
import sys
from man_spider.cli import parse_options
from man_spider.manspider import go

scope, state = sys.argv[1:]
arguments = [scope, "--extensions", "txt", "--yes", "--no-unclassified-report", "--state-file", state]
options = parse_options(arguments)
raise SystemExit(go(options, command=["manspider", *arguments]))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(scope), str(state_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not default_unclassified_report_path(state_path).exists()
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM unclassified_files").fetchone()[0] == 0


def test_fast_resume_removes_an_observed_gap_that_now_matches_the_rule(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    gap = scope / "gap.odd"
    unfinished = scope / "unfinished.keep"
    gap.write_text("small", encoding="utf-8")
    unfinished.write_text("frontier", encoding="utf-8")
    rule_file = tmp_path / "rules.json"
    rule_file.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "rules": [
                    {
                        "id": "large-odd",
                        "match": {
                            "condition": "all",
                            "predicates": [
                                {"field": "extension", "operator": "exact", "value": ".odd"},
                                {"field": "size", "operator": "gte", "value": 10},
                            ],
                        },
                        "actions": [{"type": "report"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    state_path = tmp_path / "scan.sqlite3"
    script = r"""
import sys
from man_spider.cli import parse_options
from man_spider.manspider import go

scope, rules, state, mode = sys.argv[1:]
arguments = [scope, "--rules", rules, "--yes"]
arguments.extend(["--state-file", state] if mode == "fresh" else ["--resume", state])
options = parse_options(arguments)
raise SystemExit(go(options, command=["manspider", *arguments]))
"""

    fresh = subprocess.run(
        [sys.executable, "-c", script, str(scope), str(rule_file), str(state_path), "fresh"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert fresh.returncode == 0, fresh.stdout + fresh.stderr
    initial = {
        json.loads(line)["filename"]
        for line in default_unclassified_report_path(state_path).read_text(encoding="utf-8").splitlines()
    }
    assert initial == {"gap.odd", "unfinished.keep"}

    gap.write_text("now large enough", encoding="utf-8")
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            "UPDATE objects SET status='in_progress' WHERE kind='file' AND path=?",
            (str(unfinished.resolve()),),
        )

    resumed = subprocess.run(
        [sys.executable, "-c", script, str(scope), str(rule_file), str(state_path), "resume"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    refreshed = [
        json.loads(line)
        for line in default_unclassified_report_path(state_path).read_text(encoding="utf-8").splitlines()
    ]
    assert [record["filename"] for record in refreshed] == ["unfinished.keep"]
    with sqlite3.connect(state_path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM unclassified_files WHERE filename='gap.odd'").fetchone()[0] == 0
        )
