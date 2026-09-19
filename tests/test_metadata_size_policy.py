"""Size limits constrain content and loot, never size-independent metadata reports."""

import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

from man_spider.cli import parse_options
from man_spider.filters import ScopeMatcher
from man_spider.lib.parser import FileParser
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.rules import load_builtin_rules, load_rule_files
from man_spider.state import ScanState, normalized_scan_configuration


HUGE_SIZE = 100 * 1024**3
DEFAULT_LIMIT = 10 * 1024**2


def write_pack(path, rules):
    path.write_text(
        json.dumps({"schema_version": 2, "rules": rules}),
        encoding="utf-8",
    )


def metadata_rule(*, size_bound=None):
    predicates = [{"field": "filename", "operator": "exact", "value": "important.vmdk"}]
    if size_bound is not None:
        predicates.append({"field": "size", "operator": "between", "value": [0, size_bound]})
    return {"id": "important-disk", "match": {"predicates": predicates}, "actions": [{"type": "report"}]}


def mixed_rules():
    return [
        metadata_rule(),
        {
            "id": "disk-content-secret",
            "match": {"predicates": [{"field": "filename", "operator": "exact", "value": "important.vmdk"}]},
            "actions": [{"type": "scan", "representation": "raw", "pattern": "SECRET"}],
        },
    ]


def make_parser(tmp_path, rules=None, *, filters=()):
    if rules is None:
        loaded = load_builtin_rules()
    else:
        path = tmp_path / "rules.json"
        write_pack(path, rules)
        loaded = load_rule_files([path])
    return FileParser(filters, quiet=True, blocked_extensions=[], rules=loaded)


class FileEntry:
    def __init__(self, size, name="important.vmdk"):
        self.size = size
        self.name = name

    def get_longname(self):
        return self.name

    def is_directory(self):
        return False

    def get_filesize(self):
        return self.size

    def get_mtime_epoch(self):
        return 100


def fake_worker(tmp_path, parser, *, size=HUGE_SIZE, download=False, matcher=None, state=None):
    """Use actual listing/routing/selection code but forbid remote content I/O."""
    listing_calls = []

    def ls(share, path):
        listing_calls.append((share, path))
        return [FileEntry(size)]

    def forbidden(*_args, **_kwargs):
        pytest.fail("metadata-only/oversized file attempted content retrieval or download")

    worker = Spiderling.__new__(Spiderling)
    worker.target = Target("192.0.2.25")
    worker.smb_client = SimpleNamespace(ls=ls)
    worker.parent = SimpleNamespace(
        parser=parser,
        scope_matcher=matcher or ScopeMatcher(),
        no_download=not download,
        maxdepth=15,
        max_filesize=DEFAULT_LIMIT,
        modified_after=None,
        modified_before=None,
        blocked_content_extensions=(),
        tmp_dir=tmp_path,
        state_path=str(state.path) if state else None,
        state_run_id=state.run_id if state else None,
        unclassified_report_enabled=bool(state),
        object_retry_limit=2,
        quiet=True,
    )
    worker.fast_resume = False
    worker.scan_state = state
    worker.completed_files_since_progress = 0
    worker.get_file = forbidden
    worker.save_file = forbidden
    worker.parse_file = forbidden
    completions = []
    if state is None:
        worker.complete_file = lambda file, status, **values: completions.append((file, status, values))
    return worker, listing_calls, completions


@pytest.mark.parametrize("download", [False, True])
def test_builtin_huge_virtual_disk_is_reported_without_any_content_io(tmp_path, download):
    worker, listing_calls, completions = fake_worker(tmp_path, make_parser(tmp_path), download=download)

    worker.process_remote_files(worker.files_for_share("Backups"))

    assert listing_calls == [("Backups", "")]
    assert len(completions) == 1
    file, status, values = completions[0]
    assert file.size == HUGE_SIZE
    assert status == ("skipped" if download else "processed")
    assert values["content_read"] is False
    assert {finding.rule_id for finding in values["findings"]} >= {"rule:virtual-machine-disk-file"}
    assert all(finding.representation == "metadata" for finding in values["findings"])
    assert all("important.vmdk" in finding.value for finding in values["findings"])
    assert not file.retrieved
    if download:
        assert "download skipped" in values["reason"]
    else:
        assert values["content_status"] == "not_requested"


@pytest.mark.parametrize("download", [False, True])
def test_mixed_route_keeps_metadata_but_explicitly_marks_content_size_skip(tmp_path, download):
    worker, _, completions = fake_worker(tmp_path, make_parser(tmp_path, mixed_rules()), download=download)

    assert list(worker.files_for_share("Backups")) == []

    _, status, values = completions[0]
    assert status == "skipped"
    assert values["content_read"] is False
    assert values["content_status"] == "blocked_by_size_policy"
    assert "content" in values["reason"] and "limit" in values["reason"]
    assert [finding.rule_id for finding in values["findings"]] == ["rule:important-disk"]


@pytest.mark.parametrize("or_logic", [False, True])
def test_required_cli_content_filter_is_not_bypassed_by_metadata(tmp_path, or_logic):
    parser = make_parser(tmp_path, [metadata_rule()], filters=["SECRET"])
    matcher = ScopeMatcher(filename_filters=[re.compile("important")], content_active=True, or_logic=or_logic)
    worker, _, completions = fake_worker(tmp_path, parser, matcher=matcher)

    assert list(worker.files_for_share("Backups")) == []

    _, status, values = completions[0]
    assert status == "skipped"
    assert values["content_status"] == "blocked_by_size_policy"
    assert [finding.rule_id for finding in values["findings"]] == (["rule:important-disk"] if or_logic else [])


def test_rule_specific_size_predicate_is_still_enforced(tmp_path):
    worker, _, completions = fake_worker(tmp_path, make_parser(tmp_path, [metadata_rule(size_bound=1024)]))

    assert list(worker.files_for_share("Backups")) == []

    _, status, values = completions[0]
    assert status == "skipped"
    assert "no active rule" in values["reason"]
    assert not values.get("findings")


def test_explicit_extension_exclusion_is_still_enforced(tmp_path):
    worker, _, completions = fake_worker(
        tmp_path,
        make_parser(tmp_path, [metadata_rule()]),
        matcher=ScopeMatcher(excluded_extensions=[".vmdk"]),
    )

    assert list(worker.files_for_share("Backups")) == []
    assert completions == []


def test_invalid_negative_size_does_not_generate_metadata_findings(tmp_path):
    worker, _, completions = fake_worker(tmp_path, make_parser(tmp_path, [metadata_rule()]), size=-1)

    assert list(worker.files_for_share("Backups")) == []

    _, status, values = completions[0]
    assert status == "skipped"
    assert "invalid file size" in values["reason"]
    assert values["content_read"] is False
    assert not values.get("findings")


@pytest.mark.parametrize("size", [0, 1, DEFAULT_LIMIT])
def test_metadata_within_size_limit_also_needs_no_download(tmp_path, size):
    worker, _, completions = fake_worker(tmp_path, make_parser(tmp_path, [metadata_rule()]), size=size)

    files = list(worker.files_for_share("Backups"))
    assert len(files) == 1
    worker.process_file(files[0])

    assert len(completions) == 1
    assert completions[0][1] == "processed"
    assert [finding.rule_id for finding in completions[0][2]["findings"]] == ["rule:important-disk"]
    assert not files[0].retrieved


def test_explicit_download_preserves_under_limit_metadata_loot_behavior(tmp_path):
    worker, _, completions = fake_worker(
        tmp_path, make_parser(tmp_path, [metadata_rule()]), size=12, download=True
    )
    calls = []
    worker.get_file = lambda file: calls.append(("retrieve", file.name)) or True
    worker.save_file = lambda file: calls.append(("save", file.name)) or True

    files = list(worker.files_for_share("Backups"))
    assert len(files) == 1
    worker.process_file(files[0])

    assert calls == [("retrieve", "important.vmdk"), ("save", "important.vmdk")]
    assert completions[0][1] == "processed"


def test_oversized_mixed_metadata_findings_and_coverage_persist_in_sqlite(tmp_path):
    options = parse_options([str(tmp_path), "-f", "important"])
    state = ScanState.create(tmp_path / "metadata.sqlite3", normalized_scan_configuration(options), "2.0.0")
    try:
        worker, _, _ = fake_worker(tmp_path, make_parser(tmp_path, mixed_rules()), state=state)

        assert list(worker.files_for_share("Backups")) == []
        worker.flush_state_completions()

        with sqlite3.connect(state.path) as connection:
            objects = connection.execute("SELECT status, size, reason FROM objects WHERE kind='file'").fetchall()
            findings = connection.execute("SELECT rule_id, value, representation FROM findings").fetchall()
        coverage = [
            (row["processing_status"], row["content_read"], row["content_status"])
            for row in state.report_unclassified_files()
        ]
        assert len(objects) == 1
        assert objects[0][:2] == ("skipped", HUGE_SIZE)
        assert "content" in objects[0][2]
        assert len(findings) == 1
        assert findings[0][0] == "rule:important-disk"
        assert findings[0][2] == "metadata"
        assert coverage == [("skipped", 0, "blocked_by_size_policy")]
    finally:
        state.close()


@pytest.mark.parametrize("mixed", [False, True])
def test_local_cli_retains_oversized_metadata_in_sqlite_and_json_without_source_changes(tmp_path, mixed):
    scope = tmp_path / "scope"
    scope.mkdir()
    candidate = scope / "important.vmdk"
    candidate.write_bytes(b"SECRET fixture must remain unchanged " * 3)
    before = candidate.stat()
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    rules_path = tmp_path / "rules.json"
    write_pack(rules_path, mixed_rules() if mixed else [metadata_rule()])
    state_path = tmp_path / "scan.sqlite3"
    json_path = tmp_path / "scan.json"
    loot_path = tmp_path / "loot"

    result = subprocess.run(
        [
            sys.executable, "-m", "man_spider.manspider", str(scope), "--yes",
            "--rules", str(rules_path), "--max-filesize", "16",
            "--state-file", str(state_path), "--json-file", str(json_path), "--loot-dir", str(loot_path),
        ],
        capture_output=True, text=True, timeout=30, check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    with sqlite3.connect(state_path) as connection:
        findings = connection.execute("SELECT rule_id, value, representation FROM findings").fetchall()
        objects = connection.execute("SELECT status, reason FROM objects WHERE kind='file'").fetchall()
        configuration = json.loads(connection.execute("SELECT config_json FROM runs").fetchone()[0])
    assert [row[0] for row in findings] == ["rule:important-disk"]
    assert findings[0][1] == str(candidate)
    assert findings[0][2] == "metadata"
    assert objects[0][0] == ("skipped" if mixed else "processed")
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert [item["rule"] for item in report["findings"]] == ["rule:important-disk"]
    assert report["run_status"] == "complete"
    assert configuration["semantic"]["policy"]["download_matches"] is False
    assert not loot_path.exists() or not any(path.is_file() for path in loot_path.rglob("*"))
    after = candidate.stat()
    assert (after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_size, before.st_mtime_ns, before.st_ctime_ns
    )
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == digest
