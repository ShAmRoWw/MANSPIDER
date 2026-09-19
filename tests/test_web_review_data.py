"""Specialist marks are durable local annotations, never scanner mutations."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import sqlite3
import stat
import subprocess
import sys
import time

import pytest

from man_spider.path_safety import UnsafeWritePath
from man_spider.state import FindingRecord, ScanState
from man_spider.web_data import ViewerError, ViewerStore
from man_spider.web_review import review_path
import man_spider.web_data as web_data
import man_spider.web_review as web_review


@pytest.fixture
def scan(tmp_path):
    state = ScanState.create(tmp_path / "review-test.sqlite3", {"semantic": {}}, "test")
    yield state
    state.close()


def add_file(scan, name="notes.txt", records=None):
    obj = scan.register_object(object_key=name, kind="file", path=name, size=100)
    scan.complete_object(obj.object_id, "processed", findings=records or [
        FindingRecord(rule_id="rule:critical", severity="critical", value="ExampleOnly123!"),
        FindingRecord(rule_id="rule:low", severity="low", value="notes.txt", representation="metadata"),
    ])
    return obj.object_id


def view(scan):
    store = ViewerStore([], [scan.path])
    return store, store.scans()["scans"][0]["id"]


def hits(store, scan_id, object_id):
    return {hit["rule_id"]: hit for hit in store.object_findings(scan_id, object_id)["items"]}


def digest(path):
    info = path.stat()
    return hashlib.sha256(path.read_bytes()).hexdigest(), info.st_mtime_ns, info.st_ctime_ns


def test_default_reads_and_unmark_do_not_create_sidecar(scan):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    before = set(scan.path.parent.iterdir())
    assert all(hit["reviewed"] is False for hit in hits(store, scan_id, object_id).values())
    assert store.findings(scan_id, review_status="reviewed") == {"items": [], "next_after": None}
    assert len(store.findings(scan_id, review_status="unreviewed")["items"]) == 1
    finding_id = hits(store, scan_id, object_id)["rule:low"]["finding_id"]
    assert store.set_finding_review(scan_id, finding_id, False) == {"finding_id": finding_id, "reviewed": False}
    assert not review_path(scan.path).exists()
    assert set(scan.path.parent.iterdir()) == before


def test_marks_survive_new_viewer_idempotent_and_default_shows_everything(scan):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    for _ in range(2):
        assert store.set_finding_review(scan_id, finding_id, True) == {"finding_id": finding_id, "reviewed": True}
    reopened, reopened_id = view(scan)
    item = reopened.findings(reopened_id)["items"][0]
    assert (item["total_findings"], item["max_severity"]) == (2, "critical")
    assert hits(reopened, reopened_id, object_id)["rule:critical"]["reviewed"] is True
    with sqlite3.connect(review_path(scan.path)) as connection:
        assert connection.execute("SELECT * FROM reviewed_findings").fetchall() == [(scan.run_id, finding_id)]
    assert stat.S_IMODE(review_path(scan.path).stat().st_mode) == 0o600
    assert len(ViewerStore([scan.path.parent]).scans()["scans"]) == 1
    for _ in range(2):
        reopened.set_finding_review(reopened_id, finding_id, False)
    assert hits(store, scan_id, object_id)["rule:critical"]["reviewed"] is False


@pytest.mark.parametrize("status,rule,expected", [
    ("reviewed", "critical", True), ("reviewed", "low", False),
    ("unreviewed", "critical", False), ("unreviewed", "low", True),
])
def test_rule_and_review_status_must_match_same_finding(scan, status, rule, expected):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    store.set_finding_review(scan_id, hits(store, scan_id, object_id)["rule:critical"]["finding_id"], True)
    assert bool(store.findings(scan_id, rule=rule, review_status=status)["items"]) is expected


@pytest.mark.parametrize("status,expected_rule,expected_severity", [
    ("reviewed", "rule:critical", "critical"), ("unreviewed", "rule:low", "low"),
])
def test_review_filter_controls_counts_severity_and_details(scan, status, expected_rule, expected_severity):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    before = store.summary(scan_id)
    store.set_finding_review(scan_id, hits(store, scan_id, object_id)["rule:critical"]["finding_id"], True)
    item = store.findings(scan_id, review_status=status)["items"][0]
    assert (item["total_findings"], item["max_severity"]) == (1, expected_severity)
    assert [hit["rule_id"] for hit in item["findings"]] == [expected_rule]
    assert store.object_findings(scan_id, object_id, review_status=status)["items"] == item["findings"]
    after = store.summary(scan_id)
    assert {key: value for key, value in before.items() if key not in {"revision", "results_revision"}} == {
        key: value for key, value in after.items() if key not in {"revision", "results_revision"}
    }
    assert before["revision"] != after["revision"]
    assert before["results_revision"] != after["results_revision"]


def test_review_changes_in_another_store_invalidate_live_revision(scan, monkeypatch):
    object_id = add_file(scan)
    first, scan_id = view(scan)
    second, second_id = view(scan)
    before = second.summary(second_id)
    first.set_finding_review(scan_id, hits(first, scan_id, object_id)["rule:critical"]["finding_id"], True)
    monkeypatch.setattr(web_data, "_CACHE_SECONDS", 0)
    assert second.summary(second_id)["revision"] != before["revision"]


@pytest.mark.parametrize("status", ["reviewed", "unreviewed"])
def test_pagination_has_no_reviewed_filter_gaps(scan, status):
    object_ids = [add_file(scan, f"{index}.txt") for index in range(6)]
    store, scan_id = view(scan)
    selected = object_ids[::2]
    for object_id in selected:
        for hit in hits(store, scan_id, object_id).values():
            store.set_finding_review(scan_id, hit["finding_id"], True)
    after, found = 0, []
    while True:
        page = store.findings(scan_id, limit=1, after=after, review_status=status)
        found.extend(item["object_id"] for item in page["items"])
        if page["next_after"] is None:
            break
        after = page["next_after"]
    expected = selected if status == "reviewed" else object_ids[1::2]
    assert found == list(reversed(expected))


@pytest.mark.parametrize("status", ["reviewed", "unreviewed"])
def test_detail_pagination_keeps_exact_review_status_beyond_preview(scan, status):
    object_id = add_file(scan, records=[FindingRecord(rule_id=f"rule:{index}", value=f"Fixture{index}") for index in range(43)])
    store, scan_id = view(scan)
    all_hits = list(hits(store, scan_id, object_id).values())
    reviewed_ids = {hit["finding_id"] for hit in all_hits[:22]}
    for finding_id in reviewed_ids:
        store.set_finding_review(scan_id, finding_id, True)
    item = store.findings(scan_id, review_status=status)["items"][0]
    assert item["findings_truncated"] is True
    after, found, page_token = 0, [], None
    while True:
        page = store.object_findings(
            scan_id, object_id, limit=7, after=after, review_status=status, page_token=page_token,
        )
        page_token = page["page_token"]
        found.extend(hit["finding_id"] for hit in page["items"])
        assert all(hit["reviewed"] == (status == "reviewed") for hit in page["items"])
        if page["next_after"] is None:
            break
        after = page["next_after"]
    expected = reviewed_ids if status == "reviewed" else {hit["finding_id"] for hit in all_hits} - reviewed_ids
    assert set(found) == expected and len(found) == len(expected)
    assert item["total_findings"] == len(expected)


def test_scan_bytes_rows_and_sqlite_schema_are_unchanged(scan):
    object_id = add_file(scan)
    scan.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = digest(scan.path)
    rows = list(scan.connection.iterdump())
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    store.set_finding_review(scan_id, finding_id, True)
    with store._connection(scan.path) as connection:
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        for statement in (
            "DELETE FROM main.findings", "CREATE TABLE main.forbidden(x)", "DELETE FROM review.reviewed_findings",
        ):
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                connection.execute(statement)
        # The file handles themselves must be read-only, not merely protected
        # by the normal query_only setting on this connection.
        connection.execute("PRAGMA query_only=OFF")
        for statement in ("DELETE FROM main.findings", "DELETE FROM review.reviewed_findings"):
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                connection.execute(statement)
    store.set_finding_review(scan_id, finding_id, False)
    assert digest(scan.path) == before
    assert list(scan.connection.iterdump()) == rows


def test_new_evidence_is_unreviewed_and_unchanged_identity_keeps_mark(scan):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    original = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    store.set_finding_review(scan_id, original, True)
    add_file(scan)
    assert hits(store, scan_id, object_id)["rule:critical"]["reviewed"] is True
    add_file(scan, records=[FindingRecord(rule_id="rule:critical", severity="critical", value="NewExampleOnly123!")])
    changed = hits(store, scan_id, object_id)["rule:critical"]
    assert changed["finding_id"] != original
    assert changed["reviewed"] is False


def test_identical_finding_id_is_isolated_between_databases(scan):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    other_path = scan.path.with_name("copy.sqlite3")
    with sqlite3.connect(other_path) as connection:
        scan.connection.backup(connection)
    other = ViewerStore([], [other_path])
    other_id = other.scans()["scans"][0]["id"]
    store.set_finding_review(scan_id, finding_id, True)
    assert hits(other, other_id, object_id)["rule:critical"]["reviewed"] is False
    assert not review_path(other_path).exists()


def test_identical_finding_id_in_different_run_is_not_reviewed(scan):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    store.set_finding_review(scan_id, finding_id, True)
    # A disposable legacy fixture reuses an ID after replacing the run. The
    # sidecar lookup must require both keys even if current scanner IDs include
    # the run in their hash already.
    scan.connection.execute("PRAGMA foreign_keys=OFF")
    scan.connection.execute("UPDATE runs SET run_id='other-run'")
    scan.connection.execute("UPDATE objects SET run_id='other-run'")
    scan.connection.execute("UPDATE findings SET run_id='other-run'")
    other, other_id = view(scan)
    assert hits(other, other_id, object_id)["rule:critical"]["reviewed"] is False


@pytest.mark.parametrize("reviewed", [True, False])
def test_unknown_finding_never_creates_or_updates_sidecar(scan, reviewed):
    add_file(scan)
    store, scan_id = view(scan)
    before = set(scan.path.parent.iterdir())
    with pytest.raises(ViewerError) as error:
        store.set_finding_review(scan_id, "missing", reviewed)
    assert error.value.status == 404
    assert set(scan.path.parent.iterdir()) == before


@pytest.mark.parametrize("value", [None, 0, 1, [], {}, "true", "false"])
def test_mark_requires_actual_boolean(scan, value):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    with pytest.raises(ViewerError) as error:
        store.set_finding_review(scan_id, finding_id, value)
    assert error.value.status == 400
    assert not review_path(scan.path).exists()


@pytest.mark.parametrize("value", [None, 0, 1, [], {}, "hidden", "ALL", "reviewed\0", "' OR 1=1 --"])
@pytest.mark.parametrize("method", ["findings", "object_findings"])
def test_review_filter_rejects_unknown_values(scan, value, method):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    arguments = [scan_id] if method == "findings" else [scan_id, object_id]
    with pytest.raises(ViewerError) as error:
        getattr(store, method)(*arguments, review_status=value)
    assert error.value.status == 400


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "fifo", "corrupt", "foreign-schema", "trigger"])
def test_unsafe_sidecar_rejected_without_modifying_destination(scan, kind):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    path = review_path(scan.path)
    victim = scan.path.with_name("untouched.txt")
    victim.write_text("CustomerFixtureDoNotModify")
    if kind == "symlink":
        path.symlink_to(victim)
    elif kind == "hardlink":
        os.link(victim, path)
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "corrupt":
        path.write_bytes(b"not sqlite")
    elif kind == "foreign-schema":
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE foreign_table(x)")
    else:
        store.set_finding_review(scan_id, finding_id, True)
        with sqlite3.connect(path) as connection:
            connection.execute(
                "CREATE TRIGGER unexpected AFTER INSERT ON reviewed_findings "
                "BEGIN DELETE FROM reviewed_findings; END"
            )
    before = digest(victim)
    with pytest.raises(ViewerError) as error:
        store.set_finding_review(scan_id, finding_id, True)
    assert error.value.status == 409
    assert digest(victim) == before


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_symlink_sqlite_auxiliary_sidecar_is_rejected(scan, suffix):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    victim = scan.path.with_name("untouched.txt")
    victim.write_text("LeaveThisAlone")
    review_path(scan.path).with_name(review_path(scan.path).name + suffix).symlink_to(victim)
    with pytest.raises(ViewerError) as error:
        store.set_finding_review(scan_id, finding_id, True)
    assert error.value.status == 409
    assert victim.read_text() == "LeaveThisAlone"
    assert not review_path(scan.path).exists()


def test_unproven_local_review_descriptor_is_rejected(scan, monkeypatch):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    store.set_finding_review(scan_id, finding_id, True)
    before = digest(review_path(scan.path))

    def reject(*args, **kwargs):
        raise UnsafeWritePath("not proven local")

    monkeypatch.setattr(web_review, "require_local_file_descriptor", reject)
    with pytest.raises(ViewerError) as error:
        store.set_finding_review(scan_id, finding_id, False)
    assert error.value.status == 409
    assert digest(review_path(scan.path)) == before


@pytest.mark.parametrize("kind", ["empty", "corrupt", "foreign-schema"])
def test_direct_writer_does_not_chmod_or_change_unrecognized_file(scan, kind):
    path = review_path(scan.path)
    if kind == "foreign-schema":
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE unrelated(x)")
    else:
        path.write_bytes(b"" if kind == "empty" else b"not a database")
    path.chmod(0o644)
    before = digest(path), path.stat().st_mode
    with pytest.raises((web_review.ReviewError, sqlite3.Error)):
        web_review.set_review(scan.path, scan.run_id, "fixture", True, timeout=0.25)
    assert (digest(path), path.stat().st_mode) == before


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_orphaned_sqlite_auxiliary_sidecar_is_not_silently_ignored(scan, suffix):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    auxiliary = review_path(scan.path).with_name(review_path(scan.path).name + suffix)
    auxiliary.write_bytes(b"orphan annotation state")
    before = digest(auxiliary)
    with pytest.raises(ViewerError) as error:
        store.object_findings(scan_id, object_id)
    assert error.value.status == 409
    assert digest(auxiliary) == before
    assert not review_path(scan.path).exists()


def test_concurrent_marks_from_distinct_viewers_are_durable(scan):
    object_id = add_file(scan, records=[FindingRecord(rule_id=f"rule:{index}", value=f"Fixture{index}") for index in range(24)])
    store, scan_id = view(scan)
    ids = [hit["finding_id"] for hit in hits(store, scan_id, object_id).values()]

    def mark(finding_id):
        other, other_id = view(scan)
        return other.set_finding_review(other_id, finding_id, True)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(mark, ids))
    assert len(results) == 24
    assert all(hit["reviewed"] for hit in hits(store, scan_id, object_id).values())


def test_busy_review_database_returns_bounded_retryable_error(scan):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    store.set_finding_review(scan_id, finding_id, True)
    with sqlite3.connect(review_path(scan.path)) as blocker:
        blocker.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        with pytest.raises(ViewerError) as error:
            store.set_finding_review(scan_id, finding_id, False)
        assert error.value.status == 503
        assert time.monotonic() - started < 2
    assert hits(store, scan_id, object_id)["rule:critical"]["reviewed"] is True


def test_review_lookup_uses_both_primary_key_columns(scan):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    store.set_finding_review(scan_id, hits(store, scan_id, object_id)["rule:critical"]["finding_id"], True)
    with store._connection(scan.path) as connection:
        plan = [row[3] for row in connection.execute(
            "EXPLAIN QUERY PLAN SELECT " + web_review.review_expression() + " FROM findings f WHERE object_id=?",
            (object_id,),
        )]
    assert any("PRIMARY KEY (run_id=? AND finding_id=?)" in step for step in plan)


@pytest.mark.parametrize("statement", ["BEGIN IMMEDIATE", "CREATE TABLE", "INSERT INTO", "COMMIT"])
def test_initialization_failure_never_publishes_incomplete_review(scan, monkeypatch, statement):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    original_connect = web_review.sqlite3.connect

    class FailingInitialization(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql.startswith(statement):
                raise sqlite3.OperationalError("injected initialization failure")
            return super().execute(sql, *args, **kwargs)

    def connect(source, *args, **kwargs):
        if isinstance(source, str) and source.endswith("?mode=rw"):
            kwargs["factory"] = FailingInitialization
        return original_connect(source, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(web_review.sqlite3, "connect", connect)
        with pytest.raises(ViewerError) as error:
            store.set_finding_review(scan_id, finding_id, True)
        assert error.value.status == 409
    assert not review_path(scan.path).exists()
    assert list(scan.path.parent.glob(".manspider-review-init-*")) == []
    reopened, reopened_id = view(scan)
    assert hits(reopened, reopened_id, object_id)["rule:critical"]["reviewed"] is False
    reopened.set_finding_review(reopened_id, finding_id, True)
    assert hits(reopened, reopened_id, object_id)["rule:critical"]["reviewed"] is True


def test_initialization_publishes_complete_file_with_one_rename(scan, monkeypatch):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    original_rename = web_review._rename_noreplace
    calls = []

    def publish(parent_descriptor, source, destination):
        assert not review_path(scan.path).exists()
        assert os.stat(source, dir_fd=parent_descriptor).st_nlink == 1
        with sqlite3.connect(scan.path.parent / source) as connection:
            web_review._validate_schema(connection)
            assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
            assert connection.execute("SELECT * FROM reviewed_findings").fetchall() == [(scan.run_id, finding_id)]
        calls.append((source, destination))
        original_rename(parent_descriptor, source, destination)

    monkeypatch.setattr(web_review, "_rename_noreplace", publish)
    store.set_finding_review(scan_id, finding_id, True)
    assert len(calls) == 1
    assert review_path(scan.path).stat().st_nlink == 1
    assert not review_path(scan.path).with_name(review_path(scan.path).name + "-wal").exists()
    assert list(scan.path.parent.glob(".manspider-review-init-*")) == []


@pytest.mark.parametrize("valid", [False, True])
def test_publication_race_never_overwrites_winner(scan, monkeypatch, valid):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    path = review_path(scan.path)
    original_rename = web_review._rename_noreplace
    winner = {}

    def competing_publication(parent_descriptor, source, destination):
        if valid:
            with sqlite3.connect(path) as connection:
                connection.execute(web_review._TABLE_SQL)
                connection.execute(f"PRAGMA application_id={web_review._APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={web_review._VERSION}")
                connection.execute("INSERT INTO reviewed_findings VALUES (?,?)", (scan.run_id, "winner-mark"))
        else:
            path.write_text("UnrelatedOwnerFile")
        path.chmod(0o644)
        winner["before"] = digest(path), path.stat().st_mode
        original_rename(parent_descriptor, source, destination)  # real EEXIST

    monkeypatch.setattr(web_review, "_rename_noreplace", competing_publication)
    if valid:
        store.set_finding_review(scan_id, finding_id, True)
        with sqlite3.connect(path) as connection:
            assert set(connection.execute("SELECT finding_id FROM reviewed_findings")) == {
                ("winner-mark",), (finding_id,),
            }
    else:
        with pytest.raises(ViewerError) as error:
            store.set_finding_review(scan_id, finding_id, True)
        assert error.value.status == 409
        assert (digest(path), path.stat().st_mode) == winner["before"]
    assert list(scan.path.parent.glob(".manspider-review-init-*")) == []


def test_unsupported_atomic_publication_fails_without_broken_final_file(scan, monkeypatch):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    with monkeypatch.context() as patch:
        patch.setattr(web_review.ctypes, "CDLL", lambda *args, **kwargs: object())
        with pytest.raises(ViewerError, match="Atomic local review publication"):
            store.set_finding_review(scan_id, finding_id, True)
    assert not review_path(scan.path).exists()
    assert list(scan.path.parent.glob(".manspider-review-init-*")) == []
    reopened, reopened_id = view(scan)
    reopened.set_finding_review(reopened_id, finding_id, True)
    assert hits(reopened, reopened_id, object_id)["rule:critical"]["reviewed"] is True


@pytest.mark.parametrize("stage", ["_configure_writer", "_rename_noreplace"])
def test_hard_crash_before_publication_leaves_scan_readable(scan, stage):
    object_id = add_file(scan)
    store, scan_id = view(scan)
    finding_id = hits(store, scan_id, object_id)["rule:critical"]["finding_id"]
    program = """
import os, sys
import man_spider.web_review as review
setattr(review, sys.argv[4], lambda *args, **kwargs: os._exit(47))
review.set_review(sys.argv[1], sys.argv[2], sys.argv[3], True, timeout=1)
"""
    child = subprocess.run(
        [sys.executable, "-c", program, str(scan.path), scan.run_id, finding_id, stage],
        check=False, capture_output=True, timeout=10,
    )
    assert child.returncode == 47 and child.stderr == b""
    assert not review_path(scan.path).exists()
    assert len(list(scan.path.parent.glob(".manspider-review-init-*.tmp"))) == 1
    reopened, reopened_id = view(scan)
    assert len(ViewerStore([scan.path.parent]).scans()["scans"]) == 1
    reopened.set_finding_review(reopened_id, finding_id, True)
    assert hits(reopened, reopened_id, object_id)["rule:critical"]["reviewed"] is True
