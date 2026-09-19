"""Read-only viewer queries use disposable local manifests, never SMB."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import sqlite3

import pytest

from man_spider.state import SCHEMA_VERSION, FindingRecord, ScanState
from man_spider.web_data import ViewerError, ViewerStore
import man_spider.web_data as web_data
from tests.optional_fixtures import require_private_directory


@pytest.fixture
def state(tmp_path):
    manifest = ScanState.create(tmp_path / "scan.sqlite3", {
        "semantic": {"scope": {"targets": [
            {"kind": "smb", "host": "192.0.2.10", "port": 445},
            {"kind": "smb", "host": "192.0.2.11", "port": 1445},
        ]}},
        "authentication": {"username": "FixtureUser", "password": "ConfigurationSecretNotForViewer"},
    }, "2.0.0")
    yield manifest
    manifest.close()


def add_object(state, path, *, kind="file", status="processed", reason=None, size=100, findings=()):
    decision = state.register_object(
        object_key=f"{kind}|{path}", kind=kind, target="192.0.2.10", share="Data", path=path, size=size,
    )
    if status in {"processed", "skipped", "error"}:
        state.complete_object(decision.object_id, status, reason=reason, findings=findings)
    elif status == "in_progress":
        state.begin_object(decision.object_id)
    return decision.object_id


def finding(rule="strong-rule", value="password=ExampleOnly123!", *, severity="high", confidence="high",
            representation="raw_text", category="credentials", context=None, tags=("test",)):
    return FindingRecord(
        rule_id="rule:" + rule, value=value, representation=representation,
        severity=severity, confidence=confidence, category=category, context=context, tags=tags,
    )


def viewer(state):
    store = ViewerStore([state.path.parent])
    return store, store.scans()["scans"][0]["id"]


def expire(store):
    store._catalog_time = float("-inf")
    store._summaries.clear()


def test_catalog_allowlists_only_public_scan_information(state):
    store, scan_id = viewer(state)
    result = store.scans()
    assert result["warnings"] == []
    assert result["scans"][0] == {
        "id": scan_id, "run_id": state.run_id, "status": "running",
        "created_at": state.run_row()["created_at"], "updated_at": state.run_row()["updated_at"],
        "completed_at": None, "filename": "scan.sqlite3", "targets": ["192.0.2.10", "192.0.2.11:1445"],
        "schema_version": SCHEMA_VERSION,
    }
    assert "ConfigurationSecretNotForViewer" not in json.dumps(result)
    assert "FixtureUser" not in json.dumps(result)
    assert str(state.path) not in json.dumps(result)


def test_catalog_deduplicates_inputs_orders_newest_and_ignores_other_files(state):
    newer = ScanState.create(state.path.parent / "new.sqlite3", {"scope": {"targets": ["192.0.2.20"]}}, "2.0.0")
    newer.connection.execute("UPDATE runs SET created_at='9999-01-01'")
    newer.close()
    (state.path.parent / "report.json").write_text("{}")
    store = ViewerStore([state.path.parent, state.path.parent], [state.path])
    scans = store.scans()["scans"]
    assert [scan["filename"] for scan in scans] == ["new.sqlite3", "scan.sqlite3"]


@pytest.mark.parametrize("suffix", [".sqlite", ".sqlite3", ".db"])
def test_catalog_combines_legacy_and_nested_sessions_without_duplicates(state, suffix):
    folder = state.path.parent / "nested-session"
    folder.mkdir(mode=0o700)
    path = folder / ("nested" + suffix)
    nested = ScanState.create(path, {}, "2.0.0")
    try:
        nested.connection.execute("UPDATE runs SET created_at='9999-01-01'")
        nested_id = nested.run_id
    finally:
        nested.close()
    (folder / "report.json").write_text("{}", encoding="utf-8")
    discovered = ViewerStore([state.path.parent]).scans()
    assert discovered["warnings"] == []
    assert [scan["run_id"] for scan in discovered["scans"]] == [nested_id, state.run_id]
    store = ViewerStore([state.path.parent, folder, state.path.parent], [path, state.path, path])
    result = store.scans()
    assert result["warnings"] == []
    assert [scan["run_id"] for scan in result["scans"]] == [nested_id, state.run_id]
    assert [scan["filename"] for scan in result["scans"]] == [path.name, state.path.name]


def test_catalog_does_not_descend_beyond_session_folder_but_explicit_file_is_allowed(state):
    folder = state.path.parent / "nested-session"
    folder.mkdir(mode=0o700)
    deeper = folder / "not-a-session-root"
    deeper.mkdir(mode=0o700)
    path = deeper / "deep.sqlite3"
    deep = ScanState.create(path, {}, "2.0.0")
    deep_id = deep.run_id
    deep.close()

    result = ViewerStore([state.path.parent]).scans()
    assert result["warnings"] == []
    assert [scan["run_id"] for scan in result["scans"]] == [state.run_id]
    explicit = ViewerStore([state.path.parent], [path]).scans()
    assert explicit["warnings"] == []
    assert {scan["run_id"] for scan in explicit["scans"]} == {state.run_id, deep_id}


def test_catalog_ignores_symlink_session_directories(tmp_path):
    root = tmp_path / "scans"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    manifest = ScanState.create(outside / "private.sqlite3", {}, "2.0.0")
    manifest.close()
    (root / "linked-session").symlink_to(outside, target_is_directory=True)
    (root / "broken-session").symlink_to(tmp_path / "absent", target_is_directory=True)

    assert ViewerStore([root]).scans() == {"scans": [], "warnings": []}


def test_catalog_limit_is_shared_by_flat_and_nested_sessions(state, monkeypatch):
    folder = state.path.parent / "nested-session"
    folder.mkdir(mode=0o700)
    nested = ScanState.create(folder / "nested.sqlite3", {}, "2.0.0")
    nested.close()
    monkeypatch.setattr(web_data, "_MAX_SCANS", 1)

    result = ViewerStore([state.path.parent]).scans()
    assert len(result["scans"]) == 1
    assert any("Scan discovery limit reached" in warning for warning in result["warnings"])


def test_nested_review_marks_survive_viewer_restart_without_changing_scan(tmp_path):
    root = tmp_path / "scans"
    folder = root / "nested-session"
    folder.mkdir(mode=0o700, parents=True)
    path = folder / "nested.sqlite3"
    manifest = ScanState.create(path, {}, "2.0.0")
    try:
        add_object(manifest, "notes.txt", findings=[finding("first"), finding("second")])
    finally:
        manifest.close()
    original_bytes = path.read_bytes()

    store = ViewerStore([root])
    scan_id = store.scans()["scans"][0]["id"]
    finding_id = store.findings(scan_id)["items"][0]["findings"][0]["finding_id"]
    assert store.set_finding_review(scan_id, finding_id, True) == {
        "finding_id": finding_id, "reviewed": True,
    }
    sidecar = web_data.review_path(path)
    assert sidecar.parent == folder
    assert sidecar.is_file()

    restarted = ViewerStore([root])
    catalog = restarted.scans()
    assert catalog["warnings"] == []
    assert [scan["id"] for scan in catalog["scans"]] == [scan_id]
    reviewed = restarted.findings(scan_id, review_status="reviewed")["items"][0]["findings"]
    assert [(hit["finding_id"], hit["reviewed"]) for hit in reviewed] == [(finding_id, True)]
    remaining = restarted.findings(scan_id, review_status="unreviewed")["items"][0]["findings"]
    assert len(remaining) == 1
    assert remaining[0]["finding_id"] != finding_id
    assert remaining[0]["reviewed"] is False
    assert restarted.summary(scan_id)["findings"] == 2
    assert path.read_bytes() == original_bytes


def test_catalog_missing_directory_does_not_create_it(tmp_path):
    missing = tmp_path / "does-not-exist"
    assert ViewerStore([missing]).scans() == {"scans": [], "warnings": []}
    assert not missing.exists()


@pytest.mark.parametrize("name,contents", [("empty.sqlite3", b""), ("corrupt.sqlite3", b"not sqlite")])
def test_catalog_unknown_database_safe_warning(tmp_path, name, contents):
    (tmp_path / name).write_bytes(contents)
    result = ViewerStore([tmp_path]).scans()
    assert result["scans"] == []
    assert name in result["warnings"][0]


def test_no_migration_when_database_version_is_old(state):
    state.connection.execute("UPDATE runs SET schema_version=1")
    result = ViewerStore([state.path.parent]).scans()
    assert result["scans"] == []
    assert "no automatic migration" in result["warnings"][0]
    assert state.run_row()["schema_version"] == 1


def test_old_schema_is_rejected_without_writing(tmp_path):
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE runs (run_id TEXT)")
    before = path.read_bytes()
    result = ViewerStore([tmp_path]).scans()
    assert result["scans"] == []
    assert "no automatic migration" in result["warnings"][0]
    assert path.read_bytes() == before


def test_symlink_database_is_not_followed(state):
    link = state.path.parent / "linked.db"
    link.symlink_to(state.path)
    result = ViewerStore([], [link]).scans()
    assert result["scans"] == []
    assert result["warnings"]


def test_shared_directory_is_rejected(state):
    state.path.parent.chmod(0o777)
    try:
        result = ViewerStore([], [state.path]).scans()
        assert result["scans"] == []
        assert result["warnings"]
    finally:
        state.path.parent.chmod(0o700)


def test_summary_distinguishes_states_and_unknown_content_analysis(state):
    add_object(state, "notes.txt", findings=[finding()])
    add_object(state, "large.bin", status="skipped", reason="size policy")
    add_object(state, "denied", kind="directory", status="error", reason="STATUS_ACCESS_DENIED")
    add_object(state, "waiting.txt", status="pending")
    add_object(state, "reading.txt", status="in_progress")
    add_object(state, "important", kind="directory", findings=[finding("directory-rule")])
    state.record_exclusion(object_key="excluded", kind="share", target="192.0.2.10", share="IPC$", reason="policy")
    store, scan_id = viewer(state)
    summary = store.summary(scan_id)
    assert summary["objects"] == {
        "file": {"processed": 1, "skipped": 1, "pending": 1, "in_progress": 1},
        "directory": {"error": 1, "processed": 1},
    }
    assert summary["findings"] == 2
    assert summary["matched_files"] == 1
    assert summary["matched_objects"] == 2
    assert summary["exclusions"] == {"share": 1}
    assert summary["analysis_counts_available"] is True
    assert summary["analysis_counts"] == {"unknown": 4, "not_analyzed": 0, "partial": 0, "analyzed": 0}
    assert {reason["reason"] for reason in summary["reasons"]} == {"size policy", "STATUS_ACCESS_DENIED"}


def test_summary_counts_distinct_files_and_nonfile_matches_once(state):
    add_object(state, "matched.txt", findings=[finding("first"), finding("second")])
    add_object(state, "matched-dir", kind="directory", findings=[finding("directory")])
    add_object(state, "unmatched.txt")
    store, scan_id = viewer(state)
    summary = store.summary(scan_id)
    assert (summary["findings"], summary["matched_files"], summary["matched_objects"]) == (3, 1, 2)


def test_grouped_results_keep_all_rules_and_do_not_mask_values(state):
    object_id = add_object(state, "notes.txt", findings=[finding(), finding("other-rule", severity="low")])
    store, scan_id = viewer(state)
    result = store.findings(scan_id, severity="high")
    assert len(result["items"]) == 1
    assert result["items"][0]["object_id"] == object_id
    assert len(result["items"][0]["findings"]) == 2
    assert {hit["value"] for hit in result["items"][0]["findings"]} == {"password=ExampleOnly123!"}
    assert all(hit["finding_id"] for hit in result["items"][0]["findings"])


def test_default_findings_include_weak_metadata_and_all_other_matches(state):
    weak = finding("configuration-data-file", representation="metadata", severity="low", confidence="low")
    weak_id = add_object(state, "weak.txt", findings=[weak])
    mixed = add_object(state, "mixed.txt", findings=[weak, finding()])
    vault = add_object(state, "database.kdbx", findings=[finding("password-vault", representation="metadata")])
    store, scan_id = viewer(state)
    items = store.findings(scan_id)["items"]
    assert [item["object_id"] for item in items] == [vault, mixed, weak_id]
    assert len(items[1]["findings"]) == 2
    assert items[2]["findings"][0]["rule_id"] == "rule:configuration-data-file"


def test_explicit_rule_filter_keeps_weak_metadata_and_content_with_same_id(state):
    add_object(state, "weak.txt", findings=[finding(
        "configuration-data-file", representation="metadata", severity="low", confidence="low",
    )])
    add_object(state, "custom.txt", findings=[finding("configuration-data-file", representation="raw_text")])
    store, scan_id = viewer(state)
    assert [item["path"] for item in store.findings(scan_id, rule="configuration-data-file")["items"]] == [
        "custom.txt", "weak.txt",
    ]


@pytest.mark.parametrize("severity,confidence", [
    ("info", "low"), ("low", "low"), ("critical", "low"), ("low", "high"), ("medium", "medium"),
])
def test_metadata_findings_are_visible_at_every_severity_by_default(state, severity, confidence):
    add_object(state, "custom.txt", findings=[finding(
        "configuration-data-file", representation="metadata", severity=severity, confidence=confidence,
    )])
    store, scan_id = viewer(state)
    assert len(store.findings(scan_id)["items"]) == 1


@pytest.mark.parametrize("filters,expected", [
    ({"rule": "strong-rule"}, ["secret.TXT"]),
    ({"rule": "rule:strong-rule"}, ["secret.TXT"]),
    ({"rule": "strong"}, []),
    ({"severity": "high"}, ["secret.TXT"]),
    ({"confidence": "high"}, ["secret.TXT"]),
    ({"representation": "raw_text"}, ["secret.TXT"]),
    ({"category": "credentials"}, ["secret.TXT"]),
    ({"extension": "txt"}, ["secret.TXT"]),
    ({"extension": ".TXT"}, ["secret.TXT"]),
    ({"path": "secret"}, ["secret.TXT"]),
    ({"q": "ExampleOnly"}, ["secret.TXT"]),
    ({"q": "before secret after"}, ["secret.TXT"]),
    ({"min_size": 101}, ["vault.kdbx"]),
    ({"max_size": 100}, ["secret.TXT"]),
    ({"min_size": 100, "max_size": 100}, ["secret.TXT"]),
    ({"target": "192.0.2.99"}, []),
    ({"share": "missing"}, []),
    ({"share": "data", "target": "192.0.2.10", "rule": "strong-rule"}, ["secret.TXT"]),
])
def test_filters(state, filters, expected):
    add_object(state, "secret.TXT", findings=[finding(context="before secret after")])
    add_object(state, "vault.kdbx", size=200, findings=[finding(
        "vault", value="vault.kdbx", severity="medium", confidence="medium",
        representation="metadata", category="vault",
    )])
    store, scan_id = viewer(state)
    assert [item["path"] for item in store.findings(scan_id, **filters)["items"]] == expected


@pytest.mark.parametrize("query", ["%", "_", "\\", "' OR 1=1 --", "пароль", "<script>"])
def test_search_is_literal_and_keeps_unicode_and_untrusted_text(state, query):
    add_object(state, "plain.txt", findings=[finding(value="ordinary")])
    add_object(state, f"literal{query}.txt", findings=[finding(value=f"prefix {query} suffix")])
    store, scan_id = viewer(state)
    assert len(store.findings(scan_id, q=query)["items"]) == 1
    assert len(store.findings(scan_id, path=query)["items"]) == 1
    assert len(store.objects(scan_id, q=query)["items"]) == 1


def test_filters_must_match_the_same_finding(state):
    add_object(state, "notes.txt", findings=[finding("first", severity="low"), finding("second", severity="high")])
    store, scan_id = viewer(state)
    assert store.findings(scan_id, rule="first", severity="high")["items"] == []


def test_grouped_and_object_pagination_newest_first_without_duplicates(state):
    object_ids = [add_object(state, f"{number}.txt", findings=[finding()]) for number in range(5)]
    store, scan_id = viewer(state)
    for method in (store.findings, store.objects):
        first = method(scan_id, limit=2)
        second = method(scan_id, limit=2, after=first["next_after"])
        third = method(scan_id, limit=2, after=second["next_after"])
        assert [item["object_id"] for page in (first, second, third) for item in page["items"]] == object_ids[::-1]
        assert third["next_after"] is None


@pytest.mark.parametrize("method,filters", [
    ("findings", {}), ("findings", {"severity": "high", "q": "SyntheticOnly"}),
    ("objects", {}), ("objects", {"status": "processed"}),
])
def test_first_page_uses_bounded_reverse_cursor_not_full_run_sort(tmp_path, monkeypatch, method, filters):
    require_private_directory("tools")
    from tools.benchmark_web_viewer import make_seed
    path = tmp_path / "large.sqlite3"
    make_seed(path, 20000)
    store = ViewerStore([], files=[path])
    scan_id = store.scans()["scans"][0]["id"]
    original_connection = store._connection
    progress_calls = []
    statements = []
    @contextmanager
    def measured_connection(path):
        with original_connection(path) as connection:
            # Count virtual-machine work rather than flaky elapsed time. An
            # indexed run scan + sort needs hundreds of thousands of opcodes;
            # a reverse cursor and100 matching records must stay bounded.
            connection.set_progress_handler(lambda: progress_calls.append(1) or 0, 1000)
            connection.set_trace_callback(statements.append)
            yield connection
    monkeypatch.setattr(store, "_connection", measured_connection)
    result = getattr(store, method)(scan_id, limit=100, **filters)
    assert len(result["items"]) == 100
    assert len(progress_calls) < 80
    with original_connection(path) as connection:
        page_query = next(query for query in statements if "FROM objects" in query and "ORDER BY" in query)
        plan = connection.execute("EXPLAIN QUERY PLAN " + page_query).fetchall()
    assert not any("TEMP B-TREE FOR ORDER BY" in row["detail"] for row in plan)


def test_per_object_findings_preview_paginates_without_losing_rules(state):
    object_id = add_object(state, "busy.txt", findings=[finding(f"rule-{number}") for number in range(25)])
    store, scan_id = viewer(state)
    item = store.findings(scan_id)["items"][0]
    assert len(item["findings"]) == 20
    assert item["findings_truncated"] is True
    rest = store.object_findings(
        scan_id, object_id, after=item["findings_next_after"], page_token=item["findings_page_token"],
    )
    assert len(rest["items"]) == 5
    assert rest["next_after"] is None
    assert len({hit["finding_id"] for hit in item["findings"] + rest["items"]}) == 25


def test_grouped_severity_and_count_include_findings_outside_preview(state):
    hits = [finding("old-critical", severity="critical")]
    hits.extend(finding(f"recent-low-{number}", severity="low") for number in range(25))
    add_object(state, "important.txt", findings=hits)
    store, scan_id = viewer(state)
    item = store.findings(scan_id)["items"][0]
    assert {hit["severity"] for hit in item["findings"]} == {"low"}
    assert item["max_severity"] == "critical"
    assert item["total_findings"] == 26


def test_large_evidence_explicit_preview_and_complete_chunked_access(state):
    value = "я" * 70000 + "END"
    context = "prefix" + value
    object_id = add_object(state, "large.txt", findings=[finding(value=value, context=context)])
    store, scan_id = viewer(state)
    hit = store.object_findings(scan_id, object_id)["items"][0]
    assert hit["value_truncated"] and hit["context_truncated"]
    assert hit["value"] == value[:65536]
    for field, expected in (("value", value), ("context", context)):
        first = store.evidence(scan_id, hit["finding_id"], field=field)
        second = store.evidence(scan_id, hit["finding_id"], field=field, offset=first["next_offset"])
        assert first["total"] == len(expected)
        assert first["text"] + second["text"] == expected
        assert second["next_offset"] is None


def test_evidence_null_context_is_empty(state):
    add_object(state, "a", findings=[finding()])
    store, scan_id = viewer(state)
    hit = store.findings(scan_id)["items"][0]["findings"][0]
    assert store.evidence(scan_id, hit["finding_id"], field="context") == {
        "text": "", "total": 0, "next_offset": None,
    }


def test_page_text_budget_keeps_usable_continuation(state, monkeypatch):
    monkeypatch.setattr(web_data, "_PAGE_TEXT_BUDGET", 50)
    ids = [add_object(state, f"{number}.txt", findings=[finding(value="x" * 100)]) for number in range(3)]
    store, scan_id = viewer(state)
    first = store.findings(scan_id, limit=100)
    second = store.findings(scan_id, after=first["next_after"])
    third = store.findings(scan_id, after=second["next_after"])
    assert [page["items"][0]["object_id"] for page in (first, second, third)] == ids[::-1]
    assert third["next_after"] is None


def test_per_object_budget_keeps_usable_continuation(state, monkeypatch):
    monkeypatch.setattr(web_data, "_PAGE_TEXT_BUDGET", 50)
    object_id = add_object(state, "a.txt", findings=[finding(f"r{i}", "x" * 100) for i in range(3)])
    store, scan_id = viewer(state)
    first = store.object_findings(scan_id, object_id)
    second = store.object_findings(
        scan_id, object_id, after=first["next_after"], page_token=first["page_token"],
    )
    third = store.object_findings(
        scan_id, object_id, after=second["next_after"], page_token=second["page_token"],
    )
    assert len({page["items"][0]["finding_id"] for page in (first, second, third)}) == 3
    assert third["next_after"] is None


def test_live_committed_findings_and_resume_existing_object_are_visible(state):
    object_id = add_object(state, "a.txt", findings=[finding("old")])
    store, scan_id = viewer(state)
    before = store.summary(scan_id)
    state.begin_object(object_id)
    state.complete_object(object_id, "processed", findings=[finding("new")])
    expire(store)
    after = store.summary(scan_id)
    assert after["revision"] != before["revision"]
    assert store.findings(scan_id)["items"][0]["findings"][0]["rule_id"] == "rule:new"


def test_read_only_snapshot_does_not_see_uncommitted_writer(state):
    store, scan_id = viewer(state)
    state.connection.execute("BEGIN IMMEDIATE")
    try:
        state.connection.execute(
            "INSERT INTO objects(run_id,object_key,kind,path,discovered_at,updated_at) VALUES(?,?,'file',?,'now','now')",
            (state.run_id, "uncommitted", "uncommitted.txt"),
        )
        assert store.objects(scan_id)["items"] == []
    finally:
        state.connection.rollback()


def test_reads_never_attach_write_or_change_scan_status(state, monkeypatch):
    add_object(state, "a.txt", findings=[finding()])
    def forbidden(*args, **kwargs):
        pytest.fail("Viewer attempted writable ScanState lifecycle")
    monkeypatch.setattr(ScanState, "attach", forbidden)
    monkeypatch.setattr(ScanState, "resume", forbidden)
    monkeypatch.setattr(ScanState, "_configure", forbidden)
    monkeypatch.setattr(ScanState, "_ensure_schema_version", forbidden)
    before = state.connection.total_changes
    store, scan_id = viewer(state)
    store.summary(scan_id)
    store.findings(scan_id)
    store.objects(scan_id)
    assert state.connection.total_changes == before
    assert state.run_row()["status"] == "running"
    with store._connection(state.path) as connection:
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        assert connection.execute("PRAGMA cache_size").fetchone()[0] == -2048
        assert connection.total_changes == 0
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("UPDATE runs SET status='interrupted'")


def test_completed_database_bytes_and_timestamps_unchanged_after_viewing(state):
    add_object(state, "a.txt", findings=[finding()])
    state.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = state.path.read_bytes(), state.path.stat().st_mtime_ns, state.path.stat().st_ctime_ns
    store, scan_id = viewer(state)
    store.summary(scan_id)
    store.objects(scan_id)
    store.findings(scan_id)
    assert (state.path.read_bytes(), state.path.stat().st_mtime_ns, state.path.stat().st_ctime_ns) == before


def test_cached_results_are_not_mutable_by_callers(state):
    store, scan_id = viewer(state)
    store.scans()["scans"].clear()
    assert len(store.scans()["scans"]) == 1
    store.summary(scan_id)["scan"]["targets"].clear()
    assert store.summary(scan_id)["scan"]["targets"]


def test_summary_caches_expensive_queries(state, monkeypatch):
    store, scan_id = viewer(state)
    first = store.summary(scan_id)
    def forbidden(*args, **kwargs):
        pytest.fail("Cached summary unnecessarily opened database")
    monkeypatch.setattr(store, "_connection", forbidden)
    assert store.summary(scan_id) == first


def test_unchanged_database_summary_stays_cached_after_ttl(state, monkeypatch):
    store, scan_id = viewer(state)
    first = store.summary(scan_id)
    store._summaries[scan_id] = (float("-inf"), first)
    def forbidden(*args, **kwargs):
        pytest.fail("Unchanged database summary unnecessarily opened database")
    monkeypatch.setattr(store, "_connection", forbidden)
    assert store.summary(scan_id) == first


def test_known_scan_live_view_does_not_rediscover_catalog(state, monkeypatch):
    store, scan_id = viewer(state)
    store._catalog_time = float("-inf")
    def forbidden(*args, **kwargs):
        pytest.fail("Live view unnecessarily rediscovered all historical scans")
    monkeypatch.setattr(store, "scans", forbidden)
    store.objects(scan_id)
    store.findings(scan_id)
    store.summary(scan_id)


def test_parallel_reads_use_independent_connections(state):
    add_object(state, "a", findings=[finding()])
    store, scan_id = viewer(state)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: store.findings(scan_id), range(8)))
    assert all(len(result["items"]) == 1 for result in results)


def test_query_deadline_interrupts_expensive_sql(state):
    store, _ = viewer(state)
    store.query_timeout = 0.005
    with pytest.raises(ViewerError) as caught:
        with store._connection(state.path) as connection:
            connection.execute(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT sum(x) FROM n"
            ).fetchone()
    assert caught.value.status == 503


@pytest.mark.parametrize("kwargs", [
    {"limit": 0}, {"limit": 201}, {"limit": True}, {"limit": "100"},
    {"after": -1}, {"after": True}, {"after": 2**63}, {"q": "a" * 1025}, {"q": "\x00"},
    {"min_size": -1}, {"max_size": True}, {"min_size": 2**63},
    {"min_size": 10, "max_size": 9},
])
def test_invalid_findings_filters_rejected(state, kwargs):
    store, scan_id = viewer(state)
    with pytest.raises(ViewerError) as caught:
        store.findings(scan_id, **kwargs)
    assert caught.value.status == 400


@pytest.mark.parametrize("scan_id", ["", "../../etc/passwd", "f" * 32, 5])
def test_unknown_scan_cannot_be_used_as_path(state, scan_id):
    store, _ = viewer(state)
    with pytest.raises(ViewerError) as caught:
        store.objects(scan_id)
    assert caught.value.status == 404


@pytest.mark.parametrize("kwargs", [
    {"field": "authentication"}, {"field": "value); DROP TABLE findings; --"},
    {"offset": -1}, {"offset": True}, {"limit": 0}, {"limit": 65537},
])
def test_invalid_evidence_queries_rejected(state, kwargs):
    store, scan_id = viewer(state)
    with pytest.raises(ViewerError) as caught:
        store.evidence(scan_id, "missing", **kwargs)
    assert caught.value.status == 400


def test_missing_objects_and_findings_return_404(state):
    store, scan_id = viewer(state)
    for operation in (lambda: store.object_findings(scan_id, 999), lambda: store.evidence(scan_id, "missing")):
        with pytest.raises(ViewerError) as caught:
            operation()
        assert caught.value.status == 404


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), "bad"])
def test_invalid_query_timeout_rejected(tmp_path, timeout):
    with pytest.raises(ValueError):
        ViewerStore([tmp_path], query_timeout=timeout)
