"""Legacy size omissions can be revisited without implicitly enabling downloads."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

import man_spider.manspider as manspider_module
from man_spider.cli import parse_options
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.policy import apply_scope_policy, estimate_scope
from man_spider.state import (
    FindingRecord,
    ResumeMismatchError,
    ScanState,
    directory_object_key,
    local_object_key,
    normalized_scan_configuration,
    share_object_key,
    smb_object_key,
    target_object_key,
)


def local_options(tmp_path, *, resume=False, extra=()):
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    return parse_options([
        str(source), "-f", "important", "--max-filesize", "16",
        "--resume" if resume else "--state-file", str(tmp_path / "scan.sqlite3"),
        "--loot-dir", str(tmp_path / "loot"), "--no-unclassified-report", "--no-smb-metrics",
        "--threads", "1", "--max-sessions-per-host", "1", *extra,
    ])


@pytest.fixture
def state(tmp_path):
    options = local_options(tmp_path)
    current = ScanState.create(options.state_path, normalized_scan_configuration(options), "2.0.0")
    try:
        yield current
    finally:
        current.close()


def seed(state, key, *, size=32, kind="file", status="skipped", reason=None, attempts=3, **values):
    decision = state.register_object(object_key=key, kind=kind, size=size, **values)
    for _ in range(attempts):
        state.begin_object(decision.object_id)
    if status not in {"pending", "in_progress"}:
        state.complete_object(
            decision.object_id, status,
            reason=f"size {size} exceeds active retrieval policy" if reason is None else reason,
            findings=(FindingRecord("prior-rule", "retained evidence", context="prior context"),),
        )
    return decision.object_id


def test_requeue_is_exact_selective_idempotent_and_preserves_findings_and_attempts(state):
    wanted = [seed(state, "fixture|large"), seed(state, "fixture|zero", size=0)]
    untouched = [
        seed(state, "fixture|negative", size=-1),
        seed(state, "fixture|null", size=None),
        seed(state, "fixture|processed", status="processed"),
        seed(state, "fixture|error", status="error"),
        seed(state, "fixture|directory", kind="directory"),
        seed(state, "fixture|mismatch", reason="size 33 exceeds active retrieval policy"),
        seed(state, "fixture|suffix", reason="size 32 exceeds active retrieval policy; unrelated"),
        seed(state, "fixture|format", reason="content disabled by current format policy"),
        seed(state, "fixture|new", reason="size 32 exceeds content/download limit 16; content analysis skipped"),
    ]
    original = {object_id: dict(state.object_row(object_id)) for object_id in wanted + untouched}
    findings = {object_id: [dict(row) for row in state.findings_for(object_id)] for object_id in original}
    assert state.legacy_size_skip_count() == 2
    assert state.requeue_legacy_size_skips() == 2
    assert state.requeue_legacy_size_skips() == 0
    assert state.legacy_size_skip_count() == 0
    for object_id in wanted:
        after = dict(state.object_row(object_id))
        assert after["status"] == "pending"
        assert after["reason"] is None
        for field in original[object_id]:
            if field not in {"status", "reason", "updated_at"}:
                assert after[field] == original[object_id][field], field
    for object_id in untouched:
        assert dict(state.object_row(object_id)) == original[object_id]
    for object_id in original:
        assert [dict(row) for row in state.findings_for(object_id)] == findings[object_id]


@pytest.mark.parametrize("compact", [False, True], ids=["legacy-coverage", "compact-coverage"])
def test_requeue_changes_coverage_processing_state_but_preserves_content_evidence(state, compact):
    key = "fixture|coverage"
    object_id = seed(state, key)
    record = dict(
        object_key=key, target="fixture", path="important.custom", full_path="/fixture/important.custom",
        filename="important.custom", extension=".custom", size=32, mtime=123,
        reasons=["content_not_analyzed_size_policy"], matched_rule_ids=["prior-rule"],
        content_status="blocked_by_size_policy", content_read=False, processing_status="skipped",
        processing_reason="size 32 exceeds active retrieval policy",
    )
    if compact:
        record["_manifest_object_id"] = object_id
    state.upsert_unclassified_files((record,))
    before = state.report_unclassified_files()[0]
    assert state.requeue_legacy_size_skips() == 1
    after = state.report_unclassified_files()[0]
    assert after["processing_status"] == "pending"
    assert after["processing_reason"] is None
    for field in (
        "content_status", "content_read", "size", "mtime", "full_path", "filename",
        "reasons_json", "matched_rule_ids_json", "first_seen_at", "last_seen_at",
    ):
        assert after[field] == before[field], field


def test_requeued_file_reopens_only_required_smb_ancestors_and_ignores_old_attempt_limit(state):
    target = Target("192.0.2.44")
    share_key = share_object_key(target, "Data")
    share_id = seed(
        state, share_key, kind="share", status="error", reason="BrokenPipeError",
        target=str(target), share="Data", path="Data",
    )
    file_key = smb_object_key(target, "Data", r"nested\important.vmdk")
    file_values = dict(target=str(target), share="Data", path=r"nested\important.vmdk", size=32)
    file_id = seed(state, file_key, **file_values)
    unrelated_id = seed(
        state, share_object_key(target, "Other"), kind="share", status="error",
        reason="BrokenPipeError", target=str(target), share="Other", path="Other",
    )
    assert state.prepare_resume(retry_limit=2) == 0
    assert state.requeue_legacy_size_skips() == 1
    assert state.prepare_resume(retry_limit=2) == 1
    assert state.object_row(share_id)["status"] == "pending"
    assert state.object_row(unrelated_id)["status"] == "error"
    worker = Spiderling.__new__(Spiderling)
    worker.target = target
    worker.parent = SimpleNamespace(state_path=state.path, state_run_id=state.run_id, object_retry_limit=2)
    worker.scan_state = state
    assert worker.build_resume_frontier() == frozenset({
        target_object_key(target), share_key, directory_object_key(target, "Data", ""),
        directory_object_key(target, "Data", "nested"), file_key,
    })
    assert state.claim_object(object_key=file_key, kind="file", retry_limit=2, **file_values).should_process
    assert state.object_row(file_id)["attempts"] == 4
    state.complete_object(file_id, "processed", reason="metadata-only processing; content not requested")
    assert state.requeue_legacy_size_skips() == 0
    assert not state.claim_object(object_key=file_key, kind="file", retry_limit=2, **file_values).should_process


@pytest.mark.parametrize("preflight_success", [False, True], ids=["preflight-failure", "operator-refusal"])
def test_no_legacy_size_requeue_before_successful_preflight_and_approval(monkeypatch, tmp_path, preflight_success):
    options = local_options(tmp_path)
    apply_scope_policy(options, estimate_scope(options))
    state = ScanState.create(options.state_path, normalized_scan_configuration(options), "2.0.0")
    object_id = seed(state, local_object_key(tmp_path / "source" / "important.vmdk"))
    original = dict(state.object_row(object_id))
    state.set_run_status("interrupted")
    run_id = state.run_id
    state.close()
    summaries = []

    def deny(summary):
        summaries.append(summary)
        return False

    def unexpected(*args, **kwargs):
        pytest.fail("Main traversal and legacy size recovery require operator approval")

    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0 if preflight_success else 3)
    monkeypatch.setattr(manspider_module, "_emit_terminal_output", lambda *args, **kwargs: None)
    monkeypatch.setattr(ScanState, "requeue_legacy_size_skips", unexpected)
    monkeypatch.setattr(manspider_module, "MANSPIDER", unexpected)
    assert manspider_module.go(local_options(tmp_path, resume=True), approval_request=deny) != 0
    checked = ScanState.attach(options.state_path, run_id)
    try:
        assert dict(checked.object_row(object_id)) == original
        assert checked.legacy_size_skip_count() == 1
    finally:
        checked.close()
    assert len(summaries) == int(preflight_success)
    if summaries:
        assert "Legacy size-skipped files to revisit after approval: 1" in summaries[0]


def test_old_download_enabled_session_requires_explicit_download_opt_in(tmp_path):
    common = [str(tmp_path), "-f", "important"]
    default_options = parse_options(common)
    configuration = normalized_scan_configuration(default_options)
    assert default_options.no_download is True
    legacy = deepcopy(configuration)
    legacy["semantic"]["policy"]["download_matches"] = True
    state = ScanState.create(tmp_path / "legacy-download.sqlite3", legacy, "2.0.0")
    state.set_run_status("interrupted")
    state.close()
    with pytest.raises(ResumeMismatchError, match="--download is now required"):
        ScanState.resume(tmp_path / "legacy-download.sqlite3", configuration, "2.0.0")
    explicit = normalized_scan_configuration(parse_options([*common, "--download"]))
    resumed = ScanState.resume(tmp_path / "legacy-download.sqlite3", explicit, "2.0.0")
    resumed.close()


def test_old_no_download_session_matches_new_default_without_changing_policy(tmp_path):
    common = [str(tmp_path), "-f", "important"]
    # Reproduce the stored policy of a legacy -n run without parsing a removed flag.
    legacy_options = parse_options(common)
    legacy_options.no_download = True
    legacy = normalized_scan_configuration(legacy_options)
    default = normalized_scan_configuration(parse_options(common))
    state = ScanState.create(tmp_path / "legacy-no-download.sqlite3", legacy, "2.0.0")
    state.set_run_status("interrupted")
    state.close()
    resumed = ScanState.resume(tmp_path / "legacy-no-download.sqlite3", default, "2.0.0")
    resumed.close()


def test_real_local_resume_recovers_old_oversized_metadata_once_without_reading_source(monkeypatch, tmp_path):
    options = local_options(tmp_path)
    source = tmp_path / "source" / "important.vmdk"
    source.write_bytes(b"x" * 32)
    source_stat = source.stat()
    apply_scope_policy(options, estimate_scope(options))
    state = ScanState.create(options.state_path, normalized_scan_configuration(options), "2.0.0")
    source_id = seed(
        state, local_object_key(source), target=str(source.parent), path=str(source), size=32,
        mtime=source_stat.st_mtime_ns, file_id=f"{source_stat.st_dev}:{source_stat.st_ino}",
    )
    state.set_run_status("interrupted")
    run_id = state.run_id
    state.close()

    def unexpected_parser(*args, **kwargs):
        pytest.fail("Oversized metadata recovery must never read file content")

    monkeypatch.setattr(Spiderling, "parse_file", unexpected_parser)
    monkeypatch.setattr(Spiderling, "get_file", unexpected_parser)
    assert manspider_module.go(local_options(tmp_path, resume=True), approval_request=lambda _summary: True) == 0
    checked = ScanState.attach(options.state_path, run_id)
    try:
        first = dict(checked.object_row(source_id))
        assert first["status"] == "processed"
        assert first["attempts"] == 4
        findings = [dict(row) for row in checked.findings_for(source_id)]
        assert findings
        assert any("metadata" in finding["rule_id"] for finding in findings)
        assert checked.legacy_size_skip_count() == 0
    finally:
        checked.close()
    assert manspider_module.go(local_options(tmp_path, resume=True), approval_request=lambda _summary: True) == 0
    checked = ScanState.attach(options.state_path, run_id)
    try:
        assert checked.object_row(source_id)["attempts"] == first["attempts"]
        assert [dict(row) for row in checked.findings_for(source_id)] == findings
    finally:
        checked.close()
    assert source.read_bytes() == b"x" * 32
    assert source.stat().st_mtime_ns == source_stat.st_mtime_ns
    assert not (tmp_path / "loot").exists()
