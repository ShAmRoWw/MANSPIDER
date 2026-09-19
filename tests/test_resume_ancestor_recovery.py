"""Resume must reach unfinished descendants without silently completing them."""

from pathlib import Path

import pytest

from man_spider.cli import parse_options
from man_spider.lib.util import Target
from man_spider.state import (
    FindingRecord,
    ScanState,
    StateError,
    directory_object_key,
    local_object_key,
    normalized_scan_configuration,
    share_object_key,
    smb_object_key,
    target_object_key,
)


@pytest.fixture
def state(tmp_path):
    options = parse_options([str(tmp_path), "-f", "secret"])
    current = ScanState.create(
        tmp_path / "resume-ancestors.sqlite3", normalized_scan_configuration(options), "2.0.0"
    )
    try:
        yield current
    finally:
        current.close()


def remote_values(kind, *, target=None, share="Data", path=""):
    target = target or Target("server")
    if kind == "target":
        return dict(object_key=target_object_key(target), kind=kind, target=str(target), path=str(target))
    if kind == "share":
        key = share_object_key(target, share)
        path = share
    elif kind == "directory":
        key = directory_object_key(target, share, path)
    else:
        key = smb_object_key(target, share, path)
    return dict(object_key=key, kind=kind, target=str(target), share=share, path=path)


def seed(state, values, *, status="error", attempts=2, reason="BrokenPipeError", findings=()):
    decision = state.register_object(**values)
    for _ in range(attempts):
        state.begin_object(decision.object_id)
    if status not in {"pending", "in_progress"}:
        state.complete_object(decision.object_id, status, reason=reason, findings=findings)
    return decision.object_id


def test_prepare_resume_reopens_whole_exhausted_chain_and_preserves_completed_siblings(state):
    parent_target = Target("SERVER", 1445)
    child_target = Target("server", 1445)
    ancestor_values = [
        remote_values("target", target=parent_target),
        remote_values("share", target=parent_target),
        remote_values("directory", target=parent_target),
        remote_values("directory", target=parent_target, path=r"\Folder\Nested"),
    ]
    ancestor_ids = [seed(state, values) for values in ancestor_values]
    file_values = remote_values("file", target=child_target, share="DATA", path="folder/nested/secret.txt")
    child_id = seed(state, file_values, status="in_progress", attempts=1)
    sibling_id = seed(
        state,
        remote_values("directory", target=parent_target, path="finished"),
        status="processed",
        attempts=1,
        reason=None,
        findings=(FindingRecord("fixture", "retained sibling finding"),),
    )
    sibling_before = dict(state.object_row(sibling_id))
    finding_before = [dict(row) for row in state.findings_for(sibling_id)]

    assert state.prepare_resume(retry_limit=2) == 4
    assert state.prepare_resume(retry_limit=2) == 0
    for object_id in ancestor_ids:
        assert state.object_row(object_id)["status"] == "pending"
        assert state.object_row(object_id)["attempts"] == 2
    assert state.object_row(child_id)["status"] == "in_progress"
    assert dict(state.object_row(sibling_id)) == sibling_before
    assert [dict(row) for row in state.findings_for(sibling_id)] == finding_before

    claims = state.claim_objects(dict(values, always_process=True, retry_limit=2) for values in ancestor_values)
    assert all(decision.should_process for decision in claims)
    for decision, values in zip(claims, ancestor_values, strict=True):
        assert state.object_row(decision.object_id)["attempts"] == 3
        state.complete_object(decision.object_id, "error", reason="still unavailable")
        assert not state.claim_object(**values, always_process=True, retry_limit=2).should_process


@pytest.mark.parametrize("child_status, child_attempts", [("pending", 0), ("in_progress", 3), ("error", 1)])
def test_resumable_descendant_can_reopen_exhausted_parent(state, child_status, child_attempts):
    parent_id = seed(state, remote_values("share"))
    seed(
        state,
        remote_values("file", path=r"folder\secret.txt"),
        status=child_status,
        attempts=child_attempts,
    )

    assert state.prepare_resume(retry_limit=2) == 1
    assert state.object_row(parent_id)["status"] == "pending"


def test_exhausted_leaf_does_not_reopen_parent_and_other_errors_keep_retry_budget(state):
    parent_id = seed(state, remote_values("share"))
    file_id = seed(state, remote_values("file", path="secret.txt"))
    unrelated_id = seed(state, remote_values("share", share="Other"))
    before = {object_id: dict(state.object_row(object_id)) for object_id in (parent_id, file_id, unrelated_id)}

    assert state.prepare_resume(retry_limit=2) == 0
    assert {object_id: dict(state.object_row(object_id)) for object_id in before} == before


def test_remote_ancestor_matching_respects_host_port_share_and_directory_boundaries(state):
    target = Target("server", 1445)
    correct_id = seed(state, remote_values("directory", target=target, share="Data", path=r"\FooBar"))
    unrelated_values = [
        remote_values("directory", target=target, share="Data", path="Foo"),
        remote_values("directory", target=target, share="DataBackup", path="FooBar"),
        remote_values("directory", target=Target("server", 445), share="Data", path="FooBar"),
        remote_values("directory", target=Target("server-other", 1445), share="Data", path="FooBar"),
    ]
    unrelated_ids = [seed(state, values) for values in unrelated_values]
    seed(
        state,
        remote_values("file", target=Target("SERVER", 1445), share="DATA", path="foobar/secret.txt"),
        status="in_progress",
        attempts=1,
    )

    assert state.prepare_resume(retry_limit=2) == 1
    assert state.object_row(correct_id)["status"] == "pending"
    assert all(state.object_row(object_id)["status"] == "error" for object_id in unrelated_ids)


def test_skipped_ancestor_is_not_reopened_or_used_to_hide_unfinished_child(state):
    parent_id = seed(state, remote_values("share"), status="skipped", reason="excluded by policy")
    child_id = seed(state, remote_values("file", path="secret.txt"), status="in_progress", attempts=1)

    assert state.prepare_resume(retry_limit=2) == 0
    assert state.settle_blocked_objects() == 0
    assert state.object_row(parent_id)["status"] == "skipped"
    assert state.object_row(child_id)["status"] == "in_progress"
    with pytest.raises(StateError, match="non-terminal"):
        state.finish()


def test_preparation_retains_ancestor_findings_attempts_identity_and_coverage(state):
    values = remote_values("directory", path="folder")
    parent_id = seed(state, values, findings=(FindingRecord("fixture", "known secret"),))
    state.upsert_unclassified_files((coverage_record(parent_id, values),))
    before = dict(state.object_row(parent_id))
    findings_before = [dict(row) for row in state.findings_for(parent_id)]
    seed(state, remote_values("file", path=r"folder\secret.txt"), status="pending", attempts=0)

    assert state.prepare_resume(retry_limit=2) == 1
    after = dict(state.object_row(parent_id))
    for field, old_value in before.items():
        if field not in {"status", "reason", "updated_at"}:
            assert after[field] == old_value, field
    assert [dict(row) for row in state.findings_for(parent_id)] == findings_before


def coverage_record(object_id, values):
    return dict(
        object_key=values["object_key"],
        _manifest_object_id=object_id,
        target=values["target"],
        share=values.get("share"),
        path=values["path"],
        full_path=r"\\server\Data\folder\secret.custom",
        filename="secret.custom",
        extension=".custom",
        size=123,
        mtime=456,
        reasons=["unrecognized_extension"],
        matched_rule_ids=["fixture"],
        content_status="partially_read",
        content_read=True,
        processing_status="observed",
        processing_reason="prior observation",
    )


def test_repeated_parent_failure_settles_all_53_old_objects_as_errors(state):
    share_ids = []
    child_ids = []
    for host, share in (("192.0.2.157", "MSB0166"), ("192.0.2.158", "MSB0387")):
        target = Target(host)
        share_ids.append(seed(state, remote_values("share", target=target, share=share)))
        for number in range(26):
            child_ids.append(
                seed(
                    state,
                    remote_values("directory", target=target, share=share, path=f"folder{number}"),
                    status="in_progress",
                    attempts=1,
                )
            )
    child_ids.append(
        seed(
            state,
            remote_values("file", target=Target("192.0.2.158"), share="MSB0387", path="secret.txt"),
            status="in_progress",
            attempts=1,
        )
    )
    assert state.prepare_resume(retry_limit=2) == 2
    for object_id in share_ids:
        state.begin_object(object_id)
        state.complete_object(object_id, "error", reason="BrokenPipeError: connection closed")

    assert state.settle_blocked_objects() == 53
    assert state.settle_blocked_objects() == 0
    for object_id in child_ids:
        row = state.object_row(object_id)
        assert row["status"] == "error"
        assert row["attempts"] == 1
        assert "Blocked by ancestor" in row["reason"]
        assert "BrokenPipeError: connection closed" in row["reason"]
    assert state.finish() == "complete_with_errors"
    assert state.summary()["in_progress"] == state.summary()["pending"] == 0


@pytest.mark.parametrize("parent_kind", ["target", "share", "directory"])
def test_blocked_settlement_retains_findings_identity_and_content_coverage(state, parent_kind):
    parent_values = remote_values(parent_kind, path="folder")
    parent_id = seed(state, parent_values)
    child_values = dict(remote_values("file", path=r"folder\secret.custom"), size=123, mtime=456, file_id="id:7")
    child_id = seed(
        state, child_values, attempts=1, findings=(FindingRecord("fixture", "prior partial secret"),)
    )
    state.begin_object(child_id)
    state.upsert_unclassified_files((coverage_record(child_id, child_values),))
    before = dict(state.object_row(child_id))
    findings_before = [dict(row) for row in state.findings_for(child_id)]

    assert state.settle_blocked_objects() == 1
    after = dict(state.object_row(child_id))
    for field, old_value in before.items():
        if field not in {"status", "reason", "updated_at", "coverage_processing_status", "coverage_processing_reason"}:
            assert after[field] == old_value, field
    assert [dict(row) for row in state.findings_for(child_id)] == findings_before
    assert after["coverage_processing_status"] == "error"
    assert after["coverage_processing_reason"] == after["reason"]
    report = state.report_unclassified_files()[0]
    assert report["content_status"] == "partially_read"
    assert report["content_read"] == 1
    assert report["processing_status"] == "error"
    assert report["processing_reason"] == after["reason"]
    assert state.object_row(parent_id)["status"] == "error"


def test_access_denied_blockage_remains_visible_without_degrading_run_status(state):
    seed(state, remote_values("share"), reason="STATUS_ACCESS_DENIED")
    child_id = seed(state, remote_values("file", path="secret.txt"), status="pending", attempts=0)

    assert state.settle_blocked_objects() == 1
    row = state.object_row(child_id)
    assert row["status"] == "error"
    assert "STATUS_ACCESS_DENIED" in row["reason"]
    assert row["coverage_processing_status"] is None
    assert row["coverage_processing_reason"] is None
    assert state.finish() == "complete"
    assert state.summary()["error"] == 2


def test_unrelated_error_does_not_allow_unexplained_unfinished_work_to_finish(state):
    seed(state, remote_values("directory", path="foo"))
    seed(state, remote_values("directory", path="foobar"), status="processed", reason=None)
    child_id = seed(state, remote_values("file", path=r"foobar\secret.txt"), status="in_progress", attempts=1)

    assert state.settle_blocked_objects() == 0
    assert state.object_row(child_id)["status"] == "in_progress"
    with pytest.raises(StateError, match="in_progress=1"):
        state.finish()
    assert state.run_row()["status"] == "interrupted"


def test_local_ancestor_recovery_handles_pipe_names_and_path_boundaries(state, tmp_path):
    root = tmp_path / "scope|root"
    parent = root / "folder|name"
    sibling = root / "folder"
    root_values = dict(object_key=target_object_key(root), kind="target", target=str(root), path=str(root))
    parent_values = dict(
        object_key=directory_object_key(root, None, parent), kind="directory", target=str(root), path=str(parent)
    )
    root_id = seed(state, root_values)
    parent_id = seed(state, parent_values)
    unrelated_ids = []
    for path in (sibling, Path(str(parent) + "-other")):
        unrelated_ids.append(
            seed(
                state,
                dict(object_key=directory_object_key(root, None, path), kind="directory", target=str(root), path=str(path)),
            )
        )
    file_path = parent / "secret|value.txt"
    child_id = seed(
        state,
        dict(object_key=local_object_key(file_path), kind="file", target=str(root), path=str(file_path)),
        status="in_progress",
        attempts=1,
    )

    assert state.prepare_resume(retry_limit=2) == 2
    assert state.object_row(root_id)["status"] == state.object_row(parent_id)["status"] == "pending"
    assert all(state.object_row(object_id)["status"] == "error" for object_id in unrelated_ids)
    state.begin_object(root_id)
    state.complete_object(root_id, "processed")
    state.begin_object(parent_id)
    state.complete_object(parent_id, "error", reason="local directory could not be opened")
    assert state.settle_blocked_objects() == 1
    assert state.object_row(child_id)["status"] == "error"
    assert "local directory could not be opened" in state.object_row(child_id)["reason"]
    assert not root.exists()


@pytest.mark.parametrize("child_kind, always_process", [("file", False), ("directory", True)])
def test_ancestor_blockage_does_not_exhaust_interrupted_descendants_own_retry_budget(
    state, child_kind, always_process
):
    parent_values = remote_values("share")
    parent_id = seed(state, parent_values)
    child_values = remote_values(child_kind, path="unfinished")
    child_id = seed(state, child_values, status="in_progress", attempts=3)

    assert state.settle_blocked_objects() == 1
    blocked = state.object_row(child_id)
    assert blocked["status"] == "error"
    assert blocked["reason"].startswith("Blocked by ancestor ")
    assert blocked["attempts"] == 3

    assert state.prepare_resume(retry_limit=2) == 1
    assert state.object_row(parent_id)["status"] == "pending"
    assert child_id in {row["object_id"] for row in state.resumable_objects(retry_limit=2)}
    assert state.claim_object(**parent_values, always_process=True, retry_limit=2).should_process
    state.complete_object(parent_id, "processed")

    decision = state.claim_object(**child_values, always_process=always_process, retry_limit=2)
    assert decision.should_process
    assert state.object_row(child_id)["attempts"] == 4
    assert state.object_row(child_id)["reason"] is None
    state.complete_object(child_id, "error", reason="the object itself could not be read")

    assert not state.claim_object(**child_values, always_process=always_process, retry_limit=2).should_process
    assert child_id not in {row["object_id"] for row in state.resumable_objects(retry_limit=2)}
    assert state.prepare_resume(retry_limit=2) == 0


def test_blocked_settlement_updates_legacy_coverage_without_changing_content_evidence(state):
    seed(state, remote_values("share"))
    child_values = remote_values("file", path=r"folder\secret.custom")
    child_id = seed(state, child_values, status="in_progress", attempts=3)
    legacy = coverage_record(child_id, child_values)
    legacy.pop("_manifest_object_id")
    state.upsert_unclassified_files((legacy,))
    before = state.report_unclassified_files()[0]

    assert state.settle_blocked_objects() == 1
    after = state.report_unclassified_files()[0]
    assert after["processing_status"] == "error"
    assert after["processing_reason"] == state.object_row(child_id)["reason"]
    for field in (
        "content_status", "content_read", "size", "mtime", "full_path", "filename",
        "reasons_json", "matched_rule_ids_json", "first_seen_at",
    ):
        assert after[field] == before[field], field
    assert state.object_row(child_id)["coverage_reason_mask"] == 0
