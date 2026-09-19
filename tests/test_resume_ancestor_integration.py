"""Exercise ancestor recovery through the worker and scan lifecycle, without SMB I/O."""

import sqlite3
from types import SimpleNamespace

import pytest

import man_spider.manspider as manspider_module
from man_spider.cli import parse_options
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.manspider import EXIT_COMPLETE_WITH_ERRORS, EXIT_CREDENTIALS_INVALID, go
from man_spider.policy import apply_scope_policy, estimate_scope
from man_spider.state import (
    ScanState,
    directory_object_key,
    normalized_scan_configuration,
    share_object_key,
    smb_object_key,
    target_object_key,
)


TARGET = "192.0.2.40"
SHARE = "data"


def options_for(state_path, *, resume=False, refresh=False):
    arguments = [
        TARGET,
        "-u",
        "fixture-user",
        "-p",
        "fixture-password",
        "-f",
        "secret",
        "--yes",
        "--resume" if resume else "--state-file",
        str(state_path),
    ]
    if refresh:
        arguments.append("--refresh-resume")
    return parse_options(arguments)


def add_object(state, target, kind, path, *, status="processed", attempts=1):
    if kind == "target":
        key = target_object_key(target)
        share = None
    elif kind == "share":
        key = share_object_key(target, SHARE)
        share = SHARE
    elif kind == "directory":
        key = directory_object_key(target, SHARE, path)
        share = SHARE
    else:
        key = smb_object_key(target, SHARE, path)
        share = SHARE
    values = dict(object_key=key, kind=kind, target=str(target), share=share, path=path)
    if kind == "file":
        values.update(size=12, mtime=123, file_id="fixture-id")
    for attempt in range(attempts):
        decision = state.claim_object(**values, retry_limit=attempts + 1)
        assert decision.should_process
        final_status = status if attempt + 1 == attempts else "error"
        if final_status != "in_progress":
            state.complete_object(
                decision.object_id,
                final_status,
                reason="BrokenPipeError: fixture disconnect" if final_status == "error" else None,
            )
    return decision


def worker_for(state, target, *, fast_resume):
    worker = Spiderling.__new__(Spiderling)
    worker.target = target
    worker.parent = SimpleNamespace(
        state_path=str(state.path),
        state_run_id=state.run_id,
        object_retry_limit=2,
    )
    worker.scan_state = state
    worker.fast_resume = fast_resume
    worker.resume_frontier = worker.build_resume_frontier() if fast_resume else frozenset()
    return worker


@pytest.mark.parametrize("fast_resume", [True, False], ids=["continue", "refresh"])
def test_repaired_ancestors_are_claimed_by_single_and_batch_worker_paths(tmp_path, fast_resume):
    state_path = tmp_path / "ancestors.sqlite3"
    state = ScanState.create(state_path, normalized_scan_configuration(options_for(state_path)), "2.0.0")
    target = Target(TARGET)
    try:
        add_object(state, target, "target", str(target))
        share = add_object(state, target, "share", SHARE, status="error", attempts=2)
        add_object(state, target, "directory", "")
        parent = add_object(state, target, "directory", "unfinished", status="error", attempts=2)
        sibling = add_object(state, target, "directory", "finished")
        file = add_object(state, target, "file", r"unfinished\secret.txt", status="in_progress")
        completed_file = add_object(state, target, "file", r"finished\secret.txt")
        unrelated_error = add_object(state, target, "directory", "unrelated-error", status="error", attempts=2)

        assert state.prepare_resume(retry_limit=2) == 2
        assert state.object_row(share.object_id)["attempts"] == 2
        assert state.object_row(parent.object_id)["attempts"] == 2
        assert state.object_row(unrelated_error.object_id)["status"] == "error"
        worker = worker_for(state, target, fast_resume=fast_resume)

        share_claim = worker.prepare_container(
            object_key=share_object_key(target, SHARE),
            kind="share",
            target=str(target),
            share=SHARE,
            path=SHARE,
        )
        assert share_claim.should_process
        assert state.object_row(share.object_id)["attempts"] == 3
        root_claim = worker.prepare_container(
            object_key=directory_object_key(target, SHARE, ""),
            kind="directory",
            target=str(target),
            share=SHARE,
            path="",
        )
        assert root_claim.should_process

        directories, files = worker.prepare_remote_entries(
            SHARE, ("finished", "unfinished", "unrelated-error"), ()
        )
        assert files == ()
        assert directories["unfinished"].should_process
        assert state.object_row(parent.object_id)["attempts"] == 3
        assert directories["finished"].should_process is not fast_resume
        assert state.object_row(sibling.object_id)["attempts"] == (1 if fast_resume else 2)
        assert not directories["unrelated-error"].should_process

        remote_files = [
            SimpleNamespace(target=target, share=SHARE, name=path, size=12, mtime=123, file_id="fixture-id")
            for path in (r"unfinished\secret.txt", r"finished\secret.txt")
        ]
        file_claims = worker.prepare_remote_files(remote_files)
        assert [claim.should_process for claim in file_claims] == [True, False]
        assert state.object_row(file.object_id)["attempts"] == 2
        assert state.object_row(completed_file.object_id)["attempts"] == 1
    finally:
        state.close()


def seed_interrupted_share(state_path):
    options = options_for(state_path)
    apply_scope_policy(options, estimate_scope(options))
    state = ScanState.create(state_path, normalized_scan_configuration(options), "2.0.0")
    target = Target(TARGET)
    try:
        add_object(state, target, "target", str(target))
        share = add_object(state, target, "share", SHARE, status="error", attempts=2)
        child = add_object(state, target, "file", r"nested\secret.txt", status="in_progress")
        state.set_run_status("interrupted", reason="Interrupted fixture")
        return share.object_id, child.object_id
    finally:
        state.close()


def saved_rows(state_path):
    with sqlite3.connect(state_path) as connection:
        connection.row_factory = sqlite3.Row
        run = connection.execute("SELECT * FROM runs").fetchone()
        objects = {row["object_id"]: row for row in connection.execute("SELECT * FROM objects")}
    return run, objects


def watch_recovery(monkeypatch):
    events = []
    prepare = ScanState.prepare_resume
    settle = ScanState.settle_blocked_objects

    def tracked_prepare(self, *args, **kwargs):
        events.append("prepare")
        return prepare(self, *args, **kwargs)

    def tracked_settle(self, *args, **kwargs):
        events.append("settle")
        return settle(self, *args, **kwargs)

    monkeypatch.setattr(ScanState, "prepare_resume", tracked_prepare)
    monkeypatch.setattr(ScanState, "settle_blocked_objects", tracked_settle)
    return events


def test_failed_preflight_preserves_exhausted_parent_and_unfinished_child(monkeypatch, tmp_path):
    state_path = tmp_path / "preflight.sqlite3"
    parent_id, child_id = seed_interrupted_share(state_path)
    events = watch_recovery(monkeypatch)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: EXIT_CREDENTIALS_INVALID)

    def unexpected_worker(_options):
        pytest.fail("Scanning must not start after failed credential preflight")

    monkeypatch.setattr(manspider_module, "MANSPIDER", unexpected_worker)
    assert go(options_for(state_path, resume=True), command=["manspider", TARGET]) == EXIT_CREDENTIALS_INVALID
    run, objects = saved_rows(state_path)
    assert run["status"] == "preflight_failed"
    assert events == []
    assert (objects[parent_id]["status"], objects[parent_id]["attempts"]) == ("error", 2)
    assert (objects[child_id]["status"], objects[child_id]["attempts"]) == ("in_progress", 1)


@pytest.mark.parametrize("refresh", [False, True], ids=["continue", "refresh"])
@pytest.mark.parametrize(
    ("failure", "exit_code", "run_status"),
    [
        ("BrokenPipeError: fixture disconnect", EXIT_COMPLETE_WITH_ERRORS, "complete_with_errors"),
        ("[network_access_denied] SMB SessionError: STATUS_ACCESS_DENIED", 0, "complete"),
    ],
    ids=["disconnect", "access-denied"],
)
def test_normal_resume_settles_children_only_after_single_parent_retry(
    monkeypatch, tmp_path, refresh, failure, exit_code, run_status
):
    state_path = tmp_path / "normal.sqlite3"
    parent_id, child_id = seed_interrupted_share(state_path)
    events = watch_recovery(monkeypatch)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: events.append("preflight") or 0)

    class ParentFailsAgain:
        def __init__(self, options):
            self.options = options
            events.append("worker-created")

        def start(self):
            events.append("worker-started")
            state = ScanState.attach(self.options.state_path, self.options.state_run_id)
            try:
                assert state.object_row(parent_id)["status"] == "pending"
                assert state.object_row(child_id)["status"] == "in_progress"
                worker = worker_for(state, Target(TARGET), fast_resume=not refresh)
                claim = worker.prepare_container(
                    object_key=share_object_key(worker.target, SHARE),
                    kind="share",
                    target=str(worker.target),
                    share=SHARE,
                    path=SHARE,
                )
                assert claim.should_process
                state.complete_object(claim.object_id, "error", reason=failure)
            finally:
                state.close()
            events.append("worker-finished")

    monkeypatch.setattr(manspider_module, "MANSPIDER", ParentFailsAgain)
    assert go(options_for(state_path, resume=True, refresh=refresh), command=["manspider", TARGET]) == exit_code
    run, objects = saved_rows(state_path)
    assert run["status"] == run_status
    assert events == ["preflight", "prepare", "worker-created", "worker-started", "worker-finished", "settle"]
    assert (objects[parent_id]["status"], objects[parent_id]["attempts"]) == ("error", 3)
    assert (objects[child_id]["status"], objects[child_id]["attempts"]) == ("error", 1)
    assert failure in objects[child_id]["reason"]


def test_interrupted_resume_does_not_settle_unfinished_children(monkeypatch, tmp_path):
    state_path = tmp_path / "interrupted.sqlite3"
    parent_id, child_id = seed_interrupted_share(state_path)
    events = watch_recovery(monkeypatch)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    class InterruptedSpider:
        def __init__(self, options):
            self.options = options

        def start(self):
            state = ScanState.attach(self.options.state_path, self.options.state_run_id)
            try:
                claim = state.claim_object(
                    object_key=share_object_key(Target(TARGET), SHARE),
                    kind="share",
                    target=TARGET,
                    share=SHARE,
                    path=SHARE,
                    retry_limit=2,
                )
                assert claim.should_process
                state.complete_object(claim.object_id, "error", reason="BrokenPipeError: fixture disconnect")
            finally:
                state.close()
            raise KeyboardInterrupt

    monkeypatch.setattr(manspider_module, "MANSPIDER", InterruptedSpider)
    assert go(options_for(state_path, resume=True), command=["manspider", TARGET]) == 130
    run, objects = saved_rows(state_path)
    assert run["status"] == "interrupted"
    assert events == ["prepare"]
    assert objects[parent_id]["status"] == "error"
    assert (objects[child_id]["status"], objects[child_id]["attempts"]) == ("in_progress", 1)
