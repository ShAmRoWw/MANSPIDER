import threading
from types import SimpleNamespace

import pytest

from man_spider.lib.spiderling import Spiderling
from man_spider.lib.file import RemoteFile
from man_spider.lib.util import Target
from man_spider.state import FindingRecord, ScanState, StateError


def test_thread_safe_target_state_serializes_share_workers(tmp_path):
    path = tmp_path / "threaded.sqlite3"
    state = ScanState.create(path, {}, "2.0.0")
    run_id = state.run_id
    state.close()
    state = ScanState.attach(path, run_id, thread_safe=True)
    barrier = threading.Barrier(4)
    failures = []

    def write_share(share_index):
        try:
            barrier.wait()
            decisions = state.claim_objects(
                {
                    "object_key": f"file|{share_index}|{item_index}",
                    "kind": "file",
                    "share": f"share-{share_index}",
                }
                for item_index in range(25)
            )
            state.complete_objects({"object_id": decision.object_id, "status": "processed"} for decision in decisions)
        except BaseException as exc:
            failures.append(exc)

    workers = [threading.Thread(target=write_share, args=(index,)) for index in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert failures == []
    assert state.connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 100
    assert state.connection.execute("SELECT COUNT(*) FROM objects WHERE status='processed'").fetchone()[0] == 100
    state.close()


def test_batched_state_operations_commit_complete_manifest_groups(tmp_path):
    path = tmp_path / "batched.sqlite3"
    state = ScanState.create(path, {}, "2.0.0")
    decisions = state.claim_objects(
        {
            "object_key": f"file|{index}",
            "kind": "file",
            "target": "server",
            "share": "share",
            "path": f"{index}.txt",
            "discovery_counter": "files_discovered",
        }
        for index in range(80)
    )
    state.complete_objects(
        {
            "object_id": decision.object_id,
            "status": "processed",
            "findings": (FindingRecord(rule_id="fixture", value=f"file|{index}"),),
        }
        for index, decision in enumerate(decisions)
    )
    try:
        assert state.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert state.connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 80
        assert state.connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 80
        assert state.progress_snapshot()["counters"]["files_discovered"] == 80
    finally:
        state.close()


def test_batched_completion_rolls_back_every_object_when_one_update_fails(tmp_path):
    state = ScanState.create(tmp_path / "rollback.sqlite3", {}, "2.0.0")
    first, second = state.claim_objects(
        (
            {"object_key": "file|one", "kind": "file"},
            {"object_key": "file|two", "kind": "file"},
        )
    )

    with pytest.raises(StateError, match="Unknown object id"):
        state.complete_objects(
            (
                {"object_id": first.object_id, "status": "processed"},
                {"object_id": second.object_id + 1000, "status": "processed"},
            )
        )

    assert state.object_row(first.object_id)["status"] == "in_progress"
    assert state.object_row(second.object_id)["status"] == "in_progress"
    state.close()


def test_public_state_operations_can_join_one_outer_durable_transaction(tmp_path):
    path = tmp_path / "nested.sqlite3"
    state = ScanState.create(path, {}, "2.0.0")
    with state.transaction():
        decision = state.claim_object(object_key="file|nested", kind="file")
        state.complete_object(decision.object_id, "processed")

    assert tuple(state.object_row(decision.object_id)[column] for column in ("status", "attempts")) == (
        "processed",
        1,
    )
    state.close()


def test_completion_buffer_flushes_at_a_fixed_64_object_per_worker_bound(tmp_path):
    path = tmp_path / "completion-bound.sqlite3"
    state = ScanState.create(path, {}, "2.0.0")
    decisions = state.claim_objects(
        {"object_key": f"file|{index}", "kind": "file"} for index in range(Spiderling.state_completion_batch_size)
    )
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(state_path=path, state_run_id=state.run_id)
    worker.scan_state = state
    worker.pending_state_completions = []

    for decision in decisions[:-1]:
        worker.queue_state_completion({"object_id": decision.object_id, "status": "processed"})

    assert len(worker.pending_state_completions) == Spiderling.state_completion_batch_size - 1
    assert state.connection.execute("SELECT COUNT(*) FROM objects WHERE status='processed'").fetchone()[0] == 0

    worker.queue_state_completion({"object_id": decisions[-1].object_id, "status": "processed"})

    assert worker.pending_state_completions == []
    assert (
        state.connection.execute("SELECT COUNT(*) FROM objects WHERE status='processed'").fetchone()[0]
        == Spiderling.state_completion_batch_size
    )
    state.close()


def test_fallback_identity_check_updates_pending_completion_before_flush(tmp_path):
    path = tmp_path / "pending-changed.sqlite3"
    state = ScanState.create(path, {}, "2.0.0")
    decision = state.claim_object(
        object_key="file|server|share|secret.txt",
        kind="file",
        target="server",
        share="share",
        path="secret.txt",
        size=4,
        mtime=100,
    )
    completion = {
        "object_id": decision.object_id,
        "status": "processed",
        "changed": False,
        "post_read_identity": None,
    }
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(state_path=path, state_run_id=state.run_id)
    worker.scan_state = state
    worker.pending_state_completions = [(completion, None, ())]
    remote = RemoteFile("secret.txt", "share", Target("server"), size=4, mtime=100)
    remote.object_id = decision.object_id

    worker.mark_remote_file_changed(remote, post_read_identity=(5, 101, None))
    worker.flush_state_completions()

    row = state.object_row(decision.object_id)
    assert remote.changed is True
    assert (remote.size, remote.mtime, remote.file_id) == (5, 101, None)
    assert row["status"] == "processed"
    assert row["changed"] == 1
    assert (row["size"], row["mtime"], row["file_id"]) == (5, "101", None)
    state.close()


def test_pipeline_completion_stage_is_safe_across_producer_and_consumer_threads(tmp_path):
    path = tmp_path / "pipeline.sqlite3"
    original = ScanState.create(path, {}, "2.0.0")
    decisions = original.claim_objects(
        {
            "object_key": f"file|server|share|{index}.txt",
            "kind": "file",
            "target": "server",
            "share": "share",
            "path": f"{index}.txt",
        }
        for index in range(8)
    )
    run_id = original.run_id
    original.close()
    state = ScanState.attach(path, run_id, thread_safe=True)
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(state_path=path, state_run_id=run_id)
    worker.target = Target("server")
    worker.scan_state = state
    worker.pending_state_completions = []
    worker.completed_files_since_progress = 0
    worker.emit_findings = lambda _file, _findings: None
    files = []
    for index, decision in enumerate(decisions):
        remote = RemoteFile(f"{index}.txt", "share", worker.target)
        remote.object_id = decision.object_id
        files.append(remote)
    worker.process_file = lambda remote: worker.complete_file(remote, "processed")

    worker.process_remote_files(files)
    worker.complete_container(decisions[0].object_id, "processed")
    worker.flush_state_completions()

    assert state.connection.execute("SELECT COUNT(*) FROM objects WHERE status='processed'").fetchone()[0] == 8
    assert worker.pending_state_completions == []
    state.close()
