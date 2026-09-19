"""Scope refusals stay visible without retries, reads, or false scan errors."""
from types import SimpleNamespace
from contextlib import closing
import re

import pytest

from man_spider.error_policy import DFS_SCOPE_BLOCKED_MARKER
from man_spider.filters import ScopeMatcher
from man_spider.lib.parser import FileParser
from man_spider.lib.errors import DFSReferralBlocked, FileListError, FileRetrievalError, ReadOnlySMBViolation
from man_spider.lib.file import RemoteFile
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.state import ScanState, StateError, FindingRecord, directory_object_key, smb_object_key
from tests.test_metadata_size_policy import fake_worker, make_parser, mixed_rules


def test_scope_refusal_survives_remote_file_cleanup_without_retry_or_rebuild(tmp_path):
    refusal = DFSReferralBlocked("external target is outside scope")
    calls = []

    def retrieve(*args):
        calls.append("read")
        raise refusal

    def forbidden(*args):
        pytest.fail("A policy refusal must not rebuild or authenticate a connection")

    source = SimpleNamespace(retrieve_file=retrieve, handle_impacket_error=forbidden)
    file = RemoteFile("secret.txt", "data", Target("192.0.2.20"), size=3, tmp_dir=tmp_path)
    with pytest.raises(DFSReferralBlocked) as caught:
        file.get(source)
    assert caught.value is refusal
    assert calls == ["read"]
    assert file._content is None
    assert file.content_read is False
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("failure", [DFSReferralBlocked("blocked"), FileListError("offline"), ReadOnlySMBViolation("unsafe")])
def test_directory_refusal_is_a_skip_not_a_retried_or_hidden_error(tmp_path, failure):
    worker, _, _ = fake_worker(tmp_path, make_parser(tmp_path))
    calls, completed = [], []

    def listing(*args):
        calls.append(args)
        raise failure

    worker.smb_client.ls = listing
    worker.complete_container = lambda object_id, status, **kwargs: completed.append((status, kwargs))
    if isinstance(failure, ReadOnlySMBViolation):
        with pytest.raises(ReadOnlySMBViolation):
            list(worker.list_files("data", "external"))
        assert completed == []
        assert len(calls) == 1
    else:
        assert list(worker.list_files("data", "external")) == []
        assert completed[0][0] == ("skipped" if isinstance(failure, DFSReferralBlocked) else "error")
        assert len(calls) == (1 if isinstance(failure, DFSReferralBlocked) else 2)
        if isinstance(failure, DFSReferralBlocked):
            assert completed[0][1]["reason"].startswith(DFS_SCOPE_BLOCKED_MARKER)


def test_file_scope_refusal_keeps_metadata_and_never_reports_a_retrieval_failure(tmp_path, caplog):
    worker, _, completions = fake_worker(tmp_path, make_parser(tmp_path, mixed_rules()), size=3)
    calls = []

    def retrieve(*args):
        calls.append(args[:2])
        raise DFSReferralBlocked("outside authorized scope")

    worker.smb_client.retrieve_file = retrieve
    worker.get_file = Spiderling.get_file.__get__(worker)
    assert list(worker.files_for_share("Backups")) == []
    assert len(calls) == 1 and len(completions) == 1
    file, status, values = completions[0]
    assert status == "skipped"
    assert values["reason"].startswith(DFS_SCOPE_BLOCKED_MARKER)
    assert values["content_status"] == "blocked_by_dfs_policy"
    assert [f.rule_id for f in values["findings"]] == ["rule:important-disk"]
    assert not file.content_read
    assert "Error retrieving required file" not in caplog.text


@pytest.mark.parametrize("parent_status,reason,expected", [
    ("skipped", DFS_SCOPE_BLOCKED_MARKER + " external DFS not authorized", "skipped"),
    ("error", "SMB connection lost", "error"),
])
def test_resume_descendants_of_blocked_containers_are_settled_without_losing_evidence(tmp_path, parent_status, reason, expected):
    target, share = Target("192.0.2.20"), "data"
    with closing(ScanState.create(tmp_path / "state.sqlite3", {"semantic": {}}, "test")) as state:
        parent = state.claim_object(object_key=directory_object_key(target, share, "external"), kind="directory",
                                    target=str(target), share=share, path="external")
        child = state.claim_object(object_key=smb_object_key(target, share, r"external\secret.txt"), kind="file",
                                   target=str(target), share=share, path=r"external\secret.txt", size=3, mtime=10)
        state.complete_object(child.object_id, "processed", findings=(FindingRecord("fixture", "retained evidence"),))
        state.begin_object(child.object_id)
        child_before = dict(state.object_row(child.object_id))
        state.complete_object(parent.object_id, parent_status, reason=reason)
        assert state.settle_blocked_objects() == 1
        after = state.object_row(child.object_id)
        assert after["status"] == expected
        assert after["attempts"] == child_before["attempts"]
        assert [r["value"] for r in state.findings_for(child.object_id)] == ["retained evidence"]
        assert state.finish() == ("complete" if expected == "skipped" else "complete_with_errors")
        assert state.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_ordinary_skipped_parent_does_not_conceal_unexplained_unfinished_work(tmp_path):
    target, share = Target("192.0.2.20"), "data"
    with closing(ScanState.create(tmp_path / "state.sqlite3", {"semantic": {}}, "test")) as state:
        parent = state.claim_object(object_key=directory_object_key(target, share, "branch"), kind="directory",
                                    target=str(target), share=share, path="branch")
        state.complete_object(parent.object_id, "skipped", reason="some unrecognized skip")
        state.claim_object(object_key=smb_object_key(target, share, r"branch\secret.txt"), kind="file",
                           target=str(target), share=share, path=r"branch\secret.txt")
        assert state.settle_blocked_objects() == 0
        with pytest.raises(StateError, match="non-terminal"):
            state.finish()


def test_refusal_retains_listing_and_retrieval_exception_compatibility():
    refusal = DFSReferralBlocked("scope")
    assert all(isinstance(refusal, kind) for kind in (FileListError, FileRetrievalError, RuntimeError))


def test_download_scope_refusal_preserves_legacy_metadata_only_match(tmp_path):
    worker, _, completions = fake_worker(
        tmp_path, FileParser([], quiet=True), size=3, download=True, matcher=ScopeMatcher(extensions=[".vmdk"]),
    )

    def blocked(*args):
        raise DFSReferralBlocked("outside scope")

    worker.smb_client.retrieve_file = blocked
    worker.get_file = Spiderling.get_file.__get__(worker)
    assert list(worker.files_for_share("Backups")) == []
    _, status, values = completions[0]
    assert status == "skipped" and len(values["findings"]) == 1
    assert "important.vmdk" in values["findings"][0].value


@pytest.mark.parametrize("or_logic", [False, True])
def test_scope_refusal_does_not_bypass_required_cli_content_filter(tmp_path, or_logic):
    parser = make_parser(tmp_path, mixed_rules(), filters=["SECRET"])
    matcher = ScopeMatcher(filename_filters=[re.compile("important")], content_active=True, or_logic=or_logic)
    worker, _, completions = fake_worker(tmp_path, parser, matcher=matcher, size=3)

    def blocked(*args):
        raise DFSReferralBlocked("outside scope")

    worker.smb_client.retrieve_file = blocked
    worker.get_file = Spiderling.get_file.__get__(worker)
    assert list(worker.files_for_share("Backups")) == []
    _, status, values = completions[0]
    assert status == "skipped"
    assert [finding.rule_id for finding in values["findings"]] == (["rule:important-disk"] if or_logic else [])
