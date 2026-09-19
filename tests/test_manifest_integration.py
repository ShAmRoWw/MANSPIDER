import sqlite3
import subprocess
import sys
import json
from datetime import datetime
from types import SimpleNamespace

from man_spider.cli import parse_options
from man_spider.filters import ScopeMatcher
from man_spider.lib.file import (
    FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN,
)
from man_spider.lib.parser import FileParser
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.state import (
    FindingRecord,
    ScanState,
    directory_object_key,
    local_object_key,
    normalized_scan_configuration,
    share_object_key,
    smb_object_key,
    target_object_key,
)


def rows(path, query):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute(query).fetchall()
    finally:
        connection.close()


def test_local_traversal_populates_manifest_and_resume_reuses_processed_file(tmp_path):
    # Per-invocation logs live beside the state. Keep generated outputs outside
    # the input corpus so exclusion counts describe only the fixture files.
    scan_root = tmp_path / "source"
    scan_root.mkdir()
    (scan_root / "secret.txt").write_text("metadata-only fixture", encoding="utf-8")
    (scan_root / "excluded.log").write_text("excluded fixture", encoding="utf-8")
    excluded_tree = scan_root / "excluded-tree"
    excluded_tree.mkdir()
    (excluded_tree / "secret.txt").write_text("must not be traversed", encoding="utf-8")
    state_path = tmp_path / "manifest.sqlite3"
    script = r"""
import sys
from man_spider.cli import parse_options
from man_spider.manspider import go

root, state_path = sys.argv[1:]
common = [
    root,
    "--yes",
    "-f",
    "secret",
    "--exclude-extensions",
    "log",
    "--exclude-dirnames",
    "excluded-tree",
]
first = parse_options([*common, "--state-file", state_path])
if go(first, command=["manspider", root]) != 0:
    raise SystemExit(10)
resumed = parse_options([*common, "--resume", state_path])
if go(resumed, command=["manspider", root]) != 0:
    raise SystemExit(11)
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(scan_root), str(state_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    objects = rows(state_path, "SELECT * FROM objects WHERE kind='file' ORDER BY object_id")
    assert len(objects) == 1
    assert objects[0]["path"] == str((scan_root / "secret.txt").resolve())
    assert objects[0]["status"] == "processed"
    assert objects[0]["attempts"] == 1
    counters = {row["name"]: row["value"] for row in rows(state_path, "SELECT * FROM counters")}
    assert counters["objects_discovered"] == 3
    assert counters["targets_discovered"] == 1
    assert counters["directories_discovered"] == 1
    assert counters["files_discovered"] == 1
    assert counters["excluded"] == 2
    assert counters["resume_reused"] == 1
    findings = rows(state_path, "SELECT * FROM findings")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "metadata:active-include"
    assert findings[0]["value"] == str((scan_root / "secret.txt").resolve())
    exclusions = rows(state_path, "SELECT * FROM exclusions ORDER BY kind, path")
    assert len(exclusions) == 2
    assert {row["kind"] for row in exclusions} == {"directory", "file"}
    assert all(row["occurrences"] == 1 for row in exclusions)
    assert not any(row["path"] == str((excluded_tree / "secret.txt").resolve()) for row in objects)
    checkpoints = rows(state_path, "SELECT * FROM checkpoints")
    assert len(checkpoints) == 2
    traversal = [row for row in checkpoints if row["name"] != "scan_timing"]
    assert len(traversal) == 1
    assert json.loads(traversal[0]["value_json"])["path"] == str((scan_root / "secret.txt").resolve())
    timing = next(json.loads(row["value_json"]) for row in checkpoints if row["name"] == "scan_timing")
    assert timing["eta"]["status"] == "complete"
    assert timing["eta"]["remaining_seconds"] == 0.0
    directories = rows(state_path, "SELECT * FROM objects WHERE kind='directory'")
    assert len(directories) == 1
    assert directories[0]["path"] == str(scan_root.resolve())
    assert directories[0]["status"] == "processed"
    assert directories[0]["attempts"] == 1


def test_fast_resume_follows_unfinished_frontier_and_refresh_reenumerates_completed_tree(tmp_path):
    scan_root = tmp_path / "scope"
    pending_tree = scan_root / "pending"
    completed_tree = scan_root / "completed"
    pending_tree.mkdir(parents=True)
    completed_tree.mkdir()
    pending_file = pending_tree / "secret-pending.txt"
    completed_file = completed_tree / "secret-completed.txt"
    pending_file.write_text("pending fixture", encoding="utf-8")
    completed_file.write_text("completed fixture", encoding="utf-8")
    state_path = tmp_path / "resume-frontier.sqlite3"
    script = r"""
import sys
from man_spider.cli import parse_options
from man_spider.manspider import go

root, state_path, mode = sys.argv[1:]
common = [root, "-f", "secret", "--yes"]
if mode == "fresh":
    arguments = [*common, "--state-file", state_path]
else:
    arguments = [*common, "--resume", state_path]
    if mode == "refresh":
        arguments.append("--refresh-resume")
options = parse_options(arguments)
raise SystemExit(go(options, command=["manspider", *arguments]))
"""

    def run(mode):
        return subprocess.run(
            [sys.executable, "-c", script, str(scan_root), str(state_path), mode],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    initial = run("fresh")
    assert initial.returncode == 0, initial.stdout + initial.stderr
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            "UPDATE objects SET status='in_progress' WHERE kind='file' AND path=?",
            (str(pending_file.resolve()),),
        )
        connection.execute("UPDATE runs SET status='interrupted'")

    new_file = completed_tree / "secret-new.txt"
    new_file.write_text("created after interruption", encoding="utf-8")
    resumed = run("continue")
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr

    quick_objects = rows(state_path, "SELECT * FROM objects ORDER BY object_id")
    quick_by_path = {row["path"]: row for row in quick_objects}
    assert str(new_file.resolve()) not in quick_by_path
    assert quick_by_path[str(pending_file.resolve())]["attempts"] == 2
    assert quick_by_path[str(completed_file.resolve())]["attempts"] == 1
    assert quick_by_path[str(completed_tree.resolve())]["attempts"] == 1
    assert quick_by_path[str(pending_tree.resolve())]["attempts"] == 2

    refreshed = run("refresh")
    assert refreshed.returncode == 0, refreshed.stdout + refreshed.stderr
    refreshed_objects = rows(state_path, "SELECT * FROM objects ORDER BY object_id")
    refreshed_by_path = {row["path"]: row for row in refreshed_objects}
    assert refreshed_by_path[str(new_file.resolve())]["attempts"] == 1
    assert refreshed_by_path[str(pending_file.resolve())]["attempts"] == 2
    assert refreshed_by_path[str(completed_file.resolve())]["attempts"] == 1
    assert refreshed_by_path[str(completed_tree.resolve())]["attempts"] == 2
    assert refreshed_by_path[str(pending_tree.resolve())]["attempts"] == 3


def test_large_domain_format_policy_skips_binary_content_unless_explicitly_enabled(tmp_path):
    scan_root = tmp_path / "scope"
    scan_root.mkdir()
    (scan_root / "secret.bin").write_bytes(b"PREFIX SECRET_VALUE SUFFIX")
    script = r"""
import sys
from man_spider.cli import parse_options
from man_spider.manspider import go

root, state_path, *extra = sys.argv[1:]
options = parse_options([root, "-c", "SECRET_VALUE", "--large-domain", "--yes", *extra, "--state-file", state_path])
raise SystemExit(go(options, command=["manspider", root]))
"""

    blocked_state = tmp_path / "blocked.sqlite3"
    blocked = subprocess.run(
        [sys.executable, "-c", script, str(scan_root), str(blocked_state)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert blocked.returncode == 0, blocked.stderr
    blocked_objects = rows(blocked_state, "SELECT * FROM objects WHERE kind='file'")
    assert len(blocked_objects) == 1
    assert blocked_objects[0]["status"] == "skipped"
    assert "format policy" in blocked_objects[0]["reason"]

    enabled_state = tmp_path / "enabled.sqlite3"
    enabled = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(scan_root),
            str(enabled_state),
            "--read-formats",
            "bin",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert enabled.returncode == 0, enabled.stderr
    enabled_objects = rows(enabled_state, "SELECT * FROM objects WHERE kind='file'")
    assert len(enabled_objects) == 1
    assert enabled_objects[0]["status"] == "processed"
    enabled_findings = rows(enabled_state, "SELECT * FROM findings")
    assert len(enabled_findings) == 1
    assert enabled_findings[0]["value"] == "SECRET_VALUE"


def test_successfully_read_changed_file_keeps_findings_without_a_second_read(tmp_path):
    scan_root = tmp_path / "changed-scope"
    scan_root.mkdir()
    changed_file = scan_root / "changed.txt"
    changed_file.write_text("FIRST_SECRET", encoding="utf-8")
    state_path = tmp_path / "changed.sqlite3"
    initial = changed_file.stat()
    spiderling = Spiderling.__new__(Spiderling)
    spiderling.local_initial_metadata = {
        local_object_key(changed_file): (
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_dev,
            initial.st_ino,
        )
    }
    result = FileParser(["FIRST_SECRET"], quiet=True, blocked_extensions=[]).parse_file(changed_file)
    changed_file.write_text("SECOND_VALUE", encoding="utf-8")
    assert spiderling.local_file_changed(changed_file) is True
    current = changed_file.stat()

    options = parse_options([str(scan_root), "-c", "FIRST_SECRET"])
    configuration = normalized_scan_configuration(options)
    state = ScanState.create(
        state_path,
        configuration,
        "2.0.0",
    )
    decision = state.register_object(
        object_key=local_object_key(changed_file),
        kind="file",
        path=str(changed_file),
        size=initial.st_size,
        mtime=initial.st_mtime_ns,
        file_id=f"{initial.st_dev}:{initial.st_ino}",
    )
    state.begin_object(decision.object_id)
    state.complete_object(
        decision.object_id,
        "processed",
        changed=True,
        post_read_identity=(
            current.st_size,
            current.st_mtime_ns,
            f"{current.st_dev}:{current.st_ino}",
        ),
        findings=[
            FindingRecord(
                finding.rule_id,
                finding.value,
                finding.start,
                finding.end,
                finding.context,
            )
            for finding in result.findings
        ],
    )
    original_finding_id = state.findings_for(decision.object_id)[0]["finding_id"]
    state.set_run_status("interrupted")
    state.close()

    resumed = ScanState.resume(state_path, configuration, "2.0.0")
    reused = resumed.register_object(
        object_key=local_object_key(changed_file),
        kind="file",
        path=str(changed_file),
        size=current.st_size,
        mtime=current.st_mtime_ns,
        file_id=f"{current.st_dev}:{current.st_ino}",
    )
    assert reused.should_process is False
    assert resumed.findings_for(reused.object_id)[0]["finding_id"] == original_finding_id
    resumed.close()

    objects = rows(state_path, "SELECT * FROM objects")
    findings = rows(state_path, "SELECT * FROM findings")
    assert len(objects) == 1
    assert objects[0]["status"] == "processed"
    assert objects[0]["changed"] == 1
    assert objects[0]["attempts"] == 1
    assert [finding["value"] for finding in findings] == ["FIRST_SECRET"]


def test_remote_resume_frontier_contains_only_ancestors_of_unfinished_work(tmp_path):
    target = Target("server")
    options = parse_options([str(tmp_path), "-f", "secret"])
    state = ScanState.create(
        tmp_path / "remote-frontier.sqlite3",
        normalized_scan_configuration(options),
        "2.0.0",
    )

    def completed(object_key, kind, *, share=None, path=None):
        decision = state.claim_object(
            object_key=object_key,
            kind=kind,
            target=str(target),
            share=share,
            path=path,
        )
        state.complete_object(decision.object_id, "processed")

    completed(target_object_key(target), "target", path=str(target))
    completed(share_object_key(target, "data"), "share", share="data", path="data")
    completed(directory_object_key(target, "data", ""), "directory", share="data", path="")
    completed(
        directory_object_key(target, "data", r"finished"),
        "directory",
        share="data",
        path=r"\finished",
    )
    completed(
        directory_object_key(target, "data", r"unfinished"),
        "directory",
        share="data",
        path=r"\unfinished",
    )
    completed(
        smb_object_key(target, "data", r"finished\secret.txt"),
        "file",
        share="data",
        path=r"finished\secret.txt",
    )
    unfinished = state.claim_object(
        object_key=smb_object_key(target, "data", r"unfinished\secret.txt"),
        kind="file",
        target=str(target),
        share="data",
        path=r"unfinished\secret.txt",
    )

    spiderling = Spiderling.__new__(Spiderling)
    spiderling.target = target
    spiderling.parent = SimpleNamespace(
        state_path=str(state.path),
        state_run_id=state.run_id,
        object_retry_limit=2,
    )
    spiderling.scan_state = state
    frontier = spiderling.build_resume_frontier()

    assert unfinished.object_id in {
        row["object_id"] for row in state.resumable_objects(targets=[str(target)], retry_limit=2)
    }
    assert target_object_key(target) in frontier
    assert share_object_key(target, "data") in frontier
    assert directory_object_key(target, "data", "") in frontier
    assert directory_object_key(target, "data", "unfinished") in frontier
    assert directory_object_key(target, "data", "finished") not in frontier
    state.close()


def test_remote_fast_resume_does_not_list_completed_sibling_subtree(tmp_path):
    class DirectoryEntry:
        def __init__(self, name):
            self.name = name

        def get_longname(self):
            return self.name

        @staticmethod
        def is_directory():
            return True

    class Client:
        def __init__(self):
            self.calls = []

        def ls(self, _share, path):
            self.calls.append(path)
            if path == "":
                return (DirectoryEntry("finished"), DirectoryEntry("unfinished"))
            if path == r"\unfinished":
                return ()
            raise AssertionError(f"completed subtree was listed: {path}")

    target = Target("server")
    options = parse_options([str(tmp_path), "-f", "secret"])
    state = ScanState.create(
        tmp_path / "remote-pruning.sqlite3",
        normalized_scan_configuration(options),
        "2.0.0",
    )

    def directory(path, *, terminal=True):
        decision = state.claim_object(
            object_key=directory_object_key(target, "data", path),
            kind="directory",
            target=str(target),
            share="data",
            path=path,
        )
        if terminal:
            state.complete_object(decision.object_id, "processed")
        return decision

    directory("")
    finished = directory(r"\finished")
    unfinished = directory(r"\unfinished", terminal=False)

    spiderling = Spiderling.__new__(Spiderling)
    spiderling.target = target
    spiderling.parent = SimpleNamespace(
        state_path=str(state.path),
        state_run_id=state.run_id,
        object_retry_limit=2,
        maxdepth=10,
        scope_matcher=ScopeMatcher(),
    )
    spiderling.scan_state = state
    spiderling.fast_resume = True
    spiderling.resume_frontier = spiderling.build_resume_frontier()
    spiderling.smb_client = Client()
    spiderling.complete_container = lambda object_id, status, reason=None: state.complete_object(
        object_id,
        status,
        reason=reason,
    )

    assert list(spiderling.list_files("data")) == []
    assert spiderling.smb_client.calls == ["", r"\unfinished"]
    assert state.object_row(finished.object_id)["attempts"] == 1
    assert state.object_row(unfinished.object_id)["attempts"] == 2
    state.close()


def test_remote_file_with_unreadable_mtime_is_recorded_as_error_and_scan_continues(tmp_path):
    class Entry:
        @staticmethod
        def get_longname():
            return "broken.txt"

        @staticmethod
        def is_directory():
            return False

        @staticmethod
        def get_filesize():
            return 12

        @staticmethod
        def get_mtime_epoch():
            raise ValueError("invalid timestamp")

    class Client:
        handled = []

        @staticmethod
        def ls(_share, _path):
            return (Entry(),)

        @classmethod
        def handle_impacket_error(cls, error):
            cls.handled.append(error)

    spiderling = Spiderling.__new__(Spiderling)
    spiderling.target = Target("server")
    spiderling.smb_client = Client()
    spiderling.parent = SimpleNamespace(
        maxdepth=10,
        max_filesize=1024,
        parser=SimpleNamespace(content_filters=[]),
        scope_matcher=ScopeMatcher(),
        state_path=None,
        state_run_id=None,
        tmp_dir=tmp_path,
        modified_after=None,
        modified_before=None,
    )
    spiderling.prepare_container = lambda **_kwargs: None
    completed_directories = []
    spiderling.complete_container = lambda object_id, status, reason=None: completed_directories.append(
        (object_id, status, reason)
    )
    counters = []
    spiderling.record_counter = lambda name, amount=1: counters.append((name, amount))
    spiderling.prepare_remote_file = lambda remote_file: None
    completed_files = []
    spiderling.complete_file = lambda remote_file, status, reason=None, **observations: completed_files.append(
        (remote_file, status, reason, observations)
    )

    assert list(spiderling.list_files("share")) == []

    assert len(Client.handled) == 1
    assert counters == [("metadata_errors", 1)]
    assert len(completed_files) == 1
    remote_file, status, reason, observations = completed_files[0]
    assert remote_file.name == "broken.txt"
    assert remote_file.size == 12
    assert remote_file.mtime is None
    assert status == "error"
    assert reason == "unable to read file modification time: ValueError: invalid timestamp"
    assert observations == {"content_read": False, "content_status": "metadata_unavailable"}
    assert completed_directories == [(None, "processed", None)]


def test_remote_date_filter_uses_last_write_time_while_identity_keeps_change_time(tmp_path):
    class Entry:
        @staticmethod
        def get_longname():
            return "old.txt"

        @staticmethod
        def is_directory():
            return False

        @staticmethod
        def get_filesize():
            return 12

        @staticmethod
        def get_mtime_epoch():
            return 200

        @staticmethod
        def get_wtime_epoch():
            return 100

    class Client:
        @staticmethod
        def ls(_share, _path):
            return (Entry(),)

    spiderling = Spiderling.__new__(Spiderling)
    spiderling.target = Target("server")
    spiderling.smb_client = Client()
    spiderling.parent = SimpleNamespace(
        maxdepth=10,
        max_filesize=1024,
        parser=SimpleNamespace(content_filters=[]),
        scope_matcher=ScopeMatcher(date_active=True),
        state_path=None,
        state_run_id=None,
        tmp_dir=tmp_path,
        modified_after=None,
        modified_before=datetime.fromtimestamp(150),
    )
    spiderling.prepare_container = lambda **_kwargs: None
    spiderling.complete_container = lambda *_args, **_kwargs: None

    remote_files = list(spiderling.list_files("Archive$"))

    assert len(remote_files) == 1
    remote = remote_files[0]
    assert remote.mtime == 200
    assert remote.last_write_time == 100
    remote.cleanup()


def test_remote_listing_preserves_offline_recall_attributes_for_retrieval_warning(tmp_path):
    class Entry:
        @staticmethod
        def get_longname():
            return "tiered.txt"

        @staticmethod
        def is_directory():
            return False

        @staticmethod
        def get_filesize():
            return 12

        @staticmethod
        def get_mtime_epoch():
            return 100

        @staticmethod
        def get_attributes():
            return FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | 0x20

    class Client:
        @staticmethod
        def ls(_share, _path):
            return (Entry(),)

    spiderling = Spiderling.__new__(Spiderling)
    spiderling.target = Target("server")
    spiderling.smb_client = Client()
    spiderling.parent = SimpleNamespace(
        maxdepth=10,
        max_filesize=1024,
        parser=SimpleNamespace(content_filters=[]),
        scope_matcher=ScopeMatcher(),
        state_path=None,
        state_run_id=None,
        tmp_dir=tmp_path,
        modified_after=None,
        modified_before=None,
    )
    spiderling.prepare_container = lambda **_kwargs: None
    spiderling.complete_container = lambda *_args, **_kwargs: None

    remote_files = list(spiderling.list_files("Archive$", r"\tiered"))

    assert len(remote_files) == 1
    remote = remote_files[0]
    assert remote.name == r"tiered\tiered.txt"
    assert remote.smb_attributes == FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | 0x20
    assert remote.recall_attributes == ("RECALL_ON_DATA_ACCESS",)
    remote.cleanup()


def test_offline_hsm_directory_warns_with_full_unc_path_before_enumeration(
    tmp_path,
    monkeypatch,
):
    attributes = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    events = []

    class DirectoryEntry:
        @staticmethod
        def get_longname():
            return "tiered"

        @staticmethod
        def is_directory():
            return True

        @staticmethod
        def get_attributes():
            return attributes

    class Client:
        @staticmethod
        def ls(_share, path):
            events.append(("list", path))
            if path == "":
                return (DirectoryEntry(),)
            if path == r"\tiered":
                return ()
            raise AssertionError(f"unexpected directory listing: {path}")

    monkeypatch.setattr(
        "man_spider.lib.spiderling.log.warning",
        lambda message: events.append(("warning", message)),
    )
    spiderling = Spiderling.__new__(Spiderling)
    spiderling.target = Target("files.example.test", 1445)
    spiderling.smb_client = Client()
    spiderling.parent = SimpleNamespace(
        maxdepth=10,
        scope_matcher=ScopeMatcher(),
        state_path=None,
        state_run_id=None,
    )
    spiderling.complete_container = lambda *_args, **_kwargs: None

    assert list(spiderling.list_files("Archive$")) == []

    assert events[0] == ("list", "")
    assert events[1][0] == "warning"
    assert "OFFLINE/HSM directory will be enumerated" in events[1][1]
    assert r"\\files.example.test\Archive$\tiered" in events[1][1]
    assert "SMB port 1445" in events[1][1]
    assert "OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS" in events[1][1]
    assert events[2] == ("list", r"\tiered")
