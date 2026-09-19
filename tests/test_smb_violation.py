"""A blocked SMB operation must interrupt the whole scan, never become a skip.

The end-to-end cases use real spawned workers with an injected in-memory SMB
client. No socket is created and every file/state fixture is tiny and local.
"""

import multiprocessing
import queue
import sqlite3
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

import man_spider.lib.spiderling as spiderling_module
import man_spider.manspider as main_module
from man_spider.cli import parse_options
from man_spider.lib.errors import FileRetrievalError, ReadOnlySMBViolation
from man_spider.lib.file import RemoteFile
from man_spider.lib.spider import MANSPIDER
from man_spider.lib.spiderling import ShareSubtreeWork, Spiderling, SpiderlingMessage
from man_spider.lib.util import Target
from man_spider.state import FindingRecord, ScanState


@pytest.mark.parametrize("stage", ["open", "partial", "post-read"])
def test_remote_file_preserves_safety_failure_without_retry_or_metadata_fallback(tmp_path, stage):
    events = []
    violation = ReadOnlySMBViolation("blocked unsafe request")

    class Client:
        def retrieve_file(self, share, path, callback):
            events.append("read")
            if stage != "open":
                callback(b"abc")
            if stage != "post-read":
                raise violation
            return None

        def ls(self, share, path):
            events.append("post-read")
            raise violation

        def handle_impacket_error(self, *args):
            pytest.fail("A safety violation must bypass ordinary error handling")

    remote = RemoteFile("secret.txt", "share", Target("fixture"), size=3, tmp_dir=tmp_path)
    remote.memory_spool_limit = 1
    with pytest.raises(ReadOnlySMBViolation) as captured:
        remote.get(Client())
    assert captured.value is violation
    assert events == (["read", "post-read"] if stage == "post-read" else ["read"])
    assert remote._content is None
    assert remote.retrieved_size is None
    assert not tuple(tmp_path.iterdir())


@pytest.mark.parametrize("method", ["scan_share", "iter_share_files", "scan_subtree"])
def test_share_lifecycle_never_completes_or_retries_safety_failure(method):
    worker = Spiderling.__new__(Spiderling)
    worker.target = Target("fixture")
    worker.parent = SimpleNamespace(spiderling_queue=queue.Queue())
    worker.smb_client = SimpleNamespace(pin_share=lambda share: nullcontext())
    worker.prepare_container = lambda **kwargs: None
    worker.flush_state_completions = lambda: None
    worker.complete_container = lambda *args, **kwargs: pytest.fail("Unsafe work cannot complete")
    attempts = []

    def files(*args, **kwargs):
        attempts.append(True)
        raise ReadOnlySMBViolation("blocked unsafe request")

    worker.files_for_share = files
    with pytest.raises(ReadOnlySMBViolation, match="blocked unsafe request"):
        if method == "iter_share_files":
            list(worker.iter_share_files("share"))
        elif method == "scan_subtree":
            worker.scan_subtree(ShareSubtreeWork("share", "folder", 1))
        else:
            worker.scan_share("share")
    assert len(attempts) == 1


@pytest.mark.parametrize("failed_side", ["producer", "consumer"])
def test_remote_pipeline_preserves_safety_failure_and_notifies_parent(failed_side):
    worker = Spiderling.__new__(Spiderling)
    worker.target = Target("fixture")
    worker.parent = SimpleNamespace(spiderling_queue=queue.Queue())
    cleaned = []
    remote = SimpleNamespace(cleanup=lambda: cleaned.append(True))

    def files():
        yield remote
        if failed_side == "producer":
            raise ReadOnlySMBViolation("producer blocked request")

    def process(batch):
        if failed_side == "consumer":
            raise ReadOnlySMBViolation("consumer blocked request")

    worker.process_remote_batch = process
    with pytest.raises(ReadOnlySMBViolation, match=f"{failed_side} blocked request"):
        worker.process_remote_files(files())
    messages = []
    while not worker.parent.spiderling_queue.empty():
        messages.append(worker.parent.spiderling_queue.get_nowait())
    assert any(message.type == "s" and failed_side in message.content for message in messages)


def test_parent_safety_message_raises_distinct_fatal_error():
    scanner = MANSPIDER.__new__(MANSPIDER)
    with pytest.raises(ReadOnlySMBViolation, match="fixture: blocked unsafe request"):
        scanner.process_message(SpiderlingMessage("s", "fixture", "blocked unsafe request"))


_INJECTED_STAGE = None
_AUDIT_QUEUE = None
_NESTED_LOGIN_READY = None


class _FixtureEntry:
    get_longname = staticmethod(lambda: "secret.txt")
    get_filesize = staticmethod(lambda: 3)
    get_mtime_epoch = staticmethod(lambda: 10)
    is_directory = staticmethod(lambda: False)
    get_attributes = staticmethod(lambda: 0)


class _FixtureSMBClient:
    """Used only inside spawned test workers; it has no network transport."""

    share_listing_error = None
    hostname = None
    dns_domain = None

    def __init__(self, server, username, password, domain, nthash, use_kerberos=False,
                 aes_key=None, dc_ip=None, **kwargs):
        self.server = server
        for name, value in zip(
            ("username", "password", "domain", "nthash", "use_kerberos", "aes_key", "dc_ip"),
            (username, password, domain, nthash, use_kerberos, aes_key, dc_ip),
        ):
            setattr(self, name, value)
        self.port = kwargs.get("port", 445)
        self.session_slot_directory = kwargs.get("session_slot_directory")
        self.max_sessions_per_host = kwargs.get("max_sessions_per_host")
        self.allow_external_dfs = False

    def login(self, **kwargs):
        process_name = multiprocessing.current_process().name
        _AUDIT_QUEUE.put((process_name, "login", self.server))
        if _INJECTED_STAGE == "login" or (
            _INJECTED_STAGE == "nested" and process_name.startswith("manspider-share-")
        ):
            if _INJECTED_STAGE == "nested":
                _NESTED_LOGIN_READY.set()
            raise ReadOnlySMBViolation(f"fixture blocked {_INJECTED_STAGE}")
        return True

    @property
    def shares(self):
        if _INJECTED_STAGE == "close":
            return ()
        return ("one", "two") if _INJECTED_STAGE == "nested" else ("share",)

    def share_type(self, share):
        return 0

    def pin_share(self, share):
        return nullcontext()

    def ls(self, share, path):
        _AUDIT_QUEUE.put((multiprocessing.current_process().name, "list", self.server))
        if _INJECTED_STAGE == "listing":
            raise ReadOnlySMBViolation("fixture blocked listing")
        if _INJECTED_STAGE == "nested":
            # Empty shares can drain before a spawned child is admitted. In
            # that case skipping its unnecessary login is correct, but this
            # test would never inject the violation it claims to exercise.
            # Keep work active until the actual nested login reaches it.
            if not _NESTED_LOGIN_READY.wait(5):
                raise AssertionError("Nested safety fixture did not reach login")
        return () if _INJECTED_STAGE == "nested" else (_FixtureEntry(),)

    def retrieve_file(self, share, path, callback):
        _AUDIT_QUEUE.put((multiprocessing.current_process().name, "read", self.server))
        raise ReadOnlySMBViolation("fixture blocked read")

    def close(self):
        if _INJECTED_STAGE == "close":
            _AUDIT_QUEUE.put((multiprocessing.current_process().name, "close", self.server))
            raise ReadOnlySMBViolation("fixture blocked close")


def _run_injected_worker(stage, audit_queue, nested_login_ready, target, args, kwargs):
    global _INJECTED_STAGE, _AUDIT_QUEUE, _NESTED_LOGIN_READY
    _INJECTED_STAGE, _AUDIT_QUEUE = stage, audit_queue
    _NESTED_LOGIN_READY = nested_login_ready
    spiderling_module.SMBClient = _FixtureSMBClient
    spiderling_module.configure_worker_logging = lambda value: None
    parent = args[1]
    parent.share_process_context = _InjectedSpawnContext(stage, audit_queue, nested_login_ready)
    target(*args, **kwargs)


class _InjectedSpawnContext:
    def __init__(self, stage, audit_queue, nested_login_ready=None):
        self.stage, self.audit_queue = stage, audit_queue
        self.nested_login_ready = nested_login_ready

    def Process(self, *, target, args, **kwargs):
        return multiprocessing.get_context("spawn").Process(
            target=_run_injected_worker,
            args=(self.stage, self.audit_queue, self.nested_login_ready, target, args, {}),
            **kwargs,
        )

    def JoinableQueue(self):
        return multiprocessing.get_context("spawn").JoinableQueue()

    def Queue(self):
        return multiprocessing.get_context("spawn").Queue()

    def Event(self):
        return multiprocessing.get_context("spawn").Event()


def _options(tmp_path, stage):
    threads = "2" if stage == "nested" else "1"
    return parse_options([
        "192.0.2.10", "-d", "fixture.invalid", "-u", "fixture", "-p", "synthetic",
        "--state-file", str(tmp_path / "scan.sqlite3"), "--loot-dir", str(tmp_path / "loot"),
        "--threads", threads, "--max-sessions-per-host", threads,
        "--no-smb-metrics", "--no-unclassified-report", "-c", "password", "--yes",
    ])


@pytest.mark.parametrize("stage", ["login", "listing", "read", "nested", "close"])
def test_spawned_scan_stops_and_persists_interrupted_on_safety_violation(monkeypatch, tmp_path, stage):
    options = _options(tmp_path, stage)
    if stage != "nested":
        options.targets.append(Target("192.0.2.11"))
    audit_queue = multiprocessing.get_context("spawn").Queue()
    nested_login_ready = multiprocessing.get_context("spawn").Event() if stage == "nested" else None
    scanners = []

    def scanner_factory(configuration):
        scanner = MANSPIDER(configuration)
        scanner.process_context = _InjectedSpawnContext(stage, audit_queue, nested_login_ready)
        scanners.append(scanner)
        return scanner

    monkeypatch.setattr(main_module, "MANSPIDER", scanner_factory)
    monkeypatch.setattr(main_module, "credential_preflight", lambda options: 0)
    monkeypatch.setattr(ScanState, "finish", lambda self: pytest.fail("A safety-stopped scan must not finish"))
    events = []
    try:
        result = main_module.go(options, command=["manspider", "synthetic-safety-test"])
        while True:
            try:
                events.append(audit_queue.get(timeout=0.1))
            except queue.Empty:
                break
    finally:
        audit_queue.close()
        audit_queue.join_thread()
    assert result == main_module.EXIT_SMB_SAFETY_ERROR == 8
    with sqlite3.connect(options.state_path) as connection:
        status, reason = connection.execute("SELECT status, error_reason FROM runs").fetchone()
        assert status == "interrupted"
        assert "Read-only SMB safety violation" in reason
        assert f"fixture blocked {stage}" in reason
        unfinished = connection.execute("SELECT count(*) FROM objects WHERE status='in_progress'").fetchone()[0]
        assert unfinished == 0 if stage == "close" else unfinished > 0
    assert scanners and all(not process.is_alive() for process in scanners[0].spiderling_pool if process)
    expected_operation = {
        "login": "login", "listing": "list", "read": "read", "nested": "login", "close": "close",
    }[stage]
    assert any(operation == expected_operation for _name, operation, _server in events)
    if stage == "nested":
        assert nested_login_ready.is_set()
        assert sum(
            name.startswith("manspider-share-") and operation == "login" for name, operation, _server in events
        ) == 1
    else:
        assert sum(operation == expected_operation for _name, operation, _server in events) == 1
        assert {server for _name, _operation, server in events} == {"192.0.2.10"}


def test_safety_interruption_preserves_committed_findings(monkeypatch, tmp_path):
    options = _options(tmp_path, "read")

    class Scanner:
        def __init__(self, configuration):
            self.configuration = configuration

        def start(self):
            state = ScanState.attach(options.state_path, options.state_run_id)
            try:
                result = state.claim_object(object_key="fixture|complete", kind="file", path="before.txt")
                state.complete_object(result.object_id, "processed", findings=[FindingRecord(
                    rule_id="fixture", value="saved finding", severity="high", confidence="high",
                )])
                state.claim_object(object_key="fixture|unfinished", kind="file", path="after.txt")
            finally:
                state.close()
            raise ReadOnlySMBViolation("blocked after committed finding")

    monkeypatch.setattr(main_module, "MANSPIDER", Scanner)
    monkeypatch.setattr(main_module, "credential_preflight", lambda options: 0)
    assert main_module.go(options) == 8
    with sqlite3.connect(options.state_path) as connection:
        assert connection.execute("SELECT count(*) FROM findings").fetchone()[0] == 1
        rows = dict(connection.execute("SELECT path, status FROM objects"))
        assert rows == {"before.txt": "processed", "after.txt": "in_progress"}


def test_ordinary_retrieval_failure_is_still_nonfatal(tmp_path):
    worker = Spiderling.__new__(Spiderling)
    worker.target = Target("fixture")
    worker.smb_client = object()
    worker.warn_recall_access = lambda *args: None
    remote = RemoteFile("secret.txt", "share", worker.target, size=3, tmp_dir=tmp_path)

    def unavailable(client):
        raise FileRetrievalError("ordinary access refusal")

    remote.get = unavailable
    assert worker.get_file(remote) is False
    assert remote.retrieval_error == "ordinary access refusal"
