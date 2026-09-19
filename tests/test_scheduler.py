import queue
import threading
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

import man_spider.lib.spiderling as spiderling_module
from man_spider.lib.spider import MANSPIDER
from man_spider.lib.spiderling import ShareSubtreeWork, Spiderling
from man_spider.lib.file import RemoteFile
from man_spider.lib.util import Target


class FakeSMBClient:
    instances = []

    def __init__(
        self,
        server,
        username,
        password,
        domain,
        nthash,
        use_kerberos=False,
        aes_key="",
        dc_ip=None,
        port=445,
        session_slot_directory=None,
        max_sessions_per_host=None,
        allow_external_dfs=False,
    ):
        self.server = server
        self.username = username
        self.password = password
        self.domain = domain
        self.nthash = nthash
        self.use_kerberos = use_kerberos
        self.aes_key = aes_key
        self.dc_ip = dc_ip
        self.port = port
        self.session_slot_directory = session_slot_directory
        self.max_sessions_per_host = max_sessions_per_host
        self.allow_external_dfs = allow_external_dfs
        self.hostname = None
        self.dns_domain = None
        self.login_calls = []
        self.closed = False
        self.instances.append(self)

    def login(self, *, first_try=True):
        self.login_calls.append(first_try)
        return True

    def close(self):
        self.closed = True

    def pin_share(self, _share):
        return nullcontext()


class ThreadProcess:
    """Exercise process orchestration deterministically inside the test process."""

    def __init__(self, *, target, args, name, daemon):
        self.target = target
        self.args = args
        self.name = name
        self.daemon = daemon
        self.exitcode = None
        self.pid = None
        self.failure = None
        self._thread = threading.Thread(target=self._run, name=name, daemon=daemon)

    def _run(self):
        try:
            self.target(*self.args)
        except BaseException as exc:
            self.failure = exc
            self.exitcode = 1
        else:
            self.exitcode = 0

    def start(self):
        self._thread.start()

    def join(self, timeout=None):
        self._thread.join(timeout)

    def is_alive(self):
        return self._thread.is_alive()

    def terminate(self):
        # The worker target observes its shared stop event. Tests never rely on
        # forcibly killing a Python thread.
        return None

    def kill(self):
        return None


class ThreadProcessContext:
    """Small multiprocessing-context facade retaining monkeypatch visibility."""

    @staticmethod
    def JoinableQueue():
        return queue.Queue()

    @staticmethod
    def Queue():
        return queue.Queue()

    @staticmethod
    def Event():
        return threading.Event()

    @staticmethod
    def Process(**values):
        return ThreadProcess(**values)


@pytest.fixture(autouse=True)
def reset_fake_clients(monkeypatch):
    FakeSMBClient.instances = []
    monkeypatch.setattr(spiderling_module, "configure_worker_logging", lambda _queue: None)


def scheduler_parent(*, threads=4, per_host=3, slots=2):
    return SimpleNamespace(
        threads=threads,
        max_sessions_per_host=per_host,
        share_worker_slots=threading.BoundedSemaphore(slots),
        state_path=None,
        state_run_id=None,
        log_queue=None,
        share_process_context=ThreadProcessContext(),
    )


def coordinator(parent):
    worker = Spiderling.__new__(Spiderling)
    worker.parent = parent
    worker.target = Target("server.test")
    worker.target_object_id = 1
    worker.local = False
    worker.scan_state = None
    worker.smb_client = FakeSMBClient(
        "server.test",
        "runuser",
        "FixturePassword123!",
        "TEST",
        "",
    )
    return worker


def test_share_scheduler_uses_disjoint_work_and_independent_capped_sessions(monkeypatch):
    parent = scheduler_parent()
    worker = coordinator(parent)
    shares = tuple(f"share-{index}" for index in range(9))
    monkeypatch.setattr(Spiderling, "shares", property(lambda _worker: iter(shares)))
    monkeypatch.setattr(spiderling_module, "SMBClient", FakeSMBClient)

    lock = threading.Lock()
    release = threading.Event()
    active = 0
    maximum_active = 0
    completed = []

    def scan_share(current, share):
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
            if active == 3:
                release.set()
        release.wait(timeout=1)
        with lock:
            completed.append((share, id(current.smb_client)))
            active -= 1

    monkeypatch.setattr(Spiderling, "scan_share", scan_share)

    worker.scan_remote_shares()

    assert sorted(share for share, _client in completed) == sorted(shares)
    assert len(completed) == len({share for share, _client in completed})
    assert maximum_active == 3
    assert len({client for _share, client in completed}) == 3
    additional = FakeSMBClient.instances[1:]
    assert len(additional) == 2
    assert all(client.login_calls == [False] for client in additional)
    assert all(client.closed for client in additional)


def test_unavailable_additional_session_does_not_lose_share_work(monkeypatch):
    class UnavailableSMBClient(FakeSMBClient):
        def login(self, *, first_try=True):
            self.login_calls.append(first_try)
            return False

    parent = scheduler_parent(threads=2, per_host=2, slots=1)
    worker = coordinator(parent)
    shares = ("one", "two", "three")
    monkeypatch.setattr(Spiderling, "shares", property(lambda _worker: iter(shares)))
    monkeypatch.setattr(spiderling_module, "SMBClient", UnavailableSMBClient)
    completed = []
    monkeypatch.setattr(Spiderling, "scan_share", lambda current, share: completed.append((share, current)))

    worker.scan_remote_shares()

    assert [share for share, _current in completed] == list(shares)
    assert all(current is worker for _share, current in completed)


@pytest.mark.parametrize("allow_external_dfs", [False, True])
def test_additional_session_inherits_explicit_dfs_policy(monkeypatch, allow_external_dfs):
    worker = coordinator(scheduler_parent())
    worker.smb_client.allow_external_dfs = allow_external_dfs
    monkeypatch.setattr(spiderling_module, "SMBClient", FakeSMBClient)

    child = worker._new_share_worker()
    try:
        assert child.smb_client.allow_external_dfs is allow_external_dfs
        assert child.smb_client.login_calls == [False]
    finally:
        child._close_share_worker()


def test_share_scheduler_uses_explicit_completion_markers_not_queue_empty(monkeypatch):
    class NoEmptyQueue(queue.Queue):
        def empty(self):
            raise AssertionError("multiprocessing Queue.empty() is not a synchronization primitive")

    class NoEmptyProcessContext(ThreadProcessContext):
        @staticmethod
        def JoinableQueue():
            return NoEmptyQueue()

    parent = scheduler_parent(threads=2, per_host=2, slots=1)
    parent.share_process_context = NoEmptyProcessContext()
    worker = coordinator(parent)
    shares = ("one", "two", "three")
    monkeypatch.setattr(Spiderling, "shares", property(lambda _worker: iter(shares)))
    monkeypatch.setattr(spiderling_module, "SMBClient", FakeSMBClient)
    completed = []
    monkeypatch.setattr(Spiderling, "scan_share", lambda _current, share: completed.append(share))

    worker.scan_remote_shares()

    assert sorted(completed) == sorted(shares)
    assert len(completed) == len(set(completed))


def test_single_share_uses_disjoint_top_level_subtrees_across_available_sessions(monkeypatch):
    parent = scheduler_parent(threads=4, per_host=3, slots=2)
    worker = coordinator(parent)
    monkeypatch.setattr(Spiderling, "shares", property(lambda _worker: iter(("only",))))
    monkeypatch.setattr(spiderling_module, "SMBClient", FakeSMBClient)
    decision = SimpleNamespace(object_id=42, should_process=True)
    monkeypatch.setattr(worker, "prepare_container", lambda **_values: decision)
    completions = []
    monkeypatch.setattr(
        worker,
        "complete_container",
        lambda object_id, status, reason=None: completions.append((object_id, status, reason)),
    )

    def list_root(_current, share, path="", depth=0, **kwargs):
        assert (share, path, depth) == ("only", "", 0)
        sink = kwargs["subtree_sink"]
        for index in range(6):
            sink(ShareSubtreeWork("only", f"branch-{index}", 1, None))
        return iter(())

    monkeypatch.setattr(Spiderling, "list_files", list_root)
    lock = threading.Lock()
    release = threading.Event()
    active = 0
    maximum_active = 0
    visited = []

    def scan_subtree(current, work_item, subtree_sink=None):
        nonlocal active, maximum_active
        assert subtree_sink is None
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
            if active == 3:
                release.set()
        release.wait(timeout=1)
        with lock:
            visited.append((work_item.path, id(current.smb_client)))
            active -= 1

    monkeypatch.setattr(Spiderling, "scan_subtree", scan_subtree)

    worker.scan_remote_shares()

    assert sorted(path for path, _client in visited) == [f"branch-{index}" for index in range(6)]
    assert len(visited) == len({path for path, _client in visited})
    assert maximum_active == 3
    assert len({client for _path, client in visited}) == 3
    assert completions == [(42, "processed", None)]


def test_subtree_worker_retrieves_content_before_parsing(monkeypatch):
    parent = scheduler_parent(threads=1, per_host=1, slots=0)
    parent.no_download = True
    worker = coordinator(parent)
    remote = RemoteFile("secret.txt", "only", worker.target, size=6)
    remote.rule_route = object()
    monkeypatch.setattr(Spiderling, "list_files", lambda *_args, **_kwargs: iter((remote,)))
    monkeypatch.setattr(worker, "requires_content", lambda _file: True)

    def retrieve(current):
        current.retrieved = True
        return True

    monkeypatch.setattr(worker, "get_file", retrieve)
    parsed = []

    def parse(current):
        assert current.retrieved is True
        parsed.append(current)

    monkeypatch.setattr(worker, "process_file", parse)

    worker.scan_subtree(ShareSubtreeWork("only", "branch", 1, None))

    assert parsed == [remote]


def test_remote_pipeline_overlaps_production_with_bounded_fifo_extraction(monkeypatch):
    class Item:
        def __init__(self, value):
            self.value = value
            self.cleanup_calls = 0

        def cleanup(self):
            self.cleanup_calls += 1

    worker = coordinator(scheduler_parent(threads=1, per_host=1, slots=0))
    items = [Item(index) for index in range(10)]
    yielded = []
    extraction_started = threading.Event()
    producer_reached_bound = threading.Event()
    release_extraction = threading.Event()
    processed = []
    failures = []

    def files():
        for item in items:
            yielded.append(item.value)
            if len(yielded) == worker.remote_pipeline_queue_size + 2:
                producer_reached_bound.set()
            yield item

    def process(item):
        processed.append(item.value)
        if item.value == 0:
            extraction_started.set()
            assert release_extraction.wait(timeout=2)

    monkeypatch.setattr(worker, "process_file", process)

    def run_pipeline():
        try:
            worker.process_remote_files(files())
        except BaseException as exc:
            failures.append(exc)

    pipeline = threading.Thread(target=run_pipeline)
    pipeline.start()
    try:
        assert extraction_started.wait(timeout=1)
        assert producer_reached_bound.wait(timeout=1)
        assert yielded == list(range(worker.remote_pipeline_queue_size + 2))
    finally:
        release_extraction.set()
    pipeline.join(timeout=2)

    assert not pipeline.is_alive()
    assert failures == []
    assert processed == list(range(10))
    assert all(item.cleanup_calls == 0 for item in items)


def test_remote_pipeline_does_not_start_consumer_for_empty_resume_share(monkeypatch):
    worker = coordinator(scheduler_parent(threads=1, per_host=1, slots=0))
    monkeypatch.setattr(
        spiderling_module.threading,
        "Thread",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("empty pipeline must stay threadless")),
    )

    worker.process_remote_files(())


def test_remote_pipeline_propagates_consumer_failure_and_cleans_abandoned_files(monkeypatch):
    class Item:
        def __init__(self, value):
            self.value = value
            self.cleanup_calls = 0

        def cleanup(self):
            self.cleanup_calls += 1

    worker = coordinator(scheduler_parent(threads=1, per_host=1, slots=0))
    items = [Item(index) for index in range(10)]
    yielded = []

    def files():
        for item in items:
            yielded.append(item)
            yield item

    def fail(_item):
        raise RuntimeError("extractor failed systemically")

    monkeypatch.setattr(worker, "process_file", fail)

    with pytest.raises(RuntimeError, match="extractor failed systemically"):
        worker.process_remote_files(files())

    assert yielded
    assert all(item.cleanup_calls == 1 for item in yielded)


def test_remote_pipeline_propagates_producer_failure_and_drains_bounded_handoff(monkeypatch):
    class Item:
        def __init__(self, value):
            self.value = value
            self.cleanup_calls = 0

        def cleanup(self):
            self.cleanup_calls += 1

    worker = coordinator(scheduler_parent(threads=1, per_host=1, slots=0))
    items = [Item(0), Item(1)]
    release_consumer = threading.Event()

    def files():
        yield items[0]
        yield items[1]
        raise RuntimeError("SMB producer failed")

    def process(item):
        release_consumer.wait(timeout=1)
        item.cleanup()

    monkeypatch.setattr(worker, "process_file", process)
    timer = threading.Timer(0.05, release_consumer.set)
    timer.start()
    try:
        with pytest.raises(RuntimeError, match="SMB producer failed"):
            worker.process_remote_files(files())
    finally:
        release_consumer.set()
        timer.cancel()

    assert [item.cleanup_calls for item in items] == [1, 1]


def test_remote_batch_preextracts_structured_candidates_with_fifo_completion(monkeypatch):
    class Parser:
        def __init__(self):
            self.requests = []

        @staticmethod
        def structured_bytes_mime_type(name, _route):
            return "application/test" if name.endswith(".docx") else None

        def preextract_structured_batch(self, requests):
            requests = tuple(requests)
            self.requests.append(requests)
            return {identity: (True, loader().decode()) for identity, _name, _route, loader in requests}

    parent = scheduler_parent(threads=1, per_host=1, slots=0)
    parent.parser = Parser()
    worker = coordinator(parent)
    files = [
        RemoteFile("one.docx", "share", worker.target, size=3),
        RemoteFile("middle.txt", "share", worker.target, size=6),
        RemoteFile("two.docx", "share", worker.target, size=3),
    ]
    for remote, payload in zip(files, (b"ONE", b"MIDDLE", b"TWO"), strict=True):
        remote.retrieved = True
        remote._retrieved_size = len(payload)
        remote.content_bytes = lambda payload=payload: payload
        remote.rule_route = object()
    processed = []
    monkeypatch.setattr(worker, "process_file", lambda remote: processed.append(remote))

    worker.process_remote_batch(files)

    assert len(parent.parser.requests) == 1
    assert [request[1] for request in parent.parser.requests[0]] == ["one.docx", "two.docx"]
    assert files[0].precomputed_representations == {"structured": (True, "ONE")}
    assert files[1].precomputed_representations == {}
    assert files[2].precomputed_representations == {"structured": (True, "TWO")}
    assert processed == files


def test_share_is_completed_only_after_pipeline_extraction_finishes(monkeypatch):
    parent = scheduler_parent(threads=1, per_host=1, slots=0)
    worker = coordinator(parent)
    decision = SimpleNamespace(object_id=42, should_process=True)
    monkeypatch.setattr(worker, "prepare_container", lambda **_values: decision)
    remote = RemoteFile("secret.txt", "share", worker.target)
    monkeypatch.setattr(worker, "files_for_share", lambda _share: iter((remote,)))
    events = []
    monkeypatch.setattr(worker, "process_file", lambda _remote: events.append("file"))
    monkeypatch.setattr(
        worker,
        "complete_container",
        lambda _object_id, status, reason=None: events.append((status, reason)),
    )
    monkeypatch.setattr(worker, "flush_state_completions", lambda: events.append("flush"))

    worker.scan_share("share")

    assert events == ["file", ("processed", None), "flush"]


@pytest.mark.parametrize("resolved_username", ["Guest", ""])
def test_additional_worker_reuses_fallback_identity_without_credential_fallback(
    monkeypatch,
    resolved_username,
):
    parent = scheduler_parent(threads=2, per_host=2, slots=1)
    worker = coordinator(parent)
    worker.smb_client.username = resolved_username
    worker.smb_client.password = ""
    worker.smb_client.domain = ""
    worker.smb_client.use_kerberos = True
    monkeypatch.setattr(spiderling_module, "SMBClient", FakeSMBClient)

    additional = worker._new_share_worker()
    try:
        assert additional is not None
        assert additional.smb_client.username == resolved_username
        assert additional.smb_client.password == ""
        assert additional.smb_client.domain == ""
        assert additional.smb_client.use_kerberos is False
        assert additional.smb_client.login_calls == [False]
    finally:
        additional._close_share_worker()


def test_parent_reserves_one_global_slot_per_target_process_and_releases_idempotently():
    class Slots:
        def __init__(self):
            self.acquired = 0
            self.released = 0

        def acquire(self):
            self.acquired += 1

        def release(self):
            self.released += 1

    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.targets = ["one", "two"]
    scanner.threads = 5
    scanner.share_worker_slots = Slots()
    scanner._base_slot_reserved = [False] * scanner.threads

    scanner.reserve_base_worker_slots()
    scanner.reserve_base_worker_slots()
    scanner.release_base_worker_slot(0)
    scanner.release_base_worker_slot(0)
    scanner.release_base_worker_slots()

    assert scanner.share_worker_slots.acquired == 2
    assert scanner.share_worker_slots.released == 2
    assert scanner._base_slot_reserved == [False] * scanner.threads
