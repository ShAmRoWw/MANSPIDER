from types import SimpleNamespace

import man_spider.lib.smb as smb_module
import man_spider.lib.spiderling as spiderling_module
from man_spider.cli import parse_options
from man_spider.lib.smb import SMBClient
from man_spider.lib.spider import MANSPIDER
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.state import ScanState, target_object_key


class MessageQueue:
    def __init__(self):
        self.messages = []

    def put(self, message):
        self.messages.append(message)


def test_quiet_flag_is_preserved_in_spawned_worker_context(tmp_path):
    options = parse_options(
        [
            str(tmp_path),
            "-f",
            "secret",
            "--quiet",
            "--loot-dir",
            str(tmp_path / "loot"),
        ]
    )
    scanner = MANSPIDER(options)
    try:
        assert scanner.worker_context().quiet is True
    finally:
        scanner.spiderling_queue.close()
        scanner.spiderling_queue.join_thread()


def test_kerberos_hostname_discovery_uses_dns_domain_and_closes_probe(monkeypatch):
    closed = []

    class DiscoveryConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, *_args, **_kwargs):
            raise RuntimeError("anonymous login is not required to succeed")

        @staticmethod
        def getServerName():
            return "FILESERVER"

        @staticmethod
        def getServerDNSDomainName():
            return "test.local"

        def close(self):
            closed.append(True)

    monkeypatch.setattr(smb_module, "SMBConnection", DiscoveryConnection)
    client = SMBClient("192.0.2.10", "runuser", "", "TEST", "", use_kerberos=True)

    assert client.get_hostname() == ("fileserver", "test.local")
    assert closed == [True]


def test_main_scan_auth_failure_is_local_and_next_target_is_processed(monkeypatch, tmp_path):
    targets = [Target("reject.test"), Target("success.test")]
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "2.0.0")
    run_id = state.run_id
    state.close()
    visited = []

    class FakeSMBClient:
        def __init__(self, server, *_args, **_kwargs):
            self.server = server

        def login(self):
            return self.server != "reject.test"

        def seed_shares(self, _shares):
            raise AssertionError("No preflight share cache was configured")

    def visit_target(worker):
        visited.append(worker.target.host)

    messages = MessageQueue()
    parent = SimpleNamespace(
        username="runuser",
        password="FixturePassword123!",
        domain="test.local",
        nthash="",
        use_kerberos=False,
        aes_key=None,
        dc_ip=None,
        preflight_share_cache={},
        object_retry_limit=2,
        state_path=str(tmp_path / "scan.sqlite3"),
        state_run_id=run_id,
        spiderling_queue=messages,
        log_queue=None,
    )
    monkeypatch.setattr(spiderling_module, "configure_worker_logging", lambda _queue: None)
    monkeypatch.setattr(spiderling_module, "SMBClient", FakeSMBClient)
    monkeypatch.setattr(Spiderling, "go", visit_target)

    for target in targets:
        Spiderling(target, parent)

    state = ScanState.attach(parent.state_path, run_id)
    try:
        rejected = state.connection.execute(
            "SELECT status, reason FROM objects WHERE object_key=?",
            (target_object_key(targets[0]),),
        ).fetchone()
        succeeded = state.connection.execute(
            "SELECT status, reason FROM objects WHERE object_key=?",
            (target_object_key(targets[1]),),
        ).fetchone()
        counters = {row["name"]: row["value"] for row in state.connection.execute("SELECT name, value FROM counters")}
    finally:
        state.close()

    assert visited == ["reject.test", "success.test"]
    assert tuple(rejected) == (
        "processed",
        "supplied credentials were rejected; Guest/null fallback was attempted",
    )
    assert tuple(succeeded) == ("processed", None)
    assert counters["authentication_failures"] == 1
    auth_messages = [message for message in messages.messages if message.type == "a"]
    assert len(auth_messages) == 1
    assert auth_messages[0].target == targets[0]


def test_main_scan_auth_failure_limit_is_disabled_by_default_and_explicit_when_requested():
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.failed_logons = 0
    scanner.max_failed_logons = None
    scanner.username = "runuser"
    scanner.password = "FixturePassword123!"
    scanner.nthash = "hash"
    scanner.domain = "test.local"

    scanner.process_message(SimpleNamespace(type="a", content=False))

    assert scanner.failed_logons == 1
    assert scanner.username == "runuser"
    assert scanner.password == "FixturePassword123!"
    assert scanner.domain == "test.local"

    scanner.failed_logons = 0
    scanner.max_failed_logons = 1
    scanner.process_message(SimpleNamespace(type="a", content=False))

    assert scanner.failed_logons == 1
    assert scanner.username == ""
    assert scanner.password == ""
    assert scanner.nthash == ""
    assert scanner.domain == ""
