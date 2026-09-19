"""Offline regression tests for cancellation and decoder safety-error priority."""

from types import SimpleNamespace

import pytest
from impacket.nt_errors import STATUS_PATH_NOT_COVERED
from impacket.smbconnection import SessionError

from man_spider.lib import smb as smb_module
from man_spider.lib.errors import DFSReferralBlocked, FileListError, ReadOnlySMBViolation


class Connection:
    def __init__(self, failures=None):
        self.failures = failures or {}
        self.events = []
        self.closed = False
        self._Connection = {"ServerName": "RAWNAME"}

    def _call(self, operation):
        self.events.append(operation)
        if operation in self.failures:
            raise self.failures[operation]

    def getDialect(self):
        return 0x0311

    def getSMBServer(self):
        return self

    def get_socket(self):
        class Socket:
            def close(_socket):
                self.closed = True
                self.events.append("socket-close")

        return Socket()

    def getServerName(self):
        self._call("server-name")
        return "SERVER"

    def getServerDNSDomainName(self):
        self._call("dns-domain")
        return "example.test"

    def close(self):
        self._call("protocol-close")

    def connectTree(self, share):
        assert share == "IPC$"
        self._call("tree-connect")
        return 7

    def ioctl(self, *args):
        self._call("ioctl")
        return b"response"

    def disconnectTree(self, tree):
        assert tree == 7
        self._call("tree-disconnect")


def make_client(connection):
    client = smb_module.SMBClient("fixture", "user", "dummy", "example.test", "")
    client._install_connection(connection)
    return client


def assert_poisoned(client, connection, violation):
    assert client._transport_group.safety_error is violation
    assert client.conn is None
    assert connection.closed
    before = list(connection.events)
    for operation in (client.login, client._server_aliases, lambda: list(client.list_shares())):
        with pytest.raises(ReadOnlySMBViolation) as caught:
            operation()
        assert caught.value is violation
    assert connection.events == before
    assert "protocol-close" not in connection.events


@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_dfs_cleanup_cancellation_outweighs_ordinary_referral_failure(control_type):
    cancellation = control_type("operator stopped cleanup")
    connection = Connection({"ioctl": OSError("referral receive failed"), "tree-disconnect": cancellation})
    transport = smb_module._ReadOnlyDFSReferralTransport(connection)
    request = b"\x04\x00" + r"\fixture\share".encode("utf-16-le") + b"\x00\x00"
    with pytest.raises(control_type) as caught:
        transport.request(request)
    assert caught.value is cancellation
    assert cancellation.smb_cleanup_failed is True
    assert connection.events == ["tree-connect", "ioctl", "tree-disconnect"]


@pytest.mark.parametrize("primary_type", [OSError, KeyboardInterrupt, SystemExit, GeneratorExit])
def test_dfs_primary_error_survives_ordinary_cleanup_failure(primary_type):
    primary = primary_type("primary referral failure")
    connection = Connection({"ioctl": primary, "tree-disconnect": OSError("ordinary cleanup failure")})
    transport = smb_module._ReadOnlyDFSReferralTransport(connection)
    request = b"\x04\x00" + r"\fixture\share".encode("utf-16-le") + b"\x00\x00"
    with pytest.raises(primary_type) as caught:
        transport.request(request)
    assert caught.value is primary
    assert primary.smb_cleanup_failed is True


@pytest.mark.parametrize("primary_type", [OSError, KeyboardInterrupt, SystemExit, GeneratorExit])
def test_dfs_cleanup_safety_violation_overrides_primary_error_and_poisons_client(primary_type):
    violation = ReadOnlySMBViolation("blocked DFS cleanup")
    connection = Connection({"ioctl": primary_type("primary failure"), "tree-disconnect": violation})
    client = make_client(connection)
    with pytest.raises(ReadOnlySMBViolation) as caught:
        client._request_dfs_referrals("share", "folder")
    assert caught.value is violation
    assert_poisoned(client, connection, violation)
    assert connection.events == ["tree-connect", "ioctl", "tree-disconnect", "socket-close"]


def test_primary_dfs_safety_error_never_attempts_cleanup():
    violation = ReadOnlySMBViolation("blocked DFS query")
    connection = Connection({"ioctl": violation, "tree-disconnect": KeyboardInterrupt("must not execute")})
    client = make_client(connection)
    with pytest.raises(ReadOnlySMBViolation) as caught:
        client._request_dfs_referrals("share", "folder")
    assert caught.value is violation
    assert_poisoned(client, connection, violation)
    assert connection.events == ["tree-connect", "ioctl", "socket-close"]


@pytest.mark.parametrize("field", ["shi1_netname", "shi1_type", "shi1_remark"])
@pytest.mark.parametrize("entrypoint", ["list_shares", "shares"])
def test_share_record_safety_violation_cannot_be_skipped(monkeypatch, field, entrypoint):
    violation = ReadOnlySMBViolation("artificial decoder safety violation")
    records_visited = []

    class Record(dict):
        def __getitem__(self, key):
            records_visited.append(key)
            if key == field:
                raise violation
            return super().__getitem__(key)

    record = Record(shi1_netname="share\x00", shi1_type=0, shi1_remark="comment\x00")
    connection = Connection()
    client = make_client(connection)
    monkeypatch.setattr(smb_module, "read_only_list_shares", lambda _connection: [record, record])
    with pytest.raises(ReadOnlySMBViolation) as caught:
        list(client.list_shares()) if entrypoint == "list_shares" else client.shares
    assert caught.value is violation
    assert records_visited.count(field) == 1
    assert_poisoned(client, connection, violation)


def test_share_response_length_safety_violation_poisons_direct_iterator(monkeypatch):
    violation = ReadOnlySMBViolation("artificial response decoder safety violation")

    class Response:
        def __len__(self):
            raise violation

    connection = Connection()
    client = make_client(connection)
    monkeypatch.setattr(smb_module, "read_only_list_shares", lambda _connection: Response())
    with pytest.raises(ReadOnlySMBViolation) as caught:
        list(client.list_shares())
    assert caught.value is violation
    assert_poisoned(client, connection, violation)


def test_ordinary_malformed_share_is_skipped_without_losing_following_valid_share(monkeypatch):
    connection = Connection()
    client = make_client(connection)
    records = [{}, {"shi1_netname": "valid\x00", "shi1_type": "invalid"}]
    monkeypatch.setattr(smb_module, "read_only_list_shares", lambda _connection: records)
    assert list(client.list_shares()) == ["valid"]
    assert client._share_types == {"valid": None}
    assert client._transport_group.safety_error is None
    assert connection.events == []


@pytest.mark.parametrize("stage", ["server-name", "dns-domain", "raw-name"])
def test_alias_decoder_safety_violation_poisons_transport(stage):
    violation = ReadOnlySMBViolation("artificial alias decoder safety violation")
    connection = Connection({stage: violation})
    if stage == "raw-name":
        class RawName(dict):
            def __getitem__(self, _key):
                raise violation

        connection._Connection = RawName()
    client = make_client(connection)
    with pytest.raises(ReadOnlySMBViolation) as caught:
        client._server_aliases()
    assert caught.value is violation
    assert_poisoned(client, connection, violation)


def test_ordinary_missing_server_aliases_keep_user_supplied_address():
    connection = Connection({"server-name": OSError("unavailable optional metadata")})
    connection._Connection = {}
    client = make_client(connection)
    assert client._server_aliases() == {"fixture"}
    assert client._transport_group.safety_error is None


def nested_namespace(monkeypatch, outcomes, *, deliver_before_error=False):
    """Two namespace levels on one authorized endpoint; no real SMB requests."""

    connection = Connection()
    client = make_client(connection)
    events = []
    delivered = []
    failures = {
        f"replica-{index}": (
            DFSReferralBlocked(f"external target skipped at replica {index}") if outcome == "blocked"
            else ReadOnlySMBViolation(f"unsafe replica {index}") if outcome == "unsafe"
            else OSError(f"unavailable replica {index}") if outcome == "error"
            else None
        )
        for index, outcome in enumerate(outcomes)
    }

    class Pin:
        def __init__(self, share):
            self.share = share

        def __exit__(self, *_args):
            events.append(("release", self.share))

    candidates = [
        SimpleNamespace(namespace_prefix="", target_prefix="", target_share=share, pin_context=Pin(share))
        for share in failures
    ]

    def direct(share, _path, callback=None):
        events.append(("direct", share))
        if share == "root":
            raise SessionError(STATUS_PATH_NOT_COVERED)
        failure = failures[share]
        if failure is not None:
            if deliver_before_error and callback is not None:
                callback(b"partial")
                raise failure
            if isinstance(failure, DFSReferralBlocked):
                # The allowed replica is itself a namespace whose only
                # storage target lies outside the authorized endpoint.
                raise SessionError(STATUS_PATH_NOT_COVERED)
            raise failure
        if callback is not None:
            callback(b"complete")
            return "identity"
        return [SimpleNamespace(get_longname=lambda: "item")]

    def referrals(share, _path):
        events.append(("referrals", share))
        if share != "root":
            raise failures[share]
        return candidates

    monkeypatch.setattr(client, "_list_path_direct", direct)
    monkeypatch.setattr(client, "_retrieve_file_direct", direct)
    monkeypatch.setattr(client, "_dfs_route_candidates", referrals)
    monkeypatch.setattr(client, "_cache_dfs_route", lambda candidate: candidate.target_share)
    monkeypatch.setattr(client, "_route_client", lambda _candidate: client)
    return client, connection, events, delivered, failures


@pytest.mark.parametrize("operation", ["list", "read"])
@pytest.mark.parametrize("outcomes", [("blocked", "valid"), ("error", "valid"), ("valid", "blocked")])
def test_nested_dfs_tries_authorized_alternative_before_reporting_policy_skip(monkeypatch, operation, outcomes):
    client, _connection, events, delivered, _failures = nested_namespace(monkeypatch, outcomes)
    if operation == "list":
        assert [entry.get_longname() for entry in client.ls("root", "item")] == ["item"]
    else:
        assert client.retrieve_file("root", "item", delivered.append) == "identity"
        assert delivered == [b"complete"]
    if outcomes[0] == "valid":
        assert ("direct", "replica-1") not in events
    else:
        assert ("release", "replica-0") in events
        assert ("direct", "replica-1") in events
    assert client._transport_group.safety_error is None


@pytest.mark.parametrize("operation", ["list", "read"])
def test_nested_dfs_all_blocked_candidates_preserve_policy_type(monkeypatch, operation):
    client, _connection, events, delivered, failures = nested_namespace(monkeypatch, ("blocked", "blocked"))
    with pytest.raises(DFSReferralBlocked) as caught:
        list(client.ls("root", "item")) if operation == "list" else client.retrieve_file("root", "item", delivered.append)
    assert caught.value is failures["replica-0"]
    assert ("release", "replica-0") in events
    assert ("release", "replica-1") in events
    assert delivered == []
    assert client._transport_group.safety_error is None


@pytest.mark.parametrize("operation", ["list", "read"])
@pytest.mark.parametrize("outcomes", [("blocked", "error"), ("error", "blocked")])
def test_nested_dfs_ordinary_failure_is_not_downgraded_to_policy_skip(monkeypatch, operation, outcomes):
    client, _connection, events, delivered, _failures = nested_namespace(monkeypatch, outcomes)
    with pytest.raises((FileListError, RuntimeError)) as caught:
        list(client.ls("root", "item")) if operation == "list" else client.retrieve_file("root", "item", delivered.append)
    assert not isinstance(caught.value, DFSReferralBlocked)
    assert "all DFS referral targets failed" in str(caught.value)
    assert ("release", "replica-0") in events
    assert ("release", "replica-1") in events
    assert client._transport_group.safety_error is None


def test_nested_dfs_never_replays_content_after_partial_delivery(monkeypatch):
    client, _connection, events, delivered, failures = nested_namespace(
        monkeypatch, ("blocked", "valid"), deliver_before_error=True
    )
    with pytest.raises(DFSReferralBlocked) as caught:
        client.retrieve_file("root", "item", delivered.append)
    assert caught.value is failures["replica-0"]
    assert delivered == [b"partial"]
    assert ("direct", "replica-1") not in events


@pytest.mark.parametrize("operation", ["list", "read"])
def test_nested_dfs_safety_stop_never_tries_an_alternative_or_releases_protocol_pin(monkeypatch, operation):
    client, connection, events, delivered, failures = nested_namespace(monkeypatch, ("unsafe", "valid"))
    with pytest.raises(ReadOnlySMBViolation) as caught:
        list(client.ls("root", "item")) if operation == "list" else client.retrieve_file("root", "item", delivered.append)
    assert caught.value is failures["replica-0"]
    assert ("direct", "replica-1") not in events
    assert ("release", "replica-0") not in events
    assert_poisoned(client, connection, caught.value)
