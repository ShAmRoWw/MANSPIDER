"""Safety stops remain fatal in connection/DFS cleanup; no real sockets used."""

from types import SimpleNamespace

import pytest

from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib.smb import SMBClient, _ReadOnlyDFSReferralTransport


class _Socket:
    def __init__(self, events, label):
        self.events, self.label = events, label
        self.closed = False

    def close(self):
        self.closed = True
        self.events.append((self.label, "socket-close"))


class _Connection:
    def __init__(self, events, label, *, close_error=None, ioctl_error=None, disconnect_error=None):
        self.events, self.label = events, label
        self.close_error = close_error
        self.ioctl_error = ioctl_error
        self.disconnect_error = disconnect_error
        self.socket = _Socket(events, label)

    def getSMBServer(self):
        return self

    def get_socket(self):
        return self.socket

    def getDialect(self):
        return 0x0311

    def close(self):
        self.events.append((self.label, "protocol-close"))
        if self.close_error is not None:
            raise self.close_error

    def connectTree(self, share):
        assert share == "IPC$"
        self.events.append((self.label, "tree-connect"))
        return 7

    def ioctl(self, *args):
        self.events.append((self.label, "ioctl"))
        if self.ioctl_error is not None:
            raise self.ioctl_error
        return b"fixture response"

    def disconnectTree(self, tree_id):
        assert tree_id == 7
        self.events.append((self.label, "tree-disconnect"))
        if self.disconnect_error is not None:
            raise self.disconnect_error


def _client(connection=None, *, group=None):
    client = SMBClient("fixture", "user", "synthetic", "fixture.invalid", "", transport_group=group)
    if connection is not None:
        client._install_connection(connection)
    return client


def _assert_poisoned(client, violation):
    assert client._transport_group.safety_error is violation
    assert client.conn is None
    with pytest.raises(ReadOnlySMBViolation) as captured:
        client.login()
    assert captured.value is violation


def test_suspend_transport_does_not_suppress_guard_raised_by_protocol_close():
    events = []
    violation = ReadOnlySMBViolation("blocked session close")
    connection = _Connection(events, "old", close_error=violation)
    client = _client(connection)
    with pytest.raises(ReadOnlySMBViolation) as captured:
        client._suspend_transport()
    assert captured.value is violation
    _assert_poisoned(client, violation)
    assert connection.socket.closed
    assert events == [("old", "protocol-close"), ("old", "socket-close")]


def test_replacing_connection_closes_both_sockets_after_previous_close_guard():
    events = []
    violation = ReadOnlySMBViolation("blocked previous session close")
    previous = _Connection(events, "old", close_error=violation)
    replacement = _Connection(events, "new")
    client = _client(previous)
    with pytest.raises(ReadOnlySMBViolation) as captured:
        client._install_connection(replacement)
    assert captured.value is violation
    _assert_poisoned(client, violation)
    assert previous.socket.closed and replacement.socket.closed
    assert events.count(("old", "protocol-close")) == 1
    assert ("new", "protocol-close") not in events


def test_parent_close_does_not_suppress_guard_from_active_dfs_child_cleanup():
    events = []
    violation = ReadOnlySMBViolation("blocked DFS child close")
    parent = _client()
    connection = _Connection(events, "child", close_error=violation)
    child = _client(connection, group=parent._transport_group)
    parent._dfs_clients[("child", 445)] = child
    with pytest.raises(ReadOnlySMBViolation) as captured:
        parent.close()
    assert captured.value is violation
    _assert_poisoned(parent, violation)
    _assert_poisoned(child, violation)
    assert connection.socket.closed
    assert events.count(("child", "protocol-close")) == 1


def test_dfs_route_pin_cleanup_guard_is_fatal_and_pin_is_never_reused():
    events = []
    violation = ReadOnlySMBViolation("blocked DFS pin release")
    connection = _Connection(events, "parent")
    client = _client(connection)

    class Pin:
        def __exit__(self, *args):
            events.append(("pin", "exit"))
            raise violation

    route = SimpleNamespace(pin_context=Pin())
    with pytest.raises(ReadOnlySMBViolation) as captured:
        client._release_dfs_route(route)
    assert captured.value is violation
    _assert_poisoned(client, violation)
    assert route.pin_context is None
    client._release_dfs_route(route)
    assert events.count(("pin", "exit")) == 1
    assert connection.socket.closed
    assert ("parent", "protocol-close") not in events


@pytest.mark.parametrize("nested", [False, True])
def test_guard_in_pinned_consumer_drops_socket_without_tree_cleanup(nested):
    from contextlib import nullcontext

    events = []
    violation = ReadOnlySMBViolation("guard in listing consumer")
    connection = _Connection(events, "parent")
    client = _client(connection)
    with pytest.raises(ReadOnlySMBViolation) as captured:
        with client.pin_share("IPC$"):
            with client.pin_share("IPC$") if nested else nullcontext():
                raise violation
    assert captured.value is violation
    _assert_poisoned(client, violation)
    assert client._share_pin_depths == {}
    assert client._pinned_share_trees == {}
    assert events == [("parent", "tree-connect"), ("parent", "socket-close")]


@pytest.mark.parametrize("stage", ["ioctl", "cleanup"])
def test_dfs_referral_guard_propagates_without_followup_request(stage):
    events = []
    violation = ReadOnlySMBViolation(f"blocked DFS {stage}")
    connection = _Connection(
        events, "dfs", ioctl_error=violation if stage == "ioctl" else None,
        disconnect_error=violation if stage == "cleanup" else None,
    )
    transport = _ReadOnlyDFSReferralTransport(connection)
    request = b"\x04\x00" + "\\fixture\\share\x00".encode("utf-16-le")
    with pytest.raises(ReadOnlySMBViolation) as captured:
        transport.request(request)
    assert captured.value is violation
    assert events == [
        ("dfs", "tree-connect"), ("dfs", "ioctl"),
        *([("dfs", "tree-disconnect")] if stage == "cleanup" else []),
    ]


@pytest.mark.parametrize("stage", ["ioctl", "cleanup"])
def test_direct_dfs_referral_guard_also_poisons_client(stage):
    events = []
    violation = ReadOnlySMBViolation(f"blocked DFS {stage}")
    connection = _Connection(
        events, "dfs", ioctl_error=violation if stage == "ioctl" else None,
        disconnect_error=violation if stage == "cleanup" else None,
    )
    client = _client(connection)
    with pytest.raises(ReadOnlySMBViolation) as captured:
        client._request_dfs_referrals("share", "folder")
    assert captured.value is violation
    _assert_poisoned(client, violation)
    assert connection.socket.closed
    if stage == "ioctl":
        assert ("dfs", "tree-disconnect") not in events
    assert ("dfs", "protocol-close") not in events


@pytest.mark.parametrize("operation", ["suspend", "replace", "dfs-child", "dfs-pin"])
def test_ordinary_cleanup_error_does_not_become_a_safety_stop(operation):
    events = []
    connection = _Connection(events, "old", close_error=OSError("ordinary cleanup failure"))
    client = _client(connection if operation in ("suspend", "replace") else None)
    if operation == "suspend":
        client._suspend_transport()
    elif operation == "replace":
        replacement = _Connection(events, "new")
        client._install_connection(replacement)
        assert client.conn is not None
    elif operation == "dfs-child":
        child = _client(connection, group=client._transport_group)
        client._dfs_clients[("child", 445)] = child
        client.close()
    else:
        class Pin:
            def __exit__(self, *args):
                raise OSError("ordinary pin cleanup failure")

        route = SimpleNamespace(pin_context=Pin())
        client._release_dfs_route(route)
        assert route.pin_context is None
    assert client._transport_group.safety_error is None
