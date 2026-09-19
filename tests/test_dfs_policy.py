"""Offline assertions that default DFS discovery never authenticates externally."""

import socket

import pytest
from impacket.nt_errors import STATUS_PATH_NOT_COVERED
from impacket.smbconnection import SessionError

import man_spider.lib.smb as smb_module
from man_spider.lib.errors import FileListError
from man_spider.lib.smb import SMBClient, _DFSReferral, _DFSRoute


@pytest.fixture(autouse=True)
def directory_routing_transport(monkeypatch):
    # Namespace doubles exercise referral policy; actual directory encoding is
    # verified separately without a permissive fallback in the production code.
    monkeypatch.setattr(smb_module, "read_only_list_path", lambda connection, share, path: connection.listPath(share, path))


class NamespaceConnection:
    def __init__(self):
        self.events = []
        self._Connection = {"MaxReadSize": 64 * 1024}
        self._open_payloads = {}

    def getDialect(self):
        return 0x0311

    def getSMBServer(self):
        return self

    @staticmethod
    def isSnapshotRequest(_path):
        return False

    def getServerName(self):
        return "ROOTSERVER"

    def getServerDNSDomainName(self):
        return "example.test"

    def connectTree(self, share):
        self.events.append(("tree", share))
        return share

    def disconnectTree(self, share):
        self.events.append(("disconnect", share))

    def listPath(self, share, path):
        self.events.append(("list", share, path))
        if share == "dfsroot":
            raise SessionError(STATUS_PATH_NOT_COVERED)
        return ()

    def getFile(self, share, path, callback, share_access_mode):
        self.events.append(("read", share, path))
        if share == "dfsroot":
            raise SessionError(STATUS_PATH_NOT_COVERED)
        callback(b"same-server secret")

    def create(self, tree_id, path, **kwargs):
        chunks = []
        self.getFile(tree_id, path, chunks.append, kwargs["shareMode"])
        file_id = (tree_id, path)
        self._open_payloads[file_id] = b"".join(chunks)
        return file_id

    def queryInfo(self, _tree_id, file_id):
        info = smb_module._impacket_smb.SMBQueryFileStandardInfo()
        info["AllocationSize"] = info["EndOfFile"] = len(self._open_payloads[file_id])
        info["Directory"] = 0
        return info.getData()

    def read(self, _tree_id, file_id, offset, size):
        return self._open_payloads[file_id][offset : offset + size]

    def close(self, *args):
        if args:
            _tree_id, file_id = args
            self._open_payloads.pop(file_id, None)
            return
        self.events.append(("close",))


def test_dfs_referral_capability_pins_ipc_ioctl_and_bounds():
    class Transport:
        def __init__(self):
            self.calls = []

        def connectTree(self, share):
            self.calls.append(("connect", share))
            return 17

        def ioctl(self, *args):
            self.calls.append(("ioctl", args))
            return b"response"

        def disconnectTree(self, tree_id):
            self.calls.append(("disconnect", tree_id))

    raw = Transport()
    guarded = smb_module._ReadOnlyDFSReferralTransport(raw)
    request = b"\x04\x00" + r"\server\share".encode("utf-16-le") + b"\x00\x00"

    assert guarded.request(request) == b"response"
    assert raw.calls == [
        ("connect", "IPC$"),
        ("ioctl", (17, None, 0x00060194, 0x00000001, request, 0, 65536)),
        ("disconnect", 17),
    ]
    for forbidden in ("write", "create", "sendSMB", "getSMBServer"):
        assert not hasattr(guarded, forbidden)


def test_dfs_referral_capability_rejects_malformed_request_before_tree_connect():
    class Transport:
        calls = 0
        ioctl = disconnectTree = staticmethod(lambda *_args: None)

        def connectTree(self, _share):
            self.calls += 1

    raw = Transport()
    guarded = smb_module._ReadOnlyDFSReferralTransport(raw)
    with pytest.raises(smb_module.ReadOnlySMBViolation, match="version-4"):
        guarded.request(b"\x03\x00" + r"\server\share".encode("utf-16-le") + b"\x00\x00")
    assert raw.calls == 0


@pytest.fixture
def namespace(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("DFS policy must not open a connection, authenticate, or resolve another host")

    monkeypatch.setattr(smb_module, "SMBConnection", forbidden)
    monkeypatch.setattr(SMBClient, "login", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    connection = NamespaceConnection()
    client = SMBClient("192.0.2.7", "user", "password", "EXAMPLE", "")
    client._install_connection(connection)
    yield client, connection
    client.close()


@pytest.mark.parametrize("operation", ["list", "read"])
def test_external_referral_is_warned_and_blocked_before_any_auth(namespace, monkeypatch, caplog, operation):
    client, connection = namespace
    monkeypatch.setattr(
        client,
        "_request_dfs_referrals",
        lambda *_args: [_DFSReferral("link", r"\other-server\private\nested", 600)],
    )
    payload = bytearray()
    with pytest.raises((FileListError, RuntimeError), match="Cross-server DFS referrals were skipped"):
        if operation == "list":
            list(client.ls("dfsroot", "link"))
        else:
            client.retrieve_file("dfsroot", r"link\secret.txt", payload.extend)

    assert "Cross-server DFS referral SKIPPED" in caplog.text
    assert r"\\192.0.2.7\dfsroot\link" in caplog.text
    assert r"\\other-server\private\nested" in caplog.text
    assert "--allow-external-dfs" in caplog.text
    assert not client._dfs_clients
    assert object.__getattribute__(client, "_SMBClient__connection") is connection
    assert payload == b""
    assert not any(event[:2] == ("tree", "private") for event in connection.events)


@pytest.mark.parametrize("alias", ["192.0.2.7", "ROOTSERVER", "rootserver.example.test."])
def test_known_same_server_alias_reuses_transport_without_opt_in(namespace, monkeypatch, alias):
    client, connection = namespace
    monkeypatch.setattr(
        client,
        "_request_dfs_referrals",
        lambda *_args: [_DFSReferral("link", f"\\{alias}\\target", 600)],
    )
    assert list(client.ls("dfsroot", "link")) == []
    payload = bytearray()
    client.retrieve_file("dfsroot", r"link\secret.txt", payload.extend)

    assert payload == b"same-server secret"
    assert not client._dfs_clients
    assert object.__getattribute__(client, "_SMBClient__connection") is connection
    assert ("read", "target", "secret.txt") in connection.events


def test_mixed_referrals_warn_for_external_but_keep_same_server(namespace, monkeypatch, caplog):
    client, connection = namespace
    monkeypatch.setattr(
        client,
        "_request_dfs_referrals",
        lambda *_args: [
            _DFSReferral("link", r"\unrecognized-alias\private", 600),
            _DFSReferral("link", r"\ROOTSERVER\target", 600),
        ],
    )

    assert list(client.ls("dfsroot", "link")) == []
    assert r"\\unrecognized-alias\private" in caplog.text
    assert ("list", "target", r"\*") in connection.events
    assert not client._dfs_clients


def test_low_level_external_client_creation_is_fail_closed(namespace):
    client, _connection = namespace
    with pytest.raises(RuntimeError, match="--allow-external-dfs"):
        client._create_dfs_client("other-server", 445)


def test_cached_external_route_cannot_bypass_disabled_policy(namespace):
    client, _connection = namespace
    route = _DFSRoute("dfsroot", "link", "private", "", float("inf"), target_server="other-server")
    # Even a stale/injected routing cache must not restore another SMB session.
    client._dfs_clients[("other-server", 445)] = client
    try:
        with pytest.raises(RuntimeError, match="--allow-external-dfs"):
            client._route_client(route)
    finally:
        client._dfs_clients.clear()
