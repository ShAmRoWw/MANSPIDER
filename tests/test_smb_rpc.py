"""RPC pipe ownership, fail-closed operations, and real loopback regression tests."""

import threading
from unittest.mock import Mock

import pytest
from impacket import smb, smb3structs
from impacket.dcerpc.v5 import rpcrt
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smbserver import SimpleSMBServer

from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib import smb_rpc


class FakeConnection:
    def __init__(self, failures=None):
        self.events = []
        self.failures = failures or {}
        self.handle = b"owned-pipe-handle"
        self.socket = object()

    def _call(self, name, *args, **kwargs):
        self.events.append((name, args, kwargs))
        if name in self.failures:
            raise self.failures[name]

    def getRemoteName(self):
        return "server"

    def getRemoteHost(self):
        return "192.0.2.1"

    def getCredentials(self):
        return ("user", "password", "domain", "", "", "", None, None)

    def connectTree(self, share):
        self._call("connectTree", share)
        return 7

    def openFile(self, tree, path, **kwargs):
        self._call("openFile", tree, path, **kwargs)
        return self.handle

    def getSMBServer(self):
        return self

    def get_socket(self):
        self._call("get_socket")
        return self.socket

    def closeFile(self, tree, handle):
        self._call("closeFile", tree, handle)

    def disconnectTree(self, tree):
        self._call("disconnectTree", tree)

    def writeFile(self, tree, handle, data, **kwargs):
        self._call("writeFile", tree, handle, data, **kwargs)
        return len(data)

    def readFile(self, tree, handle, **kwargs):
        self._call("readFile", tree, handle, **kwargs)
        return b"reply"


def rpc_bind_payload():
    bind = rpcrt.MSRPCBind()
    context = rpcrt.CtxItem()
    context["ContextID"] = 0
    context["TransItems"] = 1
    context["AbstractSyntax"] = smb_rpc._SRVS_INTERFACE
    context["TransferSyntax"] = smb_rpc._NDR_TRANSFER_SYNTAX
    bind.addCtxItem(context)
    message = rpcrt.MSRPCHeader()
    message["type"] = 11
    message["pduData"] = bind.getData()
    return message.get_packet()


def rpc_request_payload(opnum=15, flags=3, body=b"request body"):
    request = rpcrt.DCERPC_RawCall(opnum, body)
    request["flags"] = flags
    return request.get_packet()


def install_fake_rpc(monkeypatch, *, failure=None, stage="request", result=None):
    transports = []

    def get_dce_rpc(transport):
        transports.append(transport)
        if failure is not None and stage == "get_dce_rpc":
            raise failure
        dce = Mock()
        dce.connect.side_effect = transport.connect

        def bind(interface):
            assert interface == smb_rpc._SRVS_INTERFACE
            if failure is not None and stage == "bind":
                raise failure
            transport.send(rpc_bind_payload())

        dce.bind.side_effect = bind
        return dce

    def enumerate_shares(dce, level, *, serverName):
        assert level == 1
        assert serverName == r"\\192.0.2.1"
        if failure is not None and stage == "request":
            raise failure
        transports[-1].send(rpc_request_payload())
        return {"InfoStruct": {"ShareInfo": {"Level1": {"Buffer": result}}}}

    monkeypatch.setattr(smb_rpc._ShareEnumerationTransport, "get_dce_rpc", get_dce_rpc)
    monkeypatch.setattr(smb_rpc.srvs, "hNetrShareEnum", enumerate_shares)
    return transports


def event_names(connection):
    return [event[0] for event in connection.events]


def test_share_enumeration_closes_only_its_pipe_then_tree(monkeypatch):
    connection = FakeConnection()
    records = [{"shi1_netname": "share\x00"}]
    transports = install_fake_rpc(monkeypatch, result=records)
    assert smb_rpc.read_only_list_shares(connection) is records
    assert event_names(connection) == [
        "connectTree", "openFile", "get_socket", "writeFile", "writeFile", "closeFile", "disconnectTree"
    ]
    assert connection.events[-2] == ("closeFile", (7, connection.handle), {})
    assert connection.events[-1] == ("disconnectTree", (7,), {})
    assert connection.events[1] == (
        "openFile", (7, r"\srvsvc"), {
            "desiredAccess": 3, "shareMode": 1, "creationOption": 0x40,
            "creationDisposition": 1, "fileAttributes": 0x80, "impersonationLevel": 2,
            "securityFlags": 0, "oplockLevel": 0, "createContexts": None,
        },
    )
    transports[0].disconnect()
    assert event_names(connection).count("closeFile") == 1


@pytest.mark.parametrize("stage", ["get_dce_rpc", "connectTree", "openFile", "get_socket", "bind", "request"])
@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt])
def test_failure_preserves_primary_and_cleans_known_resources(monkeypatch, stage, error_type):
    error = error_type("original failure")
    connection = FakeConnection({stage: error})
    install_fake_rpc(monkeypatch, failure=error, stage=stage)
    with pytest.raises(error_type) as caught:
        smb_rpc.read_only_list_shares(connection)
    assert caught.value is error
    names = event_names(connection)
    if stage in {"get_dce_rpc", "connectTree"}:
        assert "closeFile" not in names and "disconnectTree" not in names
    elif stage == "openFile":
        assert names[-1] == "disconnectTree" and "closeFile" not in names
    else:
        assert names[-2:] == ["closeFile", "disconnectTree"]


@pytest.mark.parametrize("failed_cleanup", ["closeFile", "disconnectTree"])
def test_cleanup_failure_propagates_after_success(monkeypatch, failed_cleanup):
    error = OSError("cleanup failure")
    connection = FakeConnection({failed_cleanup: error})
    install_fake_rpc(monkeypatch, result=[])
    with pytest.raises(OSError) as caught:
        smb_rpc.read_only_list_shares(connection)
    assert caught.value is error
    assert caught.value.smb_cleanup_failed is True
    assert event_names(connection)[-2:] == ["closeFile", "disconnectTree"]


def test_primary_failure_survives_both_cleanup_failures(monkeypatch):
    primary = ValueError("bad RPC response")
    connection = FakeConnection({"closeFile": OSError("close failed"), "disconnectTree": OSError("tree failed")})
    install_fake_rpc(monkeypatch, failure=primary)
    with pytest.raises(ValueError) as caught:
        smb_rpc.read_only_list_shares(connection)
    assert caught.value is primary
    assert primary.smb_cleanup_failed is True
    assert event_names(connection)[-2:] == ["closeFile", "disconnectTree"]


@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize("failed_cleanup", ["closeFile", "disconnectTree"])
def test_cleanup_cancellation_outweighs_earlier_ordinary_rpc_failure(monkeypatch, control_type, failed_cleanup):
    cancellation = control_type("operator stopped cleanup")
    connection = FakeConnection({failed_cleanup: cancellation})
    install_fake_rpc(monkeypatch, failure=OSError("original RPC receive error"))
    with pytest.raises(control_type) as caught:
        smb_rpc.read_only_list_shares(connection)
    assert caught.value is cancellation
    assert cancellation.smb_cleanup_failed is True
    assert event_names(connection)[-2:] == ["closeFile", "disconnectTree"]


@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize("control_stage", ["closeFile", "disconnectTree"])
def test_cancellation_is_not_hidden_by_another_ordinary_cleanup_failure(control_type, control_stage):
    cancellation = control_type("operator stopped cleanup")
    ordinary_stage = "disconnectTree" if control_stage == "closeFile" else "closeFile"
    connection = FakeConnection({control_stage: cancellation, ordinary_stage: OSError("ordinary cleanup error")})
    transport = smb_rpc._ShareEnumerationTransport(connection)
    transport.connect()
    with pytest.raises(control_type) as caught:
        transport.disconnect()
    assert caught.value is cancellation
    assert cancellation.smb_cleanup_failed is True
    assert event_names(connection)[-2:] == ["closeFile", "disconnectTree"]
    transport.disconnect()
    assert event_names(connection).count("closeFile") == 1
    assert event_names(connection).count("disconnectTree") == 1


@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_primary_cancellation_survives_ordinary_cleanup_failure(monkeypatch, control_type):
    cancellation = control_type("original cancellation")
    connection = FakeConnection({"closeFile": OSError("ordinary close failure")})
    install_fake_rpc(monkeypatch, failure=cancellation)
    with pytest.raises(control_type) as caught:
        smb_rpc.read_only_list_shares(connection)
    assert caught.value is cancellation
    assert cancellation.smb_cleanup_failed is True


@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize("stage", ["closeFile", "disconnectTree"])
def test_cleanup_safety_violation_has_priority_over_cancellation(monkeypatch, control_type, stage):
    cancellation = control_type("operator cancellation")
    violation = ReadOnlySMBViolation("unsafe cleanup")
    connection = FakeConnection({stage: violation})
    install_fake_rpc(monkeypatch, failure=cancellation)
    with pytest.raises(ReadOnlySMBViolation) as caught:
        smb_rpc.read_only_list_shares(connection)
    assert caught.value is violation
    assert event_names(connection)[-1] == stage


def test_first_cleanup_cancellation_is_preserved():
    first = KeyboardInterrupt("first cancellation")
    connection = FakeConnection({"closeFile": first, "disconnectTree": SystemExit("later cancellation")})
    transport = smb_rpc._ShareEnumerationTransport(connection)
    transport.connect()
    with pytest.raises(KeyboardInterrupt) as caught:
        transport.disconnect()
    assert caught.value is first


@pytest.mark.parametrize("stage", ["bind", "request", "closeFile", "disconnectTree"])
def test_read_only_violation_stops_further_smb_operations(monkeypatch, stage):
    violation = ReadOnlySMBViolation("unsafe dependency")
    connection = FakeConnection({stage: violation})
    install_fake_rpc(monkeypatch, failure=violation, stage=stage)
    with pytest.raises(ReadOnlySMBViolation) as caught:
        smb_rpc.read_only_list_shares(connection)
    assert caught.value is violation
    assert violation.smb_cleanup_failed is True
    names = event_names(connection)
    if stage in {"bind", "request"}:
        assert "closeFile" not in names and "disconnectTree" not in names
    elif stage == "closeFile":
        assert names[-1] == "closeFile" and "disconnectTree" not in names


def test_cleanup_read_only_violation_outweighs_primary_rpc_error(monkeypatch):
    violation = ReadOnlySMBViolation("unsafe close")
    connection = FakeConnection({"closeFile": violation})
    install_fake_rpc(monkeypatch, failure=ValueError("primary RPC failure"))
    with pytest.raises(ReadOnlySMBViolation) as caught:
        smb_rpc.read_only_list_shares(connection)
    assert caught.value is violation
    assert violation.smb_cleanup_failed is True
    assert event_names(connection)[-1] == "closeFile"


def test_transport_only_uses_captured_connection_and_handles():
    connection = FakeConnection()
    transport = smb_rpc._ShareEnumerationTransport(connection)
    transport.connect()
    assert transport.get_socket() is connection.socket
    replacement = FakeConnection()
    with pytest.raises(ReadOnlySMBViolation):
        transport.set_smb_connection(replacement)
    with pytest.raises(ReadOnlySMBViolation):
        transport.setup_smb_connection()
    with pytest.raises(ReadOnlySMBViolation):
        transport.connect()
    transport.disconnect()
    assert replacement.events == []
    assert connection.events[-2:] == [("closeFile", (7, connection.handle), {}), ("disconnectTree", (7,), {})]
    with pytest.raises(ReadOnlySMBViolation):
        transport.connect()


@pytest.mark.parametrize("connected", [False, True])
def test_closed_or_unopened_pipe_rejects_read_write(connected):
    connection = FakeConnection()
    transport = smb_rpc._ShareEnumerationTransport(connection)
    if connected:
        transport.connect()
        transport.disconnect()
    before = len(connection.events)
    with pytest.raises(ReadOnlySMBViolation):
        transport.send(rpc_request_payload())
    with pytest.raises(ReadOnlySMBViolation):
        transport.recv()
    assert len(connection.events) == before


@pytest.mark.parametrize("flags", [1, 0, 2, 3])
def test_rpc_fragments_preserve_enumeration_operation_and_pipe_destination(flags):
    connection = FakeConnection()
    transport = smb_rpc._ShareEnumerationTransport(connection)
    transport.connect()
    payload = rpc_request_payload(flags=flags, body=b"A" * 5000)
    transport.send(payload, forceWriteAndx=1, forceRecv=flags & 2)
    assert connection.events[-1] == ("writeFile", (7, connection.handle, payload), {"offset": 0})
    assert transport.recv(forceRecv=1) == b"reply"
    assert connection.events[-1] == ("readFile", (7, connection.handle), {"bytesToRead": None})
    transport.disconnect()


@pytest.mark.parametrize("opnum", [0, 1, 14, 16, 17, 18, 19, 21, 37, 38, 65535])
def test_non_enumeration_rpc_operations_never_reach_smb_write(opnum):
    connection = FakeConnection()
    transport = smb_rpc._ShareEnumerationTransport(connection)
    transport.connect()
    with pytest.raises(ReadOnlySMBViolation, match="opnum 15"):
        transport.send(rpc_request_payload(opnum))
    assert "writeFile" not in event_names(connection)
    transport.disconnect()


@pytest.mark.parametrize("offset,value", [(0, 4), (1, 1), (2, 14), (3, 0x80), (4, 0), (8, 0), (10, 1), (24, 2), (28, 1), (32, 0), (52, 0)])
def test_malformed_or_different_rpc_bind_is_rejected(offset, value):
    payload = bytearray(rpc_bind_payload())
    payload[offset] = value
    with pytest.raises(ReadOnlySMBViolation):
        smb_rpc._validate_share_rpc_message(payload)


@pytest.mark.parametrize("payload", [None, b"", b"RPC", b"\x00" * 15, rpc_request_payload()[:23]])
def test_short_or_non_rpc_bytes_rejected(payload):
    with pytest.raises(ReadOnlySMBViolation):
        smb_rpc._validate_share_rpc_message(payload)


@pytest.fixture(params=[False, True], ids=["smb1", "smb2"])
def loopback_rpc_connection(tmp_path, request):
    source = tmp_path / "unchanged.txt"
    source.write_bytes(b"Original server file remains unchanged.\n")
    server = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=0)
    server.setSMB2Support(request.param)
    server.addShare("testshare", str(tmp_path), readOnly="no")
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    connection = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=server.getServer().server_address[1], timeout=5)
    try:
        connection.login("", "")
        yield connection, server, source
    finally:
        connection.close()
        server.getServer().shutdown()
        server.stop()
        thread.join(timeout=5)


def test_real_rpc_enumeration_closes_pipe_and_keeps_smb_session_usable(loopback_rpc_connection):
    connection, server, source = loopback_rpc_connection
    original = source.read_bytes()
    before = source.stat()
    # Another caller owns an IPC$ tree reference. Enumeration must close its
    # own pipe even when its tree release does not disconnect this shared tree.
    pinned_ipc = connection.connectTree("IPC$")
    try:
        for _ in range(2):
            shares = smb_rpc.read_only_list_shares(connection)
            assert "testshare" in [share["shi1_netname"].rstrip("\x00").lower() for share in shares]
            connections = server.getServer()._SMBSERVER__activeConnections
            assert connections
            assert all(not state["OpenedFiles"] for state in connections.values())
            assert any(state["ConnectedShares"] for state in connections.values())
        files = connection.listPath("testshare", "*")
        assert "unchanged.txt" in [file.get_longname() for file in files]
    finally:
        connection.disconnectTree(pinned_ipc)
    after = source.stat()
    assert source.read_bytes() == original
    assert (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode, before.st_ino) == (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode, after.st_ino
    )


def test_real_server_read_failure_closes_rpc_pipe_before_retry(loopback_rpc_connection):
    connection, server, source = loopback_rpc_connection
    native_server = server.getServer()
    is_smb1 = connection.getDialect() == smb.SMB_DIALECT
    failed = False

    def fail_first_read(*args):
        nonlocal failed
        if not failed:
            failed = True
            if is_smb1:
                response = smb.SMBCommand(smb.SMB.SMB_COM_READ_ANDX)
                response["Parameters"] = b""
                response["Data"] = b""
            else:
                response = smb3structs.SMB2Error()
            return [response], None, 0xC0000022
        return original(*args)

    if is_smb1:
        hook = native_server.hookSmbCommand
        command = smb.SMB.SMB_COM_READ_ANDX
    else:
        hook = native_server.hookSmb2Command
        command = smb3structs.SMB2_READ
    original = hook(command, fail_first_read)
    try:
        with pytest.raises(SessionError) as caught:
            smb_rpc.read_only_list_shares(connection)
        assert caught.value.getErrorCode() == 0xC0000022
        assert not getattr(caught.value, "smb_cleanup_failed", False)
        connections = native_server._SMBSERVER__activeConnections
        assert connections
        assert all(not state["OpenedFiles"] for state in connections.values())
        assert all(not state["ConnectedShares"] for state in connections.values())
        shares = smb_rpc.read_only_list_shares(connection)
        assert "testshare" in [share["shi1_netname"].rstrip("\x00").lower() for share in shares]
        assert all(not state["OpenedFiles"] for state in connections.values())
    finally:
        hook(command, original)
