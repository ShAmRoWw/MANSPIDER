"""Broken-stream retirement, using real NetBIOS decoding but no real sockets."""

from collections import deque
import errno
import os
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket import nmb, smb, smb3
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_END_OF_FILE, STATUS_NOT_SUPPORTED, STATUS_SHARING_VIOLATION
from impacket.smb3structs import SMB2Packet
from impacket.smbconnection import SessionError

from man_spider.lib.errors import FileChangedDuringRead
from man_spider.lib.smb import SMBClient, _ReadOnlyDFSReferralTransport
from man_spider.lib.smb_directory import _SMB1DirectoryTransport, _SMB2DirectoryTransport
from man_spider.lib.smb_rpc import _ShareEnumerationTransport
from man_spider.lib.smb_transport import transport_state


class MemorySocket:
    def __init__(self, events, chunks=()):
        self.events = events
        self.chunks = deque(chunks)

    def shutdown(self, how):
        assert how == socket.SHUT_RDWR
        self.events.append("socket-shutdown")

    def close(self):
        self.events.append("socket-close")

    def settimeout(self, _timeout):
        pass

    def recv(self, size):
        value = self.chunks.popleft()
        if isinstance(value, BaseException):
            raise value
        assert len(value) <= size
        return value


class MemoryConnection:
    """Separate protocol and raw disposal events; no constructor opens sockets."""

    SMB_PACKET = SMB2Packet
    _Connection = {"MaxReadSize": 4}
    _dialects_parameters = {"Capabilities": 0, "MaxBufferSize": 4096}
    _SignatureEnabled = False

    def __init__(self, failures=None, dialect=0x210):
        self.events = []
        self.socket = MemorySocket(self.events)
        self.failures = failures or {}
        self.dialect = dialect
        self.payload = b"password=fixture"
        self._Session = {"OpenTable": {}}
        self.GlobalFileTable = {}

    def event(self, name):
        self.events.append(name)
        error = self.failures.get(name)
        if callable(error):
            return error()
        if error is not None:
            raise error

    def getSMBServer(self):
        return self

    def get_socket(self):
        return self.socket

    def getDialect(self):
        return self.dialect

    def isSnapshotRequest(self, _path):
        return False

    def connectTree(self, _share):
        self.event("tree-connect")
        return 7

    def disconnectTree(self, _tree):
        self.event("tree-disconnect")

    def create(self, _tree, _path, **kwargs):
        assert kwargs["creationDisposition"] == 1
        assert kwargs["desiredAccess"] in (1, 0x81)
        self.event("create")
        return b"f" * 16

    def queryInfo(self, _tree, _file):
        self.event("query")
        info = smb.SMBQueryFileStandardInfo()
        info["EndOfFile"] = info["AllocationSize"] = len(self.payload)
        info["Directory"] = 0
        return info.getData()

    def read(self, _tree, _file, offset, size):
        self.event("read")
        return self.payload[offset:offset + size]

    def close(self, *args):
        self.event("file-close" if args else "protocol-logoff")

    def sendSMB(self, _packet):
        self.event("postquery-send")
        return 1

    def recvSMB(self, *_packet):
        self.event("postquery-receive")
        # A successfully acknowledged CLOSE with unusable optional attributes
        # must stay an optimization fallback, not become a damaged stream.
        return SimpleNamespace(isValidAnswer=lambda _status: True, __getitem__=lambda _key: b"")

    def get_flags(self):
        return 0, smb.SMB.FLAGS2_UNICODE

    def get_remote_name(self):
        return "fixture"

    def tree_connect_andx(self, _path, *_password):
        return self.connectTree("share")

    def nt_create_andx(self, _tree, _path, **_kwargs):
        self.event("create")
        return 7

    def query_file_info(self, tree, file, info_class=None):
        if info_class is not None:
            self.event("post-read-query")
            raise RuntimeError("optional attributes unsupported")
        return self.queryInfo(tree, file)

    def read_andx(self, tree, file, *, offset, max_size, smb_packet):
        return self.read(tree, file, offset, max_size)

    def disconnect_tree(self, tree):
        return self.disconnectTree(tree)

    def send_trans2(self, *_args):
        self.event("find-send")

    def queryDirectory(self, *_args, **_kwargs):
        self.event("directory-query")
        return b""

    def ioctl(self, *_args):
        self.event("ioctl")
        return b"response"

    def getRemoteName(self):
        return "fixture"

    def getRemoteHost(self):
        return "192.0.2.1"

    def getCredentials(self):
        return ("user", "synthetic", "domain", "", "", "", None, None)

    def openFile(self, _tree, _path, **kwargs):
        assert kwargs["creationDisposition"] == 1
        self.event("pipe-open")
        return b"pipe"

    def closeFile(self, *_args):
        self.event("pipe-close")

    def readFile(self, *_args, **_kwargs):
        self.event("pipe-read")
        return b"reply"


def installed(connection):
    client = SMBClient("fixture", "user", "synthetic", "domain", "")
    client._install_connection(connection)
    return client


def assert_disposed(connection):
    assert connection.events.count("socket-shutdown") == 1
    assert connection.events.count("socket-close") == 1
    assert "protocol-logoff" not in connection.events


@pytest.mark.parametrize("protocol", ["SMB1", "SMB2"])
@pytest.mark.parametrize("partial", ["header", "body"])
def test_actual_partial_netbios_frame_read_drops_stream_without_protocol_cleanup(protocol, partial):
    connection = MemoryConnection(dialect=smb.SMB_DIALECT if protocol == "SMB1" else 0x210)
    chunks = [b"\x00\x00", socket.timeout()] if partial == "header" else [b"\x00\x00\x00\x08", b"123", socket.timeout()]
    connection.socket = MemorySocket(connection.events, chunks)
    session = object.__new__(nmb.NetBIOSTCPSession)
    session._sock = connection.socket
    session.read_function = session.non_polling_read
    connection.failures["read"] = lambda: session.recv_packet(20)
    client = installed(connection)
    with pytest.raises(nmb.NetBIOSTimeout):
        client._retrieve_file_direct("share", "secret.txt", lambda _data: None)
    client.close()
    assert_disposed(connection)
    assert not {"postquery-send", "file-close", "tree-disconnect"}.intersection(connection.events)
    assert client.conn is None
    assert client._transport_group.safety_error is None


@pytest.mark.parametrize("stage", ["postquery-send", "postquery-receive", "file-close", "tree-disconnect"])
def test_first_transport_failure_during_cleanup_stops_remaining_cleanup(stage):
    connection = MemoryConnection({stage: nmb.NetBIOSTimeout()})
    if stage == "file-close":
        connection.SMB_PACKET = None  # Compatibility transport uses ordinary CLOSE.
    client = installed(connection)
    with pytest.raises(nmb.NetBIOSTimeout):
        client._retrieve_file_direct("share", "secret.txt", lambda _data: None)
    assert_disposed(connection)
    after_failure = connection.events[connection.events.index(stage) + 1:]
    assert after_failure == ["socket-shutdown", "socket-close"]
    assert client.conn is None


@pytest.mark.parametrize("error_type", [TimeoutError, nmb.NetBIOSTimeout, EOFError, BrokenPipeError])
def test_local_callback_transport_named_exception_does_not_poison_connection(error_type):
    connection = MemoryConnection()
    client = installed(connection)
    error = error_type("local callback failed") if error_type is not nmb.NetBIOSTimeout else error_type()
    def callback(_data):
        raise error
    with pytest.raises(error_type) as caught:
        client._retrieve_file_direct("share", "secret.txt", callback)
    assert caught.value is error
    assert not transport_state(connection).failed
    assert "socket-close" not in connection.events
    assert connection.events[-1] == "tree-disconnect"
    assert client.conn is not None
    connection.failures.clear()
    received = bytearray()
    client._retrieve_file_direct("share", "next.txt", received.extend)
    assert bytes(received) == connection.payload
    assert not transport_state(connection).failed
    client.close()
    assert connection.events[-1] == "protocol-logoff"


def test_local_enospc_does_not_poison_connection():
    connection = MemoryConnection()
    client = installed(connection)
    def callback(_data):
        raise OSError(errno.ENOSPC, "local spool is full")
    with pytest.raises(OSError):
        client._retrieve_file_direct("share", "secret.txt", callback)
    assert not transport_state(connection).failed
    assert connection.events[-1] == "tree-disconnect"
    client.close()


@pytest.mark.parametrize("code", [STATUS_ACCESS_DENIED, STATUS_SHARING_VIOLATION, STATUS_END_OF_FILE])
def test_complete_server_error_keeps_normal_cleanup_and_connection(code):
    connection = MemoryConnection({"read": SessionError(code)})
    client = installed(connection)
    with pytest.raises(FileChangedDuringRead if code == STATUS_END_OF_FILE else SessionError):
        client._retrieve_file_direct("share", "secret.txt", lambda _data: None)
    assert not transport_state(connection).failed
    assert "postquery-send" in connection.events
    assert connection.events[-1] == "tree-disconnect"
    assert client.conn is not None
    client.close()


def test_old_connection_cleanup_failure_cannot_retire_new_connection():
    old = MemoryConnection({"postquery-receive": nmb.NetBIOSTimeout()})
    new = MemoryConnection()
    client = installed(old)
    def callback(_data):
        client._install_connection(new)
        raise EOFError("local callback stopped after replacement")
    with pytest.raises(EOFError):
        client._retrieve_file_direct("share", "secret.txt", callback)
    assert transport_state(old).failed
    assert old.events.count("socket-close") == 1
    assert not transport_state(new).failed
    assert client._SMBClient__connection is new
    assert new.events == []
    client.close()
    assert new.events == ["protocol-logoff"]


def test_failed_connection_pins_metrics_and_slot_are_released_exactly_once(tmp_path):
    connection = MemoryConnection({"read": nmb.NetBIOSTimeout()})
    client = installed(connection)
    client._metric_session_stopped = Mock()
    client._unlock_slot = Mock()
    slot_path = tmp_path / "slot"
    descriptor = os.open(slot_path, os.O_CREAT | os.O_RDWR, 0o600)
    client._host_session_slot = (descriptor, slot_path)
    with client.pin_share("share"):
        with pytest.raises(nmb.NetBIOSTimeout):
            client._retrieve_file_direct("share", "secret.txt", lambda _data: None)
    client.close()
    client._metric_session_stopped.assert_called_once()
    client._unlock_slot.assert_called_once_with(descriptor)
    assert client._host_session_slot is None
    assert not client._pinned_share_trees
    assert not client._share_pin_depths
    assert_disposed(connection)


@pytest.mark.parametrize("protocol", ["SMB1", "SMB2"])
def test_directory_failure_blocks_dependency_and_outer_cleanup(protocol):
    connection = MemoryConnection({"directory-query": nmb.NetBIOSTimeout(), "postquery-receive": nmb.NetBIOSTimeout()})
    if protocol == "SMB2":
        adapter = _SMB2DirectoryTransport(connection)
        tree = adapter.connectTree("share")
        file = adapter.create(tree, "*", 0x81, 7, 0x21, 1, 0)
        with pytest.raises(nmb.NetBIOSTimeout):
            adapter.queryDirectory(tree, file, "*", maxBufferSize=65535, informationClass=2)
        adapter.close(tree, file)  # Installed listPath's own finally block.
    else:
        adapter = _SMB1DirectoryTransport(connection)
        adapter.tree_connect_andx("share", "")
        with pytest.raises(nmb.NetBIOSTimeout):
            adapter.recvSMB()
    adapter.finish()
    assert_disposed(connection)
    assert not {"file-close", "tree-disconnect"}.intersection(connection.events)


@pytest.mark.parametrize("stage", ["pipe-read", "pipe-close"])
def test_rpc_transport_failure_never_sends_following_pipe_or_tree_cleanup(stage):
    connection = MemoryConnection({stage: nmb.NetBIOSTimeout()})
    adapter = _ShareEnumerationTransport(connection)
    adapter.connect()
    with pytest.raises(nmb.NetBIOSTimeout):
        if stage == "pipe-read":
            adapter.recv()
        else:
            adapter.disconnect()
    adapter.disconnect()
    assert_disposed(connection)
    assert "tree-disconnect" not in connection.events
    assert connection.events.count("pipe-close") == (stage == "pipe-close")


@pytest.mark.parametrize("error", [nmb.NetBIOSTimeout(), SessionError(STATUS_ACCESS_DENIED)])
def test_dfs_failure_only_drops_stream_for_transport_errors(error):
    connection = MemoryConnection({"ioctl": error})
    adapter = _ReadOnlyDFSReferralTransport(connection)
    with pytest.raises(type(error)):
        adapter.request(b"\x04\x00" + "\\fixture\\share".encode("utf-16-le") + b"\x00\x00")
    assert transport_state(connection).failed == isinstance(error, nmb.NetBIOSTimeout)
    assert ("tree-disconnect" in connection.events) == isinstance(error, SessionError)


def test_smb1_post_read_query_timeout_is_not_swallowed_as_optional_metadata():
    connection = MemoryConnection({"post-read-query": nmb.NetBIOSTimeout()}, dialect=smb.SMB_DIALECT)
    client = installed(connection)
    with pytest.raises(nmb.NetBIOSTimeout):
        client._retrieve_file_direct("share", "secret.txt", lambda _data: None)
    assert_disposed(connection)
    assert not {"file-close", "tree-disconnect"}.intersection(connection.events)


def test_malformed_actual_smb_header_drops_stream_but_local_decoder_error_does_not():
    connection = object.__new__(smb3.SMB3)
    events = []
    connection.get_socket = lambda: MemorySocket(events)
    connection._Connection = {"OutstandingResponses": {}}
    connection._timeout = 1
    connection._NetBIOSSession = SimpleNamespace(recv_packet=lambda _timeout: SimpleNamespace(get_trailer=lambda: b"bad"))
    state = transport_state(connection)
    with pytest.raises(Exception):
        state.call(connection.recvSMB, 1)
    assert state.failed
    assert events == ["socket-shutdown", "socket-close"]
    healthy = MemoryConnection()
    with pytest.raises(ValueError):
        transport_state(healthy).call(lambda: int("not a metadata integer"))
    assert not transport_state(healthy).failed


def test_successful_close_with_missing_optional_attributes_never_repeats_close():
    connection = MemoryConnection()
    client = installed(connection)
    assert client._retrieve_file_direct("share", "secret.txt", lambda _data: None) is None
    assert connection.events.count("postquery-send") == 1
    assert "file-close" not in connection.events
    assert "socket-close" not in connection.events
    assert not transport_state(connection).failed
    client.close()


def test_complete_postquery_not_supported_response_keeps_ordinary_close_fallback():
    connection = MemoryConnection({"postquery-receive": SessionError(STATUS_NOT_SUPPORTED)})
    client = installed(connection)
    client._retrieve_file_direct("share", "secret.txt", lambda _data: None)
    assert connection.events[-2:] == ["file-close", "tree-disconnect"]
    assert not transport_state(connection).failed
    assert "socket-close" not in connection.events
    client.close()


@pytest.mark.parametrize("error", [
    BrokenPipeError(), ConnectionResetError(), ConnectionAbortedError(), EOFError(), TimeoutError(),
    OSError(errno.EPIPE, "pipe"), OSError(errno.ENOTCONN, "not connected"),
    OSError(errno.EBADF, "socket already closed"), OSError(errno.ENETDOWN, "interface down"),
])
def test_network_failures_dispose_only_their_own_connection(error):
    connection = MemoryConnection({"read": error})
    client = installed(connection)
    with pytest.raises(type(error)) as caught:
        client._retrieve_file_direct("share", "secret.txt", lambda _data: None)
    assert caught.value is error
    assert_disposed(connection)
    assert client.conn is None
    assert client._transport_group.safety_error is None


def test_shutdown_failure_still_closes_socket_once():
    connection = MemoryConnection()
    def failed_shutdown(_how):
        raise OSError(errno.ENOTCONN, "already disconnected")
    connection.socket.shutdown = failed_shutdown
    state = transport_state(connection)
    state.fail(nmb.NetBIOSTimeout())
    state.fail(BrokenPipeError())
    assert connection.events == ["socket-close"]


@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit])
def test_shutdown_cancellation_still_closes_and_preserves_control_exception(control_type):
    connection = MemoryConnection()
    error = control_type("operator interrupted shutdown")
    def interrupted_shutdown(_how):
        raise error
    connection.socket.shutdown = interrupted_shutdown
    state = transport_state(connection)
    with pytest.raises(control_type) as caught:
        state.fail(nmb.NetBIOSTimeout())
    assert caught.value is error
    state.fail(nmb.NetBIOSTimeout())
    assert connection.events == ["socket-close"]


@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit])
def test_cancellation_in_actual_partial_frame_disposes_stream_before_unwinding(control_type):
    connection = MemoryConnection()
    error = control_type("operator interrupted receive")
    connection.socket = MemorySocket(connection.events, [b"\x00\x00\x00\x08", b"123", error])
    session = object.__new__(nmb.NetBIOSTCPSession)
    session._sock = connection.socket
    session.read_function = session.non_polling_read
    connection.failures["read"] = lambda: session.recv_packet(20)
    client = installed(connection)
    with pytest.raises(control_type) as caught:
        client._retrieve_file_direct("share", "secret.txt", lambda _data: None)
    assert caught.value is error
    assert_disposed(connection)
    assert not {"postquery-send", "file-close", "tree-disconnect"}.intersection(connection.events)
    assert client.conn is None


@pytest.mark.parametrize("stage", ["tree-disconnect", "protocol-logoff"])
@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit])
def test_suspend_cancellation_releases_local_connection_ownership(stage, control_type, tmp_path):
    error = control_type("operator interrupted cleanup")
    connection = MemoryConnection({stage: error})
    client = installed(connection)
    client._metric_session_stopped = Mock()
    client._unlock_slot = Mock()
    slot_path = tmp_path / "slot"
    descriptor = os.open(slot_path, os.O_CREAT | os.O_RDWR, 0o600)
    client._host_session_slot = (descriptor, slot_path)
    with client.pin_share("share"):
        with pytest.raises(control_type) as caught:
            client._suspend_transport()
        assert caught.value is error
    assert client.conn is None
    assert client._transport_group.active_client is None
    assert client._host_session_slot is None
    client._unlock_slot.assert_called_once_with(descriptor)
    client._metric_session_stopped.assert_called_once()
    assert not client._pinned_share_trees
    assert not client._share_pin_depths


def test_interrupted_raw_close_can_be_retried_without_protocol_requests():
    connection = MemoryConnection()
    client = installed(connection)
    def interrupted_close():
        connection.socket.close = lambda: connection.events.append("socket-close")
        raise KeyboardInterrupt("first raw close interrupted")
    connection.socket.close = interrupted_close
    with pytest.raises(KeyboardInterrupt):
        transport_state(connection).fail(nmb.NetBIOSTimeout())
    client._suspend_transport()
    assert connection.events.count("socket-close") == 1
    assert "protocol-logoff" not in connection.events
    assert client.conn is None
