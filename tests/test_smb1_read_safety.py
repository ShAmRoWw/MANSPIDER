"""Exercise the actual Impacket SMB1 encoder/parser with no network transport."""

from collections import deque

import pytest
from impacket import smb
from impacket.nt_errors import STATUS_END_OF_FILE
from impacket.smbconnection import SessionError

import man_spider.lib.smb as smb_module
from man_spider.lib.errors import FileChangedDuringRead
from man_spider.lib.smb import ReadOnlySMBViolation, SMBClient


FILETIME = 133000000000000000


def memory_protocol(payload=b"secret", *, responses=None, unicode=True, metadata_error=False):
    protocol = object.__new__(smb.SMB)
    protocol._SMB__flags2 = smb.SMB.FLAGS2_UNICODE if unicode else 0
    protocol._dialects_parameters = {"Capabilities": 0, "MaxBufferSize": 4096}
    protocol._SignatureEnabled = False
    events, opens, reads, pending = [], [], [], []
    scripted = deque(responses) if responses is not None else None
    protocol.get_flags = lambda: (0, protocol._SMB__flags2)
    protocol.tree_connect_andx = lambda name: events.append(("connect", name)) or 11
    protocol.close = lambda tree, handle: events.append(("close", tree, handle))
    protocol.disconnect_tree = lambda tree: events.append(("disconnect", tree))

    def query(tree, handle, info_class=smb.SMB_QUERY_FILE_STANDARD_INFO):
        events.append(("query", info_class))
        if info_class == smb.SMB_QUERY_FILE_STANDARD_INFO:
            info = smb.SMBQueryFileStandardInfo()
            info["AllocationSize"] = info["EndOfFile"] = len(payload)
            info["Directory"] = 0
        else:
            if metadata_error:
                raise RuntimeError("unsupported information class")
            info = smb.SMBQueryFileAllInfo()
            for name in ("CreationTime", "LastAccessTime", "LastWriteTime", "LastChangeTime"):
                info[name] = FILETIME
            info["LastWriteTime"] = FILETIME - 100000000
            info["ExtFileAttributes"] = 0
            info["AllocationSize"] = info["EndOfFile"] = len(payload)
            info["Directory"] = 0
            info["FileName"] = b""
        return info.getData()

    def send(packet):
        incoming = smb.NewSMBPacket(data=packet.getData())
        command = smb.SMBCommand(incoming["Data"][0])
        reply = smb.NewSMBPacket()
        reply["Flags1"] = smb.SMB.FLAGS1_REPLY
        output = smb.SMBCommand(incoming["Command"])
        if incoming["Command"] == smb.SMB.SMB_COM_NT_CREATE_ANDX:
            params = smb.SMBNtCreateAndX_Parameters(command["Parameters"])
            opens.append(
                {
                    name: params[name]
                    for name in (
                        "CreateFlags",
                        "RootFid",
                        "AccessMask",
                        "AllocationSizeLo",
                        "AllocationSizeHi",
                        "FileAttributes",
                        "ShareAccess",
                        "Disposition",
                        "CreateOptions",
                        "Impersonation",
                        "SecurityFlags",
                    )
                }
            )
            output["Parameters"] = smb.SMBNtCreateAndXResponse_Parameters()
            output["Parameters"]["Fid"] = 22
            output["Parameters"]["CreateAction"] = 1
            output["Parameters"]["IsDirectory"] = 0
        elif incoming["Command"] == smb.SMB.SMB_COM_READ_ANDX:
            params = smb.SMBReadAndX_Parameters(command["Parameters"])
            offset = params["Offset"] | (params["HighOffset"] << 32)
            count = params["MaxCount"]
            reads.append((offset, count))
            data = scripted.popleft() if scripted is not None else payload[offset : offset + count]
            if isinstance(data, Exception):
                raise data
            output["Parameters"] = smb.SMBReadAndXResponse_Parameters()
            output["Parameters"]["DataCount"] = len(data)
            output["Parameters"]["DataCount_Hi"] = 0
            output["Parameters"]["DataOffset"] = 59
            output["Data"] = data
        else:
            raise AssertionError("unexpected SMB request")
        reply.addCommand(output)
        pending.append(reply.getData())

    protocol.query_file_info = query
    protocol.sendSMB = send
    protocol.recvSMB = lambda: smb.NewSMBPacket(data=pending.pop())
    return protocol, events, opens, reads


def client():
    return SMBClient("server", "", "", "", "")


@pytest.mark.parametrize("unicode", [False, True])
def test_smb1_actual_open_is_read_only_without_oplocks(unicode):
    payload = b"x" * 9000
    protocol, events, opens, reads = memory_protocol(payload, unicode=unicode)
    received = bytearray()
    identity = client()._retrieve_smb1_file(protocol, "share", "folder/secret.txt", received.extend)
    assert bytes(received) == payload
    assert identity == (len(payload), SMBClient._smb_time_epoch(FILETIME), None)
    assert opens == [
        {
            "CreateFlags": 0,
            "RootFid": 0,
            "AccessMask": 0x20089,
            "AllocationSizeLo": 0,
            "AllocationSizeHi": 0,
            "FileAttributes": 0,
            "ShareAccess": 7,
            "Disposition": 1,
            "CreateOptions": 0x40,
            "Impersonation": 2,
            "SecurityFlags": 0,
        }
    ]
    assert reads == [(0, 4096), (4096, 4096), (8192, 808)]
    assert events[-2:] == [("close", 11, 22), ("disconnect", 11)]


@pytest.mark.parametrize(
    "field,unsafe_value",
    (
        ("FileNameLength", 0),
        ("CreateFlags", 1),
        ("RootFid", 1),
        ("AccessMask", smb.FILE_WRITE_DATA),
        ("AllocationSizeLo", 1),
        ("AllocationSizeHi", 1),
        ("FileAttributes", 0x20),
        ("ShareAccess", smb.FILE_SHARE_READ),
        ("Disposition", 3),
        ("CreateOptions", 0),
        ("Impersonation", 3),
        ("SecurityFlags", 1),
    ),
)
def test_smb1_runtime_guard_rejects_every_unpinned_open_field(field, unsafe_value):
    wire_path = "secret.txt".encode("utf-16-le")
    request = smb_module._build_smb1_read_open(wire_path, smb.SMB.FLAGS2_UNICODE)
    request["Parameters"][field] = unsafe_value

    with pytest.raises(smb_module.ReadOnlySMBViolation, match="pinned read-only open"):
        smb_module._validate_smb1_read_open(request, wire_path)


@pytest.mark.parametrize("field", ("AndXCommand", "_reserved", "AndXOffset"))
def test_smb1_runtime_guard_rejects_create_command_chaining(field):
    wire_path = b"secret.txt"
    request = smb_module._build_smb1_read_open(wire_path, 0)
    request["Parameters"][field] = 1

    with pytest.raises(ReadOnlySMBViolation, match="chaining fields"):
        smb_module._validate_smb1_read_open(request, wire_path)


def test_smb1_runtime_guard_rejects_wrong_create_command_before_dispatch():
    wire_path = b"secret.txt"
    request = smb_module._build_smb1_read_open(wire_path, 0)
    request.command = smb.SMB.SMB_COM_DELETE

    with pytest.raises(ReadOnlySMBViolation, match="missing a pinned"):
        smb_module._validate_smb1_read_open(request, wire_path)


@pytest.mark.parametrize("mutation", ("command", "tree", "file", "offset", "count", "chain"))
def test_smb1_runtime_guard_rejects_noncanonical_read_packets(mutation):
    packet = smb.NewSMBPacket()
    packet["Tid"] = 11
    request = smb.SMBCommand(smb.SMB.SMB_COM_READ_ANDX)
    request["Parameters"] = smb.SMBReadAndX_Parameters()
    request["Parameters"]["Fid"] = 22
    request["Parameters"]["Offset"] = 100
    request["Parameters"]["HighOffset"] = 0
    request["Parameters"]["MaxCount"] = 512
    packet.addCommand(request)

    if mutation == "command":
        packet["Command"] = smb.SMB.SMB_COM_DELETE
    elif mutation == "tree":
        packet["Tid"] = 99
    elif mutation == "file":
        request["Parameters"]["Fid"] = 99
    elif mutation == "offset":
        request["Parameters"]["Offset"] = 101
    elif mutation == "count":
        request["Parameters"]["MaxCount"] = 513
    else:
        request["Parameters"]["AndXCommand"] = smb.SMB.SMB_COM_DELETE
        request["Parameters"]["AndXOffset"] = 64

    with pytest.raises(ReadOnlySMBViolation, match="pinned READ_ANDX"):
        smb_module._validate_smb1_read_packet(packet, 11, 22, 100, 512)


@pytest.mark.parametrize(
    "symbol,unsafe_value",
    (
        ("FILE_READ_DATA", smb.FILE_WRITE_DATA),
        ("NON_BLOCKING_READ_SHARE_ACCESS", smb.FILE_SHARE_READ),
        ("FILE_OPEN", 3),
        ("FILE_NON_DIRECTORY_FILE", 0),
    ),
)
def test_smb1_constant_drift_is_rejected_before_any_wire_request(monkeypatch, symbol, unsafe_value):
    protocol, events, opens, _reads = memory_protocol()
    monkeypatch.setattr(smb_module, symbol, unsafe_value)

    with pytest.raises(smb_module.ReadOnlySMBViolation, match="pinned read-only open"):
        client()._retrieve_smb1_file(protocol, "share", "secret.txt", lambda _data: None)

    assert opens == []
    assert events == []


@pytest.mark.parametrize(
    "responses,expected_reads", [([b""], 1), ([b"sec", b""], 2), ([SessionError(STATUS_END_OF_FILE)], 1)]
)
def test_smb1_zero_progress_and_early_eof_stop_immediately(responses, expected_reads):
    protocol, events, _opens, reads = memory_protocol(responses=responses)
    with pytest.raises(FileChangedDuringRead):
        client()._retrieve_smb1_file(protocol, "share", "secret.txt", lambda _data: None)
    assert len(reads) == expected_reads
    assert events[-2:] == [("close", 11, 22), ("disconnect", 11)]


def test_smb1_callback_error_closes_handle_and_tree():
    protocol, events, _opens, _reads = memory_protocol()

    def fail(_data):
        raise OSError("local spool is full")

    with pytest.raises(OSError, match="local spool is full"):
        client()._retrieve_smb1_file(protocol, "share", "secret.txt", fail)
    assert events[-2:] == [("close", 11, 22), ("disconnect", 11)]


def test_smb1_close_failure_still_disconnects_tree():
    protocol, events, _opens, _reads = memory_protocol()
    protocol.close = lambda *_args: (_ for _ in ()).throw(OSError("close failed"))
    with pytest.raises(OSError, match="close failed"):
        client()._retrieve_smb1_file(protocol, "share", "secret.txt", lambda _data: None)
    assert events[-1] == ("disconnect", 11)


def test_smb1_empty_file_has_no_read_request():
    protocol, _events, _opens, reads = memory_protocol(b"")
    assert client()._retrieve_smb1_file(protocol, "share", "empty.txt", lambda _data: None)[0] == 0
    assert reads == []


def test_smb1_unsupported_postquery_keeps_legacy_metadata_fallback():
    protocol, _events, _opens, _reads = memory_protocol(metadata_error=True)
    received = bytearray()
    assert client()._retrieve_smb1_file(protocol, "share", "secret.txt", received.extend) is None
    assert received == b"secret"


def test_smb1_rejects_overlong_success_before_delivering_bytes():
    protocol, _events, _opens, _reads = memory_protocol(responses=[b"more than six bytes"])
    received = bytearray()
    with pytest.raises(OSError, match="more data"):
        client()._retrieve_smb1_file(protocol, "share", "secret.txt", received.extend)
    assert not received


@pytest.mark.parametrize("signed,expected", [(False, 65000), (True, 8192)])
def test_smb1_negotiated_and_signed_read_limit(signed, expected):
    protocol, _events, _opens, reads = memory_protocol(b"x" * 66000)
    protocol._dialects_parameters = {"Capabilities": smb.SMB.CAP_LARGE_READX, "MaxBufferSize": 8192}
    protocol._SignatureEnabled = signed
    client()._retrieve_smb1_file(protocol, "share", "secret.txt", lambda _data: None)
    assert max(count for _offset, count in reads) == expected


@pytest.mark.parametrize("reply", [b"", SessionError(STATUS_END_OF_FILE)])
def test_smb2_uses_same_retryable_incomplete_read_error(monkeypatch, reply):
    class Protocol:
        _Connection = {"MaxReadSize": 4096}
        isSnapshotRequest = staticmethod(lambda path: False)
        connectTree = staticmethod(lambda share: 11)
        create = staticmethod(lambda *args, **kwargs: 22)
        queryInfo = staticmethod(lambda *args: b"")
        disconnectTree = staticmethod(lambda tree: None)
        close = staticmethod(lambda *args: None)

        @staticmethod
        def read(*args):
            if isinstance(reply, Exception):
                raise reply
            return reply

    monkeypatch.setattr(smb, "SMBQueryFileStandardInfo", lambda data: {"EndOfFile": 1})
    with pytest.raises(FileChangedDuringRead):
        client()._retrieve_smb2_file(Protocol(), "share", "secret.txt", lambda data: None)


def test_smb1_stable_snapshot_compares_change_time_not_last_write_time(tmp_path):
    from man_spider.lib.file import RemoteFile
    from man_spider.lib.util import Target

    entry = smb.SharedFile(FILETIME, FILETIME, FILETIME - 100000000, FILETIME, 6, 6, 0, "secret.txt", "secret.txt")
    assert entry.get_mtime_epoch() != entry.get_wtime_epoch()
    protocol, _events, opens, _reads = memory_protocol()

    class Source:
        def retrieve_file(self, share, path, callback):
            return client()._retrieve_smb1_file(protocol, share, path, callback)

        def handle_impacket_error(self, *args):
            pass

    file = RemoteFile("secret.txt", "share", Target("server"), size=6, mtime=entry.get_mtime_epoch(), tmp_dir=tmp_path)
    try:
        file.get(Source())
        assert file.changed is False
        assert len(opens) == 1
        assert file.post_read_identity[1] == entry.get_mtime_epoch()
    finally:
        file.cleanup()


def test_smb2_close_compares_change_time_not_last_write_time():
    from impacket.smb3structs import SMB2Close_Response, SMB2Packet

    response = SMB2Close_Response()
    for name in ("CreationTime", "LastAccessTime", "LastWriteTime", "ChangeTime"):
        response[name] = FILETIME
    response["LastWriteTime"] = FILETIME - 100000000
    response["AllocationSize"] = response["EndofFile"] = 6
    response["FileAttributes"] = 0

    class Answer(dict):
        def isValidAnswer(self, status):
            return True

    class Connection:
        SMB_PACKET = SMB2Packet
        _Connection = {"MaxReadSize": 4096}
        _Session = {"OpenTable": {}}
        GlobalFileTable = {}
        connectTree = queryInfo = read = close = disconnectTree = isSnapshotRequest = staticmethod(lambda *_args: None)
        create = staticmethod(lambda *_args, **_kwargs: b"\0" * 16)
        sendSMB = staticmethod(lambda _packet: 1)
        recvSMB = staticmethod(lambda _packet_id: Answer(Data=response.getData()))

    connection = smb_module._ReadOnlySMB2FileTransport(Connection())
    file_id = connection.create(
        11,
        "secret.txt",
        smb_module.FILE_READ_DATA,
        smb_module.NON_BLOCKING_READ_SHARE_ACCESS,
        smb_module.FILE_NON_DIRECTORY_FILE,
        smb_module.FILE_OPEN,
        0,
        smb_module.SMB2_IL_IMPERSONATION,
        0,
        smb_module.SMB2_OPLOCK_LEVEL_NONE,
        createContexts=None,
    )
    identity = client()._close_smb2_file_with_identity(connection, 11, file_id)
    entry = smb.SharedFile(FILETIME, FILETIME, FILETIME - 100000000, FILETIME, 6, 6, 0, "s", "s")
    assert identity == (6, entry.get_mtime_epoch(), None)
    assert identity[1] != entry.get_wtime_epoch()


@pytest.mark.parametrize("read_fails", [False, True])
@pytest.mark.parametrize("disconnect_fails", [False, True])
@pytest.mark.parametrize("caller_exception", [False, True])
def test_smb2_close_failures_always_disconnect_and_preserve_primary_error(
    monkeypatch, read_fails, disconnect_fails, caller_exception
):
    events = []
    read_error = OSError("primary read failure")
    close_error = OSError("normal close failure")

    class Protocol:
        _Connection = {"MaxReadSize": 4096}
        isSnapshotRequest = staticmethod(lambda path: False)
        connectTree = staticmethod(lambda share: 11)
        create = staticmethod(lambda *args, **kwargs: 22)
        queryInfo = staticmethod(lambda *args: b"")

        @staticmethod
        def read(*args):
            if read_fails:
                raise read_error
            return b"abc"

        @staticmethod
        def close(*args):
            events.append("close")
            raise close_error

        @staticmethod
        def disconnectTree(*args):
            events.append("disconnect")
            if disconnect_fails:
                raise OSError("disconnect failure")

    monkeypatch.setattr(smb, "SMBQueryFileStandardInfo", lambda data: {"EndOfFile": 3})
    scanner = client()

    def failed_postclose(*args):
        events.append("postclose")
        raise OSError("postquery close failure")

    monkeypatch.setattr(scanner, "_close_smb2_file_with_identity", failed_postclose)

    def retrieve():
        with pytest.raises(OSError) as caught:
            scanner._retrieve_smb2_file(Protocol(), "share", "secret.txt", lambda data: None)
        return caught

    if caller_exception:
        try:
            raise ValueError("unrelated outer retry context")
        except ValueError:
            caught = retrieve()
    else:
        caught = retrieve()
    assert caught.value is (read_error if read_fails else close_error)
    assert events == ["postclose", "close", "disconnect"]


def test_smb1_cleanup_failure_does_not_mask_early_eof():
    protocol, events, _opens, reads = memory_protocol(responses=[b""])

    def failed_close(*args):
        events.append("failed-close")
        raise OSError("close failure")

    protocol.close = failed_close
    with pytest.raises(FileChangedDuringRead, match="zero bytes"):
        client()._retrieve_smb1_file(protocol, "share", "secret.txt", lambda data: None)
    assert len(reads) == 1
    assert events[-2:] == ["failed-close", ("disconnect", 11)]


def test_legacy_high_level_wrapper_without_guarded_transport_fails_closed():
    class Wrapper:
        callbacks = 0
        getDialect = staticmethod(lambda: 0x0311)

        def getFile(self, share, filename, callback, share_access):
            for _ in range(5):
                self.callbacks += 1
                callback(b"")
            pytest.fail("empty callback must stop the dependency loop")

    scanner = client()
    wrapper = Wrapper()
    scanner._install_connection(wrapper)
    scanner._transport_group.active_client = scanner
    with pytest.raises(ReadOnlySMBViolation, match="guarded low-level file transport"):
        scanner.retrieve_file("share", "secret.txt", lambda data: None)
    assert wrapper.callbacks == 0
