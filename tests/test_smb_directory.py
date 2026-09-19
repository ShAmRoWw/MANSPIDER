"""Directory safety checks using the installed Impacket codecs, no sockets."""

from collections import deque
import struct

import pytest
from impacket import smb, smb3
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_NO_MORE_FILES
from impacket.smb3structs import (
    SMB2_CLOSE,
    SMB2_CREATE,
    SMB2_QUERY_DIRECTORY,
    SMB2Close,
    SMB2Create,
    SMB2Create_Response,
    SMB2Packet,
    SMB2QueryDirectory,
    SMB2QueryDirectory_Response,
)
from impacket.smbconnection import SessionError

from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib.smb_directory import (
    _SMB1DirectoryTransport,
    _SMB2DirectoryTransport,
    _snapshot_contexts,
    read_only_list_path,
)


class _Reply(dict):
    def isValidAnswer(self, _status):
        return True


class HighLevel:
    def __init__(self, raw, dialect=0x210):
        self.raw = raw
        self.dialect = dialect

    def getDialect(self):
        return self.dialect

    def getSMBServer(self):
        return self.raw

    def listPath(self, *_args):
        pytest.fail("unguarded high-level fallback must never be called")


def directory_record(name, *, smb1=False, unicode=True):
    flags = smb.SMB.FLAGS2_UNICODE if unicode else 0
    kind = smb.SMBFindFileBothDirectoryInfo if smb1 else smb.SMBFindFileFullDirectoryInfo
    record = kind(flags)
    for key in ("CreationTime", "LastAccessTime", "LastWriteTime", "LastChangeTime"):
        record[key] = 133000000000000000
    record["EaSize"] = 0
    record["EndOfFile"] = 23
    record["ExtFileAttributes"] = 0x20
    record["FileName"] = name.encode("utf-16-le" if unicode else "cp437")
    if smb1:
        record["ShortName"] = b""
    return record.getData()


class SMB2Raw(smb3.SMB3):
    def __init__(self, *, pages=(), dialect=0x210, create_error=None, close_error=None, disconnect_error=None):
        self._Connection = {
            "Dialect": dialect,
            "ServerName": "memory-only",
            "SupportsMultiCredit": False,
            "SupportsDirectoryLeasing": False,
        }
        self._Session = {"TreeConnectTable": {7: {"IsDfsShare": False}}, "OpenTable": {}}
        self.GlobalFileTable = {}
        self.SMB_PACKET = SMB2Packet
        self.pages = deque(pages)
        self.create_error = create_error
        self.close_error = close_error
        self.disconnect_error = disconnect_error
        self.events = []
        self.requests = []
        self.references = 1  # A separate owner already pinned this tree.

    def connectTree(self, share):
        self.events.append(("connect", share))
        self.references += 1
        return 7

    def disconnectTree(self, tree):
        self.events.append(("disconnect", tree))
        if self.disconnect_error is not None:
            raise self.disconnect_error
        self.references -= 1

    def sendSMB(self, packet):
        request = SMB2Packet(packet.getData())
        self.requests.append(request)
        self.events.append(("packet", request["Command"]))
        return len(self.requests)

    def recvSMB(self, packet_id):
        command = self.requests[packet_id - 1]["Command"]
        if command == SMB2_CREATE:
            if self.create_error is not None:
                raise self.create_error
            body = SMB2Create_Response()
            body["FileID"] = b"F" * 16
            body["Buffer"] = b""
            return _Reply(Data=body.getData())
        if command == SMB2_QUERY_DIRECTORY:
            if not self.pages:
                raise smb3.SessionError(STATUS_NO_MORE_FILES)
            data = self.pages.popleft()
            if isinstance(data, BaseException):
                raise data
            body = SMB2QueryDirectory_Response()
            body["OutputBufferOffset"] = 72
            body["OutputBufferLength"] = len(data)
            body["Buffer"] = data
            return _Reply(Data=body.getData())
        assert command == SMB2_CLOSE
        if self.close_error is not None:
            raise self.close_error
        return _Reply(Data=b"")


@pytest.mark.parametrize("dialect", (0x202, 0x210, 0x300, 0x302, 0x311))
@pytest.mark.parametrize("path", ("*", "folder\\*"))
def test_smb2_actual_directory_packets_are_read_only_and_release_only_owned_reference(dialect, path):
    raw = SMB2Raw(dialect=dialect)
    assert read_only_list_path(HighLevel(raw, dialect), "share", path) == []
    assert [packet["Command"] for packet in raw.requests] == [SMB2_CREATE, SMB2_QUERY_DIRECTORY, SMB2_CLOSE]
    create = SMB2Create(raw.requests[0]["Data"])
    expected = {
        "DesiredAccess": 0x81,
        "ShareAccess": 7,
        "CreateDisposition": 1,
        "CreateOptions": 0x21,
        "FileAttributes": 0,
        "RequestedOplockLevel": 0,
        "CreateContextsLength": 0,
    }
    assert {key: create[key] for key in expected} == expected
    query = SMB2QueryDirectory(raw.requests[1]["Data"])
    assert (query["Flags"], query["FileIndex"], query["FileInformationClass"], query["OutputBufferLength"]) == (
        0,
        0,
        2,
        65535,
    )
    assert SMB2Close(raw.requests[2]["Data"])["Flags"] == 0
    assert raw.events.count(("disconnect", 7)) == 1
    assert raw.references == 1


def test_smb2_pagination_preserves_names_and_metadata():
    raw = SMB2Raw(pages=(directory_record("пароль.txt"), directory_record("config.ini")))
    entries = read_only_list_path(HighLevel(raw), "share", "folder/*")
    assert [entry.get_longname() for entry in entries] == ["пароль.txt", "config.ini"]
    assert [entry.get_filesize() for entry in entries] == [23, 23]
    assert [packet["Command"] for packet in raw.requests].count(SMB2_QUERY_DIRECTORY) == 3


def test_smb2_snapshot_context_is_preserved_without_extra_requests():
    raw = SMB2Raw()
    read_only_list_path(HighLevel(raw), "share", "@GMT-2024.01.01-00.00.00\\folder\\*")
    create_packet = raw.requests[0]
    create = SMB2Create(create_packet["Data"])
    assert create["CreateContextsLength"] == 32
    wire = create_packet.getData()
    context = wire[create["CreateContextsOffset"] : create["CreateContextsOffset"] + 32]
    assert context[16:20] == b"TWrp"
    assert len(raw.requests) == 3


@pytest.mark.parametrize("close_error", (OSError("close response lost"), smb3.SessionError(STATUS_ACCESS_DENIED)))
def test_smb2_failed_close_still_disconnects_exactly_once_and_marks_session(close_error):
    raw = SMB2Raw(close_error=close_error)
    expected = SessionError if isinstance(close_error, smb3.SessionError) else OSError
    with pytest.raises(expected) as caught:
        read_only_list_path(HighLevel(raw), "share", "*")
    assert caught.value.smb_cleanup_failed is True
    assert raw.events[-1] == ("disconnect", 7)
    assert [packet["Command"] for packet in raw.requests].count(SMB2_CLOSE) == 1
    assert raw.references == 1
    # The failed handle can survive behind the owner's pin, which is why the
    # caller must retire the session rather than silently continuing.
    assert b"F" * 16 in raw._Session["OpenTable"]


@pytest.mark.parametrize("cleanup_kind", ("close", "disconnect", "both"))
def test_smb2_primary_listing_error_survives_cleanup_failures(cleanup_kind):
    original = smb3.SessionError(STATUS_ACCESS_DENIED)
    raw = SMB2Raw(
        pages=(original,),
        close_error=OSError("close failed") if cleanup_kind in ("close", "both") else None,
        disconnect_error=OSError("disconnect failed") if cleanup_kind in ("disconnect", "both") else None,
    )
    with pytest.raises(SessionError) as caught:
        read_only_list_path(HighLevel(raw), "share", "*")
    assert caught.value.getErrorCode() == STATUS_ACCESS_DENIED
    assert caught.value.__cause__ is original
    assert caught.value.smb_cleanup_failed is True
    assert raw.events.count(("disconnect", 7)) == 1
    assert [packet["Command"] for packet in raw.requests].count(SMB2_CLOSE) == 1


def test_smb2_create_error_disconnects_without_closing_unopened_handle():
    raw = SMB2Raw(create_error=smb3.SessionError(STATUS_ACCESS_DENIED))
    with pytest.raises(SessionError) as caught:
        read_only_list_path(HighLevel(raw), "share", "*")
    assert not getattr(caught.value, "smb_cleanup_failed", False)
    assert [packet["Command"] for packet in raw.requests] == [SMB2_CREATE]
    assert raw.events[-1] == ("disconnect", 7)


def test_smb2_keyboard_interrupt_preserves_type_and_releases_resources():
    interrupt = KeyboardInterrupt()
    raw = SMB2Raw(pages=(interrupt,))
    with pytest.raises(KeyboardInterrupt) as caught:
        read_only_list_path(HighLevel(raw), "share", "*")
    assert caught.value is interrupt
    assert raw.events[-2:] == [("packet", SMB2_CLOSE), ("disconnect", 7)]


@pytest.mark.parametrize("protocol", ("smb1", "smb2"))
@pytest.mark.parametrize("kind", (ReadOnlySMBViolation, ValueError, KeyboardInterrupt))
def test_parser_exceptions_stop_cleanup_only_for_safety_violations(monkeypatch, protocol, kind):
    error = kind("directory record parsing failed")

    def fail_parser(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(smb, "SharedFile", fail_parser)
    if protocol == "smb2":
        raw = SMB2Raw(pages=(directory_record("config.ini"),))
        connection = HighLevel(raw)
    else:
        raw = SMB1Raw()
        connection = HighLevel(raw, smb.SMB_DIALECT)

    with pytest.raises(kind) as caught:
        read_only_list_path(connection, "share", "*")

    assert caught.value is error
    if kind is ReadOnlySMBViolation:
        assert ("disconnect", 7) not in raw.events
        if protocol == "smb2":
            assert [packet["Command"] for packet in raw.requests] == [SMB2_CREATE, SMB2_QUERY_DIRECTORY]
    else:
        assert raw.events[-1] == ("disconnect", 7)
        if protocol == "smb2":
            assert raw.events[-2] == ("packet", SMB2_CLOSE)


@pytest.mark.parametrize("protocol", ("smb1", "smb2"))
def test_primary_guard_before_outer_finish_cannot_trigger_cleanup(monkeypatch, protocol):
    violation = ReadOnlySMBViolation("unexpected listing implementation path")

    def fail_after_connect(adapter, share, _path):
        if protocol == "smb2":
            adapter.connectTree(share)
        else:
            adapter.tree_connect_andx(share, None)
        raise violation

    if protocol == "smb2":
        raw = SMB2Raw()
        connection = HighLevel(raw)
        monkeypatch.setattr(smb3.SMB3, "listPath", fail_after_connect)
    else:
        raw = SMB1Raw()
        connection = HighLevel(raw, smb.SMB_DIALECT)
        monkeypatch.setattr(smb.SMB, "list_path", fail_after_connect)

    with pytest.raises(ReadOnlySMBViolation) as caught:
        read_only_list_path(connection, "share", "*")

    assert caught.value is violation
    assert len(raw.events) == 1
    assert raw.events[0][0] == "connect"


@pytest.mark.parametrize("phase", ("close", "disconnect"))
def test_cleanup_keyboard_interrupt_is_not_hidden_by_ordinary_listing_error(phase):
    interrupt = KeyboardInterrupt()
    raw = SMB2Raw(
        pages=(ValueError("listing failed"),),
        close_error=interrupt if phase == "close" else None,
        disconnect_error=interrupt if phase == "disconnect" else None,
    )
    with pytest.raises(KeyboardInterrupt) as caught:
        read_only_list_path(HighLevel(raw), "share", "*")
    assert caught.value is interrupt
    assert caught.value.smb_cleanup_failed is True
    assert raw.events[-1] == ("disconnect", 7)


@pytest.mark.parametrize("phase", ("create", "query", "close", "disconnect"))
def test_smb2_read_only_violation_stops_all_further_protocol_cleanup(phase):
    violation = ReadOnlySMBViolation(f"rejected during {phase}")
    raw = SMB2Raw(
        pages=(violation,) if phase == "query" else (),
        create_error=violation if phase == "create" else None,
        close_error=violation if phase == "close" else None,
        disconnect_error=violation if phase == "disconnect" else None,
    )
    with pytest.raises(ReadOnlySMBViolation) as caught:
        read_only_list_path(HighLevel(raw), "share", "*")
    assert caught.value is violation
    last = ("disconnect", 7) if phase == "disconnect" else (
        "packet",
        {"create": SMB2_CREATE, "query": SMB2_QUERY_DIRECTORY, "close": SMB2_CLOSE}[phase],
    )
    assert raw.events[-1] == last


@pytest.mark.parametrize(
    "constant,value",
    (("FILE_READ_DATA", 2), ("FILE_OPEN", 5), ("FILE_DIRECTORY_FILE", 0x1001), ("FILE_SHARE_DELETE", 0)),
)
def test_smb2_dependency_parameter_drift_is_blocked_before_create(monkeypatch, constant, value):
    raw = SMB2Raw()
    monkeypatch.setattr(smb3, constant, value)
    with pytest.raises(ReadOnlySMBViolation, match="pinned read-only"):
        read_only_list_path(HighLevel(raw), "share", "*")
    assert raw.requests == []
    assert raw.events == [("connect", "share")]


def test_smb2_cannot_close_another_read_handle():
    raw = SMB2Raw()
    adapter = _SMB2DirectoryTransport(raw)
    tree = adapter.connectTree("share")
    adapter.create(tree, "folder", 0x81, 7, 0x21, 1, 0)
    with pytest.raises(ReadOnlySMBViolation, match="own this read-only handle"):
        adapter.close(tree, b"OTHER-HANDLE-1234")
    assert [packet["Command"] for packet in raw.requests] == [SMB2_CREATE]


@pytest.mark.parametrize("position,unsafe", ((0, 3), (1, 1), (2, 0x1021), (3, 5), (4, 0x20), (5, 3), (6, 1), (7, 1)))
def test_smb2_open_validation_pins_every_permission_and_option(position, unsafe):
    raw = SMB2Raw()
    adapter = _SMB2DirectoryTransport(raw)
    tree = adapter.connectTree("share")
    arguments = [0x81, 7, 0x21, 1, 0, 2, 0, 0]
    arguments[position] = unsafe
    with pytest.raises(ReadOnlySMBViolation, match="pinned read-only"):
        adapter.create(tree, "folder", *arguments)
    assert raw.requests == []


def test_smb2_guard_in_cleanup_wins_over_ordinary_listing_error():
    violation = ReadOnlySMBViolation("cleanup rejected")
    raw = SMB2Raw(pages=(OSError("listing failed"),), close_error=violation)
    with pytest.raises(ReadOnlySMBViolation) as caught:
        read_only_list_path(HighLevel(raw), "share", "*")
    assert caught.value is violation
    assert raw.events[-1] == ("packet", SMB2_CLOSE)
    assert ("disconnect", 7) not in raw.events


def test_smb2_failed_disconnect_alone_is_reported_without_repeating():
    failure = OSError("disconnect lost")
    raw = SMB2Raw(disconnect_error=failure)
    with pytest.raises(OSError) as caught:
        read_only_list_path(HighLevel(raw), "share", "*")
    assert caught.value is failure
    assert caught.value.smb_cleanup_failed is True
    assert raw.events.count(("disconnect", 7)) == 1


@pytest.mark.parametrize("contexts", ([], [object()], [object(), object()]))
def test_snapshot_contexts_fail_closed(contexts):
    with pytest.raises(ReadOnlySMBViolation):
        _snapshot_contexts(contexts)


@pytest.mark.parametrize("position", (0, 4, 6, 8, 10, 12, 16, 20))
def test_snapshot_context_rejects_header_name_padding_changes(position):
    _path, context = SMB2Raw().timestampForSnapshot("@GMT-2024.01.01-00.00.00\\*")
    payload = bytearray(context.getData())
    payload[position] ^= 1

    class Context:
        def getData(self):
            return bytes(payload)

    with pytest.raises(ReadOnlySMBViolation):
        _snapshot_contexts([Context()])


def test_snapshot_context_is_copied_before_dependency_can_serialize_it_again():
    _path, context = SMB2Raw().timestampForSnapshot("@GMT-2024.01.01-00.00.00\\*")
    expected = context.getData()
    copied = _snapshot_contexts([context])
    context["Buffer"] = b"unsafe context"
    assert copied[0].getData() == expected


class SMB1Raw(smb.SMB):
    def __init__(self, *, names=("config.ini",), unicode=True, error=None, disconnect_error=None):
        self._SMB__remote_name = "memory-only"
        self._SMB__flags2 = smb.SMB.FLAGS2_UNICODE if unicode else 0
        self._dialects_parameters = {"MaxBufferSize": 65535}
        self.names = deque(names)
        self.unicode = unicode
        self.error = error
        self.disconnect_error = disconnect_error
        self.events = []
        self.requests = []

    def get_flags(self):
        return 0, self._SMB__flags2

    def tree_connect_andx(self, share, password):
        self.events.append(("connect", share, password))
        return 7

    def disconnect_tree(self, tree):
        self.events.append(("disconnect", tree))
        if self.disconnect_error is not None:
            raise self.disconnect_error

    def sendSMB(self, packet):
        wire = packet.getData()
        parsed = smb.NewSMBPacket(data=wire)
        assert parsed["Command"] == smb.SMB.SMB_COM_TRANSACTION2
        command = smb.SMBCommand(parsed["Data"][0])
        parameters = smb.SMBTransaction2_Parameters(command["Parameters"])
        setup = struct.unpack("<H", parameters["Setup"])[0]
        payload = wire[parameters["ParameterOffset"] : parameters["ParameterOffset"] + parameters["ParameterCount"]]
        self.requests.append((setup, payload))
        self.events.append(("find", setup))

    def recvSMB(self):
        if self.error is not None:
            raise self.error
        setup = self.requests[-1][0]
        parameters = smb.SMBFindFirst2Response_Parameters() if setup == 1 else smb.SMBFindNext2Response_Parameters()
        if setup == 1:
            parameters["SID"] = 11
        name = self.names.popleft() if self.names else None
        parameters["SearchCount"] = int(name is not None)
        parameters["EndOfSearch"] = int(not self.names)
        parameter_data = parameters.getData()
        data = b"" if name is None else directory_record(name, smb1=True, unicode=self.unicode)
        response = smb.NewSMBPacket()
        response["Flags1"] = smb.SMB.FLAGS1_REPLY
        command = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2)
        command["Parameters"] = smb.SMBTransaction2Response_Parameters()
        for key, value in {
            "TotalParameterCount": len(parameter_data),
            "TotalDataCount": len(data),
            "ParameterCount": len(parameter_data),
            "ParameterOffset": 55,
            "DataCount": len(data),
            "DataOffset": 55 + len(parameter_data),
            "Setup": b"",
        }.items():
            command["Parameters"][key] = value
        command["Data"] = parameter_data + data
        response.addCommand(command)
        return smb.NewSMBPacket(data=response.getData())


@pytest.mark.parametrize("unicode", (False, True))
@pytest.mark.parametrize("names", ((), ("config.ini",), ("config.ini", "secrets.txt")))
def test_smb1_preserves_installed_find_bytes_and_pagination(unicode, names):
    before = SMB1Raw(names=names, unicode=unicode)
    after = SMB1Raw(names=names, unicode=unicode)
    expected = smb.SMB.list_path(before, "share", "folder/*")
    actual = read_only_list_path(HighLevel(after, smb.SMB_DIALECT), "share", "folder/*")
    assert [entry.get_longname() for entry in actual] == [entry.get_longname() for entry in expected] == list(names)
    assert after.requests == before.requests
    assert after.events == before.events
    assert after.events[-1] == ("disconnect", 7)
    for setup, payload in after.requests:
        if setup == 1:
            assert struct.unpack_from("<HHHHI", payload) == (0x37, 512, 6, 0x104, 0)
        else:
            _sid, count, info, _resume, flags = struct.unpack_from("<HHHIH", payload)
            assert (count, info, flags) == (1024, 0x104, 6)


@pytest.mark.parametrize("disconnect_failure", (False, True))
def test_smb1_failed_search_releases_tree_and_preserves_primary_error(disconnect_failure):
    primary = OSError("directory read failed")
    raw = SMB1Raw(error=primary, disconnect_error=OSError("disconnect failed") if disconnect_failure else None)
    with pytest.raises(OSError) as caught:
        read_only_list_path(HighLevel(raw, smb.SMB_DIALECT), "share", "*")
    assert caught.value is primary
    assert bool(getattr(caught.value, "smb_cleanup_failed", False)) is disconnect_failure
    assert raw.events.count(("disconnect", 7)) == 1


def test_smb1_read_only_violation_does_not_send_cleanup():
    violation = ReadOnlySMBViolation("invalid request")
    raw = SMB1Raw(error=violation)
    with pytest.raises(ReadOnlySMBViolation) as caught:
        read_only_list_path(HighLevel(raw, smb.SMB_DIALECT), "share", "*")
    assert caught.value is violation
    assert raw.events[-1] == ("find", 1)


def test_smb1_unicode_names_survive_multiple_pages():
    raw = SMB1Raw(names=("пароль.txt", "секрет.ini"))
    entries = read_only_list_path(HighLevel(raw, smb.SMB_DIALECT), "share", "папка/*")
    assert [entry.get_longname() for entry in entries] == ["пароль.txt", "секрет.ini"]
    assert [setup for setup, _payload in raw.requests] == [1, 2]


def test_smb1_disconnect_failure_after_success_is_not_silently_ignored():
    failure = OSError("disconnect failed")
    raw = SMB1Raw(names=(), disconnect_error=failure)
    with pytest.raises(OSError) as caught:
        read_only_list_path(HighLevel(raw, smb.SMB_DIALECT), "share", "*")
    assert caught.value is failure
    assert caught.value.smb_cleanup_failed is True
    assert raw.events.count(("disconnect", 7)) == 1


@pytest.mark.parametrize("setup", (0, 3, 5, True))
def test_smb1_transport_refuses_non_find_transactions(setup):
    raw = SMB1Raw()
    adapter = _SMB1DirectoryTransport(raw)
    tree = adapter.tree_connect_andx("\\\\memory-only\\share", None)
    with pytest.raises(ReadOnlySMBViolation, match="FIND_FIRST2/FIND_NEXT2"):
        adapter.send_trans2(tree, setup, "\x00", b"", "")
    assert raw.requests == []


@pytest.mark.parametrize("dialect", (0, 0x999, True, "SMB3"))
def test_unknown_dialect_fails_closed(dialect):
    raw = SMB2Raw()
    with pytest.raises(ReadOnlySMBViolation, match="unsupported dialect"):
        read_only_list_path(HighLevel(raw, dialect), "share", "*")
    assert raw.events == []


def test_missing_transport_capability_does_not_use_high_level_fallback():
    with pytest.raises(ReadOnlySMBViolation, match="required capabilities"):
        read_only_list_path(HighLevel(object()), "share", "*")
