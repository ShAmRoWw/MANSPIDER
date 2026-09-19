import hashlib
import ntpath
import logging
import os
import stat
import struct
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from time import monotonic, monotonic_ns, sleep

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    fcntl = None
try:
    import msvcrt
except ImportError:  # pragma: no cover - exercised on POSIX
    msvcrt = None
from impacket import smb as _impacket_smb
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_END_OF_FILE, STATUS_PATH_NOT_COVERED, STATUS_SUCCESS
from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import (
    FILE_NON_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_READ_DATA,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    SMB2_CLOSE,
    SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB,
    SMB2_DIALECT_002,
    SMB2_IL_IMPERSONATION,
    SMB2_OPLOCK_LEVEL_NONE,
    SMB2Close,
    SMB2Close_Response,
    SMB2Packet,
)

from man_spider.lib.errors import *
from man_spider.lib.cancellation import check_worker_cancellation
from man_spider.lib.finding_log import display_text
from man_spider.lib.network_recovery import NetworkRecovery
from man_spider.lib.smb_directory import read_only_list_path
from man_spider.lib.smb_rpc import read_only_list_shares
from man_spider.lib.smb_transport import close_failed_negotiation, is_transport_error, transport_state
from man_spider.metrics import SMBMetricsEmitter
from man_spider.path_safety import (
    local_directory_descriptor,
    require_local_file_descriptor,
    require_local_write_path,
)

# set up logging
log = logging.getLogger("manspider.smb")


# ShareAccess controls what *other* clients may do while MANSPIDER's read-only
# handle is open. Allowing read/write/delete sharing avoids needlessly
# blocking an application's write, rename, or delete; it does not grant this
# handle any of those rights (DesiredAccess remains exactly FILE_READ_DATA).
NON_BLOCKING_READ_SHARE_ACCESS = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
DEFAULT_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


@dataclass(frozen=True)
class _SMB2ReadOpenParameters:
    # These are protocol values rather than aliases to mutable module globals.
    # A dependency upgrade (or accidental reassignment) therefore fails the
    # runtime check instead of silently broadening an open.
    desired_access: int = 0x00000001  # FILE_READ_DATA
    share_mode: int = 0x00000007  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    creation_options: int = 0x00000040  # FILE_NON_DIRECTORY_FILE
    creation_disposition: int = 0x00000001  # FILE_OPEN
    file_attributes: int = 0x00000000
    impersonation_level: int = 0x00000002  # SMB2_IL_IMPERSONATION
    security_flags: int = 0x00
    oplock_level: int = 0x00  # SMB2_OPLOCK_LEVEL_NONE


@dataclass(frozen=True)
class _SMB1ReadOpenParameters:
    create_flags: int = 0x00000000
    root_fid: int = 0x00000000
    access_mask: int = 0x00020089  # READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA
    allocation_size_low: int = 0x00000000
    allocation_size_high: int = 0x00000000
    file_attributes: int = 0x00000000
    share_access: int = 0x00000007
    disposition: int = 0x00000001  # FILE_OPEN
    create_options: int = 0x00000040  # FILE_NON_DIRECTORY_FILE
    impersonation: int = 0x00000002
    security_flags: int = 0x00


_SMB2_READ_OPEN = _SMB2ReadOpenParameters()
_SMB1_READ_OPEN = _SMB1ReadOpenParameters()


class _PostQueryUnavailable(RuntimeError):
    """A tracked compatibility handle supports ordinary, but not wire, CLOSE."""


class _PinnedSMB2CreateContext:
    """Immutable serialized CREATE context accepted by Impacket's encoder."""

    __slots__ = ("__payload",)

    def __init__(self, payload):
        self.__payload = payload

    def getData(self):
        return self.__payload


def _validate_smb2_create_contexts(create_contexts):
    """Permit no SMB2 CREATE context except Impacket's single time-warp token."""

    if create_contexts is None:
        return None
    if not isinstance(create_contexts, (list, tuple)) or len(create_contexts) != 1:
        raise ReadOnlySMBViolation("SMB2 read open contains an unsupported CREATE context set")
    try:
        payload = bytes(create_contexts[0].getData())
        next_offset, name_offset, name_length, reserved, data_offset, data_length = struct.unpack_from(
            "<IHHHHI", payload
        )
    except (AttributeError, TypeError, ValueError, struct.error) as exc:
        raise ReadOnlySMBViolation("SMB2 read open contains a malformed CREATE context") from exc
    if (
        len(payload) != 32
        or (next_offset, name_offset, name_length, reserved, data_offset, data_length) != (0, 16, 4, 0, 24, 8)
        or payload[16:20] != b"TWrp"
        or payload[20:24] != b"\x00" * 4
    ):
        raise ReadOnlySMBViolation("SMB2 read open contains a non-time-warp CREATE context")
    return (_PinnedSMB2CreateContext(payload),)


def _validate_smb2_read_open(
    desired_access,
    share_mode,
    creation_options,
    creation_disposition,
    file_attributes,
    impersonation_level,
    security_flags,
    oplock_level,
    create_contexts,
):
    expected = _SMB2_READ_OPEN
    observed = (
        desired_access,
        share_mode,
        creation_options,
        creation_disposition,
        file_attributes,
        impersonation_level,
        security_flags,
        oplock_level,
    )
    pinned = (
        expected.desired_access,
        expected.share_mode,
        expected.creation_options,
        expected.creation_disposition,
        expected.file_attributes,
        expected.impersonation_level,
        expected.security_flags,
        expected.oplock_level,
    )
    if any(type(value) is not int for value in observed) or observed != pinned:
        raise ReadOnlySMBViolation("SMB2 CREATE parameters do not match the pinned read-only open")
    return _validate_smb2_create_contexts(create_contexts)


def _validate_smb1_read_open(request, wire_path):
    expected = _SMB1_READ_OPEN
    expected_fields = {
        "FileNameLength": len(wire_path),
        "CreateFlags": expected.create_flags,
        "RootFid": expected.root_fid,
        "AccessMask": expected.access_mask,
        "AllocationSizeLo": expected.allocation_size_low,
        "AllocationSizeHi": expected.allocation_size_high,
        "FileAttributes": expected.file_attributes,
        "ShareAccess": expected.share_access,
        "Disposition": expected.disposition,
        "CreateOptions": expected.create_options,
        "Impersonation": expected.impersonation,
        "SecurityFlags": expected.security_flags,
    }
    try:
        if type(request) is not _impacket_smb.SMBCommand:
            raise TypeError("unexpected command object")
        if request.command != _impacket_smb.SMB.SMB_COM_NT_CREATE_ANDX:
            raise ValueError("unexpected SMB1 command")
        parameters = _impacket_smb.SMBNtCreateAndX_Parameters(request["Parameters"].getData())
        observed_fields = {name: parameters[name] for name in expected_fields}
        andx_fields = {
            "AndXCommand": parameters["AndXCommand"],
            "_reserved": parameters["_reserved"],
            "AndXOffset": parameters["AndXOffset"],
        }
        observed_path = request["Data"]["FileName"]
    except (AttributeError, KeyError, TypeError, ValueError, struct.error) as exc:
        raise ReadOnlySMBViolation("SMB1 read open is missing a pinned NT_CREATE_ANDX field") from exc
    if any(type(value) is not int for value in observed_fields.values()) or observed_fields != expected_fields:
        raise ReadOnlySMBViolation("SMB1 NT_CREATE_ANDX parameters do not match the pinned read-only open")
    if andx_fields != {"AndXCommand": 0xFF, "_reserved": 0, "AndXOffset": 0}:
        raise ReadOnlySMBViolation("SMB1 NT_CREATE_ANDX chaining fields are not disabled")
    if observed_path != wire_path:
        raise ReadOnlySMBViolation("SMB1 NT_CREATE_ANDX path differs from the validated read path")


def _validate_smb1_read_packet(packet, tree_id, file_id, offset, maximum_size):
    """Reject a caller-supplied SMB1 packet unless it is one exact READ_ANDX."""

    try:
        encoded = packet.getData()
        parsed = _impacket_smb.NewSMBPacket(data=encoded)
        commands = parsed["Data"]
        command = _impacket_smb.SMBCommand(commands[0])
        parameters = _impacket_smb.SMBReadAndX_Parameters(command["Parameters"])
        observed = {
            "AndXCommand": parameters["AndXCommand"],
            "_reserved": parameters["_reserved"],
            "AndXOffset": parameters["AndXOffset"],
            "Fid": parameters["Fid"],
            "Offset": parameters["Offset"],
            "MaxCount": parameters["MaxCount"],
            "MinCount": parameters["MinCount"],
            "Remaining": parameters["Remaining"],
            "HighOffset": parameters["HighOffset"],
        }
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, struct.error) as exc:
        raise ReadOnlySMBViolation("SMB1 read transport received a malformed packet") from exc
    expected = {
        "AndXCommand": 0xFF,
        "_reserved": 0,
        "AndXOffset": 0,
        "Fid": file_id,
        "Offset": offset & 0xFFFFFFFF,
        "MaxCount": maximum_size,
        "MinCount": maximum_size,
        "Remaining": maximum_size,
        "HighOffset": offset >> 32,
    }
    if (
        len(commands) != 1
        or parsed["Command"] != _impacket_smb.SMB.SMB_COM_READ_ANDX
        or parsed["Tid"] != tree_id
        or any(type(value) is not int for value in observed.values())
        or observed != expected
        or command["Data"] not in (b"", "")
    ):
        raise ReadOnlySMBViolation("SMB1 read packet does not match the pinned READ_ANDX request")


def _build_smb1_read_open(wire_path, flags2):
    request = _impacket_smb.SMBCommand(_impacket_smb.SMB.SMB_COM_NT_CREATE_ANDX)
    request["Parameters"] = _impacket_smb.SMBNtCreateAndX_Parameters()
    request["Data"] = _impacket_smb.SMBNtCreateAndX_Data(flags=flags2)
    request["Parameters"]["FileNameLength"] = len(wire_path)
    request["Parameters"]["CreateFlags"] = 0  # No exclusive/batch oplock, no extended response.
    request["Parameters"]["RootFid"] = 0
    request["Parameters"]["AccessMask"] = (
        _impacket_smb.READ_CONTROL
        | _impacket_smb.FILE_READ_ATTRIBUTES
        | _impacket_smb.FILE_READ_EA
        | FILE_READ_DATA
    )
    request["Parameters"]["AllocationSizeLo"] = 0
    request["Parameters"]["AllocationSizeHi"] = 0
    request["Parameters"]["FileAttributes"] = 0
    request["Parameters"]["ShareAccess"] = NON_BLOCKING_READ_SHARE_ACCESS
    request["Parameters"]["Disposition"] = FILE_OPEN
    request["Parameters"]["CreateOptions"] = FILE_NON_DIRECTORY_FILE
    request["Parameters"]["Impersonation"] = 2
    request["Parameters"]["SecurityFlags"] = 0
    request["Data"]["FileName"] = wire_path
    if flags2 & _impacket_smb.SMB.FLAGS2_UNICODE:
        request["Data"]["Pad"] = 0
    _validate_smb1_read_open(request, wire_path)
    return request


class _ReadOnlySMB2FileTransport:
    """Small capability view used by the SMB2/3 file retrieval routine."""

    __slots__ = ("__connection", "__open_files", "__close_pending", "_transport_state")

    _REQUIRED = ("connectTree", "create", "queryInfo", "read", "close", "disconnectTree", "isSnapshotRequest")

    def __init__(self, connection):
        missing = [name for name in self._REQUIRED if not callable(getattr(connection, name, None))]
        if missing:
            names = ", ".join(sorted(missing))
            raise ReadOnlySMBViolation(f"SMB2 transport lacks guarded low-level read capabilities: {names}")
        self.__connection = connection
        self.__open_files = set()
        self.__close_pending = None
        self._transport_state = transport_state(connection)

    @property
    def failed(self):
        return self._transport_state.failed

    @staticmethod
    def _file_id_token(file_id):
        if isinstance(file_id, (bytes, bytearray, memoryview)):
            value = bytes(file_id)
            if not value:
                raise ReadOnlySMBViolation("SMB2 transport returned an empty file identifier")
            return ("wire", value)
        getter = getattr(file_id, "getData", None)
        if callable(getter):
            try:
                value = bytes(getter())
            except (TypeError, ValueError) as exc:
                raise ReadOnlySMBViolation("SMB2 transport returned an invalid file identifier") from exc
            if not value:
                raise ReadOnlySMBViolation("SMB2 transport returned an empty file identifier")
            return ("wire", value)
        try:
            hash(file_id)
        except TypeError as exc:
            raise ReadOnlySMBViolation("SMB2 transport returned an untrackable file identifier") from exc
        # Test doubles and compatibility transports sometimes use opaque
        # tokens. They may be read/closed only by identity provenance and can
        # never enter the serialized post-query CLOSE path below.
        return ("opaque", type(file_id), file_id)

    def _open_key(self, tree_id, file_id):
        try:
            hash(tree_id)
        except TypeError as exc:
            raise ReadOnlySMBViolation("SMB2 tree identifier is untrackable") from exc
        return tree_id, self._file_id_token(file_id)

    def _require_open(self, tree_id, file_id):
        key = self._open_key(tree_id, file_id)
        if key not in self.__open_files:
            raise ReadOnlySMBViolation("SMB2 operation does not refer to a handle opened by the read-only capability")
        return key

    def isSnapshotRequest(self, path):
        return self.__connection.isSnapshotRequest(path)

    def timestampForSnapshot(self, path):
        method = getattr(self.__connection, "timestampForSnapshot", None)
        if not callable(method):
            raise ReadOnlySMBViolation("SMB2 transport cannot construct a guarded time-warp read")
        return method(path)

    def connectTree(self, share):
        return self._transport_state.call(self.__connection.connectTree, share)

    def create(
        self,
        tree_id,
        file_name,
        desired_access,
        share_mode,
        creation_options,
        creation_disposition,
        file_attributes,
        impersonation_level,
        security_flags,
        oplock_level,
        *,
        createContexts,
    ):
        pinned_contexts = _validate_smb2_read_open(
            desired_access,
            share_mode,
            creation_options,
            creation_disposition,
            file_attributes,
            impersonation_level,
            security_flags,
            oplock_level,
            createContexts,
        )
        file_id = self._transport_state.call(
            self.__connection.create,
            tree_id,
            file_name,
            desiredAccess=desired_access,
            shareMode=share_mode,
            creationOptions=creation_options,
            creationDisposition=creation_disposition,
            fileAttributes=file_attributes,
            impersonationLevel=impersonation_level,
            securityFlags=security_flags,
            oplockLevel=oplock_level,
            createContexts=pinned_contexts,
        )
        key = self._open_key(tree_id, file_id)
        self.__open_files.add(key)
        return file_id

    def queryInfo(self, tree_id, file_id):
        self._require_open(tree_id, file_id)
        return self._transport_state.call(self.__connection.queryInfo, tree_id, file_id)

    @property
    def max_read_size(self):
        try:
            value = self.__connection._Connection["MaxReadSize"]
        except (AttributeError, KeyError, TypeError) as exc:
            raise ReadOnlySMBViolation("SMB2 transport does not expose a bounded maximum read size") from exc
        if type(value) is not int or value <= 0:
            raise ReadOnlySMBViolation("SMB2 transport supplied an invalid maximum read size")
        return value

    def read(self, tree_id, file_id, offset, size):
        self._require_open(tree_id, file_id)
        if type(offset) is not int or type(size) is not int or offset < 0 or size <= 0:
            raise ReadOnlySMBViolation("SMB2 read range is invalid")
        check_worker_cancellation()
        return self._transport_state.call(self.__connection.read, tree_id, file_id, offset, size)

    def close(self, tree_id, file_id):
        key = self._require_open(tree_id, file_id)
        result = self._transport_state.call(self.__connection.close, tree_id, file_id)
        self.__open_files.discard(key)
        return result

    def disconnectTree(self, tree_id):
        return self._transport_state.call(self.__connection.disconnectTree, tree_id)

    def close_with_postquery(self, tree_id, file_id):
        """Send one canonical, non-compound CLOSE for this guarded read handle."""

        key = self._require_open(tree_id, file_id)
        if type(tree_id) is not int or key[1][0] != "wire":
            raise _PostQueryUnavailable("SMB2 transport uses opaque handles; ordinary tracked CLOSE is required")
        if len(key[1][1]) != 16:
            raise ReadOnlySMBViolation("SMB2 post-query CLOSE requires a 16-byte file identifier")
        wire_file_id = key[1][1]
        factory = getattr(self.__connection, "SMB_PACKET", None)
        if not callable(factory):
            raise _PostQueryUnavailable("SMB2 transport does not support post-query CLOSE")
        packet = factory()
        packet["Command"] = SMB2_CLOSE
        packet["TreeID"] = tree_id
        # Parsing the serialized header below materializes CreditCharge=0,
        # preventing Impacket.sendSMB() from applying its usual default of 1.
        # On SMB2.1/3.x an echoed zero then makes recvSMB() rewind SequenceWindow
        # and reuse the CLOSE's MessageID, which Windows rejects by disconnecting.
        # SMB2.0.2 reserves this field as zero and does not use that adjustment.
        get_dialect = getattr(self.__connection, "getDialect", None)
        dialect = get_dialect() if callable(get_dialect) else None
        credit_charge = 0 if dialect == SMB2_DIALECT_002 else 1
        packet["CreditCharge"] = credit_charge
        request = SMB2Close()
        request["Flags"] = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
        request["FileID"] = wire_file_id
        packet["Data"] = request
        try:
            encoded = packet.getData()
            canonical = SMB2Packet(data=encoded)
            canonical_request = SMB2Close(canonical["Data"])
            observed_file_id = canonical_request["FileID"].getData()
        except (AttributeError, KeyError, TypeError, ValueError, struct.error) as exc:
            raise ReadOnlySMBViolation("malformed guarded SMB2 CLOSE packet") from exc
        if (
            len(encoded) != 88
            or canonical["StructureSize"] != 64
            or canonical["Command"] != SMB2_CLOSE
            or canonical["CreditCharge"] != credit_charge
            or canonical["Flags"] != 0
            or canonical["NextCommand"] != 0
            or canonical["TreeID"] != tree_id
            or len(canonical["Data"]) != 24
            or canonical_request["StructureSize"] != 24
            or canonical_request["Flags"] != SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
            or canonical_request["Reserved"] != 0
            or observed_file_id != wire_file_id
        ):
            raise ReadOnlySMBViolation("guarded SMB2 transport may send only one canonical post-query CLOSE")
        method = getattr(self.__connection, "sendSMB", None)
        if not callable(method):
            raise ReadOnlySMBViolation("SMB2 transport cannot send a post-query CLOSE")
        try:
            packet_id = self._transport_state.call(method, canonical)
        except BaseException:
            self.__close_pending = None
            raise
        self.__close_pending = key
        return packet_id

    def recvSMB(self, packet_id):
        if self.__close_pending is None:
            raise ReadOnlySMBViolation("guarded SMB2 transport has no pending CLOSE response")
        method = getattr(self.__connection, "recvSMB", None)
        if not callable(method):
            raise ReadOnlySMBViolation("SMB2 transport cannot receive a post-query CLOSE")
        try:
            return self._transport_state.call(method, packet_id)
        finally:
            self.__close_pending = None

    def forget_closed_file(self, file_id):
        normalized_file_id = self._file_id_token(file_id)
        self.__open_files = {key for key in self.__open_files if key[1] != normalized_file_id}
        try:
            open_record = self.__connection._Session["OpenTable"].pop(file_id, None)
            if open_record is not None:
                self.__connection.GlobalFileTable.pop(open_record["FileName"], None)
        except (AttributeError, KeyError, TypeError):
            # Dependency bookkeeping is best-effort after a successful wire CLOSE.
            return


class _ReadOnlySMB1FileTransport:
    """Small capability view used by the SMB1 file retrieval routine."""

    __slots__ = ("__connection", "_transport_state")

    _REQUIRED = (
        "get_flags",
        "tree_connect_andx",
        "nt_create_andx",
        "query_file_info",
        "read_andx",
        "close",
        "disconnect_tree",
    )

    def __init__(self, connection):
        missing = [name for name in self._REQUIRED if not callable(getattr(connection, name, None))]
        if missing:
            names = ", ".join(sorted(missing))
            raise ReadOnlySMBViolation(f"SMB1 transport lacks guarded low-level read capabilities: {names}")
        self.__connection = connection
        self._transport_state = transport_state(connection)

    @property
    def failed(self):
        return self._transport_state.failed

    def get_flags(self):
        return self.__connection.get_flags()

    def tree_connect_andx(self, service):
        return self._transport_state.call(self.__connection.tree_connect_andx, service)

    def nt_create_andx(self, tree_id, path, *, cmd, wire_path):
        _validate_smb1_read_open(cmd, wire_path)
        normalized_path = str(path).replace("/", "\\")
        expected_wire_path = normalized_path.encode("utf-16-le") if isinstance(wire_path, bytes) else normalized_path
        if expected_wire_path != wire_path:
            raise ReadOnlySMBViolation("SMB1 transport path differs from the validated read-only command")
        return self._transport_state.call(self.__connection.nt_create_andx, tree_id, path, cmd=cmd)

    def query_file_info(self, tree_id, file_id, info_class=None):
        if info_class is None:
            return self._transport_state.call(self.__connection.query_file_info, tree_id, file_id)
        return self._transport_state.call(self.__connection.query_file_info, tree_id, file_id, info_class)

    @property
    def dialect_parameters(self):
        try:
            return self.__connection._dialects_parameters
        except AttributeError as exc:
            raise ReadOnlySMBViolation("SMB1 transport does not expose negotiated read limits") from exc

    @property
    def signature_enabled(self):
        try:
            return bool(self.__connection._SignatureEnabled)
        except AttributeError as exc:
            raise ReadOnlySMBViolation("SMB1 transport does not expose signing state") from exc

    def read_andx(self, tree_id, file_id, *, offset, max_size, smb_packet):
        _validate_smb1_read_packet(smb_packet, tree_id, file_id, offset, max_size)
        check_worker_cancellation()
        return self._transport_state.call(
            self.__connection.read_andx,
            tree_id,
            file_id,
            offset=offset,
            max_size=max_size,
            smb_packet=smb_packet,
        )

    def close(self, tree_id, file_id):
        return self._transport_state.call(self.__connection.close, tree_id, file_id)

    def disconnect_tree(self, tree_id):
        return self._transport_state.call(self.__connection.disconnect_tree, tree_id)


class _ReadOnlySMBConnectionView:
    """Public diagnostic view that cannot expose Impacket mutation methods.

    Historically ``SMBClient.conn`` returned the raw dependency object.  That
    made an accidental future ``client.conn.putFile(...)`` or
    ``getSMBServer().sendSMB(...)`` bypass every MANSPIDER invariant.  Keep the
    useful read-only diagnostics while deliberately omitting login, raw packet,
    CREATE, write, rename, delete, and native-transport access.
    """

    __slots__ = ("__connection",)

    def __init__(self, connection):
        self.__connection = connection

    def getDialect(self):
        return self.__connection.getDialect()

    def getServerName(self):
        return self.__connection.getServerName()

    def getServerDNSDomainName(self):
        return self.__connection.getServerDNSDomainName()

    def isGuestSession(self):
        return self.__connection.isGuestSession()


class _ReadOnlyDFSReferralTransport:
    """Capability limited to one MS-DFSC referral query over ``IPC$``."""

    __slots__ = ("__connection", "_transport_state")

    _FSCTL_DFS_GET_REFERRALS = 0x00060194
    _IOCTL_IS_FSCTL = 0x00000001
    _MAX_RESPONSE = 65536

    def __init__(self, connection):
        required = ("connectTree", "ioctl", "disconnectTree")
        if any(not callable(getattr(connection, name, None)) for name in required):
            raise ReadOnlySMBViolation("SMB transport lacks guarded DFS referral capabilities")
        self.__connection = connection
        self._transport_state = transport_state(connection)

    @staticmethod
    def _validate_request(request):
        if not isinstance(request, bytes) or len(request) < 6 or len(request) > 65536 or len(request) % 2:
            raise ReadOnlySMBViolation("DFS referral request is malformed")
        if request[:2] != b"\x04\x00" or request[-2:] != b"\x00\x00":
            raise ReadOnlySMBViolation("DFS referral request is not a version-4 path query")
        try:
            path = request[2:-2].decode("utf-16-le")
        except UnicodeDecodeError as exc:
            raise ReadOnlySMBViolation("DFS referral request path is not UTF-16LE") from exc
        if not path.startswith("\\") or "\x00" in path:
            raise ReadOnlySMBViolation("DFS referral request path is invalid")

    def request(self, request):
        self._validate_request(request)
        tree_id = self._transport_state.call(self.__connection.connectTree, "IPC$")
        operation_error = None
        try:
            return self._transport_state.call(
                self.__connection.ioctl,
                tree_id,
                None,
                self._FSCTL_DFS_GET_REFERRALS,
                self._IOCTL_IS_FSCTL,
                request,
                0,
                self._MAX_RESPONSE,
            )
        except BaseException as exc:
            operation_error = exc
            raise
        finally:
            if not isinstance(operation_error, ReadOnlySMBViolation) and not self._transport_state.failed:
                try:
                    self._transport_state.call(self.__connection.disconnectTree, tree_id)
                except ReadOnlySMBViolation:
                    raise
                except BaseException as exc:
                    # Preserve an existing cancellation, but never suppress a
                    # new Ctrl+C/SystemExit behind an ordinary referral error.
                    if operation_error is None or (
                        isinstance(operation_error, Exception) and not isinstance(exc, Exception)
                    ):
                        exc.smb_cleanup_failed = True
                        raise
                    operation_error.smb_cleanup_failed = True


def _split_ntlm_hash(value):
    """Normalize either an NT hash or an Impacket-style LM:NT pair."""

    supplied = str(value or "")
    if not supplied:
        return "", ""
    if ":" in supplied:
        lmhash, nthash = supplied.split(":", 1)
        return lmhash or DEFAULT_LM_HASH, nthash
    return DEFAULT_LM_HASH, supplied


@dataclass(frozen=True)
class _DFSReferral:
    namespace_prefix: str
    network_address: str
    ttl: int


@dataclass
class _DFSRoute:
    namespace_share: str
    namespace_prefix: str
    target_share: str
    target_prefix: str
    expires_at: float
    target_server: str | None = None
    target_port: int = 445
    target_client: object | None = None
    pin_context: object | None = None


@dataclass
class _SMBTransportGroup:
    """Clients in one worker which may own only one live transport at a time."""

    active_client: object | None = None
    safety_error: ReadOnlySMBViolation | None = None
    recovery: dict = field(default_factory=dict)


class SMBClient:
    """
    Wrapper around impacket's SMBConnection() object
    """

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
        transport_group=None,
        dfs_auth_failure_callback=None,
        session_slot_directory=None,
        max_sessions_per_host=None,
        allow_external_dfs=False,
    ):

        self.server = server
        self.port = port

        self.__connection = None

        self.username = username
        self.password = password
        self.domain = domain
        supplied_hash = str(nthash or "")
        self.lmhash, self.nthash = _split_ntlm_hash(supplied_hash)
        self.use_kerberos = use_kerberos
        self.aes_key = aes_key
        self.dc_ip = dc_ip
        # Keep the explicitly selected identity separate from the mutable
        # effective identity. login() intentionally mutates the latter after a
        # Guest/null fallback, while a new DFS target must start with the
        # identity selected for this worker.
        self._supplied_credentials = (
            username,
            password,
            domain,
            supplied_hash,
            use_kerberos,
            aes_key,
            dc_ip,
        )
        self.dfs_auth_failure_callback = dfs_auth_failure_callback
        self.allow_external_dfs = bool(allow_external_dfs)
        if session_slot_directory is None:
            self.session_slot_directory = None
        else:
            self.session_slot_directory = require_local_write_path(
                session_slot_directory,
                purpose="per-host SMB session locks",
            )
        self.max_sessions_per_host = max(1, int(max_sessions_per_host)) if max_sessions_per_host is not None else None
        self._host_session_slot = None
        self.hostname = None
        self.dns_domain = None
        self._shares = None
        self._share_types = {}
        self.share_listing_error = None
        self._connection_generation = 0
        self._share_pin_depths = {}
        self._share_pin_names = {}
        self._pinned_share_trees = {}
        self._dfs_routes = {}
        self._dfs_clients = {}
        self._transport_group = transport_group or _SMBTransportGroup()
        recovery_key = (self._normalize_server_name(server), port)
        self._network_recovery = self._transport_group.recovery.setdefault(
            recovery_key, NetworkRecovery(f"{server}:{port}"),
        )
        self.last_connection_error = None
        self._metrics = None
        self._metrics_session_open = False

    def _raise_if_unsafe(self):
        if self._transport_group.safety_error is not None:
            raise self._transport_group.safety_error

    def _abort_read_only(self, error, detached_connection=None):
        """Poison this worker's transport group and close TCP without SMB cleanup.

        A rejected protocol operation must not fall back to another request,
        reconnect, or DFS endpoint. Do not ask a suspect encoder for LOGOFF,
        CLOSE or TREE_DISCONNECT; simply release the existing socket.
        """

        self._transport_group.safety_error = error
        connection, self.__connection = self.__connection, None
        self._connection_generation += 1
        self._pinned_share_trees.clear()
        self._metric_session_stopped()
        if connection is not None:
            with suppress(Exception):
                transport_state(connection).fail(error)
        if detached_connection is not None and detached_connection is not connection:
            with suppress(Exception):
                transport_state(detached_connection).fail(error)
        if self._transport_group.active_client is self:
            self._transport_group.active_client = None
        self._release_host_session_slot()

    @staticmethod
    def _transport_failed(error):
        """Transport failures only; authorization refusals are not reconnects."""

        return is_transport_error(error)

    def _retire_failed_transport(self, error, connection=None):
        """Retire a broken connection; reconnection belongs to the next attempt."""

        if isinstance(error, ReadOnlySMBViolation):
            self._abort_read_only(error)
            raise error
        connection = self.__connection if connection is None else connection
        if connection is None or connection is not self.__connection:
            return
        # I/O capabilities mark their own captured connection before cleanup.
        # Do not classify the outer exception here: it can originate in the
        # local file callback, or belong to an already replaced connection.
        state = transport_state(connection)
        if state.failed or getattr(error, "smb_cleanup_failed", False):
            if is_network_unavailable(state.error):
                self._network_recovery.failed()
            self._suspend_transport()

    @property
    def conn(self):
        """Expose only non-mutating diagnostics, never the raw SMB transport."""

        if self.__connection is None:
            return None
        return _ReadOnlySMBConnectionView(self.__connection)

    def enable_metrics(self, sink, *, flush_interval_seconds=5.0):
        """Observe existing SMB calls without adding requests or changing flow."""

        self._metrics = SMBMetricsEmitter(
            self.server,
            self.port,
            sink,
            flush_interval_seconds=flush_interval_seconds,
        )

    def flush_metrics(self):
        if self._metrics is not None:
            with suppress(Exception):
                self._metrics.flush(force=True)

    def _metric_started(self):
        if self._metrics is None:
            return None
        return monotonic_ns()

    def _metric_operation(self, operation, started_ns, *, error=None, bytes_transferred=0, items=0):
        if self._metrics is None or started_ns is None:
            return
        with suppress(Exception):
            self._metrics.record_operation(
                operation,
                started_ns,
                error=error,
                bytes_transferred=bytes_transferred,
                items=items,
            )

    def _metric_session_started(self):
        if self._metrics is None or self._metrics_session_open:
            return
        self._metrics_session_open = True
        with suppress(Exception):
            self._metrics.record_session_opened()

    def _metric_session_stopped(self):
        if self._metrics is None or not self._metrics_session_open:
            return
        self._metrics_session_open = False
        with suppress(Exception):
            self._metrics.record_session_closed()

    @staticmethod
    def _share_key(share):
        return str(share).casefold()

    @staticmethod
    def _supports_tree_pinning(connection):
        """Return whether Impacket reference-counts trees for this dialect."""

        try:
            return connection.getDialect() != SMB_DIALECT
        except (AttributeError, TypeError):
            # Unknown wrappers are kept on the established high-level path. A
            # speculative pin is unsafe because SMB1 does not reference-count
            # the tree opened internally by listPath/getFile.
            return False

    def _claim_transport(self):
        """Make this client the sole live transport in its DFS worker group."""

        active = self._transport_group.active_client
        if active is not None and active is not self:
            active._suspend_transport()
        self._acquire_host_session_slot()
        self._transport_group.active_client = self

    @staticmethod
    def _try_lock_slot(file_descriptor):
        if fcntl is not None:
            try:
                fcntl.flock(file_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except BlockingIOError:
                return False
        if msvcrt is None:  # pragma: no cover - only possible on an unknown platform
            raise RuntimeError("no supported file-locking implementation is available")
        if os.fstat(file_descriptor).st_size == 0:
            os.write(file_descriptor, b"\x00")
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        try:  # pragma: no cover - exercised on Windows
            msvcrt.locking(file_descriptor, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    @staticmethod
    def _unlock_slot(file_descriptor):
        if fcntl is not None:
            fcntl.flock(file_descriptor, fcntl.LOCK_UN)
            return
        if msvcrt is not None:  # pragma: no cover - exercised on Windows
            os.lseek(file_descriptor, 0, os.SEEK_SET)
            msvcrt.locking(file_descriptor, msvcrt.LK_UNLCK, 1)

    def _acquire_host_session_slot(self):
        if (
            self._host_session_slot is not None
            or self.session_slot_directory is None
            or self.max_sessions_per_host is None
        ):
            return
        endpoint = self._normalize_server_name(self.server)
        endpoint_key = hashlib.sha256(endpoint.encode("utf-8", errors="surrogatepass")).hexdigest()
        slot_directory = self.session_slot_directory / endpoint_key
        slot_directory = require_local_write_path(
            slot_directory,
            purpose="per-host SMB session lock directory",
        )
        with local_directory_descriptor(
            slot_directory,
            purpose="per-host SMB session lock directory",
            create=True,
        ) as (directory_descriptor, slot_directory):
            waiting_logged = False
            while self._host_session_slot is None:
                for index in range(self.max_sessions_per_host):
                    slot_name = f"{index}.lock"
                    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
                    file_descriptor = os.open(slot_name, flags, 0o600, dir_fd=directory_descriptor)
                    try:
                        info = os.fstat(file_descriptor)
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            raise OSError("per-host SMB session lock must be a private regular file")
                        require_local_file_descriptor(file_descriptor, purpose="per-host SMB session lock")
                        acquired = self._try_lock_slot(file_descriptor)
                    except BaseException:
                        os.close(file_descriptor)
                        raise
                    if acquired:
                        self._host_session_slot = (file_descriptor, slot_directory / slot_name)
                        return
                    os.close(file_descriptor)
                if not waiting_logged:
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug(
                            f"{display_text(self.server)}: Waiting for one of {display_text(self.max_sessions_per_host)} per-host SMB session slots"
                        )
                    waiting_logged = True
                sleep(0.01)

    def _release_host_session_slot(self):
        slot = self._host_session_slot
        self._host_session_slot = None
        if slot is None:
            return
        file_descriptor, _slot_path = slot
        try:
            self._unlock_slot(file_descriptor)
        finally:
            os.close(file_descriptor)

    def _suspend_transport(self):
        """Close only the transport while retaining cache and pin intent."""

        if self._transport_group.safety_error is not None:
            self._abort_read_only(self._transport_group.safety_error)
            return
        connection = self.__connection
        try:
            if connection is not None:
                self._metric_session_stopped()
                try:
                    for key in list(self._pinned_share_trees):
                        self._release_share_tree(key)
                finally:
                    if self.__connection is connection:
                        self.__connection = None
                        self._connection_generation += 1
                        self._pinned_share_trees.clear()
                    try:
                        state = transport_state(connection)
                        if state.failed:
                            state.fail(state.error)
                        else:
                            state.call(connection.close)
                    except ReadOnlySMBViolation as exc:
                        self._abort_read_only(exc, connection)
                        raise
                    except Exception:
                        pass
        finally:
            # A control exception during tree/socket cleanup must not retain
            # a host slot or a detached active-client marker. If an old call
            # installed a replacement, that new connection still owns them.
            if self.__connection is None:
                if self._transport_group.active_client is self:
                    self._transport_group.active_client = None
                self._release_host_session_slot()

    def _ensure_active_transport(self):
        """Reconnect this endpoint after another DFS endpoint used the slot."""

        self._raise_if_unsafe()
        check_worker_cancellation()
        if (
            self._transport_group.active_client is self
            and self.__connection is not None
            and not transport_state(self.__connection).failed
        ):
            return
        if self.__connection is not None and transport_state(self.__connection).failed:
            self._retire_failed_transport(transport_state(self.__connection).error, self.__connection)
        result = self.login(first_try=False)
        if result is not True:
            error = RuntimeError(f"unable to restore authenticated SMB transport to {self.server}:{self.port}")
            if is_network_unavailable(self.last_connection_error):
                mark_network_unavailable(error)
            raise error from self.last_connection_error

    def _install_connection(self, connection):
        """Make a newly constructed connection current and invalidate old pins."""

        self._raise_if_unsafe()
        self._claim_transport()
        previous = self.__connection
        self.__connection = connection
        self._connection_generation += 1
        self._pinned_share_trees.clear()
        if previous is not None and previous is not connection:
            try:
                state = transport_state(previous)
                if state.failed:
                    state.fail(state.error)
                else:
                    state.call(previous.close)
            except ReadOnlySMBViolation as exc:
                self._abort_read_only(exc, previous)
                raise
            except Exception:
                pass

    def _ensure_share_tree(self, share):
        """Pin an active SMB2/3 share on the current connection generation."""

        self._raise_if_unsafe()
        key = self._share_key(share)
        if self._share_pin_depths.get(key, 0) <= 0 or self.__connection is None:
            return
        if not self._supports_tree_pinning(self.__connection):
            return
        current = self._pinned_share_trees.get(key)
        if current is not None:
            generation, connection, _tree_id = current
            if generation == self._connection_generation and connection is self.__connection:
                return
        connection = self.__connection
        generation = self._connection_generation
        tree_id = transport_state(connection).call(connection.connectTree, self._share_pin_names[key])
        if connection is self.__connection and generation == self._connection_generation:
            self._pinned_share_trees[key] = (generation, connection, tree_id)

    def _release_share_tree(self, key):
        pinned = self._pinned_share_trees.pop(key, None)
        if pinned is None:
            return
        generation, connection, tree_id = pinned
        if self._transport_group.safety_error is not None:
            return
        if generation != self._connection_generation or connection is not self.__connection:
            return
        state = transport_state(connection)
        if state.failed:
            return
        try:
            state.call(connection.disconnectTree, tree_id)
        except ReadOnlySMBViolation as exc:
            self._abort_read_only(exc)
            raise
        except Exception as exc:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.server)}: Unable to disconnect pinned SMB tree {display_text(self._share_pin_names[key])}: {display_text(exc)}")

    @contextmanager
    def pin_share(self, share):
        """Keep one SMB2/3 tree reference for all operations on a share.

        Impacket's SMB2/3 high-level operations connect and disconnect around
        every call. Its internal tree cache is reference-counted, so retaining
        one outer reference avoids those network round trips. SMB1 safely keeps
        its existing behavior because its tree operations are not reference-counted.
        """

        key = self._share_key(share)
        self._share_pin_depths[key] = self._share_pin_depths.get(key, 0) + 1
        self._share_pin_names.setdefault(key, str(share))
        connection = self.__connection
        try:
            try:
                self._ensure_share_tree(share)
            except Exception as error:
                if not self._try_null_after_guest_denial(error):
                    raise
                self._ensure_share_tree(share)
        except BaseException as error:
            self._share_pin_depths[key] -= 1
            if self._share_pin_depths[key] == 0:
                self._share_pin_depths.pop(key, None)
                self._share_pin_names.pop(key, None)
            self._retire_failed_transport(error, connection)
            raise
        try:
            yield
        except ReadOnlySMBViolation as exc:
            # A guard may originate in the listing consumer/parser while it
            # owns this pin, before any public SMBClient wrapper sees it.
            self._abort_read_only(exc)
            raise
        finally:
            self._share_pin_depths[key] -= 1
            if self._share_pin_depths[key] == 0:
                self._release_share_tree(key)
                self._share_pin_depths.pop(key, None)
                self._share_pin_names.pop(key, None)

    @staticmethod
    def _normalize_relative_path(path):
        value = str(path).replace("/", "\\").strip("\\")
        if not value:
            return ""
        normalized = ntpath.normpath(value)
        return "" if normalized == "." else normalized

    @staticmethod
    def _has_status(error, status):
        for accessor in ("getErrorCode", "get_error_code"):
            getter = getattr(error, accessor, None)
            if getter is not None:
                with suppress(Exception):
                    return getter() == status
        return False

    @classmethod
    def _is_path_not_covered(cls, error):
        return cls._has_status(error, STATUS_PATH_NOT_COVERED)

    def _try_null_after_guest_denial(self, error):
        """Finish the promised Guest/null fallback when Guest cannot access data."""

        if isinstance(error, ReadOnlySMBViolation):
            self._abort_read_only(error)
            raise error
        self._raise_if_unsafe()
        if self.username != "Guest" or not self._has_status(error, STATUS_ACCESS_DENIED):
            return False
        if log.isEnabledFor(logging.DEBUG):
            log.debug(f"{display_text(self.server)}: Guest session cannot access the resource; switching to null session")
        self.username = ""
        self.password = ""
        self.domain = ""
        self.lmhash = ""
        self.nthash = ""
        self.use_kerberos = False
        return self.login(refresh=True, first_try=False) is True

    @staticmethod
    def _decode_dfs_string(payload, offset, limit=None):
        limit = len(payload) if limit is None else min(limit, len(payload))
        if offset < 0 or offset >= limit or offset % 2:
            raise ValueError(f"invalid DFS string offset {offset}")
        end = offset
        while end + 1 < limit and payload[end : end + 2] != b"\x00\x00":
            end += 2
        if end + 1 >= limit:
            raise ValueError("unterminated DFS referral string")
        return payload[offset:end].decode("utf-16-le")

    @classmethod
    def _parse_dfs_referrals(cls, payload, request_path):
        """Parse storage targets from an MS-DFSC referral response."""

        if isinstance(payload, str):
            payload = payload.encode("latin-1")
        if not isinstance(payload, bytes) or len(payload) < 8:
            raise ValueError("truncated DFS referral response header")
        path_consumed, referral_count, _header_flags = struct.unpack_from("<HHI", payload)
        encoded_request = request_path.encode("utf-16-le")
        if path_consumed > len(encoded_request) or path_consumed % 2:
            raise ValueError("invalid DFS PathConsumed value")
        consumed_path = encoded_request[:path_consumed].decode("utf-16-le")
        unconsumed_path = encoded_request[path_consumed:].decode("utf-16-le")
        if unconsumed_path and not unconsumed_path.startswith("\\"):
            raise ValueError("DFS PathConsumed ended inside a path component")
        consumed_parts = [part for part in consumed_path.replace("/", "\\").split("\\") if part]
        if len(consumed_parts) < 2:
            raise ValueError("DFS response did not consume a server and share")
        namespace_prefix = "\\".join(consumed_parts[2:])

        raw_referrals = []
        relative_string_offsets = []
        entry_offset = 8
        response_version = None
        for _index in range(referral_count):
            if entry_offset + 8 > len(payload):
                raise ValueError("truncated DFS referral entry")
            version, entry_size, _server_type, entry_flags = struct.unpack_from("<HHHH", payload, entry_offset)
            if response_version is None:
                response_version = version
            elif response_version != version:
                raise ValueError("mixed DFS referral versions")
            if entry_size % 2:
                raise ValueError("invalid odd DFS referral entry size")
            if version == 1:
                minimum_size = 10
                ttl = 0
                network_offset = 8
                string_within_entry = True
            elif version == 2:
                minimum_size = 22
                if entry_offset + minimum_size > len(payload):
                    raise ValueError("truncated DFS v2 referral entry")
                ttl = struct.unpack_from("<I", payload, entry_offset + 12)[0]
                string_offsets = struct.unpack_from("<HHH", payload, entry_offset + 16)
                network_offset = string_offsets[2]
                relative_string_offsets.extend((entry_offset, offset) for offset in string_offsets if offset)
                string_within_entry = False
            elif version in (3, 4):
                name_list_referral = bool(entry_flags & 0x0002)
                minimum_size = 18 if name_list_referral else 34
                if entry_offset + minimum_size > len(payload):
                    raise ValueError(f"truncated DFS v{version} referral entry")
                ttl = struct.unpack_from("<I", payload, entry_offset + 8)[0]
                if name_list_referral:
                    network_offset = None
                else:
                    string_offsets = struct.unpack_from("<HHH", payload, entry_offset + 12)
                    network_offset = string_offsets[2]
                    relative_string_offsets.extend((entry_offset, offset) for offset in string_offsets if offset)
                string_within_entry = False
            else:
                raise ValueError(f"unsupported DFS referral version {version}")
            if entry_size < minimum_size or entry_offset + entry_size > len(payload):
                raise ValueError("invalid DFS referral entry size")
            # Name-list referrals describe domains/DCs, not storage targets.
            if network_offset is not None:
                raw_referrals.append((entry_offset, entry_size, network_offset, int(ttl), string_within_entry))
            entry_offset += entry_size

        absolute_string_offsets = sorted(
            {referral_offset + relative_offset for referral_offset, relative_offset in relative_string_offsets}
        )
        for absolute_offset in absolute_string_offsets:
            if absolute_offset < entry_offset:
                raise ValueError("DFS referral string overlaps the entry table")
            if absolute_offset >= len(payload) or absolute_offset % 2:
                raise ValueError(f"invalid DFS string offset {absolute_offset}")

        referrals = []
        for referral_offset, entry_size, network_offset, ttl, string_within_entry in raw_referrals:
            absolute_offset = referral_offset + network_offset
            if string_within_entry:
                string_limit = referral_offset + entry_size
            else:
                if absolute_offset < entry_offset:
                    raise ValueError("DFS referral string overlaps the entry table")
                string_limit = next(
                    (offset for offset in absolute_string_offsets if offset > absolute_offset),
                    len(payload),
                )
            network_address = cls._decode_dfs_string(payload, absolute_offset, string_limit)
            referrals.append(
                _DFSReferral(
                    namespace_prefix=namespace_prefix,
                    network_address=network_address,
                    ttl=ttl,
                )
            )
        if not referrals:
            raise ValueError("DFS response contained no storage targets")
        return tuple(referrals)

    def _request_dfs_referrals(self, share, path):
        metric_started = self._metric_started()
        owner_connection = None
        try:
            self._ensure_active_transport()
            owner_connection = self.__connection
            if not self._supports_tree_pinning(self.__connection):
                raise RuntimeError("SMB1 DFS referrals are not supported by the current Impacket transport")
            try:
                connection = self.__connection.getSMBServer()
            except (AttributeError, TypeError) as exc:
                raise RuntimeError("SMB transport does not expose DFS referral IOCTLs") from exc
            transport = _ReadOnlyDFSReferralTransport(connection)

            relative = self._normalize_relative_path(path)
            request_path = "\\" + "\\".join(
                component
                for component in (str(self.server).strip("\\"), str(share).strip("\\"), relative)
                if component
            )
            request = struct.pack("<H", 4) + request_path.encode("utf-16-le") + b"\x00\x00"
            response = transport.request(request)
            result = self._parse_dfs_referrals(response, request_path)
        except BaseException as exc:
            self._metric_operation("dfs_referral", metric_started, error=exc)
            self._retire_failed_transport(exc, owner_connection)
            raise
        self._metric_operation("dfs_referral", metric_started, items=len(result))
        return result

    @staticmethod
    def _normalize_server_name(server):
        return str(server).strip().strip("\\").strip("[]").rstrip(".").casefold()

    def _server_aliases(self):
        self._raise_if_unsafe()
        aliases = {self._normalize_server_name(self.server)}
        try:
            aliases.add(self._normalize_server_name(self.__connection.getServerName()))
        except ReadOnlySMBViolation as exc:
            self._abort_read_only(exc)
            raise
        except Exception:
            pass
        try:
            server_name = self._normalize_server_name(self.__connection.getServerName())
            dns_domain = self._normalize_server_name(self.__connection.getServerDNSDomainName())
            if server_name and dns_domain:
                aliases.add(f"{server_name}.{dns_domain}")
        except ReadOnlySMBViolation as exc:
            self._abort_read_only(exc)
            raise
        except Exception:
            pass
        try:
            connection = self.__connection.getSMBServer()
            aliases.add(self._normalize_server_name(connection._Connection["ServerName"]))
        except ReadOnlySMBViolation as exc:
            self._abort_read_only(exc)
            raise
        except Exception:
            pass
        if self.hostname:
            aliases.add(self._normalize_server_name(self.hostname))
            if self.dns_domain:
                aliases.add(self._normalize_server_name(f"{self.hostname}.{self.dns_domain}"))
        aliases.discard("")
        return aliases

    def _dfs_route_candidates(self, share, path):
        referrals = self._request_dfs_referrals(share, path)
        aliases = self._server_aliases()
        routes = []
        skipped_external = False
        for referral in referrals:
            normalized_address = referral.network_address.replace("/", "\\")
            if not normalized_address.startswith("\\"):
                continue
            target_parts = [part for part in normalized_address.split("\\") if part]
            if len(target_parts) < 2:
                continue
            target_server, target_share, *target_path = target_parts
            if any(part in (".", "..") for part in (target_server, target_share, *target_path)):
                continue
            same_server = self._normalize_server_name(target_server) in aliases
            if not same_server and not self.allow_external_dfs:
                skipped_external = True
                source_path = f"\\\\{self.server}\\{share}"
                relative_path = self._normalize_relative_path(path)
                if relative_path:
                    source_path += f"\\{relative_path}"
                target_unc = "\\\\" + "\\".join(target_parts)
                log.warning(
                    f"Cross-server DFS referral SKIPPED: {display_text(source_path)} -> {display_text(target_unc)}. "
                    "No connection or authentication was attempted for this referral; "
                    "use --allow-external-dfs only when that server is authorized for scanning."
                )
                continue
            routes.append(
                _DFSRoute(
                    namespace_share=str(share),
                    namespace_prefix=self._normalize_relative_path(referral.namespace_prefix),
                    target_share=target_share,
                    target_prefix=self._normalize_relative_path("\\".join(target_path)),
                    expires_at=monotonic() + max(0, referral.ttl),
                    target_server=target_server,
                    target_port=self.port if same_server else 445,
                    target_client=self if same_server else None,
                )
            )
        if routes:
            return routes
        if skipped_external:
            raise DFSReferralBlocked("Cross-server DFS referrals were skipped (requires --allow-external-dfs)")
        raise RuntimeError("DFS response contained no usable storage target")

    @staticmethod
    def _translate_dfs_path(route, path):
        normalized = SMBClient._normalize_relative_path(path)
        prefix = SMBClient._normalize_relative_path(route.namespace_prefix)
        path_parts = [part for part in normalized.split("\\") if part]
        prefix_parts = [part for part in prefix.split("\\") if part]
        if [part.casefold() for part in path_parts[: len(prefix_parts)]] != [part.casefold() for part in prefix_parts]:
            raise RuntimeError(f"DFS route prefix {prefix!r} does not cover {normalized!r}")
        suffix_parts = path_parts[len(prefix_parts) :]
        target_parts = [part for part in SMBClient._normalize_relative_path(route.target_prefix).split("\\") if part]
        return "\\".join((*target_parts, *suffix_parts))

    def _create_dfs_client(self, server, port):
        """Authenticate one external DFS endpoint in the worker's transport slot."""

        # Defense in depth: no caller may bypass the referral policy and send
        # credentials to another endpoint merely by constructing a DFS client.
        if not self.allow_external_dfs:
            raise DFSReferralBlocked("Cross-server DFS connections require --allow-external-dfs")
        username, password, domain, nthash, use_kerberos, aes_key, dc_ip = self._supplied_credentials
        supplied_identity = username not in (None, "", "Guest")
        client = SMBClient(
            server,
            username,
            password,
            domain,
            nthash,
            use_kerberos,
            aes_key,
            dc_ip,
            port=port,
            transport_group=self._transport_group,
            dfs_auth_failure_callback=self.dfs_auth_failure_callback,
            session_slot_directory=self.session_slot_directory,
            max_sessions_per_host=self.max_sessions_per_host,
            allow_external_dfs=self.allow_external_dfs,
        )
        if self._metrics is not None:
            client.enable_metrics(self._metrics.sink)
        result = client.login()
        if result is None:
            client.close()
            error = RuntimeError(f"unable to establish SMB transport to DFS target {server}:{port}")
            if is_network_unavailable(client.last_connection_error):
                mark_network_unavailable(error)
            raise error from client.last_connection_error
        if result is False and supplied_identity and self.dfs_auth_failure_callback is not None:
            with suppress(Exception):
                self.dfs_auth_failure_callback(server)
        return client

    def _route_client(self, route):
        if route.target_client is self or route.target_server is None:
            route.target_client = self
            return self
        if not self.allow_external_dfs:
            raise DFSReferralBlocked("Cross-server DFS connections require --allow-external-dfs")
        key = (self._normalize_server_name(route.target_server), route.target_port)
        client = self._dfs_clients.get(key)
        if client is None:
            client = self._create_dfs_client(route.target_server, route.target_port)
            self._dfs_clients[key] = client
        else:
            client._ensure_active_transport()
        route.target_client = client
        return client

    def _release_dfs_route(self, route):
        if route.pin_context is not None:
            context = route.pin_context
            route.pin_context = None
            if self._transport_group.safety_error is not None:
                return
            try:
                context.__exit__(None, None, None)
            except ReadOnlySMBViolation as exc:
                self._abort_read_only(exc)
                raise
            except Exception:
                pass

    def _discard_dfs_route(self, key, route):
        if self._dfs_routes.get(key) is route:
            self._dfs_routes.pop(key, None)
        self._release_dfs_route(route)

    def _cache_dfs_route(self, route):
        key = (
            self._share_key(route.namespace_share),
            self._normalize_relative_path(route.namespace_prefix).casefold(),
        )
        previous = self._dfs_routes.get(key)
        if previous is not None and previous is not route:
            self._release_dfs_route(previous)
        target_client = self._route_client(route)
        if route.pin_context is None:
            route.pin_context = target_client.pin_share(route.target_share)
            route.pin_context.__enter__()
        self._dfs_routes[key] = route
        target_path = f"\\{route.target_prefix}" if route.target_prefix else ""
        if target_client is self:
            destination = f"{route.target_share}{target_path} on the existing SMB session"
        else:
            destination = (
                f"\\\\{route.target_server}\\{route.target_share}{target_path} with exclusive transport switching"
            )
        log.info(f"{display_text(self.server)}: DFS referral {display_text(route.namespace_share)}\\{display_text(route.namespace_prefix)} -> {display_text(destination)}")
        return key

    def _find_dfs_route(self, share, path):
        normalized = self._normalize_relative_path(path)
        folded_path = normalized.casefold()
        candidates = []
        for key, route in list(self._dfs_routes.items()):
            if route.expires_at <= monotonic():
                self._discard_dfs_route(key, route)
                continue
            prefix = self._normalize_relative_path(route.namespace_prefix)
            folded_prefix = prefix.casefold()
            if key[0] == self._share_key(share) and (
                not folded_prefix or folded_path == folded_prefix or folded_path.startswith(f"{folded_prefix}\\")
            ):
                candidates.append((len(prefix), route))
        return max(candidates, default=(0, None))[1]

    def _retrieve_file_direct(self, share, filename, callback):
        metric_started = self._metric_started()
        transferred = 0
        owner_connection = None

        def measured_callback(data):
            nonlocal transferred
            # An empty successful read cannot make progress toward the size
            # already reported for this open handle.
            if not data:
                raise FileChangedDuringRead("SMB returned zero bytes before completing the requested file")
            transferred += len(data)
            callback(data)

        try:
            self._ensure_active_transport()
            owner_connection = self.__connection
            self._ensure_share_tree(share)
            try:
                connection = self.__connection.getSMBServer()
            except (AttributeError, TypeError) as exc:
                raise ReadOnlySMBViolation("SMB connection does not expose a guarded low-level file transport") from exc
            if not self._supports_tree_pinning(self.__connection):
                result = self._retrieve_smb1_file(connection, share, filename, measured_callback)
            else:
                result = self._retrieve_smb2_file(connection, share, filename, measured_callback)
        except BaseException as exc:
            self._metric_operation(
                "file_read",
                metric_started,
                error=exc,
                bytes_transferred=transferred,
            )
            self._retire_failed_transport(exc, owner_connection)
            if self._is_end_of_file(exc):
                raise FileChangedDuringRead("SMB file reached EOF before completing the requested read") from exc
            raise
        self._metric_operation("file_read", metric_started, bytes_transferred=transferred)
        self._network_recovery.succeeded()
        return result

    def _retrieve_file_routed(self, share, filename, callback, visited, delivered):
        marker = (
            self._normalize_server_name(self.server),
            self.port,
            self._share_key(share),
            self._normalize_relative_path(filename).casefold(),
        )
        route = self._find_dfs_route(share, filename)
        if route is not None:
            if marker in visited:
                raise RuntimeError(f"DFS referral loop while retrieving {share}\\{filename}")
            target_client = self._route_client(route)
            return target_client._retrieve_file_routed(
                route.target_share,
                self._translate_dfs_path(route, filename),
                callback,
                visited | {marker},
                delivered,
            )

        try:
            return self._retrieve_file_direct(share, filename, callback)
        except (ReadOnlySMBViolation, DFSReferralBlocked):
            raise
        except Exception as error:
            if not delivered[0] and self._try_null_after_guest_denial(error):
                try:
                    return self._retrieve_file_direct(share, filename, callback)
                except (ReadOnlySMBViolation, DFSReferralBlocked):
                    raise
                except Exception as retry_error:
                    error = retry_error
            if delivered[0] or not self._is_path_not_covered(error):
                raise error
            failures = []
            for candidate in self._dfs_route_candidates(share, filename):
                key = None
                try:
                    key = self._cache_dfs_route(candidate)
                    if marker in visited:
                        raise RuntimeError(f"DFS referral loop while retrieving {share}\\{filename}")
                    target_client = self._route_client(candidate)
                    return target_client._retrieve_file_routed(
                        candidate.target_share,
                        self._translate_dfs_path(candidate, filename),
                        callback,
                        visited | {marker},
                        delivered,
                    )
                except ReadOnlySMBViolation:
                    raise
                except Exception as candidate_error:
                    if delivered[0]:
                        raise
                    failures.append(candidate_error)
                    if key is not None:
                        self._discard_dfs_route(key, candidate)
                    else:
                        self._release_dfs_route(candidate)
            if failures and all(isinstance(failure, DFSReferralBlocked) for failure in failures):
                # A nested namespace may be blocked while another authorized
                # replica is usable. Try every candidate before reporting a
                # policy-only skip; an ordinary replica failure stays an error.
                raise failures[0]
            details = "; ".join(f"{type(failure).__name__}: {failure}" for failure in failures)
            failure = RuntimeError(f"all DFS referral targets failed for {share}\\{filename}: {details}")
            if any(is_network_unavailable(item) for item in failures):
                mark_network_unavailable(failure)
            raise failure from error

    def retrieve_file(self, share, filename, callback):
        """Retrieve one file and obtain post-read identity without another listing."""

        self._raise_if_unsafe()
        delivered = [False]

        def tracked_callback(data):
            delivered[0] = True
            callback(data)

        try:
            return self._retrieve_file_routed(share, filename, tracked_callback, set(), delivered)
        except ReadOnlySMBViolation as exc:
            self._abort_read_only(exc)
            raise

    @staticmethod
    def _smb_time_epoch(value):
        """Match Impacket SharedFile's FILETIME-to-Unix conversion exactly."""

        high = value >> 32
        low = value & 0xFFFFFFFF
        return (high * 4.0 * (1 << 30) + (low & 0xFFF00000)) * 1.0e-7 - 11644473600.0

    def _close_smb2_file_with_identity(self, connection, tree_id, file_id):
        """Close an SMB2/3 handle and request attributes in the same response."""

        if not isinstance(connection, _ReadOnlySMB2FileTransport):
            raise ReadOnlySMBViolation("post-query CLOSE requires the guarded SMB2 file capability")
        packet_id = connection.close_with_postquery(tree_id, file_id)
        answer = connection.recvSMB(packet_id)
        if not answer.isValidAnswer(STATUS_SUCCESS):
            raise RuntimeError("SMB2 CLOSE did not return STATUS_SUCCESS")

        connection.forget_closed_file(file_id)
        try:
            response = SMB2Close_Response(answer["Data"])
            # Some conforming servers (including Impacket's fixture server)
            # populate the requested fields while leaving the response Flags
            # member at zero. A zero ChangeTime unambiguously means that no
            # usable post-query attributes were returned.
            if int(response["ChangeTime"]) == 0:
                return None
            return (
                int(response["EndofFile"]),
                self._smb_time_epoch(int(response["ChangeTime"])),
                None,
            )
        except ReadOnlySMBViolation:
            raise
        except Exception as exc:
            # The handle is already closed successfully. Missing or malformed
            # post-query fields only disable the optimization for this file.
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.server)}: SMB CLOSE omitted usable post-read attributes: {display_text(exc)}")
            return None

    def _retrieve_smb2_file(self, connection, share, filename, callback):
        """Mirror Impacket retrieval while replacing CLOSE with post-query CLOSE."""

        if not isinstance(connection, _ReadOnlySMB2FileTransport):
            connection = _ReadOnlySMB2FileTransport(connection)
        create_contexts = None
        path = filename
        if connection.isSnapshotRequest(path):
            create_contexts = []
            path, context = connection.timestampForSnapshot(path)
            create_contexts.append(context)
        path = ntpath.normpath(path.replace("/", "\\"))
        if path.startswith("\\"):
            path = path[1:]

        tree_id = connection.connectTree(share)
        file_id = None
        post_read_identity = None
        operation_error = None
        try:
            file_id = connection.create(
                tree_id,
                path,
                FILE_READ_DATA,
                NON_BLOCKING_READ_SHARE_ACCESS,
                FILE_NON_DIRECTORY_FILE,
                FILE_OPEN,
                0,
                SMB2_IL_IMPERSONATION,
                0,
                SMB2_OPLOCK_LEVEL_NONE,
                createContexts=create_contexts,
            )
            response = connection.queryInfo(tree_id, file_id)
            file_size = int(_impacket_smb.SMBQueryFileStandardInfo(response)["EndOfFile"])
            offset = 0
            while offset < file_size:
                read_size = min(file_size - offset, connection.max_read_size)
                try:
                    data = connection.read(tree_id, file_id, offset, read_size)
                except Exception as exc:
                    if self._is_end_of_file(exc):
                        raise FileChangedDuringRead("SMB file reached EOF before its advertised size") from exc
                    raise
                if not data:
                    raise FileChangedDuringRead(f"SMB returned zero bytes with {file_size - offset} bytes remaining")
                if len(data) > read_size:
                    raise IOError("SMB returned more data than requested")
                callback(data)
                offset += len(data)
        except BaseException as exc:
            operation_error = exc
            if isinstance(exc, ReadOnlySMBViolation):
                self._abort_read_only(exc)
            raise
        finally:
            cleanup_error = None
            try:
                if file_id is not None and self._transport_group.safety_error is None and not connection.failed:
                    try:
                        post_read_identity = self._close_smb2_file_with_identity(connection, tree_id, file_id)
                    except ReadOnlySMBViolation as exc:
                        self._abort_read_only(exc)
                        raise
                    except Exception as exc:
                        if connection.failed:
                            cleanup_error = exc
                        else:
                            if log.isEnabledFor(logging.DEBUG):
                                log.debug(f"{display_text(self.server)}: Post-query CLOSE unavailable, using normal CLOSE: {display_text(exc)}")
                            try:
                                connection.close(tree_id, file_id)
                            except ReadOnlySMBViolation as exc:
                                self._abort_read_only(exc)
                                raise
                            except Exception as exc:
                                cleanup_error = exc
            finally:
                try:
                    if self._transport_group.safety_error is None and not connection.failed:
                        connection.disconnectTree(tree_id)
                except ReadOnlySMBViolation as exc:
                    self._abort_read_only(exc)
                    raise
                except Exception as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
            if cleanup_error is not None:
                if operation_error is None:
                    raise cleanup_error
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"{display_text(self.server)}: SMB2 cleanup failed after read error: {display_text(cleanup_error)}")
        return post_read_identity

    @staticmethod
    def _is_end_of_file(error):
        for accessor in ("getErrorCode", "get_error_code"):
            method = getattr(error, accessor, None)
            if method is not None:
                with suppress(Exception):
                    if method() == STATUS_END_OF_FILE:
                        return True
        return False

    def _retrieve_smb1_file(self, connection, share, filename, callback):
        """Read an existing SMB1 file without the dependency's default oplock.

        Each call is one attempt. The caller owning the spool may retry an
        incomplete/changed snapshot; callback streams are never replayed here.
        """

        if not isinstance(connection, _ReadOnlySMB1FileTransport):
            connection = _ReadOnlySMB1FileTransport(connection)
        path = ntpath.normpath(filename.replace("/", "\\")).lstrip("\\")
        _, flags2 = connection.get_flags()
        wire_path = path.encode("utf-16le") if flags2 & _impacket_smb.SMB.FLAGS2_UNICODE else path
        request = _build_smb1_read_open(wire_path, flags2)

        tree_id = connection.tree_connect_andx("\\\\" + self.server + "\\" + share)
        file_id = None
        operation_error = None
        try:
            file_id = connection.nt_create_andx(tree_id, path, cmd=request, wire_path=wire_path)
            response = connection.query_file_info(tree_id, file_id)
            file_size = int(_impacket_smb.SMBQueryFileStandardInfo(response)["EndOfFile"])
            parameters = connection.dialect_parameters
            if parameters["Capabilities"] & _impacket_smb.SMB.CAP_LARGE_READX and not connection.signature_enabled:
                maximum_read = 65000
            else:
                maximum_read = parameters["MaxBufferSize"] & ~0x3FF
                if maximum_read <= 0:
                    maximum_read = max(1, parameters["MaxBufferSize"] - 64)
                maximum_read = min(maximum_read, 65000)
            offset = 0
            while offset < file_size:
                read_size = min(file_size - offset, maximum_read)
                read_packet = _impacket_smb.NewSMBPacket()
                read_packet["Tid"] = tree_id
                read_request = _impacket_smb.SMBCommand(_impacket_smb.SMB.SMB_COM_READ_ANDX)
                read_request["Parameters"] = _impacket_smb.SMBReadAndX_Parameters()
                read_request["Parameters"]["Fid"] = file_id
                read_request["Parameters"]["Offset"] = offset & 0xFFFFFFFF
                read_request["Parameters"]["HighOffset"] = offset >> 32
                read_request["Parameters"]["MaxCount"] = read_size
                read_packet.addCommand(read_request)
                try:
                    data = connection.read_andx(
                        tree_id,
                        file_id,
                        offset=offset,
                        max_size=read_size,
                        smb_packet=read_packet,
                    )
                except Exception as exc:
                    if self._is_end_of_file(exc):
                        raise FileChangedDuringRead("SMB1 file reached EOF before its advertised size") from exc
                    raise
                if not data:
                    raise FileChangedDuringRead(f"SMB1 returned zero bytes with {file_size - offset} bytes remaining")
                if len(data) > read_size:
                    raise IOError("SMB1 returned more data than requested")
                callback(data)
                offset += len(data)

            # SMB1 CLOSE has no post-query attributes. Unsupported information
            # classes retain the existing directory-wide verification fallback.
            try:
                response = connection.query_file_info(tree_id, file_id, _impacket_smb.SMB_QUERY_FILE_ALL_INFO)
                info = _impacket_smb.SMBQueryFileAllInfo(response)
                return int(info["EndOfFile"]), self._smb_time_epoch(int(info["LastChangeTime"])), None
            except ReadOnlySMBViolation:
                raise
            except Exception as exc:
                if connection.failed:
                    raise
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"{display_text(self.server)}: SMB1 post-read attributes unavailable: {display_text(exc)}")
                return None
        except BaseException as exc:
            operation_error = exc
            if isinstance(exc, ReadOnlySMBViolation):
                self._abort_read_only(exc)
            raise
        finally:
            cleanup_error = None
            try:
                if file_id is not None and self._transport_group.safety_error is None and not connection.failed:
                    try:
                        connection.close(tree_id, file_id)
                    except ReadOnlySMBViolation as exc:
                        self._abort_read_only(exc)
                        raise
                    except Exception as exc:
                        cleanup_error = exc
            finally:
                try:
                    if self._transport_group.safety_error is None and not connection.failed:
                        connection.disconnect_tree(tree_id)
                except ReadOnlySMBViolation as exc:
                    self._abort_read_only(exc)
                    raise
                except Exception as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
            if cleanup_error is not None:
                if operation_error is None:
                    raise cleanup_error
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"{display_text(self.server)}: SMB1 cleanup failed after read error: {display_text(cleanup_error)}")

    def close(self):
        """Best-effort cleanup, but a safety violation remains a fatal error."""

        try:
            if self._transport_group.safety_error is not None:
                return
            for route in list(self._dfs_routes.values()):
                self._release_dfs_route(route)
            for client in list(self._dfs_clients.values()):
                try:
                    client.close()
                except ReadOnlySMBViolation:
                    raise
                except Exception:
                    pass
            self._suspend_transport()
        except ReadOnlySMBViolation as exc:
            self._abort_read_only(exc)
            raise
        finally:
            error = self._transport_group.safety_error
            if error is not None:
                for client in self._dfs_clients.values():
                    client._abort_read_only(error)
                self._abort_read_only(error)
            self._dfs_routes.clear()
            self._dfs_clients.clear()
            self.flush_metrics()

    def list_shares(self):
        """List shares, preserving safety stops from transport or record decoding."""

        try:
            yield from self._iter_share_names()
        except ReadOnlySMBViolation as exc:
            self._abort_read_only(exc)
            raise

    def _iter_share_names(self):

        def request():
            metric_started = self._metric_started()
            owner_connection = None
            try:
                self._ensure_active_transport()
                owner_connection = self.__connection
                response = transport_state(owner_connection).call(read_only_list_shares, owner_connection)
            except BaseException as exc:
                self._metric_operation("share_list", metric_started, error=exc)
                self._retire_failed_transport(exc, owner_connection)
                raise
            self._metric_operation("share_list", metric_started, items=len(response))
            self._network_recovery.succeeded()
            return response

        try:
            resp = request()
        except Exception as error:
            if not self._try_null_after_guest_denial(error):
                raise
            resp = request()
        if log.isEnabledFor(logging.DEBUG):
            log.debug(f"{display_text(self.server)}: Response length: {display_text(len(resp))}")
        for i in range(len(resp)):
            try:
                sharename = resp[i]["shi1_netname"].rstrip("\x00")
                try:
                    share_type = int(resp[i]["shi1_type"])
                except (KeyError, AttributeError, TypeError, ValueError):
                    share_type = None
                try:
                    share_comment = resp[i]["shi1_remark"].rstrip("\x00")
                except (KeyError, AttributeError):
                    share_comment = ""
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(
                        f"{display_text(self.server)}: Share {display_text(i)}: name='{display_text(sharename)}', type={display_text(share_type)}, comment='{display_text(share_comment)}'"
                    )
                self._share_types[sharename.lower()] = share_type
                yield sharename
            except ReadOnlySMBViolation:
                # A record decoder is outside the RPC transport adapter. Its
                # safety stop must still poison this client, not skip a share.
                raise
            except Exception as e:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"{display_text(self.server)}: Error processing share {display_text(i)}: {display_text(e)}")
                continue

    @property
    def shares(self):
        self._raise_if_unsafe()
        if self._shares is None:
            for attempt in range(2):
                try:
                    self._shares = list(self.list_shares())
                    self.share_listing_error = None
                    break
                except ReadOnlySMBViolation as exc:
                    self._abort_read_only(exc)
                    raise
                except Exception as e:
                    e = self.handle_impacket_error(e)
                    self.share_listing_error = network_error_reason(e)
                    if attempt == 0:
                        if log.isEnabledFor(logging.DEBUG):
                            log.debug(f"{display_text(self.server)}: Error listing shares: {display_text(e)}, retrying once...")
                        self.rebuild(e)
                        if self.__connection is not None:
                            continue
                        if is_network_unavailable(self.last_connection_error):
                            self.share_listing_error = network_error_reason(self.last_connection_error)
                    log.warning(f"{display_text(self.server)}: Error listing shares: {display_text(e)}")
                    self._shares = []
                    break
        return self._shares or []

    def share_type(self, share):
        """Return the raw SMB share type collected during enumeration."""

        # Ensure enumeration has populated the type map.
        self.shares
        return self._share_types.get(str(share).lower())

    def seed_shares(self, shares):
        """Reuse complete share enumeration collected by credential preflight."""

        self._shares = [name for name, _share_type in shares]
        self._share_types = {name.lower(): share_type for name, share_type in shares if share_type is not None}
        self.share_listing_error = None

    def get_hostname(self):
        """
        Get the hostname from the SMB connection
        """
        self._raise_if_unsafe()
        if self.hostname is not None and self.dns_domain is not None:
            return self.hostname, self.dns_domain or self.domain

        conn = None
        try:
            conn = SMBConnection(
                self.server,
                self.server,
                None,
                self.port,
                timeout=10,
            )
            try:
                transport_state(conn).call(conn.login, "", "")
            except ReadOnlySMBViolation:
                raise
            except Exception:
                pass

            if self.hostname is None:
                try:
                    # Get the server name from SMB
                    self.hostname = str(conn.getServerName()).strip().replace("\x00", "").lower()
                    if self.hostname:
                        if log.isEnabledFor(logging.DEBUG):
                            log.debug(f"{display_text(self.server)}: Got hostname: {display_text(self.hostname)}")
                    else:
                        if log.isEnabledFor(logging.DEBUG):
                            log.debug(f"{display_text(self.server)}: No hostname found")
                except ReadOnlySMBViolation:
                    raise
                except Exception as e:
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug(f"{display_text(self.server)}: Error getting hostname from SMB: {display_text(e)}")
                    self.hostname = ""

            if self.dns_domain is None:
                try:
                    self.dns_domain = str(conn.getServerDNSDomainName()).strip().replace("\x00", "").lower()
                    if self.dns_domain:
                        if log.isEnabledFor(logging.DEBUG):
                            log.debug(f"{display_text(self.server)}: Got DNS domain: {display_text(self.dns_domain)}")
                    else:
                        if log.isEnabledFor(logging.DEBUG):
                            log.debug(f"{display_text(self.server)}: No DNS domain found")
                except ReadOnlySMBViolation:
                    raise
                except Exception as e:
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug(f"{display_text(self.server)}: Error getting DNS domain: {display_text(e)}")
                    self.dns_domain = self.domain if self.domain else ""

        except ReadOnlySMBViolation as exc:
            self._abort_read_only(exc, conn)
            conn = None
            raise
        except Exception as e:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.server)}: Error getting hostname: {display_text(e)}")
        finally:
            if conn is not None:
                try:
                    state = transport_state(conn)
                    if state.failed:
                        state.fail(state.error)
                    else:
                        state.call(conn.close)
                except ReadOnlySMBViolation as exc:
                    self._abort_read_only(exc, conn)
                    raise
                except Exception:
                    pass

        return self.hostname, self.dns_domain or self.domain

    def login(self, refresh=False, first_try=True):
        """Authenticate with bounded transport retries and finite identity fallback.

        False still records rejection of the supplied identity even when the
        Guest/null fallback succeeds. None denotes unavailable transport, not
        invalid credentials. A refused identity is never retried here.
        """

        self._raise_if_unsafe()
        check_worker_cancellation()
        if self.__connection is not None and transport_state(self.__connection).failed:
            self._retire_failed_transport(transport_state(self.__connection).error, self.__connection)
        if self.__connection is not None and not refresh:
            return True
        if refresh:
            self._suspend_transport()
        skip_supplied = first_try and self.username in (None, "", "Guest")
        if not skip_supplied:
            result = self._login_current_identity(check_guest=first_try)
            if result is not False:
                return result
        if not first_try:
            return False

        # No recursive login: each fallback identity has its own finite
        # attempt, and an unavailable transport does not justify trying yet
        # another identity on that endpoint.
        for identity in ("Guest", ""):
            self.username = identity
            self.password = self.domain = self.lmhash = self.nthash = ""
            self.use_kerberos = False
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.server)}: Trying {display_text('guest' if identity else 'null')} session")
            result = self._login_current_identity(check_guest=False)
            if result is not False:
                break
        return False

    def _login_current_identity(self, *, check_guest):
        # One initial exchange and at most one retry after a transport error.
        # This is not the optional global failed-logon limit of the scan.
        self.last_connection_error = None
        for attempt in range(2):
            self._raise_if_unsafe()
            self._network_recovery.wait(self._raise_if_unsafe)
            metric_started = self._metric_started()
            self._claim_transport()
            target_server = self.server
            if self.use_kerberos:
                hostname, domain = self.get_hostname()
                if hostname:
                    target_server = f"{hostname}.{domain}" if domain else hostname
            try:
                # Keep the routable user-supplied address as remoteHost while
                # using the discovered hostname only as the Kerberos SPN name.
                connection = SMBConnection(target_server, self.server, sess_port=self.port, timeout=20)
                self._install_connection(connection)
            except ReadOnlySMBViolation as exc:
                self._abort_read_only(exc)
                raise
            except Exception as e:
                self.last_connection_error = e
                close_failed_negotiation(e)
                if self._transport_failed(e):
                    mark_network_unavailable(e)
                    self._network_recovery.failed()
                self._metric_operation("connect", metric_started, error=e)
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(display_text(impacket_error(e)))
                self._suspend_transport()
                if attempt == 0 and self._transport_failed(e):
                    continue
                return None

            try:
                state = transport_state(connection)
                user_str = self.username
                if self.domain:
                    user_str = f"{self.domain}\\{self.username}"
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f'{display_text(target_server)} ({display_text(self.server)}): Authenticating as "{display_text(user_str)}"')

                if self.use_kerberos:
                    state.call(
                        connection.kerberosLogin,
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                        self.aes_key,
                        kdcHost=self.dc_ip,
                    )
                # pass the hash if requested
                elif self.nthash and not self.password:
                    state.call(
                        connection.login,
                        self.username,
                        "",
                        lmhash=self.lmhash,
                        nthash=self.nthash,
                        domain=self.domain,
                    )
                # otherwise, normal login
                else:
                    state.call(
                        connection.login,
                        self.username,
                        self.password,
                        domain=self.domain,
                    )

                # A server may accept the exchange while silently mapping bad
                # credentials to Guest. That is still a rejection of the
                # supplied identity and must not pass either preflight or the
                # main-scan accounting path as a successful domain logon.
                if check_guest and self.username not in (None, "", "Guest"):
                    with suppress(AttributeError, TypeError):
                        if self.__connection.isGuestSession() != 0:
                            raise RuntimeError("supplied credentials were mapped to a Guest session")

                log.info(f'{display_text(self.server)}: Successful login as "{display_text(self.username)}"')
                self._metric_session_started()
                self._metric_operation("connect", metric_started)
                self.last_connection_error = None
                return True
            except ReadOnlySMBViolation as exc:
                self._abort_read_only(exc)
                raise
            except Exception as e:
                self.last_connection_error = e
                self._metric_operation("connect", metric_started, error=e)
                self.handle_impacket_error(e, display=True)
                self._suspend_transport()
                if self._transport_failed(e):
                    # This exception crossed the authentication I/O boundary;
                    # a complete refusal is deliberately never marked/retried.
                    mark_network_unavailable(e)
                    self._network_recovery.failed()
                    if attempt == 0:
                        continue
                    return None
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"{display_text(self.server)}: Authentication refused for {display_text(self.username)}: {display_text(e)}")
                return False

    def _list_path_direct(self, share, path):
        nt_path = ntpath.normpath(f"{path}\\*")
        metric_started = self._metric_started()
        owner_connection = None
        try:
            self._ensure_active_transport()
            owner_connection = self.__connection
            self._ensure_share_tree(share)
            result = transport_state(owner_connection).call(read_only_list_path, owner_connection, share, nt_path)
        except BaseException as exc:
            self._metric_operation("directory_list", metric_started, error=exc)
            self._retire_failed_transport(exc, owner_connection)
            raise
        self._metric_operation("directory_list", metric_started, items=len(result))
        self._network_recovery.succeeded()
        return result

    def _list_path_routed(self, share, path, visited):
        route = self._find_dfs_route(share, path)
        if route is not None:
            marker = (
                self._normalize_server_name(self.server),
                self.port,
                self._share_key(share),
                self._normalize_relative_path(path).casefold(),
            )
            if marker in visited:
                raise RuntimeError(f"DFS referral loop while listing {share}\\{path}")
            target_client = self._route_client(route)
            return target_client._list_path_routed(
                route.target_share,
                self._translate_dfs_path(route, path),
                visited | {marker},
            )

        try:
            return self._list_path_direct(share, path)
        except (ReadOnlySMBViolation, DFSReferralBlocked):
            raise
        except Exception as error:
            if self._try_null_after_guest_denial(error):
                try:
                    return self._list_path_direct(share, path)
                except (ReadOnlySMBViolation, DFSReferralBlocked):
                    raise
                except Exception as retry_error:
                    error = retry_error
            if not self._is_path_not_covered(error):
                raise error
            failures = []
            for candidate in self._dfs_route_candidates(share, path):
                key = None
                try:
                    key = self._cache_dfs_route(candidate)
                    marker = (
                        self._normalize_server_name(self.server),
                        self.port,
                        self._share_key(share),
                        self._normalize_relative_path(path).casefold(),
                    )
                    if marker in visited:
                        raise RuntimeError(f"DFS referral loop while listing {share}\\{path}")
                    target_client = self._route_client(candidate)
                    return target_client._list_path_routed(
                        candidate.target_share,
                        self._translate_dfs_path(candidate, path),
                        visited | {marker},
                    )
                except ReadOnlySMBViolation:
                    raise
                except Exception as candidate_error:
                    failures.append(candidate_error)
                    if key is not None:
                        self._discard_dfs_route(key, candidate)
                    else:
                        self._release_dfs_route(candidate)
            if failures and all(isinstance(failure, DFSReferralBlocked) for failure in failures):
                raise failures[0]
            details = "; ".join(f"{type(failure).__name__}: {failure}" for failure in failures)
            failure = RuntimeError(f"all DFS referral targets failed for {share}\\{path}: {details}")
            if any(is_network_unavailable(item) for item in failures):
                mark_network_unavailable(failure)
            raise failure from error

    def ls(self, share, path):
        """
        List files in share/path
        Raise FileListError if there's a problem
        @byt3bl33d3r it's really not that bad
        """

        self._raise_if_unsafe()
        nt_path = ntpath.normpath(f"{path}\\*")

        # for every file/dir in "path"
        try:
            for f in self._list_path_routed(share, path, set()):
                # exclude current and parent directory
                if f.get_longname() not in ["", ".", ".."]:
                    yield f
        except ReadOnlySMBViolation as exc:
            self._abort_read_only(exc)
            raise
        except DFSReferralBlocked:
            raise
        except Exception as e:
            e = self.handle_impacket_error(e)
            error = FileListError(f'{network_error_reason(e)}: Error listing files at "{share}{nt_path}"')
            if is_network_unavailable(e):
                mark_network_unavailable(error)
            raise error from e

    def rebuild(self, error=""):
        """
        Rebuild our SMBConnection() if it gets borked
        """
        if log.isEnabledFor(logging.DEBUG):
            log.debug(f"Rebuilding connection to {display_text(self.server)} after error: {display_text(error)}")
        if self._metrics is not None:
            with suppress(Exception):
                self._metrics.record_reconnect()
        self._raise_if_unsafe()
        return self.login(refresh=True)

    def handle_impacket_error(self, e, share="", filename="", display=False):
        """Format/classify an error; never initiate a network operation here."""
        resource_str = "/".join([self.server, share, filename]).rstrip("/")

        if isinstance(e, ReadOnlySMBViolation):
            raise e
        if isinstance(e, KeyboardInterrupt):
            raise e
        if type(e) in native_impacket_errors:
            e = impacket_error(e)
        if display:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(resource_str)}: {display_text(str(e)[:150])}")

        return e
