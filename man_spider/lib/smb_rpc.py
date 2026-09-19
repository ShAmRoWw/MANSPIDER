"""Read-only share enumeration with an explicitly owned RPC pipe lifetime.

RPC necessarily writes messages to a named pipe. This transport never writes
file contents: its only destination is its own existing ``IPC$\\srvsvc`` pipe,
and the only permitted service request is NetrShareEnum (opnum 15).
"""

import logging
import struct

from impacket.dcerpc.v5 import srvs
from impacket.dcerpc.v5.transport import SMBTransport
from impacket.uuid import uuidtup_to_bin

from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib.smb_transport import transport_state


log = logging.getLogger("manspider.smb")
_SRVS_INTERFACE = uuidtup_to_bin(("4B324FC8-1670-01D3-1278-5A47BF6EE188", "3.0"))
_NDR_TRANSFER_SYNTAX = uuidtup_to_bin(("8A885D04-1CEB-11C9-9FE8-08002B104860", "2.0"))


def _validate_share_rpc_message(data):
    """Reject any RPC interface/operation outside the one enumeration capability."""

    try:
        payload = bytes(data)
        version, minor, message_type, flags, representation, length, auth_length, _call = struct.unpack_from(
            "<BBBB4sHHI", payload
        )
    except (TypeError, ValueError, struct.error) as exc:
        raise ReadOnlySMBViolation("Malformed share-enumeration RPC message") from exc
    if (
        (version, minor, representation, length, auth_length) != (5, 0, b"\x10\x00\x00\x00", len(payload), 0)
        or flags & ~3
    ):
        raise ReadOnlySMBViolation("Unsupported share-enumeration RPC header")
    if message_type == 11:  # BIND: exactly SRVS v3 / NDR32, no additional contexts.
        if (
            len(payload) != 72
            or flags != 3
            or payload[24:32] != b"\x01\x00\x00\x00\x00\x00\x01\x00"
            or payload[32:52] != _SRVS_INTERFACE
            or payload[52:72] != _NDR_TRANSFER_SYNTAX
        ):
            raise ReadOnlySMBViolation("RPC binding is not the pinned share-enumeration interface")
    elif message_type == 0:  # REQUEST; each DCE fragment repeats context/opnum.
        if len(payload) < 24 or payload[20:24] != b"\x00\x00\x0f\x00":
            raise ReadOnlySMBViolation("RPC request is not NetrShareEnum (opnum 15)")
    else:
        raise ReadOnlySMBViolation("Unsupported share-enumeration RPC message type")
    return payload


class _ShareEnumerationTransport(SMBTransport):
    """Use one existing SMB session; close only this transport's resources."""

    def __init__(self, connection):
        super().__init__(
            connection.getRemoteName(),
            remote_host=connection.getRemoteHost(),
            filename=r"\srvsvc",
            smb_connection=connection,
        )
        self._enumeration_connection = connection
        self._transport_state = transport_state(connection)
        self._enumeration_tree = None
        self._enumeration_handle = None
        self._enumeration_socket = None
        self._enumeration_pending_recv = 0
        self._enumeration_closed = False

    def setup_smb_connection(self):
        raise ReadOnlySMBViolation("Share enumeration cannot create an additional SMB session")

    def set_smb_connection(self, smb_connection):
        raise ReadOnlySMBViolation("Share enumeration cannot replace its owning SMB session")

    def connect(self):
        if self._enumeration_closed or self._enumeration_tree is not None:
            raise ReadOnlySMBViolation("Share-enumeration transport cannot be reopened")
        connection = self._enumeration_connection
        self._enumeration_tree = self._transport_state.call(connection.connectTree, "IPC$")
        self._enumeration_handle = self._transport_state.call(
            connection.openFile,
            self._enumeration_tree,
            r"\srvsvc",
            desiredAccess=0x00000003,  # Pipe message read/write, never scanned file content.
            shareMode=0x00000001,
            creationOption=0x00000040,  # FILE_NON_DIRECTORY_FILE
            creationDisposition=0x00000001,  # FILE_OPEN, never create/overwrite.
            fileAttributes=0x00000080,
            impersonationLevel=0x00000002,
            securityFlags=0,
            oplockLevel=0,
            createContexts=None,
        )
        self._enumeration_socket = connection.getSMBServer().get_socket()
        return 1

    def _require_handle(self):
        if self._enumeration_closed or self._enumeration_tree is None or self._enumeration_handle is None:
            raise ReadOnlySMBViolation("Share-enumeration pipe is not open")

    def send(self, data, forceWriteAndx=0, forceRecv=0):
        self._require_handle()
        payload = _validate_share_rpc_message(data)
        # The enumeration request is tiny. DCE fragmentation, if negotiated,
        # already supplies complete RPC fragments; no separate SMB splitting
        # or nonzero file offsets are needed for this pipe transport.
        self._transport_state.call(
            self._enumeration_connection.writeFile,
            self._enumeration_tree, self._enumeration_handle, payload, offset=0
        )
        if forceRecv:
            self._enumeration_pending_recv += 1

    def recv(self, forceRecv=0, count=0):
        self._require_handle()
        if self._enumeration_pending_recv:
            self._enumeration_pending_recv -= 1
        return self._transport_state.call(
            self._enumeration_connection.readFile,
            self._enumeration_tree, self._enumeration_handle, bytesToRead=self._max_recv_frag
        )

    def get_socket(self):
        return self._enumeration_socket

    def disconnect(self):
        if self._enumeration_closed:
            return
        self._enumeration_closed = True
        connection = self._enumeration_connection
        tree, handle = self._enumeration_tree, self._enumeration_handle
        self._enumeration_tree = self._enumeration_handle = self._enumeration_socket = None
        if self._transport_state.failed:
            return
        cleanup_error = None
        if handle is not None:
            try:
                self._transport_state.call(connection.closeFile, tree, handle)
            except BaseException as exc:
                cleanup_error = exc
        if tree is not None and not isinstance(cleanup_error, ReadOnlySMBViolation) and not self._transport_state.failed:
            try:
                self._transport_state.call(connection.disconnectTree, tree)
            except BaseException as exc:
                # A stop request must not disappear behind an earlier ordinary
                # close error. Safety violations retain the highest priority.
                if (
                    cleanup_error is None
                    or isinstance(exc, ReadOnlySMBViolation)
                    or (isinstance(cleanup_error, Exception) and not isinstance(exc, Exception))
                ):
                    cleanup_error = exc
        if cleanup_error is not None:
            cleanup_error.smb_cleanup_failed = True
            raise cleanup_error


def read_only_list_shares(connection):
    """Return Impacket's level-1 share records without leaking an RPC handle.

    The existing authenticated connection always remains owned by the caller.
    Cleanup uses the captured connection and its IDs even when the caller later
    replaces a broken session. A failed RPC retains its original exception
    unless cleanup raises a safety violation or requests process termination.
    """

    rpc_transport = _ShareEnumerationTransport(connection)
    primary_error = None
    try:
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(_SRVS_INTERFACE)
        response = srvs.hNetrShareEnum(dce, 1, serverName="\\\\" + connection.getRemoteHost())
        return response["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if isinstance(primary_error, ReadOnlySMBViolation):
            # No further protocol operations after a safety violation. The
            # owning client must discard the underlying socket instead.
            primary_error.smb_cleanup_failed = True
        else:
            try:
                rpc_transport.disconnect()
            except BaseException as cleanup_error:
                if (
                    primary_error is None
                    or isinstance(cleanup_error, ReadOnlySMBViolation)
                    or (isinstance(primary_error, Exception) and not isinstance(cleanup_error, Exception))
                ):
                    raise
                primary_error.smb_cleanup_failed = True
                log.debug("Share-enumeration cleanup failed after RPC failure: %s", cleanup_error)
