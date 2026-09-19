"""Connection-local failure state for SMB's non-resumable byte stream.

Impacket does not retain a partially received NetBIOS frame after a timeout.
Once a network exchange fails, sending even a read-only CLOSE/LOGOFF on that
stream is unsafe: a late response can be consumed as the next response. This
state is shared by the narrowly scoped read-only capabilities, not by a whole
worker/DFS group. It neither sends SMB requests nor retries an operation.
"""

import errno
import socket
from contextlib import suppress

from impacket.nmb import NetBIOSError, NetBIOSTimeout, NetBIOSTCPSession
from impacket.smbconnection import SMBConnection

from man_spider.lib.errors import ReadOnlySMBViolation, mark_network_unavailable


_STATE_ATTRIBUTE = "_manspider_failed_transport_state"
# Keep the actual installed dependency code, not a forgeable module/function
# name. Impacket suppresses two NetBIOSError instances during wildcard
# negotiation and then raises a plain Exception outside the receive frame.
_WILDCARD_NEGOTIATION_CODE = SMBConnection.negotiateSessionWildcard.__code__
_SOCKET_ERRNOS = frozenset(
    getattr(errno, name)
    for name in (
        "EPIPE", "ECONNRESET", "ECONNABORTED", "ENOTCONN", "ETIMEDOUT",
        "EBADF", "ENOTSOCK", "ENETRESET", "ESHUTDOWN", "ECONNREFUSED",
        "ENETDOWN", "ENETUNREACH", "EHOSTDOWN", "EHOSTUNREACH", "ENOBUFS",
    )
    if hasattr(errno, name)
)


def _failed_wildcard_frame(error):
    """The real terminal negotiation raise, not matching untrusted text."""

    if type(error) is not Exception or error.args != ("No answer!",):
        return None
    traceback = error.__traceback__
    if traceback is None:
        return None
    while traceback.tb_next is not None:
        traceback = traceback.tb_next
    frame = traceback.tb_frame
    # A nested local failure can traverse this method with identical text,
    # but originates in a different final traceback frame.
    return frame if frame.f_code is _WILDCARD_NEGOTIATION_CODE else None


def close_failed_negotiation(error):
    """Dispose only the captured raw socket of an unreturned SMB constructor.

    No SMBConnection was installed, so ordinary client cleanup cannot own it.
    Retaining the exception for diagnostics also retains its negotiation
    frame/session/socket. Never call protocol CLOSE/LOGOFF on this stream.
    """

    frame = _failed_wildcard_frame(error)
    if frame is None:
        return False
    connection = frame.f_locals.get("self")
    if type(connection) is not SMBConnection:
        return False
    session = vars(connection).get("_nmbSession")
    if type(session) is not NetBIOSTCPSession:
        return False
    sock = vars(session).get("_sock")
    if not isinstance(sock, socket.socket):
        return False
    try:
        with suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
    finally:
        # Cancellation during shutdown must not retain the descriptor.
        with suppress(OSError):
            sock.close()
    return True


def is_transport_error(error):
    """Classify transport errors, never a complete SMB status response.

Call this only at an SMB I/O boundary. In particular, a caller's local spool
callback can raise TimeoutError/OSError without damaging the SMB connection.
"""

    if isinstance(error, ReadOnlySMBViolation):
        return False
    if isinstance(error, (NetBIOSError, NetBIOSTimeout, ConnectionError, TimeoutError, EOFError)):
        return True
    if isinstance(error, OSError) and error.errno in _SOCKET_ERRNOS:
        return True
    # Impacket's SMB header decoder raises ordinary Exception/struct.error,
    # not a dedicated framing exception. Restrict this fallback to an actual
    # dependency receive/decode frame, excluding typed server status errors.
    if callable(getattr(error, "get_error_code", None)) or callable(getattr(error, "getErrorCode", None)):
        return False
    if _failed_wildcard_frame(error) is not None:
        return True
    traceback = error.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        module, operation = frame.f_globals.get("__name__"), frame.f_code.co_name
        if (
            module in ("impacket.smb", "impacket.smb3") and operation == "recvSMB"
        ) or (
            module == "impacket.nmb"
            and operation in ("send_packet", "recv_packet", "non_polling_read", "polling_read", "__read")
        ):
            # A cancellation in actual wire I/O can discard the same partial
            # frame as a timeout. A callback/local parser cancellation has no
            # such frame and must not be classified merely by its type.
            return isinstance(error, (Exception, KeyboardInterrupt, SystemExit))
        traceback = traceback.tb_next
    return False


class SMBTransportState:
    """Sticky failure for one raw connection; raw socket disposal is idempotent."""

    def __init__(self, connection):
        self.__connection = connection
        self.error = None
        self._socket_closed = False

    @property
    def failed(self):
        return self.error is not None

    def owns(self, connection):
        return self.__connection is connection

    def fail(self, error):
        if self.error is None:
            self.error = error
        if self._socket_closed:
            return
        # Never call SMBConnection.close(): that performs LOGOFF first.
        # Dispose only this captured connection, even if its owner has already
        # installed a replacement while an earlier operation unwinds.
        with suppress(Exception):
            sock = self.__connection.get_socket()
            try:
                with suppress(Exception):
                    sock.shutdown(socket.SHUT_RDWR)
            finally:
                # Do not swallow KeyboardInterrupt/SystemExit, but still close
                # if shutdown was interrupted. Mark disposal complete only
                # after close returns (or raises an ordinary socket error).
                with suppress(Exception):
                    sock.close()
                self._socket_closed = True

    def call(self, method, *args, **kwargs):
        if self.error is not None:
            raise self.error
        try:
            return method(*args, **kwargs)
        except BaseException as error:
            if is_transport_error(error):
                mark_network_unavailable(error)
                self.fail(error)
            raise


def transport_state(connection):
    """Return the shared state on a raw SMB1/2/3 connection or its facade."""

    getter = getattr(connection, "getSMBServer", None)
    raw = getter() if callable(getter) else connection
    state = getattr(raw, _STATE_ATTRIBUTE, None)
    if not isinstance(state, SMBTransportState) or not state.owns(raw):
        state = SMBTransportState(raw)
        setattr(raw, _STATE_ATTRIBUTE, state)
    return state
