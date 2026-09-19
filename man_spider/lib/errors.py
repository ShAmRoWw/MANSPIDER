import struct
import logging

from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.smb import SessionError, UnsupportedFeature
from impacket.smbconnection import SessionError as CSessionError

from man_spider.error_policy import (
    NETWORK_ACCESS_DENIED_MARKER,
    NETWORK_UNAVAILABLE_MARKER,
    is_network_access_denied,
)

# set up logging
log = logging.getLogger("manspider")


class MANSPIDERError(Exception):
    pass


class ReadOnlySMBViolation(RuntimeError):
    """An SMB operation violated the scanner's non-mutating protocol contract.

    This is a fatal safety failure, never a retryable per-file/server refusal.
    Kept outside the transport module so every worker can preserve its type.
    """


class FileRetrievalError(MANSPIDERError):
    pass


class FileChangedDuringRead(FileRetrievalError):
    """The advertised file length could not be read without losing progress."""


class ShareListError(MANSPIDERError):
    pass


class FileListError(MANSPIDERError):
    pass


class DFSReferralBlocked(FileListError, FileRetrievalError, RuntimeError):
    """A referral was deliberately refused by the caller's scope policy.

    Preserve this type through listing/retrieval wrappers so it cannot turn
    into a retryable network failure or be mistaken for a successful read.
    """


class LogonFailure(MANSPIDERError):
    pass


_NETWORK_UNAVAILABLE_ATTRIBUTE = "_manspider_network_unavailable"


def is_network_unavailable(error) -> bool:
    """Use proven SMB I/O provenance, not exception names or message text.

    Local spool/parser failures can also be TimeoutError or BrokenPipeError.
    Only the guarded SMB boundary may mark an original exception; wrappers
    explicitly propagate that mark. Cancellation and safety stops never retry.
    """

    return (
        isinstance(error, Exception)
        and not isinstance(error, (ReadOnlySMBViolation, DFSReferralBlocked))
        and not is_network_access_denied(error, include_context=False)
        and getattr(error, _NETWORK_UNAVAILABLE_ATTRIBUTE, False) is True
    )


def mark_network_unavailable(error):
    """Tag an error already classified at a remote I/O boundary; return it."""

    if (
        isinstance(error, Exception)
        and not isinstance(error, (ReadOnlySMBViolation, DFSReferralBlocked))
        and not is_network_access_denied(error, include_context=False)
    ):
        setattr(error, _NETWORK_UNAVAILABLE_ATTRIBUTE, True)
    return error


def network_error_reason(error) -> str:
    """Format a remote-operation error and durably tag access refusal."""

    reason = f"{type(error).__name__}: {error}"
    # A new wire failure during a permitted fallback can inherit the earlier
    # handled AccessDenied as __context__. Proven current I/O takes priority.
    if is_network_unavailable(error):
        return f"{NETWORK_UNAVAILABLE_MARKER} {reason}"
    if is_network_access_denied(error):
        reason = reason.replace(NETWORK_ACCESS_DENIED_MARKER, "", 1).strip()
        return f"{NETWORK_ACCESS_DENIED_MARKER} {reason}"
    return reason


native_impacket_errors = (
    struct.error,
    NetBIOSError,
    NetBIOSTimeout,
    SessionError,
    CSessionError,
    UnsupportedFeature,
)


impacket_errors = (
    OSError,
    BrokenPipeError,
) + native_impacket_errors


def impacket_error(e):
    """
    Tries to format impacket exceptions nicely
    """
    if type(e) in (SessionError, CSessionError):
        try:
            error_str = e.getErrorString()[0]
            e.args = (error_str,)
        except (IndexError,):
            pass
    if not e.args:
        e.args = ("",)
    return e
