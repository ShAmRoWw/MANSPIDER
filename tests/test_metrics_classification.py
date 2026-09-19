"""Passive metric categories must not be controlled by filenames or error text."""

import errno
import json

import pytest
from impacket import nt_errors, system_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.srvs import DCERPCSessionError
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.smb import SessionError as SMB1SessionError
from impacket.smbconnection import SessionError

from man_spider.metrics import SMBMetricsEmitter, classify_smb_error


MISLEADING_NAMES = (
    "STATUS_ACCESS_DENIED.txt",
    "access denied.txt",
    "timed out.txt",
    "STATUS_LOGON_FAILURE.txt",
    "password_expired.txt",
    "connection reset.txt",
    "brokenpipe.txt",
    "NetBIOSerror.txt",
    "STATUS_ACCESS_DENIED notes.txt",
    "mapped to a guest session.txt",
    'embedded\": STATUS_ACCESS_DENIED filename.txt',
)


@pytest.mark.parametrize("filename", MISLEADING_NAMES)
@pytest.mark.parametrize("exception,expected", [
    (ConnectionResetError, "disconnect"),
    (BrokenPipeError, "disconnect"),
    (TimeoutError, "timeout"),
    (NetBIOSTimeout, "timeout"),
    (NetBIOSError, "disconnect"),
    (EOFError, "disconnect"),
])
def test_typed_transport_failure_wins_over_resource_name(filename, exception, expected):
    assert classify_smb_error(exception(f'Error retrieving "{filename}"')) == expected


@pytest.mark.parametrize("filename", MISLEADING_NAMES)
def test_ambiguous_untyped_path_is_other(filename):
    assert classify_smb_error(OSError(f'Error retrieving "{filename}": failed')) == "other"
    assert classify_smb_error(RuntimeError(filename)) == "other"


@pytest.mark.parametrize("code,expected", [
    (nt_errors.STATUS_ACCESS_DENIED, "access_denied"),
    (nt_errors.STATUS_NETWORK_ACCESS_DENIED, "access_denied"),
    (nt_errors.STATUS_LOGON_FAILURE, "authentication"),
    (nt_errors.STATUS_PASSWORD_MUST_CHANGE, "authentication"),
    (nt_errors.STATUS_ACCOUNT_DISABLED, "authentication"),
    (nt_errors.STATUS_IO_TIMEOUT, "timeout"),
    (nt_errors.STATUS_CONNECTION_RESET, "disconnect"),
    (nt_errors.STATUS_USER_SESSION_DELETED, "disconnect"),
    (nt_errors.STATUS_NETWORK_NAME_DELETED, "disconnect"),
    (nt_errors.STATUS_SHARING_VIOLATION, "other"),
    (nt_errors.STATUS_OBJECT_NAME_NOT_FOUND, "other"),
    (5, "other"),  # A Win32 code is not an NTSTATUS denial.
    (1326, "other"),
])
def test_smb_numeric_status_is_authoritative_over_misleading_text(code, expected):
    class MisleadingError(SessionError):
        def __str__(self):
            return "STATUS_ACCESS_DENIED - filename timed out logon failure connection reset.txt"

    assert classify_smb_error(MisleadingError(code)) == expected
    assert classify_smb_error(SessionError(code)) == expected


@pytest.mark.parametrize("error_class,code,expected", [
    (1, SMB1SessionError.ERRnoaccess, "access_denied"),
    (2, SMB1SessionError.ERRaccess, "access_denied"),
    (1, SMB1SessionError.ERRlogonfailure, "authentication"),
    (2, SMB1SessionError.ERRbadpw, "authentication"),
    (2, SMB1SessionError.ERRtimeout, "timeout"),
    (1, SMB1SessionError.ERRnetnamedel, "disconnect"),
    (1, SMB1SessionError.ERRpipeclosing, "disconnect"),
    (1, SMB1SessionError.ERRnotconnected, "disconnect"),
    (1, SMB1SessionError.ERRbadfile, "other"),
    (2, 5, "other"),  # ERRSRV 5 is ERRinvnid, not ERRDOS 5 access denial.
    (1, 88, "other"),  # ERRSRV timeout cannot be applied to ERRDOS.
])
def test_smb1_error_class_keeps_its_own_numeric_namespace(error_class, code, expected):
    error = SMB1SessionError("STATUS_ACCESS_DENIED timed out.txt", error_class, code)
    assert classify_smb_error(error) == expected


def test_smb1_ntstatus_uses_full_32_bit_code():
    code = nt_errors.STATUS_CONNECTION_RESET
    error = SMB1SessionError("access denied.txt", code & 0xFFFF, code >> 16, nt_status=1)
    assert classify_smb_error(error) == "disconnect"


@pytest.mark.parametrize("exception", [DCERPCException, DCERPCSessionError])
@pytest.mark.parametrize("code,expected", [
    (system_errors.ERROR_ACCESS_DENIED, "access_denied"),
    (system_errors.ERROR_LOGON_FAILURE, "authentication"),
    (system_errors.ERROR_ACCOUNT_LOCKED_OUT, "authentication"),
    (system_errors.ERROR_SEM_TIMEOUT, "timeout"),
    (system_errors.ERROR_NETNAME_DELETED, "disconnect"),
    (system_errors.RPC_S_SERVER_UNAVAILABLE, "disconnect"),
    (system_errors.ERROR_FILE_NOT_FOUND, "other"),
])
def test_rpc_numeric_status_is_authoritative(exception, code, expected):
    error = exception(error_code=code)
    error.error_string = "STATUS_ACCESS_DENIED timed out logon failure.txt"
    assert classify_smb_error(error) == expected


@pytest.mark.parametrize("cause,expected", [
    (ConnectionResetError("access denied.txt"), "disconnect"),
    (TimeoutError("logon failure.txt"), "timeout"),
    (SessionError(nt_errors.STATUS_ACCESS_DENIED), "access_denied"),
    (SessionError(nt_errors.STATUS_LOGON_FAILURE), "authentication"),
    (SessionError(nt_errors.STATUS_SHARING_VIOLATION), "other"),
    (OSError(errno.ENOENT, "STATUS_ACCESS_DENIED", "timed out.txt"), "other"),
])
def test_typed_cause_precedes_legacy_wrapper_text(cause, expected):
    error = RuntimeError('Error retrieving file "STATUS_ACCESS_DENIED.txt": OSError: access denied')
    error.__cause__ = cause
    assert classify_smb_error(error) == expected


def test_explicit_cause_precedes_unrelated_context():
    error = RuntimeError("unclassified wrapper")
    error.__cause__ = ConnectionResetError()
    error.__context__ = SessionError(nt_errors.STATUS_ACCESS_DENIED)
    assert classify_smb_error(error) == "disconnect"


def test_suppressed_context_is_not_used():
    error = RuntimeError("unclassified wrapper")
    error.__context__ = SessionError(nt_errors.STATUS_ACCESS_DENIED)
    assert classify_smb_error(error) == "access_denied"
    error.__suppress_context__ = True
    assert classify_smb_error(error) == "other"


@pytest.mark.parametrize("text,expected", [
    ("access denied", "access_denied"),
    ("access_denied", "access_denied"),
    ("OSError: access denied", "access_denied"),
    ("timed out", "timeout"),
    ("connection reset by peer", "disconnect"),
    ("logon failure", "authentication"),
    ("mapped to a guest session", "authentication"),
    ("supplied credentials were mapped to a Guest session", "authentication"),
    ("NetBIOSTimeout: timed out reading access denied.txt", "timeout"),
    ("BrokenPipeError: STATUS_ACCESS_DENIED.txt", "disconnect"),
    ('Error retrieving file "STATUS_ACCESS_DENIED.txt": OSError: connection reset', "disconnect"),
    ('Error retrieving file "timed out.txt": SMB SessionError: STATUS_LOGON_FAILURE', "authentication"),
    (str(SessionError(nt_errors.STATUS_ACCESS_DENIED)), "access_denied"),
    (str(SessionError(nt_errors.STATUS_CONNECTION_RESET)), "disconnect"),
    (str(DCERPCException(error_code=5)), "access_denied"),
    ("SMB SessionError: code: 0xc0000043 - STATUS_ACCESS_DENIED", "other"),
    ("SMB SessionError: code: 5 - STATUS_ACCESS_DENIED", "other"),
    ('Error retrieving file "embedded\": STATUS_ACCESS_DENIED filename.txt": OSError: reset', "other"),
    ('OSError: failed to open "STATUS_ACCESS_DENIED": connection reset', "other"),
])
def test_legacy_diagnostics_are_anchored_and_numeric_status_wins(text, expected):
    assert classify_smb_error(OSError(text)) == expected


def test_arbitrary_exception_class_names_are_not_diagnostics():
    class FilenameTimeoutError(Exception):
        pass

    assert classify_smb_error(FilenameTimeoutError("not a transport timeout")) == "other"


def test_unusable_error_text_does_not_break_telemetry():
    class BrokenString(Exception):
        def __str__(self):
            raise ValueError("broken diagnostic")

    assert classify_smb_error(BrokenString()) == "other"


def test_broken_status_accessor_does_not_break_telemetry():
    class BrokenStatus(Exception):
        @property
        def getErrorCode(self):
            raise ValueError("broken accessor")

    assert classify_smb_error(BrokenStatus("STATUS_ACCESS_DENIED")) == "other"


def test_failing_status_getter_does_not_fall_back_to_misleading_text():
    class BrokenStatus(Exception):
        def getErrorCode(self):
            raise ValueError("broken accessor")

    assert classify_smb_error(BrokenStatus("STATUS_ACCESS_DENIED")) == "other"


def test_signed_ntstatus_has_same_category():
    assert classify_smb_error(SessionError(nt_errors.STATUS_CONNECTION_RESET - 2**32)) == "disconnect"


def test_cyclic_and_excessive_cause_chains_are_bounded():
    error = RuntimeError("STATUS_ACCESS_DENIED")
    error.__cause__ = error
    assert classify_smb_error(error) == "other"
    root = error = RuntimeError("STATUS_ACCESS_DENIED")
    for _ in range(20):
        error.__cause__ = RuntimeError("wrapper")
        error = error.__cause__
    error.__cause__ = ConnectionResetError()
    assert classify_smb_error(root) == "other"


def test_emitter_records_only_correct_category_not_sensitive_error_text():
    snapshots = []
    emitter = SMBMetricsEmitter("test-server", 445, snapshots.append)
    emitter.record_operation(
        "file_read", emitter.started(),
        error=ConnectionResetError('failed STATUS_ACCESS_DENIED.txt password=secret-fixture'),
    )
    emitter.flush(force=True)
    counts = snapshots[0]["operations"]["file_read"]["errors"]
    assert counts["disconnect"] == 1
    assert sum(counts.values()) == 1
    serialized = json.dumps(snapshots)
    assert "secret-fixture" not in serialized
    assert "STATUS_ACCESS_DENIED" not in serialized
