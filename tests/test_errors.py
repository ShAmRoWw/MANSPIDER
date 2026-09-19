import pytest
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_NETWORK_ACCESS_DENIED
from impacket.smb import SessionError as SMB1SessionError
from impacket.smbconnection import SessionError as SMBSessionError

from man_spider.lib.errors import (
    NETWORK_ACCESS_DENIED_MARKER,
    is_network_access_denied,
    network_error_reason,
)


@pytest.mark.parametrize(
    "error",
    [
        SMBSessionError(STATUS_ACCESS_DENIED),
        SMBSessionError(STATUS_NETWORK_ACCESS_DENIED),
        SMB1SessionError(
            "fixture",
            SMB1SessionError.ERRDOS,
            SMB1SessionError.ERRnoaccess,
        ),
        SMB1SessionError(
            "fixture",
            0x02,  # SMB1 ERRSRV error class
            SMB1SessionError.ERRaccess,
        ),
        RuntimeError("STATUS_ACCESS_DENIED"),
        RuntimeError("NT_STATUS_ACCESS_DENIED"),
        RuntimeError(f"{NETWORK_ACCESS_DENIED_MARKER} persisted fixture"),
    ],
)
def test_network_access_denied_recognizes_smb_statuses_and_durable_markers(error):
    assert is_network_access_denied(error) is True
    assert network_error_reason(error).startswith(NETWORK_ACCESS_DENIED_MARKER)


@pytest.mark.parametrize(
    "error",
    [
        PermissionError("Permission denied in local loot directory"),
        RuntimeError("STATUS_SHARING_VIOLATION"),
        RuntimeError("connection reset"),
        RuntimeError("document extraction failed"),
    ],
)
def test_network_access_denied_does_not_hide_local_or_non_authorization_errors(error):
    assert is_network_access_denied(error) is False
    assert not network_error_reason(error).startswith(NETWORK_ACCESS_DENIED_MARKER)


def test_network_access_denied_follows_wrapped_smb_exception_context():
    try:
        raise SMBSessionError(STATUS_ACCESS_DENIED)
    except SMBSessionError:
        try:
            raise RuntimeError("wrapped retrieval failure")
        except RuntimeError as error:
            assert is_network_access_denied(error) is True
            assert network_error_reason(error).startswith(NETWORK_ACCESS_DENIED_MARKER)
