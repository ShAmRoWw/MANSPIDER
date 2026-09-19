"""Exercise guarded CLOSE with Impacket's real credit/MessageID bookkeeping."""

from collections import deque

import pytest
from impacket.nt_errors import STATUS_SUCCESS
from impacket.smb3 import SMB3
from impacket.smb3structs import (
    SMB2_CLOSE,
    SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB,
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_302,
    SMB2_DIALECT_311,
    SMB2_ECHO,
    SMB2_FLAGS_SERVER_TO_REDIR,
    SMB2Close_Response,
    SMB2Echo,
    SMB2Packet,
    SMB3Packet,
)

import man_spider.lib.smb as smb_module


class _NetBIOSResponse:
    def __init__(self, payload):
        self.payload = payload

    def get_trailer(self):
        return self.payload


class _WindowsCreditSession:
    """No sockets: echo the request charge, as observed on the Windows lab."""

    def __init__(self, dialect):
        self.dialect = dialect
        self.requests = []
        self.responses = deque()
        self.message_ids = set()

    def send_packet(self, payload):
        request = SMB2Packet(payload)
        message_id = request["MessageID"]
        if message_id in self.message_ids:
            raise BrokenPipeError(f"server rejected duplicate SMB2 MessageID {message_id}")
        self.message_ids.add(message_id)
        self.requests.append(request)

        response = SMB2Packet()
        response["Command"] = request["Command"]
        response["MessageID"] = message_id
        response["SessionID"] = request["SessionID"]
        response["TreeID"] = request["TreeID"]
        response["Flags"] = SMB2_FLAGS_SERVER_TO_REDIR
        response["Status"] = STATUS_SUCCESS
        response["CreditCharge"] = 0 if self.dialect == SMB2_DIALECT_002 else request["CreditCharge"]
        response["CreditRequestResponse"] = 1
        if request["Command"] == SMB2_CLOSE:
            body = SMB2Close_Response()
            body["Flags"] = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
            response["Data"] = body
        else:
            assert request["Command"] == SMB2_ECHO
            response["Data"] = SMB2Echo()
        self.responses.append(_NetBIOSResponse(response.getData()))

    def recv_packet(self, _timeout):
        return self.responses.popleft()


class _InMemorySMB3(SMB3):
    """Keep real send/receive/echo methods without SMB3's network constructor."""

    def __init__(self, dialect):
        self._Connection = {
            "Dialect": dialect,
            "SequenceWindow": 8,
            "OutstandingResponses": {},
            "MaxReadSize": 65536,
        }
        self._Session = {
            "SessionID": 1,
            "SigningActivated": False,
            "SessionFlags": 0,
            "TreeConnectTable": {7: {"EncryptData": False}},
            "CalculatePreAuthHash": False,
            "OpenTable": {},
        }
        self._timeout = 1
        self.SMB_PACKET = SMB3Packet if dialect >= SMB2_DIALECT_30 else SMB2Packet
        self._NetBIOSSession = _WindowsCreditSession(dialect)
        self._file_number = 0

    def create(self, _tree_id, _file_name, **kwargs):
        # The capability must still acquire a read-only handle before CLOSE.
        assert kwargs["desiredAccess"] == smb_module.FILE_READ_DATA
        assert kwargs["creationDisposition"] == smb_module.FILE_OPEN
        self._file_number += 1
        return self._file_number.to_bytes(16, "little")


@pytest.fixture(
    params=[SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_DIALECT_302, SMB2_DIALECT_311],
    ids=["SMB2.0.2", "SMB2.1", "SMB3.0", "SMB3.0.2", "SMB3.1.1"],
)
def raw_connection(request):
    return _InMemorySMB3(request.param)


def _open_read_only(guarded):
    return guarded.create(
        7,
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


def test_postquery_close_sends_dialect_appropriate_credit_charge(raw_connection):
    guarded = smb_module._ReadOnlySMB2FileTransport(raw_connection)
    file_id = _open_read_only(guarded)

    packet_id = guarded.close_with_postquery(7, file_id)
    answer = guarded.recvSMB(packet_id)

    assert answer.isValidAnswer(STATUS_SUCCESS)
    request = raw_connection._NetBIOSSession.requests[0]
    expected_charge = 0 if raw_connection.getDialect() == SMB2_DIALECT_002 else 1
    assert request["CreditCharge"] == expected_charge
    assert raw_connection._Connection["SequenceWindow"] == 9


def test_postquery_close_does_not_reuse_message_id_for_following_request(raw_connection):
    guarded = smb_module._ReadOnlySMB2FileTransport(raw_connection)

    for _ in range(3):
        file_id = _open_read_only(guarded)
        packet_id = guarded.close_with_postquery(7, file_id)
        assert guarded.recvSMB(packet_id).isValidAnswer(STATUS_SUCCESS)
        guarded.forget_closed_file(file_id)
        # Real Impacket ECHO sends the next packet on the same SMB session.
        assert raw_connection.echo() is True

    requests = raw_connection._NetBIOSSession.requests
    assert [request["Command"] for request in requests] == [SMB2_CLOSE, SMB2_ECHO] * 3
    assert [request["MessageID"] for request in requests] == list(range(8, 14))
    assert raw_connection._Connection["SequenceWindow"] == 14
    assert not raw_connection._NetBIOSSession.responses


def test_postquery_close_rejects_packet_factory_that_changes_credit_charge(raw_connection):
    incorrect_charge = 1 if raw_connection.getDialect() == SMB2_DIALECT_002 else 0

    class CorruptedChargePacket(raw_connection.SMB_PACKET):
        def getData(self):
            encoded = super().getData()
            # Alter only the serialized charge: validating the object is insufficient.
            return encoded[:6] + incorrect_charge.to_bytes(2, "little") + encoded[8:]

    raw_connection.SMB_PACKET = CorruptedChargePacket
    guarded = smb_module._ReadOnlySMB2FileTransport(raw_connection)
    file_id = _open_read_only(guarded)

    with pytest.raises(smb_module.ReadOnlySMBViolation, match="canonical post-query CLOSE"):
        guarded.close_with_postquery(7, file_id)

    assert not raw_connection._NetBIOSSession.requests
    assert raw_connection._Connection["SequenceWindow"] == 8
