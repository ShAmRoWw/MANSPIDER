"""Bounded authentication/reconnect policy without real authentication attempts."""

from types import SimpleNamespace

import pytest
from impacket.nmb import NetBIOSTimeout
from impacket.nt_errors import STATUS_LOGON_FAILURE, STATUS_PASSWORD_EXPIRED, STATUS_PASSWORD_MUST_CHANGE
from impacket.smbconnection import SessionError

from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib.smb import SMBClient
import man_spider.lib.smb as smb_module
import man_spider.preflight as preflight


def install_auth_model(monkeypatch, results):
    instances = []
    calls = []
    outcomes = iter(results)

    class Connection:
        def __init__(self, *_args, **_kwargs):
            self.closed = False
            self.socket_closed = False
            instances.append(self)

        def login(self, username, password, **kwargs):
            calls.append((username, password, kwargs))
            outcome = next(outcomes)
            if isinstance(outcome, BaseException):
                raise outcome

        def isGuestSession(self):
            return 0

        def close(self):
            self.closed = True

        def getSMBServer(self):
            return self

        def get_socket(self):
            def close():
                self.socket_closed = True
            return SimpleNamespace(close=close)

    monkeypatch.setattr(smb_module, "SMBConnection", Connection)
    return instances, calls


@pytest.mark.parametrize("code", [STATUS_PASSWORD_EXPIRED, STATUS_PASSWORD_MUST_CHANGE, STATUS_LOGON_FAILURE])
@pytest.mark.parametrize("fallback", [False, True])
def test_auth_rejection_never_retries_same_identity(monkeypatch, code, fallback):
    instances, calls = install_auth_model(monkeypatch, [SessionError(code)] * 3)
    client = SMBClient("audit", "operator", "fixture", "TEST", "")
    assert client.login(first_try=fallback) is False
    assert [call[0] for call in calls] == (["operator", "Guest", ""] if fallback else ["operator"])
    assert all(connection.closed for connection in instances)


@pytest.mark.parametrize("error", [BrokenPipeError, NetBIOSTimeout, ConnectionResetError, EOFError])
@pytest.mark.parametrize("fallback", [False, True])
def test_transport_error_has_one_retry_without_guest_fallback(monkeypatch, error, fallback):
    instances, calls = install_auth_model(monkeypatch, [error(), error()])
    client = SMBClient("audit", "operator", "fixture", "TEST", "")
    assert client.login(first_try=fallback) is None
    assert [call[0] for call in calls] == ["operator", "operator"]
    assert len(instances) == 2
    assert all(connection.socket_closed and not connection.closed for connection in instances)
    assert client.conn is None


def test_transient_auth_transport_error_recovers_once(monkeypatch):
    instances, calls = install_auth_model(monkeypatch, [BrokenPipeError(), None])
    client = SMBClient("audit", "operator", "fixture", "TEST", "")
    try:
        assert client.login() is True
        assert len(calls) == 2
        assert instances[0].socket_closed and not instances[0].closed
        assert not instances[1].closed
    finally:
        client.close()


def test_constructor_transport_failure_is_bounded(monkeypatch):
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(1)
        raise NetBIOSTimeout()
    monkeypatch.setattr(smb_module, "SMBConnection", unavailable)
    client = SMBClient("audit", "operator", "fixture", "TEST", "")
    assert client.login() is None
    assert len(calls) == 2


def test_error_formatting_never_reconnects(monkeypatch):
    client = SMBClient("audit", "operator", "fixture", "TEST", "")
    monkeypatch.setattr(client, "rebuild", lambda *_: pytest.fail("formatter attempted network recovery"))
    for error in (BrokenPipeError(), NetBIOSTimeout(), SessionError(STATUS_PASSWORD_EXPIRED)):
        assert client.handle_impacket_error(error) is error


@pytest.mark.parametrize("second_failure", [False, True])
def test_share_failure_rebuilds_at_most_once(monkeypatch, second_failure):
    instances, auth_calls = install_auth_model(monkeypatch, [None, None])
    client = SMBClient("audit", "operator", "fixture", "TEST", "")
    assert client.login()
    requests = []
    def enumerate_shares(connection):
        requests.append(connection)
        if len(requests) == 1 or second_failure:
            raise BrokenPipeError("fixture disconnected")
        return []
    monkeypatch.setattr(smb_module, "read_only_list_shares", enumerate_shares)
    try:
        assert client.shares == []
        assert client.shares == []  # A failed observation is cached until a new scan/worker.
        assert len(requests) == 2
        assert len(auth_calls) == 2  # Initial login + exactly one rebuild.
        assert instances[0].socket_closed and not instances[0].closed
        assert bool(client.share_listing_error) is second_failure
    finally:
        client.close()


def test_auth_guard_drops_socket_and_permanently_blocks_reconnect(monkeypatch):
    violation = ReadOnlySMBViolation("fixture safety fault")
    instances, calls = install_auth_model(monkeypatch, [violation])
    client = SMBClient("audit", "operator", "fixture", "TEST", "")
    with pytest.raises(ReadOnlySMBViolation) as caught:
        client.login()
    assert caught.value is violation
    assert len(calls) == 1
    assert instances[0].socket_closed
    assert not instances[0].closed  # No LOGOFF/CLOSE encoded after the violation.
    for attempt in (lambda: client.login(refresh=True), client.rebuild, lambda: list(client.ls("share", "")),
                    lambda: client.retrieve_file("share", "secret", lambda _: None)):
        with pytest.raises(ReadOnlySMBViolation):
            attempt()
    assert len(calls) == 1


def test_rpc_guard_does_not_rebuild_or_retry(monkeypatch):
    instances, calls = install_auth_model(monkeypatch, [None])
    client = SMBClient("audit", "operator", "fixture", "TEST", "")
    assert client.login()
    def refuse(_connection):
        raise ReadOnlySMBViolation("unapproved RPC operation")
    monkeypatch.setattr(smb_module, "read_only_list_shares", refuse)
    with pytest.raises(ReadOnlySMBViolation):
        _ = client.shares
    assert len(calls) == 1
    assert instances[0].socket_closed
    assert not instances[0].closed


def test_preflight_still_attempts_each_rejected_target_only_once(monkeypatch):
    instances, calls = install_auth_model(monkeypatch, [SessionError(STATUS_PASSWORD_EXPIRED)] * 3)
    monkeypatch.setattr(preflight, "SMBConnection", smb_module.SMBConnection)
    from man_spider.lib.util import Target
    options = SimpleNamespace(targets=[Target(name) for name in ("one", "two", "three", "unused")],
                              username="operator", password="fixture", domain="TEST", hash="", kerberos=False)
    result = preflight.verify_credentials(options, shuffle=lambda _: None)
    assert result.status == preflight.PreflightStatus.CREDENTIALS_INVALID
    assert len(instances) == len(calls) == 3


def test_per_target_retry_bound_does_not_add_global_auth_limit(monkeypatch):
    instances, calls = install_auth_model(monkeypatch, [SessionError(STATUS_LOGON_FAILURE)] * 5)
    for index in range(5):
        client = SMBClient(f"audit-{index}", "operator", "fixture", "TEST", "")
        assert client.login(first_try=False) is False
    assert len(calls) == 5
    assert all(connection.closed for connection in instances)
