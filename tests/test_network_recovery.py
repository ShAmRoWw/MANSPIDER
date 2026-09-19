"""Offline network recovery: pacing, wire provenance, and error persistence."""

import pytest
from impacket.nmb import NetBIOSTimeout
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE
from impacket.smbconnection import SessionError

from man_spider.lib import smb as smb_module
from man_spider.lib.errors import (
    DFSReferralBlocked,
    FileListError,
    NETWORK_UNAVAILABLE_MARKER,
    ReadOnlySMBViolation,
    is_network_unavailable,
    mark_network_unavailable,
    network_error_reason,
)
from man_spider.lib.network_recovery import NetworkRecovery
from man_spider.lib.smb import SMBClient, _SMBTransportGroup
from man_spider.lib.smb_transport import transport_state
from test_smb_auth_recovery import install_auth_model
from test_smb_transport_failure import MemoryConnection, installed


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay + 1e-9


def recovery(endpoint="fixture:445"):
    clock = Clock()
    return NetworkRecovery(endpoint, clock=clock, sleeper=clock.sleep), clock


def test_backoff_is_bounded_interruptible_and_resets_without_traffic():
    gate, clock = recovery()
    checks = []
    gate.wait(lambda: checks.append(1))
    assert not clock.sleeps and not checks
    for expected in (1, 2, 4, 8, 16, 30, 30):
        start = clock.now
        gate.failed()
        gate.wait(lambda: checks.append(1))
        assert clock.now - start == pytest.approx(expected)
        assert max(clock.sleeps) <= 0.2
    gate.succeeded()
    start = clock.now
    gate.wait(lambda: None)
    assert clock.now == start and gate.failures == 0
    gate.failed()
    assert gate.not_before - clock.now == pytest.approx(1)


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(), ReadOnlySMBViolation("stop")])
def test_pause_obeys_cancellation_and_safety_before_any_reconnect(error):
    gate, clock = recovery()
    gate.failed()
    def stop():
        raise error
    with pytest.raises(type(error)) as caught:
        gate.wait(stop)
    assert caught.value is error
    assert clock.sleeps == []


def test_cancellation_during_sleep_is_not_swallowed():
    def stop(_delay):
        raise KeyboardInterrupt
    gate = NetworkRecovery("fixture", clock=lambda: 0, sleeper=stop)
    gate.failed()
    with pytest.raises(KeyboardInterrupt):
        gate.wait(lambda: None)


@pytest.mark.parametrize("error", [TimeoutError(), EOFError(), BrokenPipeError(), NetBIOSTimeout()])
def test_same_exception_class_is_retryable_only_at_wire_boundary(error):
    assert not is_network_unavailable(error)
    connection = MemoryConnection({"read": error})
    client = installed(connection)
    gate, _clock = recovery()
    client._network_recovery = gate
    with pytest.raises(type(error)) as caught:
        client.retrieve_file("share", "secret.txt", lambda _chunk: None)
    assert caught.value is error
    assert is_network_unavailable(error)
    assert network_error_reason(error).startswith(NETWORK_UNAVAILABLE_MARKER)
    assert gate.failures == 1
    assert client.conn is None


@pytest.mark.parametrize("error", [TimeoutError(), EOFError(), BrokenPipeError(), NetBIOSTimeout()])
def test_local_callback_exception_never_becomes_retryable(error):
    connection = MemoryConnection()
    client = installed(connection)
    gate, _clock = recovery()
    client._network_recovery = gate
    def reject(_chunk):
        raise error
    with pytest.raises(type(error)):
        client.retrieve_file("share", "secret.txt", reject)
    assert not is_network_unavailable(error)
    assert not transport_state(connection).failed
    assert gate.failures == 0
    client.close()


@pytest.mark.parametrize("error", [
    SessionError(STATUS_ACCESS_DENIED), SessionError(STATUS_LOGON_FAILURE),
    DFSReferralBlocked("scope"), ReadOnlySMBViolation("guard"), KeyboardInterrupt(), SystemExit(),
])
def test_server_refusals_scope_and_control_do_not_get_wire_retry(error):
    connection = MemoryConnection({"read": error})
    client = installed(connection)
    with pytest.raises(type(error)):
        client.retrieve_file("share", "secret.txt", lambda _chunk: None)
    assert not is_network_unavailable(error)
    assert client._network_recovery.failures == 0
    client.close()


def test_local_error_with_network_failure_during_cleanup_is_not_retried():
    local_error = TimeoutError("local spool unavailable")
    connection = MemoryConnection({"postquery-receive": NetBIOSTimeout()})
    client = installed(connection)
    def reject(_chunk):
        raise local_error
    with pytest.raises(TimeoutError) as caught:
        client.retrieve_file("share", "secret.txt", reject)
    assert caught.value is local_error
    assert not is_network_unavailable(local_error)
    assert client.conn is None


def test_login_retries_are_paced_without_extra_identity_attempts(monkeypatch):
    _instances, calls = install_auth_model(monkeypatch, [NetBIOSTimeout(), NetBIOSTimeout(), None])
    client = SMBClient("fixture", "user", "fixture", "domain", "")
    client._network_recovery, clock = recovery()
    assert client.login() is None
    assert len(calls) == 2
    assert clock.now == pytest.approx(1)
    assert is_network_unavailable(client.last_connection_error)
    assert client.login(first_try=False) is True
    assert len(calls) == 3
    assert clock.now == pytest.approx(3)
    assert client.last_connection_error is None
    # Mere authentication must not reset failures of actual data operations.
    assert client._network_recovery.failures == 2
    client.close()


def test_auth_refusal_does_not_pause_or_mark(monkeypatch):
    _instances, calls = install_auth_model(monkeypatch, [SessionError(STATUS_LOGON_FAILURE)])
    client = SMBClient("fixture", "user", "fixture", "domain", "")
    client._network_recovery, clock = recovery()
    assert client.login(first_try=False) is False
    assert len(calls) == 1 and not clock.sleeps
    assert not is_network_unavailable(client.last_connection_error)


def test_connect_failure_survives_restore_and_listing_wrappers(monkeypatch):
    calls = []
    def unavailable(*_args, **_kwargs):
        calls.append(1)
        raise ConnectionRefusedError("offline fixture")
    monkeypatch.setattr(smb_module, "SMBConnection", unavailable)
    client = SMBClient("fixture", "user", "fixture", "domain", "")
    client._network_recovery, clock = recovery()
    with pytest.raises(FileListError) as caught:
        list(client.ls("share", "folder"))
    assert len(calls) == 2 and clock.now == pytest.approx(1)
    assert is_network_unavailable(caught.value)
    assert str(caught.value).startswith(NETWORK_UNAVAILABLE_MARKER)
    assert caught.value.__cause__ is not None


def test_successful_read_resets_failure_counter():
    connection = MemoryConnection()
    client = installed(connection)
    gate, _clock = recovery()
    client._network_recovery = gate
    gate.failed()
    assert client.retrieve_file("share", "file.txt", lambda _chunk: None) is None
    assert gate.failures == 0
    client.close()


def test_healthy_reads_have_identical_wire_operations_with_recovery_enabled():
    observations = []
    for enabled in (False, True):
        connection = MemoryConnection()
        client = installed(connection)
        gate, clock = recovery()
        client._network_recovery = gate
        if not enabled:
            gate.succeeded = lambda: None
        for _index in range(3):
            client.retrieve_file("share", "file.txt", lambda _chunk: None)
        client.close()
        assert not clock.sleeps
        observations.append(connection.events)
    assert observations[0] == observations[1]
    assert observations[1].count("create") == 3
    assert observations[1].count("read") == 12


def test_same_endpoint_dfs_clients_share_gate_but_other_endpoints_do_not():
    group = _SMBTransportGroup()
    def make(host, port=445):
        return SMBClient(host, "u", "p", "d", "", port=port, transport_group=group)
    first, same, other, other_port = make("fixture"), make("FIXTURE"), make("other"), make("fixture", 1445)
    assert first._network_recovery is same._network_recovery
    assert first._network_recovery is not other._network_recovery
    assert first._network_recovery is not other_port._network_recovery
    first._network_recovery.failed()
    assert same._network_recovery.failures == 1
    assert other._network_recovery.failures == other_port._network_recovery.failures == 0


def test_exception_text_cannot_claim_network_provenance():
    error = RuntimeError(f"{NETWORK_UNAVAILABLE_MARKER} TimeoutError from a local parser")
    assert not is_network_unavailable(error)
    assert not network_error_reason(error).startswith(NETWORK_UNAVAILABLE_MARKER)


def test_new_wire_failure_during_handled_access_denial_keeps_network_provenance():
    failure = TimeoutError("transport lost during permitted fallback")
    connection = MemoryConnection({"read": failure})
    client = installed(connection)
    try:
        raise SessionError(STATUS_ACCESS_DENIED)
    except SessionError as previous:
        with pytest.raises(TimeoutError):
            client.retrieve_file("share", "secret.txt", lambda _chunk: None)
        assert failure.__context__ is previous
    assert is_network_unavailable(failure)
    assert network_error_reason(failure).startswith(NETWORK_UNAVAILABLE_MARKER)
    assert client._network_recovery.failures == 1
    client.close()


def test_safety_scope_and_interrupts_cannot_be_manually_tagged():
    for error in (ReadOnlySMBViolation("guard"), DFSReferralBlocked("scope"), KeyboardInterrupt(),
                  SessionError(STATUS_ACCESS_DENIED)):
        mark_network_unavailable(error)
        assert not is_network_unavailable(error)
