from types import SimpleNamespace

import pytest
from impacket.nt_errors import STATUS_LOGON_FAILURE, STATUS_NO_LOGON_SERVERS
from impacket.smbconnection import SessionError

from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib.util import Target
from man_spider.preflight import (
    AttemptOutcome,
    AuthenticationAttempt,
    PreflightStatus,
    _close_connection,
    _kerberos_remote_name,
    _observe_shares,
    authenticate_target,
    verify_credentials,
)


def options_for(*hosts):
    return SimpleNamespace(
        targets=[Target(host) for host in hosts],
        username="runuser",
        password="FixturePassword123!",
        domain="test.local",
        hash="",
        kerberos=False,
        aes_key=None,
        dc_ip=None,
    )


def ordered(_targets):
    """Keep test candidates in their declared order."""


def authenticator_for(outcomes, calls):
    def authenticate(target, _options):
        calls.append(target.host)
        outcome = outcomes[target.host]
        return AuthenticationAttempt(target, outcome, f"fixture {outcome.value}")

    return authenticate


def test_first_success_is_enough_and_stops_further_attempts():
    options = options_for("reject", "success", "unused")
    calls = []
    result = verify_credentials(
        options,
        authenticator=authenticator_for(
            {
                "reject": AttemptOutcome.REJECTED,
                "success": AttemptOutcome.SUCCESS,
                "unused": AttemptOutcome.REJECTED,
            },
            calls,
        ),
        shuffle=ordered,
    )

    assert result.status == PreflightStatus.SUCCESS
    assert calls == ["reject", "success"]
    assert result.definitive_attempts == 2


def test_three_definitive_rejections_fail_without_trying_more_targets():
    options = options_for("one", "two", "three", "unused")
    calls = []
    outcomes = {host: AttemptOutcome.REJECTED for host in ("one", "two", "three", "unused")}

    result = verify_credentials(
        options,
        authenticator=authenticator_for(outcomes, calls),
        shuffle=ordered,
    )

    assert result.status == PreflightStatus.CREDENTIALS_INVALID
    assert calls == ["one", "two", "three"]
    assert result.definitive_attempts == 3


def test_transport_failures_are_replaced_until_three_definitive_results():
    options = options_for("offline-1", "reject-1", "offline-2", "reject-2", "reject-3")
    calls = []
    outcomes = {
        "offline-1": AttemptOutcome.UNAVAILABLE,
        "reject-1": AttemptOutcome.REJECTED,
        "offline-2": AttemptOutcome.UNAVAILABLE,
        "reject-2": AttemptOutcome.REJECTED,
        "reject-3": AttemptOutcome.REJECTED,
    }

    result = verify_credentials(
        options,
        authenticator=authenticator_for(outcomes, calls),
        shuffle=ordered,
    )

    assert result.status == PreflightStatus.CREDENTIALS_INVALID
    assert calls == ["offline-1", "reject-1", "offline-2", "reject-2", "reject-3"]
    assert result.definitive_attempts == 3


def test_insufficient_definitive_results_is_not_reported_as_invalid_credentials():
    options = options_for("offline-1", "reject-1", "offline-2", "reject-2")
    calls = []
    outcomes = {
        "offline-1": AttemptOutcome.UNAVAILABLE,
        "reject-1": AttemptOutcome.REJECTED,
        "offline-2": AttemptOutcome.UNAVAILABLE,
        "reject-2": AttemptOutcome.REJECTED,
    }

    result = verify_credentials(
        options,
        authenticator=authenticator_for(outcomes, calls),
        shuffle=ordered,
    )

    assert result.status == PreflightStatus.VERIFICATION_UNAVAILABLE
    assert result.required_definitive_results == 3
    assert result.definitive_attempts == 2


def test_transport_replacements_stop_at_the_overridable_total_time_budget():
    options = options_for("offline-1", "offline-2", "offline-3", "unused")
    options.preflight_time_budget = 2
    now = [0.0]
    calls = []

    def unavailable(target, _options):
        calls.append(target.host)
        now[0] += 1.1
        return AuthenticationAttempt(target, AttemptOutcome.UNAVAILABLE, "fixture unavailable")

    result = verify_credentials(
        options,
        authenticator=unavailable,
        shuffle=ordered,
        clock=lambda: now[0],
    )

    assert calls == ["offline-1", "offline-2"]
    assert result.status == PreflightStatus.VERIFICATION_UNAVAILABLE
    assert result.budget_exhausted is True


def test_default_authenticator_receives_the_configured_per_target_timeout(monkeypatch):
    options = options_for("server")
    options.preflight_timeout = 7
    received = []

    def successful(target, _options, timeout):
        received.append(timeout)
        return AuthenticationAttempt(target, AttemptOutcome.SUCCESS, "fixture success")

    monkeypatch.setattr("man_spider.preflight.authenticate_target", successful)
    result = verify_credentials(options, shuffle=ordered)

    assert result.status == PreflightStatus.SUCCESS
    assert received == [7]


def test_fewer_than_three_targets_requires_all_of_them_to_reject():
    options = options_for("one", "two")
    calls = []
    outcomes = {"one": AttemptOutcome.REJECTED, "two": AttemptOutcome.REJECTED}

    result = verify_credentials(
        options,
        authenticator=authenticator_for(outcomes, calls),
        shuffle=ordered,
    )

    assert result.status == PreflightStatus.CREDENTIALS_INVALID
    assert result.required_definitive_results == 2
    assert calls == ["one", "two"]


def test_local_only_scan_does_not_authenticate(tmp_path):
    options = options_for()
    options.targets = [tmp_path]

    result = verify_credentials(options, authenticator=lambda *_: (_ for _ in ()).throw(AssertionError()))

    assert result.status == PreflightStatus.NOT_REQUIRED
    assert result.attempts == ()


def test_kerberos_ip_target_uses_unauthenticated_netbios_name_for_spn(monkeypatch):
    class FakeNetBIOS:
        @staticmethod
        def getnetbiosname(host):
            assert host == "192.0.2.10"
            return "FILESERVER"

    monkeypatch.setattr("man_spider.preflight.socket.gethostbyaddr", lambda _host: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr("man_spider.preflight.NetBIOS", FakeNetBIOS)

    assert _kerberos_remote_name(Target("192.0.2.10"), "TEST.LOCAL", timeout=10) == "FILESERVER.TEST.LOCAL"


def test_authenticator_does_not_fall_back_after_explicit_rejection(monkeypatch):
    calls = []

    class RejectingConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, username, password, **kwargs):
            calls.append((username, password, kwargs))
            raise SessionError(STATUS_LOGON_FAILURE)

        def close(self):
            pass

    monkeypatch.setattr("man_spider.preflight.SMBConnection", RejectingConnection)
    target = Target("server")
    attempt = authenticate_target(target, options_for("server"))

    assert attempt.outcome == AttemptOutcome.REJECTED
    assert len(calls) == 1
    assert calls[0][0:2] == ("runuser", "FixturePassword123!")


def test_server_guest_mapping_does_not_count_as_supplied_credential_success(monkeypatch):
    class GuestConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, *_args, **_kwargs):
            pass

        def isGuestSession(self):
            return 1

        def close(self):
            pass

    monkeypatch.setattr("man_spider.preflight.SMBConnection", GuestConnection)
    attempt = authenticate_target(Target("server"), options_for("server"))

    assert attempt.outcome == AttemptOutcome.REJECTED
    assert "Guest" in attempt.reason


def test_transport_error_is_reported_as_unavailable(monkeypatch):
    class OfflineConnection:
        def __init__(self, *_args, **_kwargs):
            raise ConnectionRefusedError("offline")

    monkeypatch.setattr("man_spider.preflight.SMBConnection", OfflineConnection)
    attempt = authenticate_target(Target("server"), options_for("server"))

    assert attempt.outcome == AttemptOutcome.UNAVAILABLE
    assert "offline" in attempt.reason


def test_missing_domain_logon_server_is_not_misreported_as_bad_credentials(monkeypatch):
    class UnavailableDomainConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, *_args, **_kwargs):
            raise SessionError(STATUS_NO_LOGON_SERVERS)

        def close(self):
            pass

    monkeypatch.setattr("man_spider.preflight.SMBConnection", UnavailableDomainConnection)
    attempt = authenticate_target(Target("server"), options_for("server"))

    assert attempt.outcome == AttemptOutcome.UNAVAILABLE


def test_successful_preflight_reuses_authenticated_session_to_observe_shares(monkeypatch):
    class SuccessfulConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, *_args, **_kwargs):
            pass

        def isGuestSession(self):
            return 0

        def listShares(self):
            return [
                {"shi1_netname": "Public\x00", "shi1_type": 0},
                {"shi1_netname": "IPC$\x00", "shi1_type": 3},
            ]

        def close(self):
            pass

    monkeypatch.setattr("man_spider.preflight.SMBConnection", SuccessfulConnection)
    monkeypatch.setattr("man_spider.preflight.read_only_list_shares", lambda connection: connection.listShares())
    attempt = authenticate_target(Target("server"), options_for("server"))

    assert attempt.outcome == AttemptOutcome.SUCCESS
    assert attempt.share_count == 2
    assert attempt.shares == (("Public", 0), ("IPC$", 3))
    assert attempt.share_observation_error is None


def test_share_observation_never_downgrades_read_only_violation(monkeypatch):
    violation = ReadOnlySMBViolation("unsafe RPC operation")
    connection = object()

    def rejected(actual):
        assert actual is connection
        raise violation

    monkeypatch.setattr("man_spider.preflight.read_only_list_shares", rejected)
    with pytest.raises(ReadOnlySMBViolation) as caught:
        _observe_shares(connection)
    assert caught.value is violation


@pytest.mark.parametrize("entrypoint", ["authenticate_target", "verify_credentials"])
@pytest.mark.parametrize("stage", ["login", "observation"])
def test_preflight_read_only_violation_closes_socket_without_smb_cleanup_or_more_targets(
    monkeypatch, entrypoint, stage
):
    violation = ReadOnlySMBViolation("unsafe SMB dependency")
    calls = []

    class GuardedConnection:
        def __init__(self, remote_name, remote_host, **kwargs):
            calls.append(("connect", remote_host))

        def login(self, *args, **kwargs):
            calls.append(("login",))
            if stage == "login":
                raise violation

        def isGuestSession(self):
            return 0

        def getSMBServer(self):
            return SimpleNamespace(get_socket=lambda: SimpleNamespace(close=self.close_socket))

        def close_socket(self):
            calls.append(("socket_close",))

        def close(self):
            calls.append(("normal_close",))
            raise AssertionError("Must not emit LOGOFF after a safety violation")

    def rejected_observation(connection):
        calls.append(("observe",))
        raise violation

    monkeypatch.setattr("man_spider.preflight.SMBConnection", GuardedConnection)
    monkeypatch.setattr("man_spider.preflight.read_only_list_shares", rejected_observation)
    options = options_for("first", "must-not-connect", "also-unused")
    with pytest.raises(ReadOnlySMBViolation) as caught:
        if entrypoint == "authenticate_target":
            authenticate_target(options.targets[0], options)
        else:
            verify_credentials(options, shuffle=ordered)
    assert caught.value is violation
    assert [call for call in calls if call[0] == "connect"] == [("connect", "first")]
    assert calls[-1] == ("socket_close",)
    assert ("normal_close",) not in calls
    assert calls.count(("login",)) == 1


def test_custom_authenticator_read_only_violation_stops_preflight_candidates():
    violation = ReadOnlySMBViolation("unsafe custom transport")
    calls = []

    def rejected(target, _options):
        calls.append(target.host)
        raise violation

    with pytest.raises(ReadOnlySMBViolation) as caught:
        verify_credentials(options_for("first", "unused"), authenticator=rejected, shuffle=ordered)
    assert caught.value is violation
    assert calls == ["first"]


def test_ordinary_share_access_failure_does_not_invalidate_authenticated_credentials(monkeypatch):
    calls = []

    class AuthenticatedConnection:
        def __init__(self, *args, **kwargs):
            pass

        def login(self, *args, **kwargs):
            pass

        def isGuestSession(self):
            return 0

        def close(self):
            calls.append("normal_close")

    def denied(connection):
        raise PermissionError("share enumeration denied")

    monkeypatch.setattr("man_spider.preflight.SMBConnection", AuthenticatedConnection)
    monkeypatch.setattr("man_spider.preflight.read_only_list_shares", denied)
    attempt = authenticate_target(Target("server"), options_for("server"))
    assert attempt.outcome == AttemptOutcome.SUCCESS
    assert attempt.share_count is None
    assert attempt.shares == ()
    assert "share enumeration denied" in attempt.share_observation_error
    assert calls == ["normal_close"]


@pytest.mark.parametrize("socket_error", [None, OSError("socket already gone"), ReadOnlySMBViolation("secondary guard")])
def test_preflight_cleanup_guard_is_preserved_and_socket_dropped(socket_error):
    original = ReadOnlySMBViolation("unsafe SMB cleanup")
    calls = []

    def close():
        calls.append("normal_close")
        raise original

    def socket_close():
        calls.append("socket_close")
        if socket_error is not None:
            raise socket_error

    connection = SimpleNamespace(
        close=close,
        getSMBServer=lambda: SimpleNamespace(get_socket=lambda: SimpleNamespace(close=socket_close)),
    )
    with pytest.raises(ReadOnlySMBViolation) as caught:
        _close_connection(connection)
    assert caught.value is original
    assert calls == ["normal_close", "socket_close"]


def test_ordinary_preflight_cleanup_failure_remains_best_effort():
    calls = []

    def close():
        calls.append("normal_close")
        raise OSError("ordinary close failure")

    _close_connection(SimpleNamespace(close=close))
    _close_connection(None)
    assert calls == ["normal_close"]


@pytest.mark.parametrize("login_succeeded", [False, True])
def test_cleanup_guard_stops_preflight_after_success_or_rejection(monkeypatch, login_succeeded):
    original = ReadOnlySMBViolation("unsafe cleanup")
    calls = []

    class CleanupGuardConnection:
        def __init__(self, remote_name, remote_host, **kwargs):
            calls.append(("connect", remote_host))

        def login(self, *args, **kwargs):
            if not login_succeeded:
                raise SessionError(STATUS_LOGON_FAILURE)

        def isGuestSession(self):
            return 0

        def close(self):
            calls.append(("normal_close",))
            raise original

        def getSMBServer(self):
            return SimpleNamespace(get_socket=lambda: SimpleNamespace(close=lambda: calls.append(("socket_close",))))

    monkeypatch.setattr("man_spider.preflight.SMBConnection", CleanupGuardConnection)
    monkeypatch.setattr("man_spider.preflight.read_only_list_shares", lambda _connection: [])
    with pytest.raises(ReadOnlySMBViolation) as caught:
        verify_credentials(options_for("first", "unused"), shuffle=ordered)
    assert caught.value is original
    assert calls == [("connect", "first"), ("normal_close",), ("socket_close",)]


@pytest.mark.parametrize("source", ["dns", "netbios"])
def test_kerberos_name_guard_stops_before_smb_authentication_or_next_host(monkeypatch, source):
    original = ReadOnlySMBViolation("unsafe name lookup")
    calls = []

    def reverse_name(host):
        calls.append(("dns", host))
        if source == "dns":
            raise original
        raise OSError("no reverse record")

    class GuardedNetBIOS:
        def __init__(self):
            self._NetBIOS__sock = SimpleNamespace(close=lambda: calls.append(("udp_close",)))

        def getnetbiosname(self, host):
            calls.append(("netbios", host))
            raise original

    def forbidden_smb_connection(*args, **kwargs):
        pytest.fail("Name-lookup guard must prevent SMB construction")

    monkeypatch.setattr("man_spider.preflight.socket.gethostbyaddr", reverse_name)
    monkeypatch.setattr("man_spider.preflight.NetBIOS", GuardedNetBIOS)
    monkeypatch.setattr("man_spider.preflight.SMBConnection", forbidden_smb_connection)
    options = options_for("192.0.2.1", "192.0.2.2")
    options.kerberos = True
    with pytest.raises(ReadOnlySMBViolation) as caught:
        verify_credentials(options, shuffle=ordered)
    assert caught.value is original
    expected = [("dns", "192.0.2.1")]
    if source == "netbios":
        expected.extend([("netbios", "192.0.2.1"), ("udp_close",)])
    assert calls == expected


def test_ordinary_kerberos_name_lookup_failure_keeps_original_fallback(monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("ordinary name-service failure")

    monkeypatch.setattr("man_spider.preflight.socket.gethostbyaddr", unavailable)
    monkeypatch.setattr("man_spider.preflight.NetBIOS", lambda: SimpleNamespace(getnetbiosname=unavailable))
    assert _kerberos_remote_name(Target("192.0.2.1"), "example.test", 1) == "192.0.2.1"
