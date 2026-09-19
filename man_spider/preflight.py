import ipaddress
import random
import socket
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable

from impacket.krb5.kerberosv5 import KerberosError
from impacket.nmb import NetBIOS, NetBIOSError, NetBIOSTimeout
from impacket.nt_errors import (
    STATUS_ACCESS_DENIED,
    STATUS_ACCOUNT_DISABLED,
    STATUS_ACCOUNT_EXPIRED,
    STATUS_ACCOUNT_LOCKED_OUT,
    STATUS_ACCOUNT_RESTRICTION,
    STATUS_ILL_FORMED_PASSWORD,
    STATUS_INVALID_ACCOUNT_NAME,
    STATUS_INVALID_LOGON_HOURS,
    STATUS_INVALID_LOGON_TYPE,
    STATUS_LOGON_FAILURE,
    STATUS_LOGON_NOT_GRANTED,
    STATUS_LOGON_TYPE_NOT_GRANTED,
    STATUS_NO_SUCH_USER,
    STATUS_PASSWORD_EXPIRED,
    STATUS_PASSWORD_MUST_CHANGE,
    STATUS_PASSWORD_RESTRICTION,
    STATUS_WRONG_PASSWORD,
)
from impacket.smb import SessionError as SMB1SessionError
from impacket.smbconnection import SMBConnection, SessionError

from man_spider.lib.util import Target
from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib.smb_rpc import read_only_list_shares


PREFLIGHT_TARGET_LIMIT = 3
DEFAULT_AUTH_TIMEOUT_SECONDS = 10
DEFAULT_PREFLIGHT_TIME_BUDGET_SECONDS = 300
DEFAULT_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


class AttemptOutcome(str, Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"


class PreflightStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    SUCCESS = "success"
    CREDENTIALS_INVALID = "credentials_invalid"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"


@dataclass(frozen=True)
class AuthenticationAttempt:
    target: Target
    outcome: AttemptOutcome
    reason: str
    share_count: int | None = None
    shares: tuple[tuple[str, int | None], ...] = ()
    share_observation_error: str | None = None


@dataclass(frozen=True)
class PreflightResult:
    status: PreflightStatus
    attempts: tuple[AuthenticationAttempt, ...]
    required_definitive_results: int
    budget_exhausted: bool = False

    @property
    def successful(self) -> bool:
        return self.status in (PreflightStatus.NOT_REQUIRED, PreflightStatus.SUCCESS)

    @property
    def definitive_attempts(self) -> int:
        return sum(attempt.outcome != AttemptOutcome.UNAVAILABLE for attempt in self.attempts)


AUTH_REJECTION_STATUS_CODES = {
    STATUS_ACCESS_DENIED,
    STATUS_ACCOUNT_DISABLED,
    STATUS_ACCOUNT_EXPIRED,
    STATUS_ACCOUNT_LOCKED_OUT,
    STATUS_ACCOUNT_RESTRICTION,
    STATUS_ILL_FORMED_PASSWORD,
    STATUS_INVALID_ACCOUNT_NAME,
    STATUS_INVALID_LOGON_HOURS,
    STATUS_INVALID_LOGON_TYPE,
    STATUS_LOGON_FAILURE,
    STATUS_LOGON_NOT_GRANTED,
    STATUS_LOGON_TYPE_NOT_GRANTED,
    STATUS_NO_SUCH_USER,
    STATUS_PASSWORD_EXPIRED,
    STATUS_PASSWORD_MUST_CHANGE,
    STATUS_PASSWORD_RESTRICTION,
    STATUS_WRONG_PASSWORD,
}

# RFC 4120/Kerberos errors that definitively reject the client identity or key.
KERBEROS_REJECTION_CODES = {6, 12, 18, 21, 23, 24, 31}


def _drop_connection_socket(connection: SMBConnection | None) -> None:
    """Discard TCP after a safety violation without emitting SMB cleanup."""

    if connection is None:
        return
    try:
        connection.getSMBServer().get_socket().close()
    except Exception:
        # Already handling a safety violation: preserve it even if the socket
        # is unavailable or its local close fails.
        pass


def _close_connection(connection: SMBConnection | None) -> None:
    if connection is None:
        return
    try:
        connection.close()
    except ReadOnlySMBViolation:
        _drop_connection_socket(connection)
        raise
    except Exception:
        pass


def _kerberos_remote_name(target: Target, domain: str, timeout: int) -> str:
    """Resolve an IP target to an SPN name without an SMB authentication attempt."""

    try:
        address = ipaddress.ip_address(target.host)
    except ValueError:
        return target.host

    try:
        reverse_name = socket.gethostbyaddr(target.host)[0].rstrip(".")
        if reverse_name and reverse_name != target.host:
            return reverse_name
    except (OSError, socket.herror):
        pass

    if address.version == 4:
        resolver = None
        try:
            resolver = NetBIOS()
            hostname = str(resolver.getnetbiosname(target.host) or "").strip().replace("\x00", "")
            dns_domain = str(domain or "").strip().strip(".")
            if hostname and dns_domain and "." not in hostname:
                return f"{hostname}.{dns_domain}"
            if hostname:
                return hostname
        except ReadOnlySMBViolation:
            # NetBIOS owns only a UDP socket, not an authenticated session.
            # Impacket has no public close method for this resolver object.
            if resolver is not None:
                try:
                    resolver_socket = getattr(resolver, "_NetBIOS__sock", None)
                    if resolver_socket is not None:
                        resolver_socket.close()
                except Exception:
                    pass
            raise
        except Exception:
            pass

    return target.host


def _split_ntlm_hash(value: str) -> tuple[str, str]:
    if ":" in value:
        lmhash, nthash = value.split(":", 1)
        return lmhash or DEFAULT_LM_HASH, nthash
    return DEFAULT_LM_HASH, value


def _observe_shares(connection: SMBConnection) -> tuple[int | None, tuple[tuple[str, int | None], ...], str | None]:
    """Reuse the authenticated preflight session for one bounded-target share observation."""

    try:
        response = read_only_list_shares(connection)
        shares = []
        for record in response:
            name = str(record["shi1_netname"]).rstrip("\x00")
            try:
                share_type = int(record["shi1_type"])
            except (KeyError, TypeError, ValueError):
                share_type = None
            shares.append((name, share_type))
        return len(shares), tuple(shares), None
    except ReadOnlySMBViolation:
        raise
    except Exception as exc:
        return None, (), f"{type(exc).__name__}: {exc}"


def _classify_authentication_error(target: Target, exc: Exception) -> AuthenticationAttempt:
    if isinstance(exc, KerberosError):
        try:
            error_code = exc.getErrorCode()
        except Exception:
            error_code = None
        outcome = AttemptOutcome.REJECTED if error_code in KERBEROS_REJECTION_CODES else AttemptOutcome.UNAVAILABLE
        return AuthenticationAttempt(target, outcome, str(exc))

    if isinstance(exc, (SessionError, SMB1SessionError)):
        try:
            error_code = exc.getErrorCode()
        except Exception:
            error_code = None
        outcome = AttemptOutcome.REJECTED if error_code in AUTH_REJECTION_STATUS_CODES else AttemptOutcome.UNAVAILABLE
        return AuthenticationAttempt(target, outcome, str(exc))

    if isinstance(exc, (NetBIOSError, NetBIOSTimeout, TimeoutError, ConnectionError, OSError)):
        return AuthenticationAttempt(target, AttemptOutcome.UNAVAILABLE, str(exc))

    return AuthenticationAttempt(target, AttemptOutcome.UNAVAILABLE, f"{type(exc).__name__}: {exc}")


def authenticate_target(target: Target, options, timeout: int = DEFAULT_AUTH_TIMEOUT_SECONDS) -> AuthenticationAttempt:
    """Attempt supplied credentials exactly once, without Guest/null fallback."""

    connection = None
    try:
        remote_name = target.host
        if options.kerberos:
            remote_name = _kerberos_remote_name(target, options.domain, timeout)

        connection = SMBConnection(remote_name, target.host, sess_port=target.port, timeout=timeout)
        if options.kerberos:
            lmhash, nthash = _split_ntlm_hash(options.hash) if options.hash else ("", "")
            connection.kerberosLogin(
                options.username,
                options.password,
                options.domain,
                lmhash,
                nthash,
                options.aes_key or "",
                kdcHost=options.dc_ip,
            )
        elif options.hash and not options.password:
            lmhash, nthash = _split_ntlm_hash(options.hash)
            connection.login(options.username, "", domain=options.domain, lmhash=lmhash, nthash=nthash)
        else:
            connection.login(options.username, options.password, domain=options.domain)

        if connection.isGuestSession() != 0:
            return AuthenticationAttempt(
                target,
                AttemptOutcome.REJECTED,
                "server mapped the supplied credentials to a Guest session",
            )
        share_count, shares, observation_error = _observe_shares(connection)
        return AuthenticationAttempt(
            target,
            AttemptOutcome.SUCCESS,
            "supplied credentials authenticated",
            share_count=share_count,
            shares=shares,
            share_observation_error=observation_error,
        )
    except ReadOnlySMBViolation:
        # The normal high-level close sends LOGOFF. A safety violation must
        # instead discard TCP without emitting any further SMB request.
        if connection is not None:
            _drop_connection_socket(connection)
            connection = None
        raise
    except Exception as exc:
        return _classify_authentication_error(target, exc)
    finally:
        _close_connection(connection)


def verify_credentials(
    options,
    *,
    authenticator: Callable[[Target, object], AuthenticationAttempt] | None = None,
    shuffle: Callable[[list[Target]], None] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> PreflightResult:
    """Verify credentials on up to three definitive, randomly ordered SMB targets."""

    candidates = [target for target in options.targets if not isinstance(target, Path)]
    if not candidates:
        return PreflightResult(PreflightStatus.NOT_REQUIRED, (), 0)

    if shuffle is None:
        random.SystemRandom().shuffle(candidates)
    else:
        shuffle(candidates)

    required = min(PREFLIGHT_TARGET_LIMIT, len(candidates))
    attempts: list[AuthenticationAttempt] = []
    rejections = 0
    started = clock()
    budget = getattr(options, "preflight_time_budget", DEFAULT_PREFLIGHT_TIME_BUDGET_SECONDS)
    timeout = getattr(options, "preflight_timeout", DEFAULT_AUTH_TIMEOUT_SECONDS)
    budget_exhausted = False

    for target in candidates:
        if attempts and clock() - started >= budget:
            budget_exhausted = True
            break
        try:
            if authenticator is None:
                attempt = authenticate_target(target, options, timeout=timeout)
            else:
                attempt = authenticator(target, options)
        except ReadOnlySMBViolation:
            raise
        except Exception as exc:
            attempt = AuthenticationAttempt(target, AttemptOutcome.UNAVAILABLE, f"{type(exc).__name__}: {exc}")
        attempts.append(attempt)

        if attempt.outcome == AttemptOutcome.SUCCESS:
            return PreflightResult(PreflightStatus.SUCCESS, tuple(attempts), required)
        if attempt.outcome == AttemptOutcome.REJECTED:
            rejections += 1
            if rejections == required:
                return PreflightResult(PreflightStatus.CREDENTIALS_INVALID, tuple(attempts), required)

    return PreflightResult(
        PreflightStatus.VERIFICATION_UNAVAILABLE,
        tuple(attempts),
        required,
        budget_exhausted=budget_exhausted,
    )
