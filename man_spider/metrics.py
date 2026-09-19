"""Low-overhead, passive SMB client telemetry and reporting.

The collector deliberately observes only SMB operations MANSPIDER already
performs.  It does not issue probes and it never changes scan concurrency.
"""

from __future__ import annotations

import json
import math
import re
from bisect import bisect_left
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic_ns

from impacket import nt_errors, system_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.smb import SessionError as SMB1SessionError

from man_spider.error_policy import is_network_access_denied
from man_spider.path_safety import require_local_write_path


METRICS_SCHEMA_VERSION = 1
DEFAULT_FLUSH_INTERVAL_SECONDS = 5.0
WARNING_WINDOW_SECONDS = 10.0
WARNING_CONSECUTIVE_WINDOWS = 2
WARNING_COOLDOWN_SECONDS = 60.0

# Histogram aggregation keeps memory and IPC volume bounded independently of
# scan size.  Percentiles in reports are conservative bucket upper bounds.
LATENCY_BUCKETS_MS = (
    0.25,
    0.5,
    1.0,
    2.0,
    4.0,
    8.0,
    16.0,
    32.0,
    64.0,
    125.0,
    250.0,
    500.0,
    1_000.0,
    2_000.0,
    5_000.0,
    10_000.0,
    30_000.0,
)
LATENCY_BUCKETS_NS = tuple(int(value * 1_000_000) for value in LATENCY_BUCKETS_MS)
ERROR_KINDS = ("timeout", "disconnect", "authentication", "access_denied", "other")
OPERATION_NAMES = ("connect", "share_list", "directory_list", "file_read", "dfs_referral")

_STATUS_NAMES = {
    "timeout": ("STATUS_TIMEOUT", "STATUS_IO_TIMEOUT"),
    "disconnect": (
        "STATUS_PORT_DISCONNECTED", "STATUS_CONNECTION_DISCONNECTED", "STATUS_CONNECTION_RESET",
        "STATUS_CONNECTION_ABORTED", "STATUS_NETWORK_NAME_DELETED", "STATUS_USER_SESSION_DELETED",
        "STATUS_NETWORK_SESSION_EXPIRED", "STATUS_PIPE_BROKEN", "STATUS_PIPE_DISCONNECTED",
        "STATUS_PIPE_CLOSING",
    ),
    "authentication": (
        "STATUS_LOGON_FAILURE", "STATUS_LOGON_NOT_GRANTED", "STATUS_LOGON_TYPE_NOT_GRANTED",
        "STATUS_WRONG_PASSWORD", "STATUS_PASSWORD_EXPIRED", "STATUS_PASSWORD_MUST_CHANGE",
        "STATUS_PASSWORD_RESTRICTION", "STATUS_ILL_FORMED_PASSWORD", "STATUS_ACCOUNT_DISABLED",
        "STATUS_ACCOUNT_EXPIRED", "STATUS_ACCOUNT_LOCKED_OUT", "STATUS_ACCOUNT_RESTRICTION",
        "STATUS_INVALID_ACCOUNT_NAME", "STATUS_INVALID_LOGON_HOURS", "STATUS_INVALID_LOGON_TYPE",
        "STATUS_NO_SUCH_USER", "STATUS_NO_LOGON_SERVERS",
    ),
    "access_denied": (
        "STATUS_ACCESS_DENIED", "STATUS_NETWORK_ACCESS_DENIED", "STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT",
        "STATUS_ACCESS_DISABLED_BY_POLICY_OTHER", "STATUS_ACCESS_DISABLED_BY_POLICY_PATH",
        "STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER", "STATUS_CTX_WINSTATION_ACCESS_DENIED",
        "STATUS_VHD_PARENT_VHD_ACCESS_DENIED",
    ),
}
_RPC_STATUS_NAMES = {
    "timeout": ("ERROR_SEM_TIMEOUT", "ERROR_TIMEOUT"),
    "disconnect": (
        "ERROR_NETNAME_DELETED", "ERROR_BROKEN_PIPE", "ERROR_PIPE_NOT_CONNECTED",
        "ERROR_CONNECTION_ABORTED", "ERROR_CONNECTION_REFUSED", "RPC_S_SERVER_UNAVAILABLE",
    ),
    "authentication": (
        "ERROR_LOGON_FAILURE", "ERROR_PASSWORD_EXPIRED", "ERROR_PASSWORD_MUST_CHANGE",
        "ERROR_ACCOUNT_DISABLED", "ERROR_ACCOUNT_EXPIRED", "ERROR_ACCOUNT_LOCKED_OUT",
        "ERROR_ACCOUNT_RESTRICTION", "ERROR_INVALID_LOGON_HOURS", "ERROR_LOGON_TYPE_NOT_GRANTED",
        "ERROR_NO_SUCH_USER", "ERROR_NO_LOGON_SERVERS", "ERROR_INVALID_PASSWORD",
    ),
    "access_denied": ("ERROR_ACCESS_DENIED", "RPC_S_ACCESS_DENIED"),
}
_NT_STATUS_KINDS = {
    getattr(nt_errors, name): kind
    for kind, names in _STATUS_NAMES.items() for name in names if hasattr(nt_errors, name)
}
_RPC_STATUS_KINDS = {
    getattr(system_errors, name): kind
    for kind, names in _RPC_STATUS_NAMES.items() for name in names if hasattr(system_errors, name)
}
_LEGACY_STATUS_KINDS = {
    name.casefold(): kind for names_by_kind in (_STATUS_NAMES, _RPC_STATUS_NAMES)
    for kind, names in names_by_kind.items() for name in names
}
_LEGACY_STATUS_KINDS["nt_status_access_denied"] = "access_denied"
_LEGACY_STATUS_RE = re.compile(r"\A([a-z][a-z0-9_]+)(?=$| - |:|\()")
_LEGACY_PREFIX_RE = re.compile(
    r"\A(?:(?:[a-z][a-z0-9_]{1,15} )?sessionerror|csessionerror|dcerpcsessionerror|"
    r"dcerpc runtime error|filelisterror|fileretrievalerror|runtimeerror|oserror):\s*"
)
_LEGACY_CODE_RE = re.compile(r"\Acode:\s*(0x[0-9a-f]{1,8}|[0-9]{1,10})\s*-\s*")
_LEGACY_RETRIEVAL_RE = re.compile(r'\Aerror retrieving file "[^"\r\n]*": ([^"\r\n]*)\Z')
_LEGACY_TRANSPORT_RE = re.compile(
    r"\A(brokenpipeerror|connectionreseterror|connectionabortederror|connectionrefusederror|"
    r"connectionerror|eoferror|netbioserror|timeouterror|netbiostimeout):"
)
_LEGACY_DIAGNOSTICS = {
    "timeout": frozenset(("timeout", "timed out", "connection timed out", "operation timed out")),
    "disconnect": frozenset((
        "broken pipe", "connection reset", "connection reset by peer", "connection aborted",
        "connection closed", "network name deleted",
    )),
    "authentication": frozenset((
        "logon failure", "logon_fail", "password_expired", "account_locked", "locked_out",
        "no_logon_servers", "mapped to a guest session",
        "supplied credentials were mapped to a guest session",
    )),
    "access_denied": frozenset(("access denied", "access_denied")),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def endpoint_name(host: str, port: int) -> str:
    host = str(host)
    if port == 445:
        return host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}"


def _typed_smb_error(error: BaseException) -> str | None:
    """None means no structured diagnosis; 'other' is an authoritative code."""

    if isinstance(error, (TimeoutError, NetBIOSTimeout)):
        return "timeout"
    if isinstance(error, (ConnectionError, EOFError, NetBIOSError)):
        return "disconnect"
    if isinstance(error, OSError) and error.errno is not None:
        return "other"
    if isinstance(error, SMB1SessionError) and not error.nt_status:
        key = (error.get_error_class(), error.get_error_code())
        return {
            (1, SMB1SessionError.ERRnoaccess): "access_denied",
            (2, SMB1SessionError.ERRaccess): "access_denied",
            (1, SMB1SessionError.ERRlogonfailure): "authentication",
            (2, SMB1SessionError.ERRbadpw): "authentication",
            (2, SMB1SessionError.ERRtimeout): "timeout",
            (1, SMB1SessionError.ERRnetnamedel): "disconnect",
            (1, SMB1SessionError.ERRpipeclosing): "disconnect",
            (1, SMB1SessionError.ERRnotconnected): "disconnect",
        }.get(key, "other")
    for name in ("getErrorCode", "get_error_code"):
        getter = getattr(error, name, None)
        if not callable(getter):
            continue
        try:
            code = getter()
        except Exception:
            return "other"
        if isinstance(code, int) and not isinstance(code, bool):
            code &= 0xFFFFFFFF
            if isinstance(error, DCERPCException) and code in _RPC_STATUS_KINDS:
                return _RPC_STATUS_KINDS[code]
            return _NT_STATUS_KINDS.get(code, "other")
    return None


def _legacy_smb_error(text: str) -> str:
    """Accept diagnostic syntax, not words contained in a resource path."""

    text = text.casefold().strip()
    rpc_diagnostic = False
    for _ in range(8):
        retrieval = _LEGACY_RETRIEVAL_RE.fullmatch(text)
        if retrieval is not None:
            text = retrieval.group(1).strip()
            continue
        transport = _LEGACY_TRANSPORT_RE.match(text)
        if transport is not None:
            return "timeout" if transport.group(1) in ("timeouterror", "netbiostimeout") else "disconnect"
        prefix = _LEGACY_PREFIX_RE.match(text)
        if prefix is None:
            break
        rpc_diagnostic = rpc_diagnostic or text.startswith("dcerpc")
        text = text[prefix.end():]
    numeric = _LEGACY_CODE_RE.match(text)
    if numeric is not None:
        value = numeric.group(1)
        code = int(value, 16 if value.startswith("0x") else 10)
        if rpc_diagnostic and code in _RPC_STATUS_KINDS:
            return _RPC_STATUS_KINDS[code]
        return _NT_STATUS_KINDS.get(code, "other")
    status = _LEGACY_STATUS_RE.match(text)
    if status is not None and status.group(1) in _LEGACY_STATUS_KINDS:
        return _LEGACY_STATUS_KINDS[status.group(1)]
    if is_network_access_denied(text):
        return "access_denied"
    for kind, diagnostics in _LEGACY_DIAGNOSTICS.items():
        if text in diagnostics:
            return kind
    return "other"


def classify_smb_error(error: BaseException | None) -> str:
    """Prefer structured errors/causes; never retain paths or credentials.

    An unknown numeric status must not become a different category merely
    because its diagnostic quotes a filename containing a familiar error word.
    Only the explicit cause (or unsuppressed implicit context) is followed.
    """

    chain = []
    seen = set()
    current = error
    while isinstance(current, BaseException) and id(current) not in seen and len(chain) < 16:
        seen.add(id(current))
        chain.append(current)
        try:
            kind = _typed_smb_error(current)
        except Exception:
            # An unusable structured diagnostic is unknown, not an invitation
            # to guess from its possibly misleading string representation.
            return "other"
        if kind is not None:
            return kind
        if type(current) is Exception and current.args == ("No answer!",) and current.__traceback__ is not None:
            # Wildcard negotiation suppresses its typed receive errors. The
            # transport classifier requires real dependency provenance; text
            # alone must not recategorize a local error or a server refusal.
            # Defer the lib import: its legacy package initializer imports the
            # scanner, whereas importing/reporting passive metrics must not.
            from man_spider.lib.smb_transport import is_transport_error

            if is_transport_error(current):
                return "disconnect"
        current = current.__cause__
        if current is None and not chain[-1].__suppress_context__:
            current = chain[-1].__context__
    if current is not None:
        return "other"
    # Prefer the deepest diagnostic over a generic wrapper which may embed a
    # resource path. Never inspect text at all when a typed cause was available.
    for current in reversed(chain):
        try:
            kind = _legacy_smb_error(str(current))
        except Exception:
            # Broken __str__ implementations must not break passive telemetry.
            continue
        if kind != "other":
            return kind
    return "other"


def empty_operation() -> dict:
    return {
        "attempts": 0,
        "successes": 0,
        "failures": 0,
        "duration_ns": 0,
        "max_duration_ns": 0,
        "bytes": 0,
        "items": 0,
        "latency_buckets": [0] * (len(LATENCY_BUCKETS_NS) + 1),
        "errors": {kind: 0 for kind in ERROR_KINDS},
    }


def merge_operation(destination: dict, source: dict) -> None:
    for name in ("attempts", "successes", "failures", "duration_ns", "bytes", "items"):
        destination[name] += int(source.get(name, 0))
    destination["max_duration_ns"] = max(
        destination["max_duration_ns"],
        int(source.get("max_duration_ns", 0)),
    )
    source_buckets = source.get("latency_buckets", ())
    for index in range(min(len(destination["latency_buckets"]), len(source_buckets))):
        destination["latency_buckets"][index] += int(source_buckets[index])
    source_errors = source.get("errors", {})
    for kind in ERROR_KINDS:
        destination["errors"][kind] += int(source_errors.get(kind, 0))


def merge_operations(destination: dict, source: dict) -> None:
    for operation, values in source.items():
        current = destination.setdefault(operation, empty_operation())
        merge_operation(current, values)


def histogram_percentile(operation: dict, percentile: float) -> float | None:
    attempts = int(operation.get("attempts", 0))
    if attempts <= 0:
        return None
    rank = max(1, math.ceil(attempts * percentile))
    cumulative = 0
    buckets = operation.get("latency_buckets", ())
    for index, count in enumerate(buckets):
        cumulative += int(count)
        if cumulative < rank:
            continue
        if index < len(LATENCY_BUCKETS_MS):
            return LATENCY_BUCKETS_MS[index]
        return round(int(operation.get("max_duration_ns", 0)) / 1_000_000, 3)
    return round(int(operation.get("max_duration_ns", 0)) / 1_000_000, 3)


def operation_report(operation: dict) -> dict:
    attempts = int(operation["attempts"])
    duration_ns = int(operation["duration_ns"])
    failures = int(operation["failures"])
    transferred = int(operation["bytes"])
    duration_seconds = duration_ns / 1_000_000_000
    return {
        "attempts": attempts,
        "successes": int(operation["successes"]),
        "failures": failures,
        "failure_rate": round(failures / attempts, 6) if attempts else 0.0,
        "duration_seconds": round(duration_seconds, 6),
        "latency_ms": {
            "mean": round(duration_ns / attempts / 1_000_000, 3) if attempts else None,
            "p50_upper_bound": histogram_percentile(operation, 0.50),
            "p95_upper_bound": histogram_percentile(operation, 0.95),
            "p99_upper_bound": histogram_percentile(operation, 0.99),
            "maximum": round(int(operation["max_duration_ns"]) / 1_000_000, 3) if attempts else None,
        },
        "bytes_transferred": transferred,
        "items_returned": int(operation["items"]),
        "average_transfer_mib_per_second": (
            round(transferred / 1_048_576 / duration_seconds, 3) if transferred and duration_seconds > 0 else None
        ),
        "errors": {kind: int(operation["errors"][kind]) for kind in ERROR_KINDS},
    }


class SMBMetricsEmitter:
    """Process-local aggregation which emits one small snapshot periodically."""

    def __init__(
        self,
        host: str,
        port: int,
        sink,
        *,
        flush_interval_seconds: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
        clock=monotonic_ns,
    ):
        self.host = str(host)
        self.port = int(port)
        self.sink = sink
        self.clock = clock
        self.flush_interval_ns = max(0, int(flush_interval_seconds * 1_000_000_000))
        self.last_flush_ns = self.clock()
        self.operations = {}
        self.sessions_opened = 0
        self.sessions_closed = 0
        self.reconnects = 0
        self.first_started_ns = None
        self.last_ended_ns = None

    def started(self) -> int:
        return self.clock()

    def record_operation(
        self,
        operation: str,
        started_ns: int,
        *,
        error: BaseException | None = None,
        bytes_transferred: int = 0,
        items: int = 0,
    ) -> None:
        ended_ns = self.clock()
        duration_ns = max(0, ended_ns - int(started_ns))
        values = self.operations.setdefault(str(operation), empty_operation())
        values["attempts"] += 1
        values["duration_ns"] += duration_ns
        values["max_duration_ns"] = max(values["max_duration_ns"], duration_ns)
        values["bytes"] += max(0, int(bytes_transferred))
        values["items"] += max(0, int(items))
        values["latency_buckets"][bisect_left(LATENCY_BUCKETS_NS, duration_ns)] += 1
        if error is None:
            values["successes"] += 1
        else:
            values["failures"] += 1
            values["errors"][classify_smb_error(error)] += 1
        self._touch(started_ns, ended_ns)
        self.flush(now_ns=ended_ns)

    def record_session_opened(self) -> None:
        now_ns = self.clock()
        self.sessions_opened += 1
        self._touch(now_ns, now_ns)
        self.flush(now_ns=now_ns)

    def record_session_closed(self) -> None:
        now_ns = self.clock()
        self.sessions_closed += 1
        self._touch(now_ns, now_ns)
        self.flush(now_ns=now_ns)

    def record_reconnect(self) -> None:
        now_ns = self.clock()
        self.reconnects += 1
        self._touch(now_ns, now_ns)
        self.flush(now_ns=now_ns)

    def _touch(self, started_ns: int, ended_ns: int) -> None:
        if self.first_started_ns is None:
            self.first_started_ns = int(started_ns)
        else:
            self.first_started_ns = min(self.first_started_ns, int(started_ns))
        if self.last_ended_ns is None:
            self.last_ended_ns = int(ended_ns)
        else:
            self.last_ended_ns = max(self.last_ended_ns, int(ended_ns))

    def flush(self, *, force: bool = False, now_ns: int | None = None) -> None:
        if self.first_started_ns is None:
            return
        now_ns = self.clock() if now_ns is None else int(now_ns)
        if not force and now_ns - self.last_flush_ns < self.flush_interval_ns:
            return
        snapshot = {
            "schema_version": METRICS_SCHEMA_VERSION,
            "host": self.host,
            "port": self.port,
            "first_started_ns": self.first_started_ns,
            "last_ended_ns": self.last_ended_ns,
            "operations": self.operations,
            "sessions_opened": self.sessions_opened,
            "sessions_closed": self.sessions_closed,
            "reconnects": self.reconnects,
        }
        try:
            self.sink(snapshot)
        except Exception:
            # Telemetry is deliberately best-effort and must never alter scan
            # completion, SMB retries, or result accuracy.
            pass
        self.operations = {}
        self.sessions_opened = 0
        self.sessions_closed = 0
        self.reconnects = 0
        self.first_started_ns = None
        self.last_ended_ns = None
        self.last_flush_ns = now_ns


class SMBMetricsCollector:
    """Merge process snapshots and detect conservative, sustained degradation."""

    def __init__(self):
        self.created_at = utc_now()
        self.hosts = {}

    @staticmethod
    def _new_host(snapshot: dict) -> dict:
        return {
            "host": str(snapshot["host"]),
            "port": int(snapshot["port"]),
            "first_started_ns": None,
            "last_ended_ns": None,
            "operations": {},
            "sessions_opened": 0,
            "sessions_closed": 0,
            "reconnects": 0,
            "warnings": [],
            "warning_window": {
                "first_started_ns": None,
                "last_ended_ns": None,
                "operations": {},
                "reconnects": 0,
            },
            "baseline_candidates": {},
            "baselines": {},
            "warning_streaks": {},
            "last_warning_ns": {},
        }

    def ingest(self, snapshot: dict) -> tuple[str, ...]:
        if int(snapshot.get("schema_version", 0)) != METRICS_SCHEMA_VERSION:
            return ()
        host = str(snapshot.get("host", ""))
        port = int(snapshot.get("port", 445))
        key = (host.casefold(), port)
        current = self.hosts.setdefault(key, self._new_host(snapshot))
        first_ns = int(snapshot.get("first_started_ns", 0))
        last_ns = int(snapshot.get("last_ended_ns", first_ns))
        current["first_started_ns"] = (
            first_ns if current["first_started_ns"] is None else min(current["first_started_ns"], first_ns)
        )
        current["last_ended_ns"] = (
            last_ns if current["last_ended_ns"] is None else max(current["last_ended_ns"], last_ns)
        )
        merge_operations(current["operations"], snapshot.get("operations", {}))
        current["sessions_opened"] += int(snapshot.get("sessions_opened", 0))
        current["sessions_closed"] += int(snapshot.get("sessions_closed", 0))
        current["reconnects"] += int(snapshot.get("reconnects", 0))

        window = current["warning_window"]
        window["first_started_ns"] = (
            first_ns if window["first_started_ns"] is None else min(window["first_started_ns"], first_ns)
        )
        window["last_ended_ns"] = last_ns if window["last_ended_ns"] is None else max(window["last_ended_ns"], last_ns)
        merge_operations(window["operations"], snapshot.get("operations", {}))
        window["reconnects"] += int(snapshot.get("reconnects", 0))
        if window["last_ended_ns"] - window["first_started_ns"] < int(WARNING_WINDOW_SECONDS * 1_000_000_000):
            return ()

        warnings = tuple(self._evaluate_window(current, window))
        current["warning_window"] = {
            "first_started_ns": None,
            "last_ended_ns": None,
            "operations": {},
            "reconnects": 0,
        }
        return warnings

    def _baseline_ready(self, operation: str, values: dict) -> bool:
        if operation == "directory_list":
            return values["successes"] >= 30
        if operation == "file_read":
            return values["successes"] >= 10 and values["bytes"] >= 8 * 1_048_576
        return False

    def _record_signal(self, host: dict, signal: str, degraded: bool, now_ns: int, detail: str) -> str | None:
        if not degraded:
            host["warning_streaks"][signal] = 0
            return None
        streak = host["warning_streaks"].get(signal, 0) + 1
        host["warning_streaks"][signal] = streak
        if streak < WARNING_CONSECUTIVE_WINDOWS:
            return None
        last_warning = host["last_warning_ns"].get(signal)
        if last_warning is not None and now_ns - last_warning < int(WARNING_COOLDOWN_SECONDS * 1_000_000_000):
            return None
        host["last_warning_ns"][signal] = now_ns
        message = (
            f"{endpoint_name(host['host'], host['port'])}: sustained SMB service degradation observed: "
            f"{detail}; passive warning only, scan concurrency was not changed"
        )
        host["warnings"].append(
            {
                "detected_at": utc_now(),
                "signal": signal,
                "message": message,
            }
        )
        return message

    def _evaluate_window(self, host: dict, window: dict):
        now_ns = int(window["last_ended_ns"])
        warnings = []

        all_attempts = sum(values["attempts"] for values in window["operations"].values())
        unstable_errors = sum(
            values["errors"]["timeout"] + values["errors"]["disconnect"] for values in window["operations"].values()
        )
        transport_degraded = all_attempts >= 10 and unstable_errors >= 3 and unstable_errors / all_attempts >= 0.05
        transport_detail = (
            f"{unstable_errors} timeout/disconnect errors in {all_attempts} observed operations "
            f"during consecutive {WARNING_WINDOW_SECONDS:g}-second windows"
        )
        warning = self._record_signal(host, "transport_errors", transport_degraded, now_ns, transport_detail)
        if warning:
            warnings.append(warning)

        for operation in ("directory_list", "file_read"):
            values = window["operations"].get(operation)
            if values is None:
                host["warning_streaks"][operation] = 0
                continue
            baseline = host["baselines"].get(operation)
            if baseline is None:
                candidate = host["baseline_candidates"].setdefault(operation, empty_operation())
                merge_operation(candidate, values)
                if self._baseline_ready(operation, candidate):
                    host["baselines"][operation] = deepcopy(candidate)
                host["warning_streaks"][operation] = 0
                continue

            if operation == "directory_list":
                enough = values["successes"] >= 30
                baseline_p95 = histogram_percentile(baseline, 0.95) or 0.0
                current_p95 = histogram_percentile(values, 0.95) or 0.0
                degraded = enough and current_p95 >= max(baseline_p95 * 3.0, baseline_p95 + 100.0)
                detail = f"directory-list p95 upper bound {current_p95:g} ms versus initial {baseline_p95:g} ms"
            else:
                enough = values["successes"] >= 10 and values["bytes"] >= 8 * 1_048_576
                baseline_seconds = baseline["duration_ns"] / 1_000_000_000
                current_seconds = values["duration_ns"] / 1_000_000_000
                baseline_rate = baseline["bytes"] / baseline_seconds if baseline_seconds > 0 else 0.0
                current_rate = values["bytes"] / current_seconds if current_seconds > 0 else 0.0
                degraded = enough and baseline_rate > 0 and current_rate <= baseline_rate / 3.0
                detail = (
                    f"file-read average {current_rate / 1_048_576:.3f} MiB/s versus "
                    f"initial {baseline_rate / 1_048_576:.3f} MiB/s"
                )
            warning = self._record_signal(host, operation, degraded, now_ns, detail)
            if warning:
                warnings.append(warning)
        return warnings

    def report(self, *, run_id: str | None, run_status: str, state_path: str | Path) -> dict:
        hosts = []
        total_operations = 0
        total_failures = 0
        total_bytes = 0
        for key in sorted(self.hosts):
            current = self.hosts[key]
            first_ns = current["first_started_ns"]
            last_ns = current["last_ended_ns"]
            observation_seconds = (
                max(0.0, (last_ns - first_ns) / 1_000_000_000) if first_ns is not None and last_ns is not None else 0.0
            )
            operations = {
                operation: operation_report(current["operations"].get(operation, empty_operation()))
                for operation in OPERATION_NAMES
                if operation in current["operations"]
            }
            operation_count = sum(values["attempts"] for values in current["operations"].values())
            failures = sum(values["failures"] for values in current["operations"].values())
            bytes_read = current["operations"].get("file_read", empty_operation())["bytes"]
            total_operations += operation_count
            total_failures += failures
            total_bytes += bytes_read
            hosts.append(
                {
                    "endpoint": endpoint_name(current["host"], current["port"]),
                    "host": current["host"],
                    "port": current["port"],
                    "observation_seconds": round(observation_seconds, 6),
                    "operations": operation_count,
                    "failures": failures,
                    "bytes_read": bytes_read,
                    "effective_read_mib_per_second": (
                        round(bytes_read / 1_048_576 / observation_seconds, 3)
                        if bytes_read and observation_seconds > 0
                        else None
                    ),
                    "sessions_opened": current["sessions_opened"],
                    "sessions_closed": current["sessions_closed"],
                    "reconnects": current["reconnects"],
                    "degradation_warnings": list(current["warnings"]),
                    "operation_details": operations,
                }
            )
        return {
            "schema_version": METRICS_SCHEMA_VERSION,
            "mode": "passive-observation",
            "automatic_throttling": False,
            "created_at": self.created_at,
            "completed_at": utc_now(),
            "run_id": run_id,
            "run_status": run_status,
            "state_file": str(Path(state_path).expanduser()),
            "measurement_scope": "main scan SMB operations only; no additional probes are issued",
            "percentile_method": "conservative fixed-histogram bucket upper bounds",
            "warning_policy": {
                "window_seconds": WARNING_WINDOW_SECONDS,
                "consecutive_windows": WARNING_CONSECUTIVE_WINDOWS,
                "cooldown_seconds": WARNING_COOLDOWN_SECONDS,
                "automatic_action": "none",
            },
            "totals": {
                "hosts": len(hosts),
                "operations": total_operations,
                "failures": total_failures,
                "bytes_read": total_bytes,
                "degradation_warnings": sum(len(host["degradation_warnings"]) for host in hosts),
            },
            "hosts": hosts,
        }


def default_smb_metrics_path(state_path: str | Path) -> Path:
    return Path(state_path).expanduser().with_suffix(".smb-metrics.json")


def write_smb_metrics_report(report: dict, destination: str | Path) -> Path:
    """Atomically replace the invocation report next to its durable state."""

    # Import on use: lib.__init__ loads SMB, which imports SMBMetricsEmitter.
    # Keeping that dependency out of module initialization permits metrics-first
    # imports without changing the report writer's local-only safety checks.
    from man_spider.lib.localfs import atomic_local_text_output

    destination = require_local_write_path(destination, purpose="SMB metrics report")
    with atomic_local_text_output(destination, purpose="SMB metrics report") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return destination
