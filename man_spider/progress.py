from __future__ import annotations

import math
from collections import deque
from dataclasses import asdict, dataclass
from statistics import median
from time import monotonic

from man_spider.state import OBJECT_STATUSES


TERMINAL_STATUSES = ("processed", "skipped", "error")
ETA_STALL_SECONDS = 5.0
WORK_WEIGHTS = {
    "target": 4.0,
    "share": 2.0,
    "directory": 1.0,
    "file": 1.0,
}


def _kind_counts(snapshot, kind):
    counts = {status: 0 for status in OBJECT_STATUSES}
    counts.update(snapshot.get("objects", {}).get(kind, {}))
    return counts


def _discovered(counts):
    return sum(counts.values())


def _terminal(counts):
    return sum(counts[status] for status in TERMINAL_STATUSES)


def _object_totals(snapshot: dict) -> tuple[dict[str, int], dict[str, int]]:
    discovered = {}
    terminal = {}
    for kind in WORK_WEIGHTS:
        counts = _kind_counts(snapshot, kind)
        discovered[kind] = _discovered(counts)
        terminal[kind] = _terminal(counts)
    return discovered, terminal


def _weighted(values: dict[str, int]) -> float:
    return sum(values.get(kind, 0) * weight for kind, weight in WORK_WEIGHTS.items())


def format_duration(seconds: float | int | None) -> str:
    """Format an ETA duration without implying sub-second precision."""

    if seconds is None or not math.isfinite(float(seconds)) or seconds < 0:
        return "unknown"
    total = int(round(float(seconds)))
    days, remainder = divmod(total, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


@dataclass(frozen=True)
class ETAEstimate:
    status: str
    elapsed_seconds: float
    remaining_seconds: float | None = None
    lower_seconds: float | None = None
    upper_seconds: float | None = None
    total_seconds: float | None = None
    confidence: str | None = None
    basis: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class _ETASample:
    elapsed: float
    completed_work_events: float
    processed_file_events: int
    completed_share_events: int
    completed_target_events: int
    discovered_work_events: float


class DynamicETAEstimator:
    """Estimate remaining scan time from passive, already-recorded progress.

    The complete directory tree is not known before it is traversed. The
    estimator therefore combines top-level share/target completion with the
    drain rate of the manifest already discovered, and explicitly reports an
    uncertainty range. It never performs network I/O.
    """

    def __init__(
        self,
        *,
        total_targets: int,
        estimated_total_shares: int | None = None,
        warmup_seconds: float = 10.0,
        rate_window_seconds: float = 90.0,
        clock=monotonic,
    ):
        self.total_targets = max(0, int(total_targets))
        self.estimated_total_shares = (
            max(0, int(estimated_total_shares)) if estimated_total_shares is not None else None
        )
        self.warmup_seconds = max(0.0, float(warmup_seconds))
        self.rate_window_seconds = max(5.0, float(rate_window_seconds))
        self.clock = clock
        self.started_at: float | None = None
        self.previous_discovered: dict[str, int] | None = None
        self.previous_terminal: dict[str, int] | None = None
        self.completed_work_events = 0.0
        self.previous_processed_files = 0
        self.processed_file_events = 0
        self.last_file_progress_elapsed = 0.0
        self.observation_intervals: deque[float] = deque(maxlen=12)
        self.completed_share_events = 0
        self.completed_target_events = 0
        self.discovered_work_events = 0.0
        self.history: deque[_ETASample] = deque(maxlen=512)
        self.last_estimate: ETAEstimate | None = None
        self.last_estimate_at: float | None = None
        self.last_progress_elapsed = 0.0

    def initialize(self, snapshot: dict) -> None:
        """Set an invocation-local baseline, including for durable resume."""

        now = self.clock()
        discovered, terminal = _object_totals(snapshot)
        self.started_at = now
        self.previous_discovered = discovered
        self.previous_terminal = terminal
        self.completed_work_events = 0.0
        self.previous_processed_files = _kind_counts(snapshot, "file")["processed"]
        self.processed_file_events = 0
        self.last_file_progress_elapsed = 0.0
        self.observation_intervals.clear()
        self.completed_share_events = 0
        self.completed_target_events = 0
        self.discovered_work_events = 0.0
        self.history.clear()
        self.history.append(_ETASample(0.0, 0.0, 0, 0, 0, 0.0))
        self.last_estimate = None
        self.last_estimate_at = None
        self.last_progress_elapsed = 0.0

    def _observe(self, snapshot: dict, elapsed: float) -> tuple[dict[str, int], dict[str, int]]:
        discovered, terminal = _object_totals(snapshot)
        processed_files = _kind_counts(snapshot, "file")["processed"]
        processed_delta = max(0, processed_files - self.previous_processed_files)
        self.processed_file_events += processed_delta
        if processed_delta:
            self.last_file_progress_elapsed = elapsed
        self.previous_processed_files = processed_files
        if self.previous_discovered is None or self.previous_terminal is None:
            self.previous_discovered = discovered
            self.previous_terminal = terminal
        else:
            discovered_delta = {
                kind: max(0, discovered[kind] - self.previous_discovered.get(kind, 0)) for kind in WORK_WEIGHTS
            }
            terminal_delta = {
                kind: max(0, terminal[kind] - self.previous_terminal.get(kind, 0)) for kind in WORK_WEIGHTS
            }
            self.discovered_work_events += _weighted(discovered_delta)
            completed_delta = _weighted(terminal_delta)
            self.completed_work_events += completed_delta
            if completed_delta > 0:
                self.last_progress_elapsed = elapsed
            self.completed_share_events += terminal_delta["share"]
            self.completed_target_events += terminal_delta["target"]
            self.previous_discovered = discovered
            self.previous_terminal = terminal

        sample = _ETASample(
            elapsed,
            self.completed_work_events,
            self.processed_file_events,
            self.completed_share_events,
            self.completed_target_events,
            self.discovered_work_events,
        )
        if not self.history or elapsed - self.history[-1].elapsed >= 0.5:
            if self.history:
                self.observation_intervals.append(elapsed - self.history[-1].elapsed)
            self.history.append(sample)
        else:
            self.history[-1] = sample
        return discovered, terminal

    def _rate(self, field: str, elapsed: float) -> tuple[float | None, float | None]:
        if not self.history or elapsed <= 0:
            return None, None
        current = self.history[-1]
        initial = self.history[0]
        cumulative_delta = float(getattr(current, field) - getattr(initial, field))
        cumulative_rate = cumulative_delta / max(0.001, current.elapsed - initial.elapsed)
        if cumulative_rate <= 0:
            cumulative_rate = None

        cutoff = elapsed - self.rate_window_seconds
        reference = initial
        for sample in self.history:
            if sample.elapsed >= cutoff:
                reference = sample
                break
        recent_elapsed = current.elapsed - reference.elapsed
        recent_delta = float(getattr(current, field) - getattr(reference, field))
        recent_rate = recent_delta / recent_elapsed if recent_elapsed >= 5.0 and recent_delta > 0 else None
        return cumulative_rate, recent_rate

    @staticmethod
    def _duration_candidates(remaining: float, rates: tuple[float | None, float | None]) -> list[float]:
        if remaining <= 0:
            return [0.0]
        return [remaining / rate for rate in rates if rate is not None and rate > 0]

    @staticmethod
    def _central(values: list[float]) -> float | None:
        finite = [value for value in values if math.isfinite(value) and value >= 0]
        return float(median(finite)) if finite else None

    def _smooth(self, raw_remaining: float, now: float) -> float:
        previous = self.last_estimate
        if (
            previous is None
            or previous.status != "estimated"
            or previous.remaining_seconds is None
            or self.last_estimate_at is None
        ):
            return raw_remaining
        elapsed_since_estimate = max(0.0, now - self.last_estimate_at)
        expected = max(0.0, previous.remaining_seconds - elapsed_since_estimate)
        # Allow genuine growth when a large subtree appears, while damping the
        # ordinary saw-tooth caused by batched manifest commits.
        bounded = min(raw_remaining, max(expected * 3.0, expected + 30.0))
        return expected * 0.65 + bounded * 0.35

    def _without_estimate(self, elapsed: float, *, status="calculating", basis=None) -> ETAEstimate:
        # Do not resume smoothing a stale countdown after a stall or restart.
        self.last_estimate = None
        self.last_estimate_at = None
        return ETAEstimate(status=status, elapsed_seconds=elapsed, basis=basis)

    def update(
        self,
        snapshot: dict,
        *,
        targets_completed: int | None = None,
    ) -> ETAEstimate:
        if self.started_at is None:
            self.initialize(snapshot)
        now = self.clock()
        elapsed = max(0.0, now - self.started_at)
        discovered, terminal = self._observe(snapshot, elapsed)

        run_status = snapshot.get("run_status", "running")
        completed_target_count = (
            max(0, int(targets_completed)) if targets_completed is not None else terminal["target"]
        )
        # Target completion messages can precede durable manifest finalization.
        # Only the saved run status proves that the entire scan has finished.
        if run_status in {"complete", "complete_with_errors"}:
            estimate = ETAEstimate(
                status="complete",
                elapsed_seconds=elapsed,
                remaining_seconds=0.0,
                lower_seconds=0.0,
                upper_seconds=0.0,
                total_seconds=elapsed,
                confidence="high",
                basis="completed scope",
            )
            self.last_estimate = estimate
            self.last_estimate_at = now
            return estimate

        if run_status != "running":
            return self._without_estimate(elapsed, status="unavailable", basis=run_status)

        if elapsed < self.warmup_seconds:
            return self._without_estimate(elapsed)

        # A burst of small objects does not predict a slow final read/extractor.
        # Discovery, findings and repeated snapshots are not completed work.
        if elapsed - self.last_progress_elapsed >= ETA_STALL_SECONDS:
            return self._without_estimate(elapsed)

        completed_work_rates = self._rate("completed_work_events", elapsed)
        processed_file_rates = self._rate("processed_file_events", elapsed)
        completed_share_rates = self._rate("completed_share_events", elapsed)
        completed_target_rates = self._rate("completed_target_events", elapsed)
        discovered_work_rates = self._rate("discovered_work_events", elapsed)

        discovered_work = _weighted(discovered)
        terminal_work = _weighted(terminal)
        known_remaining_work = max(0.0, discovered_work - terminal_work)
        known_candidates = self._duration_candidates(known_remaining_work, completed_work_rates)
        known_eta = self._central(known_candidates)
        pending_files = discovered["file"] - terminal["file"]
        if pending_files > 0:
            # Directory enumeration, skips and errors do not measure the cost
            # of successfully processing files still waiting in the manifest.
            # A busy enumerator must not disguise a stalled extraction queue.
            file_eta = self._central(self._duration_candidates(pending_files, processed_file_rates))
            if file_eta is None or elapsed - self.last_file_progress_elapsed >= ETA_STALL_SECONDS:
                return self._without_estimate(elapsed, basis="unfinished file processing is not yet measured")
            known_eta = max(known_eta or 0.0, file_eta)

        share_total = max(discovered["share"], self.estimated_total_shares or 0)
        share_remaining = max(0, share_total - terminal["share"])
        share_candidates = self._duration_candidates(share_remaining, completed_share_rates)

        target_remaining = max(0, self.total_targets - completed_target_count)
        target_candidates = self._duration_candidates(target_remaining, completed_target_rates)

        flow_candidates = []
        completion_rate = completed_work_rates[1] or completed_work_rates[0]
        discovery_rate = discovered_work_rates[1] or discovered_work_rates[0]
        if known_remaining_work > 0 and completion_rate:
            if discovery_rate is not None and completion_rate > discovery_rate * 1.02:
                flow_candidates.append(known_remaining_work / (completion_rate - discovery_rate))
            else:
                growth_ratio = (discovery_rate or 0.0) / completion_rate
                flow_candidates.append((known_eta or 0.0) * (1.0 + min(2.0, growth_ratio)))

        projection_candidates = []
        if completion_rate and share_total > 0 and discovered["share"] > 0:
            # Before every share has been discovered, scale only the work seen
            # so far. This is deliberately a weak, low-confidence candidate.
            projected_work = discovered_work * min(10.0, share_total / discovered["share"])
            projection_candidates.extend(
                self._duration_candidates(max(0.0, projected_work - terminal_work), (completion_rate, None))
            )

        basis = None
        primary_candidates: list[float] = []
        coverage = 0.0
        evidence = 0
        if share_remaining > 0 and share_candidates and self.completed_share_events >= 3:
            basis = "share completion"
            primary_candidates = share_candidates
            coverage = terminal["share"] / share_total if share_total else 0.0
            evidence = self.completed_share_events
        elif target_remaining > 0 and target_candidates and self.completed_target_events >= 1:
            basis = "target completion"
            primary_candidates = target_candidates
            coverage = completed_target_count / self.total_targets if self.total_targets else 0.0
            evidence = self.completed_target_events
        elif flow_candidates:
            basis = "manifest discovery/drain"
            primary_candidates = flow_candidates
            coverage = terminal_work / discovered_work if discovered_work else 0.0
            evidence = int(self.completed_work_events)
        elif known_candidates or projection_candidates:
            basis = "known manifest work"
            primary_candidates = projection_candidates or known_candidates
            coverage = terminal_work / discovered_work if discovered_work else 0.0
            evidence = int(self.completed_work_events)
        else:
            return self._without_estimate(elapsed)

        raw_remaining = self._central(primary_candidates)
        if raw_remaining is None:
            return self._without_estimate(elapsed)
        # Never report less than the time currently implied by already-known
        # pending work. Unknown descendants can only increase this quantity.
        if known_eta is not None:
            raw_remaining = max(raw_remaining, known_eta)
        if raw_remaining <= 0:
            # A drained known manifest does not prove that discovery or local
            # finalization is complete. Wait for progress or the saved status.
            return self._without_estimate(elapsed)

        manifest_only = basis in {"manifest discovery/drain", "known manifest work"}
        resolution = median(self.observation_intervals) if self.observation_intervals else ETA_STALL_SECONDS
        if manifest_only and raw_remaining < resolution:
            # Counts cannot justify a global near-finish promise shorter than
            # their observation interval, especially for a slow final document.
            return self._without_estimate(elapsed, basis="unfinished work below observation resolution")

        supporting = list(primary_candidates)
        if known_eta is not None:
            supporting.append(known_eta)
        supporting.extend(flow_candidates)

        finite_support = [value for value in supporting if math.isfinite(value) and value >= 0]
        spread = max(finite_support) / max(1.0, min(finite_support)) if len(finite_support) >= 2 else 1.0
        if basis == "share completion" and evidence >= 20 and coverage >= 0.5 and spread <= 1.6:
            confidence = "high"
        elif basis == "share completion" and evidence >= 5 and coverage >= 0.1:
            confidence = "medium"
        elif basis == "target completion" and evidence >= 3 and coverage >= 0.25:
            confidence = "medium"
        else:
            confidence = "low"

        # Running scans must not render a rounded zero-second promise.
        smoothed = max(1.0, self._smooth(raw_remaining, now), known_eta or 0.0)
        if manifest_only and smoothed < resolution:
            return self._without_estimate(elapsed, basis="unfinished work below observation resolution")
        uncertainty = {
            "low": (0.50, 2.00),
            "medium": (0.70, 1.50),
            "high": (0.85, 1.25),
        }[confidence]
        lower = smoothed * uncertainty[0]
        upper = smoothed * uncertainty[1]
        if finite_support:
            upper = max(upper, max(finite_support))

        estimate = ETAEstimate(
            status="estimated",
            elapsed_seconds=elapsed,
            remaining_seconds=smoothed,
            lower_seconds=max(1.0, lower),
            upper_seconds=max(smoothed, upper),
            total_seconds=elapsed + smoothed,
            confidence=confidence,
            basis=basis,
        )
        self.last_estimate = estimate
        self.last_estimate_at = now
        return estimate


def format_eta(estimate: ETAEstimate | dict | None) -> str | None:
    if estimate is None:
        return None
    if isinstance(estimate, dict):
        estimate = ETAEstimate(**estimate)
    elapsed = format_duration(estimate.elapsed_seconds)
    if estimate.status == "calculating":
        return f"elapsed={elapsed}; ETA=calculating"
    if estimate.status == "unavailable":
        reason = f" ({estimate.basis})" if estimate.basis else ""
        return f"elapsed={elapsed}; ETA=unavailable{reason}"
    if estimate.status == "complete":
        return f"elapsed={elapsed}; remaining=00:00; ETA confidence=high"
    return (
        f"elapsed={elapsed}; remaining~{format_duration(estimate.remaining_seconds)} "
        f"({format_duration(estimate.lower_seconds)}-{format_duration(estimate.upper_seconds)}); "
        f"total~{format_duration(estimate.total_seconds)}; ETA confidence={estimate.confidence}"
    )


def format_progress(
    snapshot: dict,
    *,
    targets_completed: int | None = None,
    targets_total: int | None = None,
    eta: ETAEstimate | dict | None = None,
) -> str:
    targets = _kind_counts(snapshot, "target")
    shares = _kind_counts(snapshot, "share")
    directories = _kind_counts(snapshot, "directory")
    files = _kind_counts(snapshot, "file")
    if targets_completed is None:
        targets_completed = targets["processed"] + targets["skipped"] + targets["error"]
    if targets_total is None:
        targets_total = _discovered(targets)
    object_errors = sum(values.get("error", 0) for values in snapshot.get("objects", {}).values())
    rendered = (
        f"Progress: run={snapshot.get('run_status', 'running')}; "
        f"targets={targets_completed}/{targets_total}; "
        f"shares discovered={_discovered(shares)}, processed={shares['processed']}, "
        f"skipped={shares['skipped']}, error={shares['error']}; "
        f"directories discovered={_discovered(directories)}, processed={directories['processed']}, "
        f"skipped={directories['skipped']}, error={directories['error']}; "
        f"files discovered={_discovered(files)}, processed={files['processed']}, "
        f"skipped={files['skipped']}, error={files['error']}, changed={snapshot.get('changed_files', 0)}; "
        f"findings={snapshot.get('findings', 0)}; excluded={snapshot.get('excluded', 0)}; "
        f"all_object_errors={object_errors}"
    )
    eta_text = format_eta(eta)
    return f"{rendered}; {eta_text}" if eta_text else rendered
