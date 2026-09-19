"""A slow final object must not leave a stale near-zero ETA on screen."""

import socket
import sqlite3

import pytest

from man_spider.progress import DynamicETAEstimator, format_eta


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


def snapshot(*, files=(0, 0), targets=(1, 0), status="running"):
    return {
        "run_status": status,
        "objects": {
            kind: {"processed": completed, "in_progress": discovered - completed}
            for kind, (discovered, completed) in {"target": targets, "file": files}.items()
        },
    }


def fast_initial_progress():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=1, clock=clock)
    estimator.initialize(snapshot())
    clock.value = 10.0
    # Stall behavior needs a measurable backlog. A single unmeasured final
    # file now intentionally withholds the numeric forecast (workload tests).
    current = snapshot(files=(2_000, 999))
    estimate = estimator.update(current)
    assert estimate.status == "estimated"
    return clock, estimator, current, estimate


def test_running_scan_does_not_display_rounded_zero_remaining_or_range():
    _, _, _, estimate = fast_initial_progress()

    assert estimate.remaining_seconds >= 1.0
    assert estimate.lower_seconds >= 1.0
    assert estimate.upper_seconds >= estimate.remaining_seconds
    assert "00:00" not in format_eta(estimate)


def test_unchanged_completion_invalidates_eta_at_five_seconds_and_clears_smoothing():
    clock, estimator, current, _ = fast_initial_progress()
    clock.value = 14.999
    assert estimator.update(current).status == "estimated"

    clock.value = 15.0
    stalled = estimator.update(current)

    assert stalled.status == "calculating"
    assert stalled.remaining_seconds is None
    assert stalled.lower_seconds is None
    assert stalled.upper_seconds is None
    assert estimator.last_estimate is None
    assert estimator.last_estimate_at is None
    assert "ETA=calculating" in format_eta(stalled)
    assert "remaining" not in format_eta(stalled)

    clock.value = 35.0
    assert estimator.update(current).status == "calculating"


@pytest.mark.parametrize("change", ["discovery", "findings", "analysis", "target_message"])
def test_non_completion_activity_does_not_restart_the_stall_timer(change):
    clock, estimator, current, _ = fast_initial_progress()
    clock.value = 14.0
    if change == "discovery":
        current = snapshot(files=(2_000, 999))
    elif change == "findings":
        current["findings"] = 100
    elif change == "analysis":
        current["analysis_counts"] = {"analyzed": 999}
    target_messages = 1 if change == "target_message" else 0
    estimator.update(current, targets_completed=target_messages)

    clock.value = 15.0
    assert estimator.update(current, targets_completed=target_messages).status == "calculating"


def test_eta_recovers_only_after_new_terminal_work_and_can_stall_again():
    clock, estimator, current, _ = fast_initial_progress()
    clock.value = 25.0
    assert estimator.update(current).status == "calculating"

    clock.value = 30.0
    recovered = estimator.update(snapshot(files=(2_000, 1_000)))
    assert recovered.status == "estimated"
    assert recovered.remaining_seconds >= 1.0
    assert estimator.last_estimate is recovered

    clock.value = 35.0
    assert estimator.update(snapshot(files=(2_000, 1_000))).status == "calculating"


@pytest.mark.parametrize("terminal_status", ["skipped", "error"])
def test_skips_and_errors_are_completed_work_but_not_file_processing_samples(terminal_status):
    clock, estimator, current, _ = fast_initial_progress()
    clock.value = 20.0
    assert estimator.update(current).status == "calculating"
    current = snapshot(files=(1_002, 999))
    current["objects"]["file"][terminal_status] = 1
    current["objects"]["file"]["in_progress"] -= 1
    clock.value = 21.0

    assert estimator.update(current).status == "calculating"
    assert estimator.last_progress_elapsed == 21.0
    assert estimator.last_file_progress_elapsed == 10.0


def test_new_work_keeps_the_unsmoothed_known_work_upper_bound_before_a_stall():
    clock, estimator, _, _ = fast_initial_progress()
    clock.value = 11.0
    estimate = estimator.update(snapshot(files=(10_000, 999)))
    # The pending target weighs four units; smoothing may damp the central
    # estimate but must not hide the larger known-work uncertainty bound.
    known_remaining = 10_000 - 999 + 4
    known_eta = known_remaining / (999 / clock.value)

    assert estimate.status == "estimated"
    assert estimate.upper_seconds >= known_eta


@pytest.mark.parametrize("status", ["interrupted", "preflight_failed"])
@pytest.mark.parametrize("files", [(1_000, 999), (1_000, 1_000)])
def test_stopped_scan_never_claims_completion_even_with_all_target_messages(status, files):
    clock, estimator, _, _ = fast_initial_progress()
    clock.value = 12.0
    stopped = estimator.update(snapshot(files=files, targets=(1, 1), status=status), targets_completed=1)

    assert stopped.status == "unavailable"
    assert stopped.remaining_seconds is None
    assert stopped.confidence is None
    assert estimator.last_estimate is None
    assert "ETA=unavailable" in format_eta(stopped)
    assert status in format_eta(stopped)
    assert "remaining=00:00" not in format_eta(stopped)


@pytest.mark.parametrize("pending_status", ["pending", "in_progress"])
def test_target_completion_is_not_scan_completion_with_non_terminal_manifest(pending_status):
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=1, warmup_seconds=0, clock=clock)
    estimator.initialize(snapshot())
    clock.value = 10.0
    current = snapshot(files=(1, 1), targets=(1, 1))
    current["objects"]["file"][pending_status] = 1

    estimate = estimator.update(current, targets_completed=1)

    assert estimate.status == "estimated"
    assert estimate.remaining_seconds >= 1.0


def test_running_scan_with_drained_manifest_waits_for_durable_completion():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=1, warmup_seconds=0, clock=clock)
    estimator.initialize(snapshot())
    clock.value = 10.0

    estimate = estimator.update(snapshot(files=(1, 1), targets=(1, 1)), targets_completed=1)

    assert estimate.status == "calculating"
    assert estimate.remaining_seconds is None


@pytest.mark.parametrize("status", ["complete", "complete_with_errors"])
def test_durable_completion_can_finish_stalled_eta_immediately(status):
    clock, estimator, current, _ = fast_initial_progress()
    clock.value = 30.0
    assert estimator.update(current).status == "calculating"
    clock.value = 40.0

    complete = estimator.update(snapshot(files=(1_000, 1_000), targets=(1, 1), status=status))

    assert complete.status == "complete"
    assert complete.remaining_seconds == 0.0
    assert "remaining=00:00" in format_eta(complete)


def test_resume_baseline_does_not_mistake_old_terminal_objects_for_new_progress():
    clock, estimator, current, _ = fast_initial_progress()
    clock.value = 25.0
    assert estimator.update(current).status == "calculating"
    estimator.initialize(current)
    clock.value = 35.0
    assert estimator.update(current).status == "calculating"
    assert estimator.completed_work_events == 0

    clock.value = 36.0
    estimate = estimator.update(snapshot(files=(2_000, 1_000)))
    assert estimate.status == "estimated"
    assert estimator.completed_work_events == 1


def test_empty_running_scope_cannot_produce_a_zero_eta_without_progress():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=1, clock=clock)
    estimator.initialize(snapshot(targets=(0, 0)))
    clock.value = 10.0

    estimate = estimator.update(snapshot(targets=(0, 0)))

    assert estimate.status == "calculating"
    assert estimate.remaining_seconds is None


def test_eta_uses_only_existing_snapshot_without_network_or_database_access(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("ETA must not perform I/O")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    clock, estimator, current, _ = fast_initial_progress()
    clock.value = 15.0
    assert estimator.update(current).status == "calculating"
