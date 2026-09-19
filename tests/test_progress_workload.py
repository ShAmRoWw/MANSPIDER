"""Cheap skips and an unmeasured final document must not imply scan completion."""
import socket
import sqlite3

import pytest

from man_spider.progress import DynamicETAEstimator, format_eta
from tests.test_progress import FakeClock, progress_snapshot


def snapshot(*, processed=0, skipped=0, pending=0, directories=(0, 0), shares=(2, 0)):
    result = progress_snapshot(targets=(2, 0), shares=shares, directories=directories)
    result["objects"]["file"] = {"processed": processed, "skipped": skipped, "in_progress": pending}
    return result


def test_actual_windows_acceptance_sequence_does_not_promise_one_second_remaining():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=2, estimated_total_shares=2, clock=clock)
    estimator.initialize(snapshot(shares=(0, 0)))
    for elapsed, processed, skipped, pending, directories in (
        (5, 650, 2056, 30, (660, 494)),
        (10, 1092, 2056, 26, (1505, 1332)),
        (15, 1202, 2056, 26, (1658, 1606)),
        (20, 1202, 2056, 26, (1658, 1606)),
        (25, 1202, 2056, 26, (1658, 1606)),
    ):
        clock.value = elapsed
        estimate = estimator.update(snapshot(processed=processed, skipped=skipped, pending=pending, directories=directories))
        assert estimate.status == "calculating", (elapsed, estimate)
        assert estimate.remaining_seconds is None
        assert "remaining~00:01" not in format_eta(estimate)
    clock.value = 28
    done = estimator.update(progress_snapshot(targets=(2, 2), files=(3284, 3284), run_status="complete"))
    assert done.status == "complete" and done.remaining_seconds == 0


@pytest.mark.parametrize("cheap_status", ["skipped", "error"])
def test_skip_or_error_burst_does_not_inflate_pending_file_throughput(cheap_status):
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=2, clock=clock)
    estimator.initialize(snapshot())
    clock.value = 10
    current = snapshot(processed=10, pending=100, directories=(10000, 9999))
    current["objects"]["file"][cheap_status] = 100000
    estimate = estimator.update(current)
    assert estimate.status == "estimated"
    assert estimator.processed_file_events == 10
    assert estimate.remaining_seconds >= 100
    assert estimate.confidence == "low"


def test_a_large_single_share_still_has_a_dynamic_numeric_estimate():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=1, estimated_total_shares=1, clock=clock)
    estimator.initialize(progress_snapshot())
    clock.value = 10
    first = estimator.update(progress_snapshot(targets=(1, 0), shares=(1, 0), files=(10000, 1000)))
    clock.value = 20
    second = estimator.update(progress_snapshot(targets=(1, 0), shares=(1, 0), files=(10000, 2000)))
    assert first.status == second.status == "estimated"
    assert first.confidence == second.confidence == "low"
    assert first.remaining_seconds > second.remaining_seconds >= 80


def test_busy_directory_enumeration_does_not_disguise_stalled_file_processing():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=2, clock=clock)
    estimator.initialize(snapshot())
    clock.value = 10
    assert estimator.update(snapshot(processed=100, pending=1000)).status == "estimated"
    clock.value = 15
    estimate = estimator.update(snapshot(processed=100, pending=1000, directories=(20000, 19000)))
    assert estimate.status == "calculating"
    assert "file processing" in estimate.basis
    assert estimator.last_estimate is None


def test_resume_processed_file_baseline_does_not_use_historical_throughput():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=2, clock=clock)
    estimator.initialize(snapshot(processed=100000, skipped=200000, pending=1000))
    clock.value = 10
    estimate = estimator.update(snapshot(processed=100001, skipped=300000, pending=999))
    assert estimate.status == "estimated"
    assert estimator.processed_file_events == 1
    assert estimate.remaining_seconds >= 9990


def test_no_processed_file_samples_cannot_forecast_content_from_only_skips():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=2, clock=clock)
    estimator.initialize(snapshot())
    clock.value = 10
    estimate = estimator.update(snapshot(skipped=100000, pending=10, directories=(10000, 9000)))
    assert estimate.status == "calculating"
    assert "file processing" in estimate.basis


def test_manifest_forecast_below_actual_observation_resolution_is_withdrawn():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=2, clock=clock)
    estimator.initialize(snapshot())
    clock.value = 10
    assert estimator.update(snapshot(processed=1000, pending=10000)).status == "estimated"
    clock.value = 20
    estimate = estimator.update(snapshot(processed=10999, pending=1))
    assert estimate.status == "calculating"
    assert "observation resolution" in estimate.basis
    assert estimator.last_estimate is None


def test_observation_resolution_and_file_rates_reset_on_resume():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=2, clock=clock)
    estimator.initialize(snapshot())
    clock.value = 10
    estimator.update(snapshot(processed=10, pending=1000))
    assert estimator.observation_intervals
    estimator.initialize(snapshot(processed=10, pending=1000))
    assert not estimator.observation_intervals
    assert estimator.processed_file_events == 0
    clock.value = 20
    assert estimator.update(snapshot(processed=10, pending=1000)).status == "calculating"


def test_new_workload_model_still_never_performs_io(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("ETA must not use network or SQLite")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=2, clock=clock)
    estimator.initialize(snapshot())
    clock.value = 10
    assert estimator.update(snapshot(processed=100, pending=1000)).status == "estimated"


@pytest.mark.parametrize("completed_level", ["share", "target"])
def test_completed_top_level_does_not_bypass_resolution_for_unfinished_tail(completed_level):
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=2, estimated_total_shares=3, clock=clock)
    estimator.initialize(progress_snapshot())
    clock.value = 10
    current = progress_snapshot(
        targets=(2, 2 if completed_level == "target" else 0),
        shares=(3, 3 if completed_level == "share" else 0),
        files=(1000, 999),
    )
    estimate = estimator.update(current)
    assert estimate.status == "calculating"
    assert "observation resolution" in estimate.basis
