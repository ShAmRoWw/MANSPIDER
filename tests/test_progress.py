import pytest

from man_spider.lib import spider as spider_module
from man_spider.lib.spider import estimated_eta_share_scope
from man_spider.lib.spider import MANSPIDER
from man_spider.lib.util import Target
from man_spider.progress import DynamicETAEstimator, format_duration, format_progress


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def progress_snapshot(
    *,
    targets=(0, 0),
    shares=(0, 0),
    directories=(0, 0),
    files=(0, 0),
    run_status="running",
):
    """Build discovered/terminal pairs with the remainder in progress."""

    objects = {}
    for kind, (discovered, terminal) in {
        "target": targets,
        "share": shares,
        "directory": directories,
        "file": files,
    }.items():
        objects[kind] = {
            "processed": terminal,
            "in_progress": discovered - terminal,
        }
    return {"run_status": run_status, "objects": objects}


def test_progress_reports_dynamic_work_outcomes_exclusions_and_run_state():
    rendered = format_progress(
        {
            "run_status": "complete_with_errors",
            "objects": {
                "target": {"processed": 2, "error": 1},
                "share": {"processed": 4, "skipped": 1, "error": 1},
                "directory": {"processed": 20, "skipped": 2, "error": 3},
                "file": {"processed": 100, "skipped": 7, "error": 2},
            },
            "changed_files": 4,
            "findings": 12,
            "excluded": 9,
        },
        targets_completed=3,
        targets_total=5,
    )

    assert "run=complete_with_errors" in rendered
    assert "targets=3/5" in rendered
    assert "shares discovered=6, processed=4, skipped=1, error=1" in rendered
    assert "files discovered=109, processed=100, skipped=7, error=2, changed=4" in rendered
    assert "findings=12" in rendered
    assert "excluded=9" in rendered
    assert "all_object_errors=7" in rendered


@pytest.mark.parametrize(
    "run_status",
    ["running", "complete", "complete_with_errors", "interrupted", "preflight_failed"],
)
def test_progress_preserves_every_run_status(run_status):
    rendered = format_progress({"run_status": run_status, "objects": {}})

    assert f"run={run_status}" in rendered


def test_duration_format_does_not_imply_subsecond_precision():
    assert format_duration(65.2) == "01:05"
    assert format_duration(3_661) == "01:01:01"
    assert format_duration(90_061) == "1d 01:01:01"
    assert format_duration(None) == "unknown"


def test_explicit_share_scope_overrides_domain_wide_preflight_estimate(tmp_path):
    options = type(
        "Options",
        (),
        {
            "targets": [Target("server-a"), Target("server-b")],
            "sharenames": ["one", "two", "three"],
            "exclude_sharenames": [],
            "scope_estimate": {"estimated_shares": 1_000},
        },
    )()

    assert estimated_eta_share_scope(options) == 6
    options.exclude_sharenames = ["TWO"]
    assert estimated_eta_share_scope(options) == 4
    options.sharenames = []
    assert estimated_eta_share_scope(options) == 1_000
    options.targets.append(tmp_path)
    assert estimated_eta_share_scope(options) is None


def test_progress_uses_wall_clock_cadence_even_without_completion_messages(monkeypatch):
    clock = FakeClock()
    scanner = MANSPIDER.__new__(MANSPIDER)
    scanner.progress_interval_seconds = 5.0
    scanner.next_progress_at = 5.0
    reports = []
    scanner.report_progress = lambda: reports.append(clock.value)
    monkeypatch.setattr(spider_module, "monotonic", clock)

    scanner.maybe_report_progress()
    assert reports == []
    clock.advance(5)
    scanner.maybe_report_progress()
    assert reports == [5.0]
    clock.advance(4.9)
    scanner.maybe_report_progress()
    assert reports == [5.0]
    clock.advance(0.1)
    scanner.maybe_report_progress()
    assert reports == [5.0, 10.0]


def test_dynamic_eta_waits_for_warmup_then_uses_share_completion():
    clock = FakeClock()
    estimator = DynamicETAEstimator(
        total_targets=1,
        estimated_total_shares=100,
        warmup_seconds=10,
        clock=clock,
    )
    estimator.initialize(progress_snapshot())

    clock.advance(5)
    warming = estimator.update(
        progress_snapshot(targets=(1, 0), shares=(100, 10), directories=(1_000, 300), files=(1_000, 300)),
        targets_completed=0,
    )
    assert warming.status == "calculating"

    clock.advance(5)
    first = estimator.update(
        progress_snapshot(targets=(1, 0), shares=(100, 20), directories=(1_000, 500), files=(1_000, 500)),
        targets_completed=0,
    )
    assert first.status == "estimated"
    assert first.basis == "share completion"
    assert first.confidence == "medium"
    assert first.remaining_seconds == pytest.approx(40.0)
    assert first.lower_seconds < first.remaining_seconds < first.upper_seconds

    clock.advance(10)
    second = estimator.update(
        progress_snapshot(targets=(1, 0), shares=(100, 40), directories=(1_000, 750), files=(1_000, 750)),
        targets_completed=0,
    )
    assert second.remaining_seconds == pytest.approx(30.0)
    assert second.total_seconds == pytest.approx(50.0)


def test_dynamic_eta_resume_baseline_does_not_count_old_terminal_objects_as_throughput():
    clock = FakeClock()
    estimator = DynamicETAEstimator(
        total_targets=1,
        estimated_total_shares=100,
        warmup_seconds=10,
        clock=clock,
    )
    estimator.initialize(
        progress_snapshot(targets=(1, 0), shares=(100, 80), directories=(1_000, 800), files=(1_000, 800))
    )

    clock.advance(10)
    estimate = estimator.update(
        progress_snapshot(targets=(1, 0), shares=(100, 85), directories=(1_000, 850), files=(1_000, 850)),
        targets_completed=0,
    )

    assert estimator.completed_share_events == 5
    assert estimate.status == "estimated"
    assert 30.0 <= estimate.remaining_seconds < 31.0


def test_dynamic_eta_falls_back_to_manifest_flow_for_one_large_share():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=1, estimated_total_shares=1, warmup_seconds=10, clock=clock)
    estimator.initialize(progress_snapshot())

    clock.advance(10)
    estimate = estimator.update(
        progress_snapshot(targets=(1, 0), shares=(1, 0), directories=(500, 400), files=(10_000, 800)),
        targets_completed=0,
    )

    assert estimate.status == "estimated"
    assert estimate.basis == "manifest discovery/drain"
    assert estimate.confidence == "low"
    assert estimate.remaining_seconds > 0


def test_dynamic_eta_reports_completion_and_is_rendered_in_progress():
    clock = FakeClock()
    estimator = DynamicETAEstimator(total_targets=1, warmup_seconds=0, clock=clock)
    estimator.initialize(progress_snapshot())
    clock.advance(12)
    estimate = estimator.update(
        progress_snapshot(targets=(1, 1), run_status="complete_with_errors"),
        targets_completed=1,
    )

    rendered = format_progress(
        progress_snapshot(targets=(1, 1), run_status="complete_with_errors"),
        targets_completed=1,
        targets_total=1,
        eta=estimate,
    )
    assert estimate.status == "complete"
    assert "elapsed=00:12" in rendered
    assert "remaining=00:00" in rendered
    assert "ETA confidence=high" in rendered
