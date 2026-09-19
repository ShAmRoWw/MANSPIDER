"""Opt-in Chromium timing regressions: tiny local data, real summary polling.

MANSPIDER_BROWSER_TESTS=1 python -m pytest -q tests/test_web_timing_browser.py
Use the bounded systemd scope documented in test_web_live_recovery.py. Summary
responses carry controlled scanner snapshots; no clock overrides or SMB scans.
"""

from datetime import datetime, timedelta, timezone
import os

import pytest

from tests import test_web_live_recovery as fixtures


chromium = fixtures.chromium
live_viewer = fixtures.live_viewer
pytestmark = pytest.mark.skipif(
    os.environ.get("MANSPIDER_BROWSER_TESTS") != "1", reason="explicit bounded browser test only",
)


def _snapshot(status="calculating", elapsed=1.2, remaining=None, lower=None, upper=None, confidence=None):
    return {
        "elapsed_seconds": elapsed, "remaining_seconds": remaining,
        "lower_seconds": lower, "upper_seconds": upper,
        "eta_status": status, "confidence": confidence,
        "updated_at": "2026-09-19T12:00:00+00:00",
    }


def _control_timing(viewer, initial):
    controlled = {"timing": initial}

    def summary(route):
        response = route.fetch()
        data = response.json()
        if controlled["timing"] is None:
            data.pop("timing", None)  # A legacy server/session supplies no timing.
        else:
            data["timing"] = controlled["timing"]
        route.fulfill(response=response, json=data)

    viewer.page.route(viewer.origin + "/api/scans/*/summary", summary)
    return controlled


def test_polling_timing_transitions_translate_and_preserve_results(live_viewer):
    viewer = live_viewer
    state = viewer.create_scan()
    controlled = _control_timing(viewer, _snapshot())
    changes = state.connection.total_changes
    viewer.open_ready()
    viewer.expect(viewer.page.locator("#scan-timing")).to_be_visible()
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("1 s")
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("Calculating…")
    viewer.expect(viewer.page.locator("#scan-timing-estimate")).to_be_hidden()
    viewer.page.locator('#filters [name="severity"]').select_option("high")
    viewer.page.locator('#filters button[type="submit"]').click()
    card = viewer.page.locator("#results .file-result").first
    card.locator("summary").click()
    viewer.expect(card.locator("mark").first).to_be_visible()
    card.evaluate("element => { element.dataset.timingTestIdentity = 'retained'; }")

    controlled["timing"] = _snapshot("estimated", 125.9, 90, 60, 150, "medium")
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("2 min 5 s", timeout=12000)
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("≈ 1 min 30 s")
    viewer.expect(viewer.page.locator("#scan-timing-estimate")).to_have_text(
        "Estimated range: 1 min 0 s–2 min 30 s · Estimate confidence: Medium",
    )
    viewer.expect(viewer.page.locator("#scan-timing-updated")).to_contain_text("Last scan update:")
    viewer.page.locator("#language-select").select_option("ru")
    viewer.page.locator("#theme-select").select_option("dark")
    viewer.expect(viewer.page.locator("html")).to_have_attribute("data-theme", "dark")
    viewer.expect(viewer.page.locator("#scan-timing")).to_contain_text("Длительность текущего запуска")
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("2 мин 5 с")
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("≈ 1 мин 30 с")
    viewer.expect(viewer.page.locator("#scan-timing-estimate")).to_contain_text("Уверенность в оценке: Средняя")
    # Another real poll with the same snapshot must not invent a countdown.
    viewer.next_summary()
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("2 мин 5 с")
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("≈ 1 мин 30 с")
    viewer.expect(card).to_have_attribute("data-timing-test-identity", "retained")
    viewer.expect(card).to_have_attribute("open", "")
    assert viewer.page.locator('#filters [name="severity"]').input_value() == "high"
    assert state.connection.total_changes == changes

    state.finish()
    controlled["timing"] = _snapshot("complete", 3661.9)
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("1 ч 1 мин 1 с", timeout=12000)
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("Завершено")
    viewer.expect(viewer.page.locator("#scan-timing-estimate")).to_be_hidden()
    viewer.next_summary()
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("1 ч 1 мин 1 с")
    viewer.page.locator("#language-select").select_option("en")
    viewer.page.locator("#theme-select").select_option("light")
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("1 h 1 min 1 s")
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("Complete")
    viewer.expect(viewer.page.locator("#metrics .metric")).to_have_count(6)


def test_summary_failure_hides_stale_estimate_without_clearing_other_errors(live_viewer):
    viewer = live_viewer
    viewer.create_scan()
    controlled = _control_timing(viewer, _snapshot("estimated", 90, 300, 200, 400, "low"))
    viewer.open_ready()

    def failed_results(route):
        route.fulfill(status=400, json={"detail": "synthetic result failure"})

    viewer.page.route(viewer.origin + "/api/scans/*/findings?*", failed_results)
    viewer.page.locator("#refresh-results").click()
    independent_error = "Check the filter settings: values and size ranges must be valid."
    viewer.expect(viewer.page.locator("#error")).to_contain_text(independent_error)
    pattern, failed_summary = viewer.fail_summary()
    viewer.next_summary(status=503)
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("Estimate out of date")
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("1 min 30 s")
    viewer.expect(viewer.page.locator("#scan-timing-estimate")).to_be_hidden()

    controlled["timing"] = _snapshot("estimated", 95, 270)
    viewer.page.unroute(pattern, failed_summary)
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("≈ 4 min 30 s", timeout=12000)
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("1 min 35 s")
    viewer.expect(viewer.page.locator("#error")).to_have_text(independent_error)
    viewer.expect(viewer.page.locator("#scan-timing-estimate")).to_be_hidden()


def test_unavailable_states_and_scan_switch_never_reuse_old_timing(live_viewer):
    viewer = live_viewer
    viewer.create_scan("legacy")
    viewer.create_scan("modern")
    controlled = _control_timing(viewer, _snapshot("estimated", 70, .2))
    viewer.open_ready()
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("≈ 1 s")
    viewer.page.locator("#language-select").select_option("ru")
    for status, expected in (
        ("calculating", "Вычисляется…"),
        ("unavailable", "Нет данных"),
        ("disabled", "Оценка отключена"),
        ("stale", "Оценка устарела"),
        ("not_started", "Основное сканирование не запущено"),
    ):
        # Even a contradictory numeric field cannot turn a non-estimated state
        # into a zero-second ETA. Values change only on the normal summary poll.
        controlled["timing"] = _snapshot(status, elapsed=None, remaining=0, lower=0, upper=0)
        viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text(expected, timeout=12000)
        viewer.expect(viewer.page.locator("#scan-timing-estimate")).to_be_hidden()
    controlled["timing"] = _snapshot("estimated", elapsed=-1, remaining="bad")
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("Нет данных", timeout=12000)
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("Нет данных")

    controlled["timing"] = _snapshot("estimated", 7200, 3600)
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("2 ч 0 мин 0 с", timeout=12000)
    selected = viewer.page.locator("#scan-select").input_value()
    other = next(option.get_attribute("value") for option in viewer.page.locator("#scan-select option").all()
                 if option.get_attribute("value") != selected)
    controlled["timing"] = None
    viewer.page.locator("#scan-select").select_option(other)
    viewer.expect(viewer.page.locator("#scan-overview")).to_be_visible()
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("Нет данных")
    viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("Нет данных")
    viewer.expect(viewer.page.locator("#scan-timing-updated")).to_be_hidden()
    viewer.expect(viewer.page.locator("#scan-timing-estimate")).to_be_hidden()
    viewer.expect(viewer.page.locator("#metrics .metric")).to_have_count(6)


def test_real_timing_checkpoint_updates_do_not_announce_new_results(live_viewer):
    viewer = live_viewer
    state = viewer.create_scan()

    def publish(elapsed):
        now = datetime.now(timezone.utc)
        state.set_checkpoint("scan_timing", {
            "version": 1,
            "started_at": (now - timedelta(seconds=elapsed)).isoformat(),
            "updated_at": now.isoformat(),
            "elapsed_seconds": elapsed,
            "eta": {
                "status": "estimated", "elapsed_seconds": elapsed,
                "remaining_seconds": 120, "lower_seconds": 60, "upper_seconds": 180,
                "confidence": "low",
            },
        })

    publish(5)
    viewer.open_ready()
    viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text("5 s")
    viewer.expect(viewer.page.locator("#new-results")).to_be_hidden()
    card = viewer.page.locator("#results .file-result").first
    card.locator("summary").click()
    viewer.expect(card.locator("mark").first).to_be_visible()
    card.evaluate("element => { element.dataset.timingTestIdentity = 'retained'; }")

    for elapsed in (12, 19):
        publish(elapsed)
        changes = state.connection.total_changes
        viewer.expect(viewer.page.locator("#scan-elapsed")).to_have_text(f"{elapsed} s", timeout=12000)
        viewer.expect(viewer.page.locator("#scan-remaining")).to_have_text("≈ 2 min 0 s")
        viewer.expect(viewer.page.locator("#new-results")).to_be_hidden()
        viewer.expect(card).to_have_attribute("data-timing-test-identity", "retained")
        viewer.expect(card).to_have_attribute("open", "")
        assert state.connection.total_changes == changes

    viewer.add_file(state, "found-after-timing-updates.txt")
    viewer.expect(viewer.page.locator("#new-results")).to_be_visible(timeout=12000)
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(1)
    viewer.page.locator("#new-results").click()
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(2)
    viewer.expect(viewer.page.locator("#new-results")).to_be_hidden()
