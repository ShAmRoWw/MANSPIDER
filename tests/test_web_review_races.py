"""Opt-in Chromium review races; tiny local fixtures, never an SMB scan.

MANSPIDER_BROWSER_TESTS=1 python -m pytest -q tests/test_web_review_races.py
Run sequentially with the other browser tests, using their documented scope.
"""

import os
import time
from urllib.parse import parse_qs, urlsplit

import pytest

from tests import test_web_live_recovery as fixtures


chromium = fixtures.chromium
live_viewer = fixtures.live_viewer


pytestmark = pytest.mark.skipif(
    os.environ.get("MANSPIDER_BROWSER_TESTS") != "1", reason="explicit bounded browser test only",
)


def _open_first(viewer):
    card = viewer.page.locator("#results .file-result").first
    if card.get_attribute("open") is None:
        card.locator("summary").first.click()
    article = card.locator("article.finding").first
    viewer.expect(article.locator(".review-toggle")).to_be_visible()
    return card, article


def _wait_held(viewer, held):
    deadline = time.monotonic() + 10
    while not held and time.monotonic() < deadline:
        viewer.page.wait_for_timeout(20)
    assert held, "The controlled HTTP response was not held"


def _select_scan(viewer, scan_id, path):
    with viewer.page.expect_response(
        lambda response: f"/api/scans/{scan_id}/findings?" in response.url,
    ):
        viewer.page.locator("#scan-select").select_option(scan_id)
    viewer.expect(viewer.page.locator("#results .file-path").first).to_contain_text(path)


def test_delayed_old_generation_patch_cannot_reapply_a_reverted_mark(live_viewer):
    viewer = live_viewer
    # Deliberately reuse an ID across TWO distinct local fixture databases.
    # Production finding IDs are content-derived, not sequential integers.
    for name in ("older", "newer"):
        state = viewer.create_scan(name)
        state.connection.execute("UPDATE findings SET finding_id=?", ("1" * 64,))
        state.connection.commit()
    viewer.open_ready()
    original_id = viewer.page.locator("#scan-select").input_value()
    other_id = next(
        option.get_attribute("value") for option in viewer.page.locator("#scan-select option").all()
        if option.get_attribute("value") != original_id
    )
    viewer.expect(viewer.page.locator(".file-path").first).to_contain_text("newer-000.txt")
    _, article = _open_first(viewer)
    finding_id = article.get_attribute("data-finding-id")
    held = []
    pattern = viewer.origin + "/api/scans/*/findings/*/review"

    def hold_first_reply(route):
        if not held:
            # The real local write completes, but the old page has not received
            # its confirmation. Subsequent writes use the actual API normally.
            response = route.fetch()
            assert response.status == 200
            held.append((route, response))
        else:
            route.continue_()

    viewer.page.route(pattern, hold_first_reply)
    article.locator(".review-toggle").click()
    _wait_held(viewer, held)
    viewer.expect(article.locator(".review-toggle")).to_be_disabled()
    viewer.expect(article).to_have_attribute("data-reviewed", "false")

    _select_scan(viewer, other_id, "older-000.txt")
    _, other_article = _open_first(viewer)
    # The synthetic ID is identical: the finding ID alone cannot identify its scan.
    assert other_article.get_attribute("data-finding-id") == finding_id
    viewer.expect(other_article).to_have_attribute("data-reviewed", "false")
    viewer.expect(viewer.page.locator("#review-notice")).to_be_hidden()

    _select_scan(viewer, original_id, "newer-000.txt")
    _, current = _open_first(viewer)
    viewer.expect(current).to_have_attribute("data-reviewed", "true")
    viewer.expect(current.locator(".review-toggle")).to_be_enabled()
    current.locator(".review-toggle").click()
    viewer.expect(current).to_have_attribute("data-reviewed", "false")
    # Returning to the same scan is still a NEW generation. The earlier true
    # response must not overwrite the newer, successfully persisted false mark.
    route, response = held.pop()
    with viewer.page.expect_response(lambda reply: reply.request.method == "PATCH"):
        route.fulfill(response=response)
    # Let the deliberately late body and its continuation settle before
    # asserting that the obsolete generation made no DOM change.
    viewer.page.wait_for_timeout(100)
    viewer.expect(current).to_have_attribute("data-reviewed", "false")
    viewer.expect(current.locator(".review-toggle")).to_have_text("Mark reviewed")
    viewer.page.unroute(pattern, hold_first_reply)
    viewer.page.locator("#refresh-results").click()
    viewer.expect(viewer.page.locator("#refresh-results")).to_be_enabled()
    _, refreshed = _open_first(viewer)
    viewer.expect(refreshed).to_have_attribute("data-reviewed", "false")
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()


def test_old_or_failed_list_reply_preserves_successfully_changed_mark(live_viewer):
    viewer = live_viewer
    viewer.create_scan("list-race")
    viewer.open_ready()
    pattern = viewer.origin + "/api/scans/*/findings?*"
    for reply_status in (200, 503):
        card, article = _open_first(viewer)
        initial_count = viewer.page.locator("#result-count").inner_text()
        previous = article.get_attribute("data-reviewed")
        expected = "false" if previous == "true" else "true"
        held = []

        def hold_list(route):
            held.append((route, route.fetch()))

        viewer.page.route(pattern, hold_list)
        viewer.page.locator("#refresh-results").click()
        _wait_held(viewer, held)
        viewer.expect(viewer.page.locator("#refresh-results")).to_be_disabled()
        article.locator(".review-toggle").click()
        viewer.expect(article).to_have_attribute("data-reviewed", expected)
        route, response = held.pop()
        with viewer.page.expect_response(lambda reply: "/findings?" in reply.url):
            if reply_status == 200:
                route.fulfill(response=response)
            else:
                route.fulfill(status=503, json={"detail": "Synthetic delayed list failure"})
        viewer.expect(viewer.page.locator("#refresh-results")).to_be_enabled()
        viewer.expect(article).to_have_attribute("data-reviewed", expected)
        assert card.get_attribute("open") is not None
        viewer.expect(viewer.page.locator("#review-notice")).to_be_visible()
        if reply_status == 200:
            viewer.expect(viewer.page.locator("#result-count")).to_have_text(initial_count)
            viewer.expect(viewer.page.locator("#error")).to_be_hidden()
        else:
            viewer.expect(viewer.page.locator("#error")).to_be_visible()
        viewer.page.unroute(pattern, hold_list)
        with viewer.page.expect_response(lambda reply: "/findings?" in reply.url and reply.status == 200):
            viewer.page.locator("#refresh-results").click()
        viewer.expect(viewer.page.locator("#refresh-results")).to_be_enabled()
        _, refreshed = _open_first(viewer)
        viewer.expect(refreshed).to_have_attribute("data-reviewed", expected)
        viewer.expect(viewer.page.locator("#error")).to_be_hidden()


def test_full_finding_pages_sync_preview_marks_and_keep_applied_review_filter(live_viewer):
    from man_spider.state import FindingRecord

    viewer = live_viewer
    state = viewer.create_scan("many-reviews", files=0)
    decision = state.claim_object(object_key="many", kind="file", path="many.txt", size=100)
    state.complete_object(
        decision.object_id, "processed",
        findings=tuple(FindingRecord(
            f"rule:many-{index:03}", f"SyntheticOnly-{index:03}", severity="high", confidence="high",
        ) for index in range(70)),
        analysis_status="analyzed", analysis_read=True,
    )
    viewer.open_ready()
    viewer.page.locator('#filters [name="review_status"]').select_option("unreviewed")
    with viewer.page.expect_response(lambda response: "/findings?" in response.url):
        viewer.page.locator('#filters button[type="submit"]').click()
    viewer.expect(viewer.page.locator("#refresh-results")).to_be_enabled()
    card, preview = _open_first(viewer)
    finding_id = preview.get_attribute("data-finding-id")
    detail_requests = []
    viewer.page.on("request", lambda request: detail_requests.append(request.url)
                   if "/objects/" in request.url and "/findings?" in request.url else None)
    card.get_by_role("button", name="All file matches — 50 per page", exact=True).click()
    viewer.expect(card.locator("article.finding:visible")).to_have_count(50)
    copies = card.locator(f'article[data-finding-id="{finding_id}"]')
    viewer.expect(copies).to_have_count(2)
    full = card.locator(f'article[data-finding-id="{finding_id}"]:visible')
    full.locator(".review-toggle").click()
    viewer.expect(copies.nth(0)).to_have_attribute("data-reviewed", "true")
    viewer.expect(copies.nth(1)).to_have_attribute("data-reviewed", "true")
    card.get_by_role("button", name="Collapse full set", exact=True).click()
    viewer.expect(preview).to_be_visible()
    viewer.expect(preview.locator(".review-toggle")).to_have_text("Mark unreviewed")

    with viewer.page.expect_response(lambda response: "/findings?" in response.url):
        viewer.page.locator("#refresh-results").click()
    viewer.expect(viewer.page.locator("#refresh-results")).to_be_enabled()
    card, _ = _open_first(viewer)
    viewer.expect(card.locator(f'article[data-finding-id="{finding_id}"]')).to_have_count(0)
    card.get_by_role("button", name="All file matches — 50 per page", exact=True).click()
    viewer.expect(card.locator("article.finding:visible")).to_have_count(50)
    # Editing the form is not applying it. Paging uses the filter captured when
    # this file was rendered, not the unsaved control value or another page.
    viewer.page.locator('#filters [name="review_status"]').select_option("reviewed")
    card.get_by_role("button", name="Next →", exact=True).click()
    viewer.expect(card.locator("article.finding:visible")).to_have_count(19)
    assert detail_requests
    assert all(parse_qs(urlsplit(url).query).get("review_status") == ["unreviewed"] for url in detail_requests)
    assert parse_qs(urlsplit(detail_requests[-1]).query)["after"] != ["0"]
    viewer.expect(card.locator(f'article[data-finding-id="{finding_id}"]')).to_have_count(0)
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()
