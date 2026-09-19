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


def _apply_review_filter(viewer, status):
    viewer.page.locator('#filters [name="review_status"]').select_option(status)
    with viewer.page.expect_response(_is_result_page):
        viewer.page.locator('#filters button[type="submit"]').click()
    viewer.expect(viewer.page.locator("#refresh-results")).to_be_enabled()


def _is_result_page(response):
    return "/findings?" in response.url and "/objects/" not in response.url


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
    with viewer.page.expect_response(_is_result_page):
        full.locator(".review-toggle").click()
    viewer.expect(viewer.page.locator("#refresh-results")).to_be_enabled()
    viewer.expect(card.locator(f'article[data-finding-id="{finding_id}"]')).to_have_count(0)
    # The current file remains expanded, but its full-set page is rebuilt from
    # the current filtered preview instead of retaining stale match copies.
    assert card.get_attribute("open") is not None
    viewer.expect(card.locator("article.finding").first).to_be_visible()
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


@pytest.mark.parametrize("status", ["", "unreviewed", "reviewed"])
def test_only_applied_review_filter_hides_a_confirmed_change(live_viewer, status):
    viewer = live_viewer
    viewer.create_scan("applied-review", files=2)
    viewer.open_ready()
    if status == "reviewed":
        for card in viewer.page.locator("#results .file-result").all():
            card.locator("summary").first.click()
            article = card.locator("article.finding").first
            article.locator(".review-toggle").click()
            viewer.expect(article).to_have_attribute("data-reviewed", "true")
    _apply_review_filter(viewer, status)
    _, article = _open_first(viewer)
    finding_id = article.get_attribute("data-finding-id")
    finding = viewer.page.locator(f'#results article[data-finding-id="{finding_id}"]')
    requests = []
    viewer.page.on("request", lambda request: requests.append(request.url) if _is_result_page(request) else None)
    # Unsubmitted controls must neither enable hiding in All mode nor change
    # which saved review filter is used by the automatic reload.
    unsaved = "unreviewed" if status == "reviewed" else "reviewed"
    viewer.page.locator('#filters [name="review_status"]').select_option(unsaved)
    if status:
        with viewer.page.expect_response(_is_result_page):
            article.locator(".review-toggle").click()
        viewer.expect(finding).to_have_count(0)
        viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(1)
        assert len(requests) == 1
        assert parse_qs(urlsplit(requests[0]).query)["review_status"] == [status]
    else:
        article.locator(".review-toggle").click()
        viewer.expect(finding).to_have_attribute("data-reviewed", "true")
        viewer.expect(finding.locator(".review-toggle")).to_be_enabled()
        viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(2)
        assert requests == []
    assert viewer.page.locator('#filters [name="review_status"]').input_value() == unsaved
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()


@pytest.mark.parametrize("succeeds", [False, True])
def test_filtered_finding_stays_until_patch_is_successfully_confirmed(live_viewer, succeeds):
    viewer = live_viewer
    viewer.create_scan("pending-review")
    viewer.open_ready()
    _apply_review_filter(viewer, "unreviewed")
    _, article = _open_first(viewer)
    finding_id = article.get_attribute("data-finding-id")
    finding = viewer.page.locator(f'#results article[data-finding-id="{finding_id}"]')
    held, requests = [], []
    pattern = viewer.origin + "/api/scans/*/findings/*/review"

    def hold_patch(route):
        held.append(route)

    viewer.page.route(pattern, hold_patch)
    viewer.page.on("request", lambda request: requests.append(request.url) if _is_result_page(request) else None)
    article.locator(".review-toggle").click()
    _wait_held(viewer, held)
    viewer.expect(finding).to_be_visible()
    viewer.expect(finding).to_have_attribute("data-reviewed", "false")
    viewer.expect(finding.locator(".review-toggle")).to_be_disabled()
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(1)
    assert requests == []
    route = held.pop()
    if succeeds:
        with viewer.page.expect_response(_is_result_page):
            route.continue_()
        viewer.expect(finding).to_have_count(0)
        viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(0)
        assert len(requests) == 1
        viewer.expect(viewer.page.locator("#error")).to_be_hidden()
    else:
        route.fulfill(status=503, json={"detail": "Synthetic review save failure"})
        viewer.expect(viewer.page.locator("#error")).to_be_visible()
        viewer.expect(finding).to_have_attribute("data-reviewed", "false")
        viewer.expect(finding.locator(".review-toggle")).to_be_enabled()
        viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(1)
        assert requests == []
    viewer.page.unroute(pattern, hold_patch)


def test_failed_automatic_list_reload_retains_confirmed_mark_and_can_retry(live_viewer):
    viewer = live_viewer
    viewer.create_scan("failed-auto-list")
    viewer.open_ready()
    _apply_review_filter(viewer, "unreviewed")
    card, article = _open_first(viewer)
    pattern = viewer.origin + "/api/scans/*/findings?*"

    def fail_list(route):
        route.fulfill(status=503, json={"detail": "Synthetic automatic list failure"})

    viewer.page.route(pattern, fail_list)
    with viewer.page.expect_response(lambda response: _is_result_page(response) and response.status == 503):
        article.locator(".review-toggle").click()
    viewer.expect(viewer.page.locator("#error")).to_be_visible()
    viewer.expect(article).to_have_attribute("data-reviewed", "true")
    viewer.expect(article.locator(".review-toggle")).to_be_enabled()
    viewer.expect(viewer.page.locator("#review-notice")).to_be_visible()
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(1)
    assert card.get_attribute("open") is not None
    viewer.page.unroute(pattern, fail_list)
    with viewer.page.expect_response(_is_result_page):
        viewer.page.locator("#refresh-results").click()
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(0)
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()


def test_delayed_filtered_list_cannot_restore_an_automatically_removed_finding(live_viewer):
    viewer = live_viewer
    viewer.create_scan("old-filtered-list")
    viewer.open_ready()
    _apply_review_filter(viewer, "unreviewed")
    _, article = _open_first(viewer)
    held = []
    pattern = viewer.origin + "/api/scans/*/findings?*"

    def hold_first_list(route):
        if not held:
            held.append((route, route.fetch()))
        else:
            route.continue_()

    viewer.page.route(pattern, hold_first_list)
    viewer.page.locator("#refresh-results").click()
    _wait_held(viewer, held)
    with viewer.page.expect_response(_is_result_page):
        article.locator(".review-toggle").click()
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(0)
    route, response = held.pop()
    # The superseded fetch may already be aborted; its late successful body
    # must never restore the old filtered page in either case.
    route.fulfill(response=response)
    viewer.page.wait_for_timeout(100)
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(0)
    viewer.expect(viewer.page.locator("#refresh-results")).to_be_enabled()
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()
    viewer.page.unroute(pattern, hold_first_list)


def test_automatic_filter_reload_keeps_second_page_cursor_even_when_page_empties(live_viewer):
    viewer = live_viewer
    viewer.create_scan("second-review-page", files=102)
    viewer.open_ready()
    _apply_review_filter(viewer, "unreviewed")
    with viewer.page.expect_response(_is_result_page) as second_page:
        viewer.page.locator("#next-page").click()
    cursor = parse_qs(urlsplit(second_page.value.url).query)["after"]
    assert cursor != ["0"]
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(2)
    for remaining in (1, 0):
        _, article = _open_first(viewer)
        with viewer.page.expect_response(_is_result_page) as refreshed:
            article.locator(".review-toggle").click()
        assert parse_qs(urlsplit(refreshed.value.url).query)["after"] == cursor
        viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(remaining)
        viewer.expect(viewer.page.locator("#page-number")).to_have_text("Page 2")
        viewer.expect(viewer.page.locator("#previous-page")).to_be_enabled()
    viewer.expect(viewer.page.locator("#next-page")).to_be_disabled()
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()
