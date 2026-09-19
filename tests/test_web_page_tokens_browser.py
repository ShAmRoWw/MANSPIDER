"""Opt-in, bounded Chromium regressions for stale per-file finding pages.

Use MANSPIDER_BROWSER_TESTS=1 in the browser suite's documented systemd scope.
Only disposable local manifests, loopback HTTP and generated evidence are used.
"""

from dataclasses import replace
import os
import time
from urllib.parse import parse_qs, urlsplit

import pytest

from man_spider.state import FindingRecord
from tests import test_web_live_recovery as fixtures


chromium = fixtures.chromium
live_viewer = fixtures.live_viewer
pytestmark = pytest.mark.skipif(
    os.environ.get("MANSPIDER_BROWSER_TESTS") != "1", reason="explicit bounded browser test only",
)


def many_findings(viewer, count=60):
    scan = viewer.create_scan("page-tokens", files=0)
    records = tuple(FindingRecord(
        "rule:fixture-secret", f"SyntheticOnly-{index:03}", index, index + 1,
        context=f"SyntheticOnly-{index:03}",
    ) for index in range(count))
    obj = scan.claim_object(object_key="retry", kind="file", path="retry.txt", size=100)
    scan.complete_object(obj.object_id, "error", findings=records)
    viewer.add_file(scan, "later.txt")  # Prevent deleted findings' rowids being reused.
    return scan, obj.object_id, records


def open_file(viewer):
    card = viewer.page.locator("#results .file-result").filter(has_text="retry.txt")
    if card.get_attribute("open") is None:
        card.locator("summary").click()
    return card


def open_full(viewer, card):
    with viewer.page.expect_response(is_detail) as reply:
        card.get_by_role("button", name="All file matches — 50 per page", exact=True).click()
    assert reply.value.status == 200
    assert reply.value.json()["page_token"].startswith("v1.")
    viewer.expect(card.locator("article.finding:visible")).to_have_count(50)
    return reply.value


def is_detail(response):
    return "/objects/" in response.url and "/findings?" in response.url


def ids(card):
    return card.locator("article.finding:visible").evaluate_all(
        "nodes => nodes.map(node => node.dataset.findingId)",
    )


def next_page(viewer, card, expected_status=200):
    with viewer.page.expect_response(is_detail) as reply:
        card.get_by_role("button", name="Next →", exact=True).click()
    assert reply.value.status == expected_status
    return reply.value


def wait_held(viewer, held):
    deadline = time.monotonic() + 10
    while not held and time.monotonic() < deadline:
        viewer.page.wait_for_timeout(20)
    assert held, "The diagnostic response was not held"


@pytest.mark.parametrize("change", ["retry", "reverse", "delete_anchor", "change_anchor"])
def test_stale_file_pages_preserve_evidence_and_restart_only_that_file(live_viewer, change):
    viewer = live_viewer
    scan, object_id, records = many_findings(viewer)
    viewer.open_ready()
    other = viewer.page.locator("#results .file-result").filter(has_text="later.txt")
    other.locator("summary").click()
    viewer.expect(other.locator("article.finding")).to_be_visible()
    other_evidence = other.inner_text()
    card = open_file(viewer)
    first_reply = open_full(viewer, card)
    before_ids = ids(card)
    anchor_value = first_reply.json()["items"][-1]["value"]
    if change == "reverse":
        records = records[::-1]
    elif change == "delete_anchor":
        records = tuple(record for record in records if record.value != anchor_value)
    elif change == "change_anchor":
        records = tuple(replace(record, value="ChangedSyntheticOnly") if record.value == anchor_value else record for record in records)
    scan.begin_object(object_id)
    scan.complete_object(object_id, "processed", findings=records)
    expected_ids = [row[0] for row in scan.connection.execute(
        "SELECT finding_id FROM findings WHERE object_id=? ORDER BY rowid DESC", (object_id,),
    )]
    scan_before_reads = list(scan.connection.iterdump())
    reply = next_page(viewer, card, 409)
    assert reply.json()["code"] == "stale_page"
    viewer.expect(card.locator(".file-page-notice")).to_be_visible()
    viewer.expect(card).to_contain_text("Page 1: 50 matches")
    viewer.expect(card.get_by_role("button", name="Next →", exact=True)).to_be_disabled()
    assert ids(card) == before_ids
    assert other.inner_text() == other_evidence
    assert other.get_attribute("open") is not None

    # Polling and translation do not silently restart or remove evidence.
    detail_requests = []
    viewer.page.on("request", lambda request: detail_requests.append(request.url) if is_detail(request) else None)
    viewer.page.locator("#language-select").select_option("ru")
    viewer.expect(card.locator(".file-page-notice")).to_contain_text("Показанные данные сохранены")
    assert ids(card) == before_ids
    viewer.page.locator("#language-select").select_option("en")
    if change == "retry":
        viewer.next_summary()
        assert detail_requests == []

    with viewer.page.expect_response(is_detail) as restarted:
        card.locator(".restart-file-pages").click()
    assert restarted.value.status == 200
    query = parse_qs(urlsplit(restarted.value.url).query)
    assert query["after"] == ["0"] and "page_token" not in query
    viewer.expect(card.locator(".file-page-notice")).to_be_hidden()
    viewer.expect(card.locator("article.finding:visible")).to_have_count(50)
    all_ids = ids(card)
    next_page(viewer, card)
    viewer.expect(card.locator("article.finding:visible")).to_have_count(len(records) - 50)
    all_ids.extend(ids(card))
    assert all_ids == expected_ids
    assert other.inner_text() == other_evidence
    assert other.get_attribute("open") is not None
    assert list(scan.connection.iterdump()) == scan_before_reads


@pytest.mark.parametrize("append_unrelated", [False, True])
def test_same_version_keeps_next_back_and_collapsed_page_cursors(live_viewer, append_unrelated):
    viewer = live_viewer
    scan, object_id, _ = many_findings(viewer, count=120)
    viewer.open_ready()
    card = open_file(viewer)
    first = open_full(viewer, card)
    token = first.json()["page_token"]
    first_ids = ids(card)
    if append_unrelated:
        viewer.add_file(scan, "unrelated.txt")
    second = next_page(viewer, card)
    viewer.expect(card).to_contain_text("Page 2: 50 matches")
    second_ids = ids(card)
    assert second.json()["page_token"] == token
    with viewer.page.expect_response(is_detail) as back:
        card.get_by_role("button", name="← Previous", exact=True).click()
    viewer.expect(card).to_contain_text("Page 1: 50 matches")
    assert ids(card) == first_ids
    back_query = parse_qs(urlsplit(back.value.url).query)
    assert back_query["after"] == ["0"] and back_query["page_token"] == [token]
    card.get_by_role("button", name="Collapse full set", exact=True).click()
    reopened = open_full(viewer, card)
    assert parse_qs(urlsplit(reopened.url).query)["page_token"] == [token]
    next_page(viewer, card)
    viewer.expect(card).to_contain_text("Page 2: 50 matches")
    assert ids(card) == second_ids
    next_page(viewer, card)
    viewer.expect(card.locator("article.finding:visible")).to_have_count(20)
    expected = [row[0] for row in scan.connection.execute(
        "SELECT finding_id FROM findings WHERE object_id=? ORDER BY rowid DESC", (object_id,),
    )]
    assert first_ids + second_ids + ids(card) == expected


def test_another_tab_review_change_invalidates_filtered_file_pages(live_viewer):
    viewer = live_viewer
    scan, object_id, _ = many_findings(viewer, count=70)
    viewer.open_ready()
    viewer.page.locator('#filters [name="review_status"]').select_option("unreviewed")
    with viewer.page.expect_response(lambda response: "/findings?" in response.url):
        viewer.page.locator('#filters button[type="submit"]').click()
    viewer.expect(viewer.page.locator("#refresh-results")).to_be_enabled()
    card = open_file(viewer)
    open_full(viewer, card)
    before_ids = ids(card)
    other_tab = viewer.page.context.new_page()
    try:
        other_tab.goto(viewer.origin + "/")
        other_card = other_tab.locator("#results .file-result").filter(has_text="retry.txt")
        other_card.locator("summary").click()
        article = other_card.locator("article.finding").first
        marked_id = article.get_attribute("data-finding-id")
        article.locator(".review-toggle").click()
        viewer.expect(article).to_have_attribute("data-reviewed", "true")
        next_page(viewer, card, 409)
        viewer.expect(card.locator(".file-page-notice")).to_be_visible()
        assert ids(card) == before_ids
        with viewer.page.expect_response(is_detail):
            card.locator(".restart-file-pages").click()
        viewer.expect(card.locator(".file-page-notice")).to_be_hidden()
        viewer.expect(card.locator("article.finding:visible")).to_have_count(50)
        collected = ids(card)
        assert marked_id not in collected
        next_page(viewer, card)
        viewer.expect(card.locator("article.finding:visible")).to_have_count(19)
        collected += ids(card)
        assert len(set(collected)) == 69 and marked_id not in collected
        assert len(scan.findings_for(object_id)) == 70
    finally:
        other_tab.close()


def test_stale_back_reopen_and_failed_restart_retain_the_displayed_second_page(live_viewer):
    viewer = live_viewer
    scan, object_id, records = many_findings(viewer, count=120)
    viewer.open_ready()
    card = open_file(viewer)
    open_full(viewer, card)
    next_page(viewer, card)
    viewer.expect(card).to_contain_text("Page 2: 50 matches")
    second_ids = ids(card)
    scan.complete_object(object_id, "processed", findings=records)
    with viewer.page.expect_response(is_detail) as back:
        card.get_by_role("button", name="← Previous", exact=True).click()
    assert back.value.status == 409
    query = parse_qs(urlsplit(back.value.url).query)
    assert query["after"] == ["0"] and "page_token" in query
    viewer.expect(card.locator(".file-page-notice")).to_be_visible()
    viewer.expect(card).to_contain_text("Page 2: 50 matches")
    assert ids(card) == second_ids
    card.get_by_role("button", name="Collapse full set", exact=True).click()
    viewer.expect(card.locator("article.finding:visible")).to_have_count(20)
    card.get_by_role("button", name="All file matches — 50 per page", exact=True).click()
    viewer.expect(card.locator("article.finding:visible")).to_have_count(50)
    assert ids(card) == second_ids
    pattern = viewer.origin + "/api/scans/*/objects/*/findings?*"

    def fail_restart(route):
        route.fulfill(status=503, json={"detail": "Synthetic failed restart"})

    viewer.page.route(pattern, fail_restart)
    with viewer.page.expect_response(is_detail) as failed:
        card.locator(".restart-file-pages").click()
    assert failed.value.status == 503
    viewer.expect(viewer.page.locator("#error")).to_be_visible()
    viewer.expect(card.locator(".file-page-notice")).to_be_visible()
    viewer.expect(card.locator(".restart-file-pages")).to_be_enabled()
    assert ids(card) == second_ids
    viewer.expect(card).to_contain_text("Page 2: 50 matches")
    viewer.page.unroute(pattern, fail_restart)
    with viewer.page.expect_response(is_detail):
        card.locator(".restart-file-pages").click()
    viewer.expect(card.locator(".file-page-notice")).to_be_hidden()
    viewer.expect(card).to_contain_text("Page 1: 50 matches")
    viewer.expect(card.get_by_role("button", name="← Previous", exact=True)).to_be_disabled()
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()
    next_page(viewer, card)
    viewer.expect(card).to_contain_text("Page 2: 50 matches")


def test_collapsed_page_reopen_checks_its_token_before_replacing_preview(live_viewer):
    viewer = live_viewer
    scan, object_id, records = many_findings(viewer)
    viewer.open_ready()
    card = open_file(viewer)
    first = open_full(viewer, card)
    token = first.json()["page_token"]
    card.get_by_role("button", name="Collapse full set", exact=True).click()
    viewer.expect(card.locator("article.finding:visible")).to_have_count(20)
    preview_ids = ids(card)
    scan.complete_object(object_id, "processed", findings=records)
    with viewer.page.expect_response(is_detail) as reopened:
        card.get_by_role("button", name="All file matches — 50 per page", exact=True).click()
    assert reopened.value.status == 409
    query = parse_qs(urlsplit(reopened.value.url).query)
    assert query["after"] == ["0"] and query["page_token"] == [token]
    viewer.expect(card.locator(".file-page-notice")).to_be_visible()
    assert ids(card) == preview_ids
    viewer.expect(card.locator(".restart-file-pages")).to_be_enabled()


def test_missing_page_token_is_not_accepted_as_an_unversioned_page(live_viewer):
    viewer = live_viewer
    many_findings(viewer)
    viewer.open_ready()
    card = open_file(viewer)
    viewer.expect(card.locator("article.finding:visible")).to_have_count(20)
    preview_ids = ids(card)
    pattern = viewer.origin + "/api/scans/*/objects/*/findings?*"

    def missing_token(route):
        response = route.fetch()
        value = response.json()
        value.pop("page_token")
        route.fulfill(response=response, json=value)

    viewer.page.route(pattern, missing_token)
    with viewer.page.expect_response(is_detail):
        card.get_by_role("button", name="All file matches — 50 per page", exact=True).click()
    viewer.expect(viewer.page.locator("#error")).to_be_visible()
    viewer.expect(card.locator(".file-page-notice")).to_be_hidden()
    assert ids(card) == preview_ids
    viewer.page.unroute(pattern, missing_token)
    open_full(viewer, card)
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()


@pytest.mark.parametrize("status", [503, 409])
def test_nonstale_failure_keeps_page_cursor_and_does_not_offer_restart(live_viewer, status):
    viewer = live_viewer
    many_findings(viewer)
    viewer.open_ready()
    card = open_file(viewer)
    open_full(viewer, card)
    before_ids = ids(card)
    pattern = viewer.origin + "/api/scans/*/objects/*/findings?*"

    def fail(route):
        route.fulfill(status=status, json={"detail": "Synthetic non-stale database error"})

    viewer.page.route(pattern, fail)
    next_page(viewer, card, status)
    viewer.expect(viewer.page.locator("#error")).to_be_visible()
    viewer.expect(card.locator(".file-page-notice")).to_be_hidden()
    viewer.expect(card.get_by_role("button", name="← Previous", exact=True)).to_be_disabled()
    viewer.expect(card).to_contain_text("Page 1: 50 matches")
    assert ids(card) == before_ids
    viewer.page.unroute(pattern, fail)
    next_page(viewer, card)
    viewer.expect(card).to_contain_text("Page 2: 10 matches")
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()


@pytest.mark.parametrize("intervening", ["review", "detach", "generation"])
def test_delayed_stale_reply_cannot_affect_newer_ui_or_advance_cursor(live_viewer, intervening):
    viewer = live_viewer
    viewer.create_scan("older")
    many_findings(viewer)
    viewer.open_ready()
    original_scan_id = viewer.page.locator("#scan-select").input_value()
    card = open_file(viewer)
    open_full(viewer, card)
    first_ids = ids(card)
    held = []
    pattern = viewer.origin + "/api/scans/*/objects/*/findings?*"

    def hold(route):
        held.append((route, route.fetch()))

    viewer.page.route(pattern, hold)
    card.get_by_role("button", name="Next →", exact=True).click()
    wait_held(viewer, held)
    if intervening == "review":
        article = card.locator("article.finding:visible").first
        article.locator(".review-toggle").click()
        viewer.expect(article).to_have_attribute("data-reviewed", "true")
    elif intervening == "detach":
        with viewer.page.expect_response(lambda response: "/findings?" in response.url and "/objects/" not in response.url):
            viewer.page.locator("#refresh-results").click()
    else:
        other_id = next(option.get_attribute("value") for option in viewer.page.locator("#scan-select option").all()
                        if option.get_attribute("value") != original_scan_id)
        viewer.page.locator("#scan-select").select_option(other_id)
        viewer.expect(viewer.page.locator("#results .file-path").first).to_contain_text("older-000.txt")
    route, _ = held.pop()
    with viewer.page.expect_response(is_detail):
        route.fulfill(status=409, json={"detail": "Synthetic delayed stale page", "code": "stale_page"})
    viewer.page.unroute(pattern, hold)
    viewer.page.wait_for_timeout(100)
    viewer.expect(viewer.page.locator(".file-page-notice:visible")).to_have_count(0)
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()
    if intervening == "review":
        assert ids(card) == first_ids
        viewer.expect(card).to_contain_text("Page 1: 50 matches")
        viewer.expect(card.get_by_role("button", name="← Previous", exact=True)).to_be_disabled()
        next_page(viewer, card)
        viewer.expect(card).to_contain_text("Page 2: 10 matches")
