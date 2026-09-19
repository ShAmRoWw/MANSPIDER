"""Opt-in real Chromium manual-review flow; tiny local fixtures, no SMB."""

import os

import pytest

from tests import test_web_live_recovery as fixtures


chromium = fixtures.chromium
live_viewer = fixtures.live_viewer


pytestmark = pytest.mark.skipif(
    os.environ.get("MANSPIDER_BROWSER_TESTS") != "1", reason="explicit bounded browser test only",
)


def _filter(viewer, status):
    viewer.page.locator('#filters select[name="review_status"]').select_option(status)
    viewer.page.locator('#filters button[type="submit"]').click()


def _open_first(viewer):
    card = viewer.page.locator(".file-result").first
    card.locator("summary").first.click()
    article = card.locator("article.finding").first
    viewer.expect(article.locator(".review-toggle")).to_be_visible()
    return article


def test_review_persists_filters_and_can_be_undone_without_changing_scan(live_viewer):
    viewer = live_viewer
    state = viewer.create_scan("manual", files=2)
    before_rows = [tuple(row) for row in state.connection.execute("SELECT * FROM findings ORDER BY finding_id")]
    before_changes = state.connection.total_changes
    viewer.open_ready()
    assert viewer.page.locator('[name="review_status"]').input_value() == ""
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(2)
    article = _open_first(viewer)
    finding_id = article.get_attribute("data-finding-id")
    viewer.expect(article).to_have_attribute("data-reviewed", "false")
    article.locator(".review-toggle").click()
    viewer.expect(article).to_have_attribute("data-reviewed", "true")
    viewer.expect(article.locator(".review-toggle")).to_have_text("Mark unreviewed")
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(2)  # No implicit hiding.
    viewer.expect(viewer.page.locator("#review-notice")).to_be_visible()

    _filter(viewer, "unreviewed")
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(1)
    _filter(viewer, "reviewed")
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(1)
    marked = _open_first(viewer)
    assert marked.get_attribute("data-finding-id") == finding_id
    viewer.expect(marked).to_have_attribute("data-reviewed", "true")

    viewer.page.reload()
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(2)
    _filter(viewer, "reviewed")
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(1)
    marked = _open_first(viewer)
    viewer.expect(marked).to_have_attribute("data-reviewed", "true")
    viewer.page.locator("#language-select").select_option("ru")
    viewer.expect(marked.locator(".review-toggle")).to_have_text("Снять отметку проверки")
    viewer.page.locator("#theme-select").select_option("dark")
    viewer.expect(marked.locator(".review-toggle")).to_be_visible()
    marked.locator(".review-toggle").click()
    # The active reviewed-only filter is refreshed after a confirmed save.
    # No manual Refresh is needed, even after changing language and theme.
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(0)
    viewer.page.locator("#show-all").click()
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(2)
    assert viewer.page.locator('[name="review_status"]').input_value() == ""
    assert [tuple(row) for row in state.connection.execute("SELECT * FROM findings ORDER BY finding_id")] == before_rows
    assert state.connection.total_changes == before_changes
    assert state.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_failed_save_is_visible_and_new_live_findings_remain_unreviewed(live_viewer):
    viewer = live_viewer
    state = viewer.create_scan("failure", files=1)
    viewer.open_ready()
    article = _open_first(viewer)
    pattern = viewer.origin + "/api/scans/*/findings/*/review"

    def failed(route):
        route.fulfill(status=503, content_type="application/json", body='{"detail":"synthetic review failure"}')

    viewer.page.route(pattern, failed)
    article.locator(".review-toggle").click()
    viewer.expect(viewer.page.locator("#error")).to_be_visible()
    viewer.expect(article).to_have_attribute("data-reviewed", "false")
    viewer.expect(article.locator(".review-toggle")).to_be_enabled()
    viewer.page.unroute(pattern, failed)
    article.locator(".review-toggle").click()
    viewer.expect(article).to_have_attribute("data-reviewed", "true")
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()
    _filter(viewer, "unreviewed")
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(0)

    viewer.add_file(state, "new-live-file.txt")
    viewer.expect(viewer.page.locator("#new-results")).to_be_visible(timeout=12000)
    viewer.page.locator("#new-results").click()
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(1)
    viewer.expect(viewer.page.locator(".file-result")).to_contain_text("new-live-file.txt")
    article = _open_first(viewer)
    viewer.expect(article).to_have_attribute("data-reviewed", "false")


def test_automatic_session_folder_is_visible_and_preserves_review_marks(live_viewer):
    from man_spider.state import default_state_path

    viewer = live_viewer
    path = default_state_path(viewer.directory)
    state = viewer.create_scan(str(path.relative_to(viewer.directory).with_suffix("")))
    assert state.path == path
    viewer.open_ready()
    article = _open_first(viewer)
    finding_id = article.get_attribute("data-finding-id")
    article.locator(".review-toggle").click()
    viewer.expect(article).to_have_attribute("data-reviewed", "true")
    assert path.with_name(path.name + ".review").is_file()

    viewer.page.reload()
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(1)
    restored = _open_first(viewer)
    assert restored.get_attribute("data-finding-id") == finding_id
    viewer.expect(restored).to_have_attribute("data-reviewed", "true")
    _filter(viewer, "unreviewed")
    viewer.expect(viewer.page.locator(".file-result")).to_have_count(0)
