"""Opt-in Chromium regressions for polling recovery and background discovery.

MANSPIDER_BROWSER_TESTS=1 python -m pytest -q tests/test_web_live_recovery.py

Run in a bounded systemd scope (MemoryMax=1G, MemorySwapMax=0, CPUQuota=100%).
These tests use real 3/15-second browser timers and the normal SQLite cache;
only HTTP failures and generated local scan data are controlled. No SMB scan,
remote server connection, browser-clock override or production test hook.
"""

from collections import Counter
from dataclasses import dataclass, field
import os
from pathlib import Path
import socket
import threading
from urllib.parse import urlsplit

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("MANSPIDER_BROWSER_TESTS") != "1", reason="explicit bounded browser test only",
)


@pytest.fixture(scope="module")
def chromium():
    browser_api = pytest.importorskip("playwright.sync_api")
    if not Path("/usr/bin/chromium").exists():
        pytest.skip("system Chromium is not installed")
    with browser_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path="/usr/bin/chromium", headless=True,
            args=["--disable-dev-shm-usage", "--disable-background-networking", "--disable-extensions"],
        )
        try:
            yield browser
        finally:
            browser.close()


@dataclass
class LiveViewer:
    directory: Path
    page: object
    origin: str
    expect: object
    states: list = field(default_factory=list)
    failures: list = field(default_factory=list)
    external: list = field(default_factory=list)
    active: Counter = field(default_factory=Counter)
    maximum_active: Counter = field(default_factory=Counter)

    def create_scan(self, name="first", files=1, long_evidence=False):
        from man_spider.state import ScanState

        configuration = {"semantic": {"scope": {"targets": [f"fixture-{name}"]}}}
        state = ScanState.create(self.directory / f"{name}.sqlite3", configuration, "browser-live-recovery")
        self.states.append(state)
        for number in range(files):
            self.add_file(state, f"{name}-{number:03}.txt", long_evidence=long_evidence)
        return state

    @staticmethod
    def add_file(state, name, long_evidence=False):
        from man_spider.state import FindingRecord

        decision = state.claim_object(object_key="fixture|" + name, kind="file", path=name, size=70000 if long_evidence else 100)
        value = "SyntheticOnly-" + ("Z" * 66000 if long_evidence else name)
        state.complete_object(
            decision.object_id, "processed",
            findings=(FindingRecord("rule:fixture-secret", value, context=value, severity="high", confidence="high"),),
            analysis_status="analyzed", analysis_read=True,
        )

    def open_ready(self):
        self.page.goto(self.origin + "/")
        self.expect(self.page.locator("#metrics .metric")).to_have_count(6, timeout=10000)
        self.expect(self.page.locator("#results .file-result").first).to_be_visible(timeout=10000)

    def next_summary(self, status=200):
        with self.page.expect_response(
            lambda response: response.url.endswith("/summary") and response.status == status, timeout=12000,
        ):
            pass

    def fail_summary(self):
        def failed(route):
            route.fulfill(status=503, content_type="application/json", body='{"detail":"synthetic summary failure"}')

        pattern = self.origin + "/api/scans/*/summary"
        self.page.route(pattern, failed)
        return pattern, failed

    def request_started(self, request):
        path = urlsplit(request.url).path
        kind = "catalog" if path == "/api/scans" else "summary" if path.endswith("/summary") else None
        if kind:
            self.active[kind] += 1
            self.maximum_active[kind] = max(self.maximum_active[kind], self.active[kind])

    def request_ended(self, request):
        path = urlsplit(request.url).path
        kind = "catalog" if path == "/api/scans" else "summary" if path.endswith("/summary") else None
        if kind:
            self.active[kind] -= 1


@pytest.fixture
def live_viewer(tmp_path, chromium):
    pytest.importorskip("fastapi")
    uvicorn = pytest.importorskip("uvicorn")
    from playwright.sync_api import expect
    from man_spider.web import create_app
    from man_spider.web_data import ViewerStore

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(16)
    app = create_app(ViewerStore([tmp_path]), port=port)
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=port, access_log=False, log_level="error", proxy_headers=False, ws="none",
    ))
    server_thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    server_thread.start()
    context = chromium.new_context(viewport={"width": 1440, "height": 1050}, locale="en-US")
    page = context.new_page()
    viewer = LiveViewer(tmp_path, page, f"http://127.0.0.1:{port}", expect)

    def intercept(route):
        if not route.request.url.startswith(viewer.origin + "/"):
            viewer.external.append(route.request.url)
            route.abort()
        else:
            route.continue_()

    context.route("**/*", intercept)
    page.on("pageerror", lambda error: viewer.failures.append(str(error)))
    page.on("request", viewer.request_started)
    page.on("requestfinished", viewer.request_ended)
    page.on("requestfailed", viewer.request_ended)
    try:
        yield viewer
        assert not viewer.failures
        assert not viewer.external
        assert all(value <= 1 for value in viewer.maximum_active.values()), viewer.maximum_active
    finally:
        context.close()
        server.should_exit = True
        server_thread.join(timeout=5)
        listener.close()
        for state in viewer.states:
            state.close()
        assert not server_thread.is_alive()


def test_initial_summary_failure_still_notifies_after_successful_poll(live_viewer):
    viewer = live_viewer
    state = viewer.create_scan()
    pattern, failed = viewer.fail_summary()
    viewer.page.goto(viewer.origin + "/")
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(1, timeout=10000)
    assert viewer.page.locator("#metrics .metric").count() == 0
    old_results = viewer.page.locator("#results").inner_text()
    viewer.add_file(state, "committed-after-first-page.txt")
    viewer.page.unroute(pattern, failed)
    viewer.expect(viewer.page.locator("#metrics .metric")).to_have_count(6, timeout=12000)
    viewer.expect(viewer.page.locator("#new-results")).to_be_visible(timeout=12000)
    assert viewer.page.locator("#results").inner_text() == old_results
    viewer.page.locator("#new-results").click()
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(2)


def test_successful_poll_clears_transient_summary_error(live_viewer):
    viewer = live_viewer
    viewer.create_scan()
    viewer.open_ready()
    pattern, failed = viewer.fail_summary()
    viewer.next_summary(status=503)
    viewer.expect(viewer.page.locator("#error")).to_be_visible()
    viewer.page.unroute(pattern, failed)
    viewer.next_summary()
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()


@pytest.mark.parametrize("independent_source", ["results", "evidence"])
def test_summary_recovery_does_not_clear_independent_error(live_viewer, independent_source):
    viewer = live_viewer
    viewer.create_scan(long_evidence=independent_source == "evidence")
    viewer.open_ready()
    summary_pattern, failed_summary = viewer.fail_summary()
    viewer.next_summary(status=503)
    viewer.expect(viewer.page.locator("#error")).to_be_visible()

    def independent_failure(route):
        status = 400 if independent_source == "results" else 404
        route.fulfill(status=status, content_type="application/json", body='{"detail":"synthetic independent failure"}')

    if independent_source == "results":
        viewer.page.route(viewer.origin + "/api/scans/*/findings?*", independent_failure)
        viewer.page.locator("#refresh-results").click()
        expected_error = "Check the filter settings: values and size ranges must be valid."
    else:
        viewer.page.route(viewer.origin + "/api/scans/*/findings/*/evidence?*", independent_failure)
        card = viewer.page.locator("#results .file-result").first
        card.locator("summary").click()
        card.get_by_role("button", name="Full value — read in chunks", exact=True).click()
        expected_error = "Scan unavailable. Refresh the scan list."
    viewer.expect(viewer.page.locator("#error")).to_contain_text(expected_error)
    viewer.page.unroute(summary_pattern, failed_summary)
    viewer.next_summary()
    viewer.expect(viewer.page.locator("#error")).to_have_text(expected_error)
    viewer.expect(viewer.page.locator("#error")).to_be_visible()


def test_empty_catalog_auto_discovers_first_scan_and_recovers_catalog_failure(live_viewer):
    viewer = live_viewer
    viewer.page.goto(viewer.origin + "/")
    viewer.expect(viewer.page.locator("#connection-state")).to_have_text("No saved scans found", timeout=10000)
    viewer.expect(viewer.page.locator("#scan-select option")).to_have_count(0)
    attempts = []

    def fail_once(route):
        attempts.append(route.request.url)
        if len(attempts) == 1:
            route.fulfill(status=503, content_type="application/json", body='{"detail":"synthetic catalog failure"}')
        else:
            route.continue_()

    viewer.page.route(viewer.origin + "/api/scans", fail_once)
    viewer.create_scan()
    viewer.expect(viewer.page.locator("#error")).to_be_visible(timeout=22000)
    viewer.expect(viewer.page.locator("#metrics .metric")).to_have_count(6, timeout=22000)
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(1, timeout=10000)
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()
    assert len(attempts) >= 2


def test_background_catalog_preserves_selection_page_filter_and_open_evidence(live_viewer):
    viewer = live_viewer
    first = viewer.create_scan(files=112)
    viewer.open_ready()
    selected = viewer.page.locator("#scan-select").input_value()
    viewer.page.locator('#filters [name="severity"]').select_option("high")
    viewer.page.locator("#filters").get_by_role("button", name="Apply filters", exact=True).click()
    viewer.expect(viewer.page.locator("#next-page")).to_be_enabled()
    viewer.page.locator("#next-page").click()
    viewer.expect(viewer.page.locator("#page-number")).to_have_text("Page 2")
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(12)
    card = viewer.page.locator("#results .file-result").first
    card.locator("summary").click()
    viewer.expect(card.locator("mark").first).to_be_visible()
    paths = viewer.page.locator("#results .file-path").all_text_contents()
    evidence = card.inner_text()
    first.set_run_status("interrupted")
    viewer.expect(viewer.page.locator("#scan-status")).to_have_text("Interrupted", timeout=12000)
    viewer.expect(viewer.page.locator("#scan-select option:checked")).to_contain_text("Interrupted")
    viewer.create_scan(name="second")
    viewer.expect(viewer.page.locator("#scan-select option")).to_have_count(2, timeout=22000)
    assert viewer.page.locator("#scan-select").input_value() == selected
    assert viewer.page.locator('#filters [name="severity"]').input_value() == "high"
    viewer.expect(viewer.page.locator("#page-number")).to_have_text("Page 2")
    assert viewer.page.locator("#results .file-path").all_text_contents() == paths
    assert card.get_attribute("open") is not None
    assert card.inner_text() == evidence
    first.set_run_status("running")
    viewer.expect(viewer.page.locator("#scan-status")).to_have_text("Running", timeout=12000)
    viewer.expect(viewer.page.locator("#scan-select option:checked")).to_contain_text("Running")
    first.finish()
    viewer.expect(viewer.page.locator("#scan-status")).to_have_text("Complete", timeout=12000)
    viewer.expect(viewer.page.locator("#scan-select option:checked")).to_contain_text("Complete")


def test_missing_or_stale_catalog_keeps_selected_scan_and_fresh_status(live_viewer):
    viewer = live_viewer
    state = viewer.create_scan()
    viewer.open_ready()
    selected = viewer.page.locator("#scan-select").input_value()
    stale_catalog = viewer.page.request.get(viewer.origin + "/api/scans").json()
    state.set_run_status("interrupted")
    viewer.expect(viewer.page.locator("#scan-status")).to_have_text("Interrupted", timeout=12000)
    paths = viewer.page.locator("#results .file-path").all_text_contents()
    # A successful following summary must not conceal a stale catalog rollback.
    summary_pattern, failed_summary = viewer.fail_summary()
    response_data = {"scans": [], "warnings": []}

    def controlled_catalog(route):
        route.fulfill(status=200, json=response_data)

    viewer.page.route(viewer.origin + "/api/scans", controlled_catalog)
    for response_data in ({"scans": [], "warnings": []}, stale_catalog):
        with viewer.page.expect_response(lambda response: response.url.endswith("/api/scans")):
            viewer.page.locator("#reload-scans").click()
        viewer.expect(viewer.page.locator("#reload-scans")).to_be_enabled()
        viewer.expect(viewer.page.locator("#scan-select option")).to_have_count(1)
        assert viewer.page.locator("#scan-select").input_value() == selected
        viewer.expect(viewer.page.locator("#scan-select option:checked")).to_contain_text("Interrupted")
        viewer.expect(viewer.page.locator("#scan-status")).to_have_text("Interrupted")
        assert viewer.page.locator("#results .file-path").all_text_contents() == paths
    viewer.page.unroute(summary_pattern, failed_summary)
    viewer.next_summary()
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()


def test_hidden_initial_summary_body_abort_defers_first_results_without_error(live_viewer):
    viewer = live_viewer
    viewer.create_scan()
    findings_requests = []
    viewer.page.on("request", lambda request: findings_requests.append(request.url)
                   if "/findings?" in request.url else None)
    viewer.page.add_init_script("""(() => {
      window.__testHidden = false;
      Object.defineProperty(document, 'hidden', { configurable: true, get: () => window.__testHidden });
      const originalFetch = window.fetch.bind(window);
      let firstSummary = true;
      window.fetch = async (input, options) => {
        const response = await originalFetch(input, options);
        if (firstSummary && String(input).endsWith('/summary')) {
          firstSummary = false;
          response.json = () => new Promise((resolve, reject) => {
            document.documentElement.dataset.summaryBodyPending = 'true';
            const aborted = () => {
              document.documentElement.dataset.summaryBodyCancelled = 'true';
              reject(new DOMException('Synthetic cancelled response body', 'AbortError'));
            };
            if (options.signal.aborted) aborted();
            else options.signal.addEventListener('abort', aborted, { once: true });
          });
        }
        return response;
      };
    })();""")
    viewer.page.goto(viewer.origin + "/")
    viewer.expect(viewer.page.locator("html")).to_have_attribute("data-summary-body-pending", "true")
    viewer.page.evaluate("""() => {
      window.__testHidden = true;
      document.dispatchEvent(new Event('visibilitychange'));
    }""")
    viewer.expect(viewer.page.locator("html")).to_have_attribute("data-summary-body-cancelled", "true")
    viewer.expect(viewer.page.locator("#reload-scans")).to_be_enabled()
    # Keep one real polling interval hidden: no first-page request or false error.
    viewer.page.wait_for_timeout(3200)
    assert findings_requests == []
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()
    viewer.page.evaluate("""() => {
      window.__testHidden = false;
      document.dispatchEvent(new Event('visibilitychange'));
    }""")
    viewer.expect(viewer.page.locator("#metrics .metric")).to_have_count(6, timeout=12000)
    viewer.expect(viewer.page.locator("#results .file-result")).to_have_count(1, timeout=12000)
    assert len(findings_requests) == 1
    viewer.expect(viewer.page.locator("#error")).to_be_hidden()
