"""Opt-in real Chromium smoke test; never run a browser in the default suite.

MANSPIDER_BROWSER_TESTS=1 python -m pytest -q tests/test_web_browser.py
Requires the optional web dependencies, Playwright and /usr/bin/chromium.
Use the documented systemd resource scope, not an unrestricted full suite.
"""

import os
from pathlib import Path
import socket
import threading

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("MANSPIDER_BROWSER_TESTS") != "1", reason="explicit bounded browser test only",
)


def test_real_browser_live_filters_inert_evidence_and_read_only_state(tmp_path):
    pytest.importorskip("fastapi")
    uvicorn = pytest.importorskip("uvicorn")
    browser_api = pytest.importorskip("playwright.sync_api")
    sync_playwright, expect = browser_api.sync_playwright, browser_api.expect
    if not Path("/usr/bin/chromium").exists():
        pytest.skip("system Chromium is not installed")

    from man_spider.state import FindingRecord, ScanState
    from man_spider.web import create_app
    from man_spider.web_data import ViewerStore

    config = {"semantic": {"scope": {"targets": [{"kind": "smb", "host": "192.0.2.1", "port": 445}]}}}
    state = ScanState.create(tmp_path / "browser.sqlite3", config, "2.0.0")

    def add(name, findings=(), status="processed", reason=None, analysis_status="unknown"):
        decision = state.register_object(
            object_key=f"fixture|{name}", kind="file", target="192.0.2.1",
            share="Fixture", path=name, size=123,
        )
        state.complete_object(
            decision.object_id, status, findings=findings, reason=reason,
            analysis_status=analysis_status, analysis_read=analysis_status in {"partial", "analyzed"},
        )
        return decision.object_id

    def finding(rule, value, representation="text", severity="high", context=None):
        return FindingRecord(
            rule_id=f"rule:{rule}", value=value, context=context or value,
            representation=representation, severity=severity, confidence="low" if severity == "low" else "high",
        )

    add("boring.txt", [finding("configuration-data-file", "boring.txt", "metadata", "low")], analysis_status="not_analyzed")
    add("vault.kdbx", [finding("password-database", "vault.kdbx", "metadata")], analysis_status="not_analyzed")
    payload = '<img src="https://example.invalid/tracker" onerror="window.__injected=1">'
    attack_id = add("attack.txt", [finding("fixture-secret", payload, context="before " + payload + " after")], analysis_status="analyzed")
    add("denied.txt", status="error", reason="STATUS_ACCESS_DENIED", analysis_status="not_analyzed")
    add("long.txt", [finding("fixture-long", "Ж" * 70000 + "END-EVIDENCE")], analysis_status="analyzed")
    add("many.txt", [finding(f"fixture-many-{n}", f"ExampleOnly-{n}") for n in range(25)], analysis_status="partial")
    before = state.connection.total_changes
    before_rows = state.connection.execute("SELECT * FROM findings ORDER BY finding_id").fetchall()

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(16)
    app = create_app(ViewerStore([], files=[state.path]), port=port)
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=port, access_log=False, log_level="error",
        proxy_headers=False, ws="none",
    ))
    server_thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    server_thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path="/usr/bin/chromium", headless=True,
                args=["--disable-dev-shm-usage", "--disable-background-networking", "--disable-extensions"],
            )
            try:
                context = browser.new_context(viewport={"width": 1440, "height": 1050}, locale="ru-RU")
                page = context.new_page()
                failures, requests, external = [], [], []
                request_metadata = []
                page.on("pageerror", lambda error: failures.append(str(error)))
                origin = f"http://127.0.0.1:{port}"

                def intercept(route):
                    url = route.request.url
                    requests.append(url)
                    request_metadata.append((route.request.method, route.request.headers))
                    if not url.startswith(origin + "/"):
                        external.append(url)
                        route.abort()
                    else:
                        route.continue_()

                context.route("**/*", intercept)
                context.add_init_script("""
                    if (!localStorage.getItem("manspider.viewer.filters.v1")) {
                        localStorage.setItem("manspider.viewer.filters.v1", JSON.stringify([
                            {name: "Legacy scoped", filters: {hide_weak: true, extension: "txt", representation: "metadata"}},
                            {name: "Legacy hidden-only", filters: {hide_weak: "true"}}
                        ]));
                    }
                """)

                def denied_scans(route):
                    route.fulfill(status=403, content_type="application/json", body='{"detail":"denied"}')

                # Even an initial request failure leaves a visible workspace
                # and a retry button, with no access form to get stuck behind.
                page.route(origin + "/api/scans", denied_scans)
                page.goto(origin + "/")
                expect(page.locator("#error")).to_contain_text("Доступ к локальному просмотрщику заблокирован")
                expect(page.locator("#workspace")).to_be_visible()
                expect(page.locator("#reload-scans")).to_be_enabled()
                assert page.locator("#authentication").count() == 0
                page.unroute(origin + "/api/scans", denied_scans)
                page.locator("#reload-scans").click()
                page.locator("#metrics .metric").first.wait_for()
                page.locator(".file-result").first.wait_for()
                expect(page.locator("#filters")).to_be_visible()
                selection_box = page.locator(".scan-selection").bounding_box()
                overview_box = page.locator("#scan-overview").bounding_box()
                assert selection_box["y"] + selection_box["height"] <= overview_box["y"]
                assert abs(selection_box["width"] - overview_box["width"]) < 2
                expect(page.locator("html")).to_have_attribute("lang", "ru")
                assert page.locator("#theme-select").input_value() == "system"
                page.emulate_media(color_scheme="dark")
                expect(page.locator("html")).to_have_attribute("data-theme", "dark")
                page.emulate_media(color_scheme="light")
                expect(page.locator("html")).to_have_attribute("data-theme", "light")
                expect(page.locator('#analysis-metrics [data-analysis="analyzed"]')).to_contain_text("2")
                expect(page.locator('#analysis-metrics [data-analysis="partial"]')).to_contain_text("1")
                assert page.url == origin + "/"
                assert "boring.txt" in page.locator("#results").inner_text()
                assert "vault.kdbx" in page.locator("#results").inner_text()
                expect(page.locator("#results .file-result")).to_have_count(5)
                assert page.locator('[name="hide_weak"]').count() == 0
                expect(page.locator("#result-count")).not_to_contain_text("Применены фильтры")

                # Old saved views retain supported filters, but their retired
                # implicit-hiding option neither hides candidates nor reaches HTTP.
                page.locator("#saved-select").select_option(label="Legacy scoped")
                page.locator("#load-filter").click()
                expect(page.locator("#results .file-result")).to_have_count(1)
                assert "boring.txt" in page.locator("#results").inner_text()
                assert page.locator('#filters [name="extension"]').input_value() == "txt"
                assert page.locator('#filters [name="representation"]').input_value() == "metadata"
                expect(page.locator("#result-count")).to_contain_text("Применены фильтры")
                page.locator("#reset-filters").click()
                expect(page.locator("#results .file-result")).to_have_count(5)
                expect(page.locator("#result-count")).to_contain_text("На странице: 5 объектов.")
                expect(page.locator("#result-count")).not_to_contain_text("Применены фильтры")
                page.locator("#saved-select").select_option(label="Legacy hidden-only")
                page.locator("#load-filter").click()
                expect(page.locator("#results .file-result")).to_have_count(5)
                expect(page.locator("#result-count")).to_contain_text("На странице: 5 объектов.")
                expect(page.locator("#result-count")).not_to_contain_text("Применены фильтры")
                assert all("hide_weak" not in url for url in requests)
                attack = page.locator("details.file-result").filter(has=page.locator(".file-path", has_text="attack.txt"))
                attack.locator("summary").click()
                assert attack.locator("mark").inner_text() == payload
                assert attack.locator("img").count() == 0
                assert page.evaluate("window.__injected") is None

                # Theme/language changes are purely presentational: the open
                # evidence remains intact, without any access form.
                page.locator("#theme-select").select_option("dark")
                expect(page.locator("html")).to_have_attribute("data-theme", "dark")
                page.locator("#language-select").select_option("en")
                expect(page.locator("html")).to_have_attribute("lang", "en")
                assert attack.locator("mark").inner_text() == payload
                assert attack.get_attribute("open") is not None
                assert page.locator("#authentication").count() == 0
                assert page.locator("#tab-findings").inner_text() == "Findings"
                page.evaluate("window.scrollTo(0, 0)")
                page.screenshot(path=str(tmp_path / "viewer-dark-en.png"), full_page=True)
                page.locator("#theme-select").select_option("light")
                expect(page.locator("html")).to_have_attribute("data-theme", "light")
                page.locator("#language-select").select_option("ru")
                expect(page.locator("html")).to_have_attribute("lang", "ru")
                assert attack.locator("mark").inner_text() == payload
                page.screenshot(path=str(tmp_path / "viewer-light-ru.png"), full_page=True)

                many = page.locator("details.file-result").filter(has=page.locator(".file-path", has_text="many.txt"))
                many.locator("summary").click()
                many.get_by_role("button", name="Все срабатывания файла — по 50 на странице").click()
                many.get_by_text("Страница 1: 25 срабатываний").wait_for()

                long_result = page.locator("details.file-result").filter(has=page.locator(".file-path", has_text="long.txt"))
                long_result.locator("summary").click()
                long_result.get_by_role("button", name="Полное значение — читать по частям", exact=True).click()
                long_result.locator(".evidence-viewer").first.get_by_role("button", name="Следующий фрагмент →").click()
                long_result.locator(".evidence-viewer").first.get_by_text("END-EVIDENCE", exact=False).wait_for()
                assert "END-EVIDENCE" in long_result.locator(".evidence-viewer").first.inner_text()
                page.locator("#language-select").select_option("en")
                assert "END-EVIDENCE" in long_result.locator(".evidence-viewer").first.inner_text()
                assert long_result.get_attribute("open") is not None
                expect(long_result.locator(".evidence-viewer").first.get_by_role("button", name="← Previous chunk")).to_be_enabled()
                page.locator("#language-select").select_option("ru")

                expect(page.locator("#filters")).to_be_visible()
                page.locator("#show-all").click()
                page.locator(".file-path", has_text="boring.txt").wait_for()
                page.locator('#filters [name="analysis_status"]').select_option("partial")
                page.locator("#filters").get_by_role("button", name="Применить фильтры").click()
                expect(page.locator("#results .file-result")).to_have_count(1)
                assert "many.txt" in page.locator("#results").inner_text()
                page.locator('#filters [name="analysis_status"]').select_option("")
                page.locator('#filters [name="severity"]').select_option("high")
                page.locator('#filters [name="q"]').fill("ExampleOnly")
                page.locator("#filters").get_by_role("button", name="Применить фильтры").click()
                expect(page.locator("#results .file-result")).to_have_count(1)
                assert "many.txt" in page.locator("#results").inner_text()
                page.locator("#saved-name").fill("Тестовый фильтр")
                page.locator("#save-filter").click()
                storage = page.evaluate("JSON.stringify(localStorage)")
                assert "ExampleOnly" in storage and payload not in storage
                assert "hide_weak" not in storage
                page.locator("#show-all").click()
                page.locator(".file-path", has_text="boring.txt").wait_for()
                expect(page.locator("#results .file-result")).to_have_count(5)
                expect(page.locator("#result-count")).not_to_contain_text("Применены фильтры")

                # UI reads must not affect source manifest rows/status.
                assert state.connection.total_changes == before
                assert state.connection.execute("SELECT * FROM findings ORDER BY finding_id").fetchall() == before_rows
                assert state.run_row()["status"] == "running"

                # Simulate a new committed finding, without SMB or any scanner.
                old_display = page.locator("#results").inner_text()
                add("new-live.txt", [finding("fixture-live", "ExampleOnlyLive123!")])
                page.locator("#new-results").wait_for(state="visible", timeout=12000)
                assert page.locator("#results").inner_text() == old_display
                page.locator("#new-results").click()
                page.locator(".file-path", has_text="new-live.txt").wait_for()

                # Simulate resume replacing evidence on an existing object.
                state.complete_object(attack_id, "processed", findings=[finding("fixture-replaced", "REPLACED")])
                page.locator("#new-results").wait_for(state="visible", timeout=12000)
                page.locator("#new-results").click()
                # Refresh keeps the old cards until its response renders. Wait
                # for that replacement before opening the new, closed card.
                expect(page.locator("#new-results")).to_be_hidden()
                attack = page.locator("details.file-result").filter(has=page.locator(".file-path", has_text="attack.txt"))
                attack.locator("summary").click()
                attack.get_by_text("REPLACED", exact=True).wait_for()
                assert "REPLACED" in attack.inner_text()
                assert payload not in attack.inner_text()

                page.locator("#tab-coverage").click()
                page.locator('#coverage-filters [name="status"]').select_option("error")
                page.locator("#coverage-filters").get_by_role("button", name="Применить").click()
                page.locator("#results td", has_text="STATUS_ACCESS_DENIED").wait_for()
                assert "denied.txt" in page.locator("#results").inner_text()
                assert not failures
                assert not external
                assert all("/api/session" not in url for url in requests)
                assert all("hide_weak" not in url for url in requests)
                page.screenshot(path=str(tmp_path / "viewer.png"), full_page=True)

                # Plain reload immediately opens results, preserving display
                # preferences but requiring no form, cookie or access header.
                page.locator("#theme-select").select_option("dark")
                page.locator("#language-select").select_option("en")
                page.reload()
                expect(page.locator("html")).to_have_attribute("lang", "en")
                expect(page.locator("html")).to_have_attribute("data-theme", "dark")
                page.locator("#metrics .metric").first.wait_for()
                page.locator(".file-path", has_text="boring.txt").wait_for()
                assert page.locator("#authentication").count() == 0

                # Stale launch fragments are discarded without interpreting
                # their contents or using them for an API request.
                page.evaluate("window.location.hash = 'token=retired-fragment-value'")
                expect(page).to_have_url(origin + "/")
                assert "retired-fragment-value" not in page.evaluate("JSON.stringify(localStorage)")
                assert all("retired-fragment-value" not in url for url in requests)

                # A local access rejection remains an error with a usable
                # refresh button; it must never replace results with a login.
                page.route(origin + "/api/scans", denied_scans)
                page.locator("#reload-scans").click()
                expect(page.locator("#error")).to_contain_text("Access to the local viewer was blocked")
                expect(page.locator("#reload-scans")).to_be_enabled()
                assert page.locator("#authentication").count() == 0
                assert "boring.txt" in page.locator("#results").inner_text()
                page.unroute(origin + "/api/scans", denied_scans)
                page.locator("#reload-scans").click()
                expect(page.locator("#error")).to_be_hidden()
                assert context.cookies() == []
                assert all(method == "GET" for method, _headers in request_metadata)
                assert all(
                    not {"x-manspider-session", "authorization", "cookie"} & headers.keys()
                    for _method, headers in request_metadata
                )
                page.set_viewport_size({"width": 390, "height": 844})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
                assert page.locator("#scan-select").bounding_box()["width"] >= 250
                page.screenshot(path=str(tmp_path / "viewer-mobile-dark-en.png"), full_page=True)
                assert not failures
                assert not external
            finally:
                browser.close()
    finally:
        server.should_exit = True
        server_thread.join(timeout=5)
        listener.close()
        state.close()
        assert not server_thread.is_alive()
