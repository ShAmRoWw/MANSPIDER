"""Static local-viewer invariants; real browser checks cover runtime behavior."""

from html.parser import HTMLParser
import json
from pathlib import Path
import re


STATIC = Path(__file__).resolve().parents[1] / "man_spider" / "web_static"


class Document(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.feed(source)

    def handle_starttag(self, tag, attributes):
        self.tags.append((tag, dict(attributes)))


def test_assets_are_local_and_compatible_with_strict_csp():
    document = Document((STATIC / "index.html").read_text())
    urls = []
    for tag, attrs in document.tags:
        assert not any(name.lower().startswith("on") for name in attrs)
        assert "style" not in attrs
        assert tag not in {"iframe", "object", "embed", "base"}
        if tag == "script":
            assert attrs["src"] == "/assets/app.js"
            assert "defer" in attrs
        for name in ("src", "href"):
            if name in attrs:
                urls.append(attrs[name])
                assert attrs[name].startswith("/assets/")
    assert set(urls) == {"/assets/app.js", "/assets/style.css"}
    assert all(tag != "style" for tag, _ in document.tags)


def test_untrusted_data_uses_text_dom_without_external_execution():
    script = (STATIC / "app.js").read_text()
    for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "window.open", "XMLHttpRequest", "WebSocket", "sendBeacon"):
        assert unsafe not in script
    assert "element.textContent = text(value)" in script
    assert "document.createTextNode" in script
    assert "http://" not in script
    assert "https://" not in script
    assert "@import" not in (STATIC / "style.css").read_text()


def test_dom_references_exist_and_ids_are_unique():
    document = Document((STATIC / "index.html").read_text())
    ids = [attrs["id"] for _, attrs in document.tags if "id" in attrs]
    assert len(ids) == len(set(ids))
    references = re.findall(r'byId\("([a-z-]+)"\)', (STATIC / "app.js").read_text())
    assert set(references) <= set(ids)


def test_previous_layout_keeps_filters_visible_and_new_controls():
    source = (STATIC / "index.html").read_text()
    document = Document(source)
    assert all(tag != "aside" for tag, _ in document.tags)
    classes = {value for _, attrs in document.tags for value in attrs.get("class", "").split()}
    assert not {"sidebar", "workspace-grid", "brand-mark", "filter-panel"} & classes
    assert source.index('id="scan-select"') < source.index('id="scan-overview"')
    assert source.index('id="scan-overview"') < source.index('id="results-panel"')
    ids = {attrs["id"] for _, attrs in document.tags if "id" in attrs}
    assert {"filters", "language-select", "theme-select", "analysis-metrics"} <= ids


def test_no_implicit_weak_finding_filter_or_retired_saved_filter_option():
    source = (STATIC / "index.html").read_text()
    script = (STATIC / "app.js").read_text()
    assert "hide_weak" not in source
    assert "hide_weak" not in script
    assert "hideWeak" not in source
    assert "hideWeak" not in script
    assert "filters: {}, coverageFilters:" in script
    assert "Object.values(state.filters).some(Boolean)" in script
    assert "Object.entries(entry.filters).filter(([name]) => filterNames.includes(name))" in script
    assert 'byId("show-all").addEventListener("click", () => { applyFilterValues({});' in script
    assert 'byId("reset-filters").addEventListener("click", () => { byId("filters").reset();' in script


def test_direct_loading_without_auth_and_only_explicit_filter_and_display_storage():
    script = (STATIC / "app.js").read_text()
    document = Document((STATIC / "index.html").read_text())
    assert 'window.history.replaceState(null, "", window.location.pathname)' in script
    assert 'window.addEventListener("hashchange", clearFragment)' in script
    assert 'new URLSearchParams(window.location.hash' not in script
    assert 'credentials: "omit", cache: "no-store"' in script
    assert 'method: "GET"' in script
    assert 'refreshSavedFilters();\n  loadScans();' in script
    for retired in ("/api/session", "X-Manspider-Session", "sessionKey", "authenticate(", "authenticated", "needAuthentication", "consumeAccessToken"):
        assert retired not in script
    assert all(attrs.get("id") not in {"authentication", "auth-form", "auth-token"} for _, attrs in document.tags)
    workspace = next(attrs for _, attrs in document.tags if attrs.get("id") == "workspace")
    assert "hidden" not in workspace
    assert '#auth-form' not in (STATIC / "style.css").read_text()
    assert 'throw new ViewerError(msg("errorAccess"))' in script
    assert 'document.cookie' not in script
    assert script.count("localStorage.setItem(") == 2
    assert "localStorage.setItem(storageKey, JSON.stringify(entries))" in script
    assert "localStorage.setItem(preferenceKey, JSON.stringify({ language: preferences.language, theme: preferences.theme }))" in script
    assert "sessionStorage" not in script


def test_live_updates_are_bounded_and_dont_replace_results_automatically():
    script = (STATIC / "app.js").read_text()
    polling = script.split("async function pollOnce()", 1)[1].split('byId("scan-select")', 1)[0]
    assert "3000" in polling
    assert "document.hidden" in polling
    assert "loadSummary" in polling
    assert "loadScans({ refreshSummary: false })" in polling
    assert "pollBusy" in polling
    assert "!state.resultsLoaded && !state.listBusy) await loadResults()" in polling
    assert "performance.now() + 15000" in script
    assert 'if (document.hidden || !state.scanId)' not in script
    assert 'limit: "100"' in script
    assert "state.generation" in script
    assert "AbortController" in script
    assert "container.isConnected" in script


def test_recovery_keeps_independent_errors_and_unknown_page_revisions():
    script = (STATIC / "app.js").read_text()
    assert 'state.latestRevision = JSON.stringify(data.results_revision ?? data.revision)' in script
    assert 'state.resultsLoaded && state.latestRevision !== state.renderedRevision' in script
    assert 'state.resultsLoaded = true' in script
    assert 'state.resultsLoaded = false' in script
    assert 'const errors = new Map()' in script
    for source in ('"catalog"', '"summary"', '"results"', 'viewer', 'content'):
        assert f'showError("", {source})' in script
        assert f'showError(error, {source})' in script
    assert 'source instanceof Element && !source.isConnected' in script


def test_no_remote_file_open_links_or_scanned_server_network_actions():
    document = Document((STATIC / "index.html").read_text())
    assert all(tag != "a" for tag, _ in document.tags)
    script = (STATIC / "app.js").read_text()
    assert 'node("a"' not in script
    assert 'fetch(path, { method: "GET", ...options, credentials: "omit"' in script
    assert '"/api/session"' not in script
    # The only explicit non-GET request annotates a local finding; it never
    # opens a discovered path or contacts an SMB server.
    assert script.count('method: "PATCH"') == 1
    assert '/findings/${encodeURIComponent(findingId)}/review' in script
    assert '"X-Manspider-Review": "1"' in script
    assert '"Content-Type": "application/json"' in script
    assert 'body: JSON.stringify({ reviewed })' in script
    assert 'method: "POST"' not in script
    assert 'method: "DELETE"' not in script


def test_full_evidence_and_full_finding_pagination_are_explicit():
    script = (STATIC / "app.js").read_text()
    assert 'finding[`${field}_truncated`]' in script
    assert "/evidence?${query}" in script
    assert 'limit: "65536"' in script
    assert 'new URLSearchParams({ limit: "50", after: text(cursor) })' in script
    assert '/findings?${query}' in script
    assert "rows.replaceChildren(fragment)" in script
    assert 'chunk.textContent = text(data.text)' in script


def test_full_finding_cursor_is_versioned_and_restarted_only_explicitly():
    script = (STATIC / "app.js").read_text()
    paging = script.split("function fullFindingPages(", 1)[1].split("function renderFindings(", 1)[0]
    assert 'query.set("page_token", requestToken)' in paging
    assert 'typeof data.page_token !== "string"' in paging
    assert 'requestToken !== data.page_token' in paging
    assert 'error.code === "stale_page"' in paging
    assert 'detail.code === "stale_page"' in script
    assert 'notice.setAttribute("role", "status")' in paging
    assert 'restart.addEventListener("click", () => { if (!busy) loadPage([0], true); })' in paging
    assert paging.index('await api(') < paging.index('cursors = candidateCursors')
    assert 'cursors.push(' not in paging and 'cursors.pop(' not in paging
    assert 'reviewRevision === state.reviewRevision' in paging
    assert 'restartResults(' not in paging
    assert 'setTimeout(' not in paging


def test_manual_review_is_explicit_reversible_and_preserves_filter_context():
    source = (STATIC / "index.html").read_text()
    document = Document(source)
    controls = [attrs for tag, attrs in document.tags if tag == "select" and attrs.get("name") == "review_status"]
    assert len(controls) == 1
    select = source.split('<select name="review_status">', 1)[1].split('</select>', 1)[0]
    options = [attrs for tag, attrs in Document(select).tags if tag == "option"]
    assert [attrs["value"] for attrs in options] == ["", "unreviewed", "reviewed"]
    assert not any("selected" in attrs for attrs in options)
    script = (STATIC / "app.js").read_text()
    filters = script.split("const filterNames = ", 1)[1].split(";", 1)[0]
    assert '"review_status"' in filters
    assert 'if (reviewStatus) query.set("review_status", reviewStatus)' in script
    assert 'const context = { scanId: state.scanId, generation: state.generation, reviewStatus }' in script
    assert 'if (reviewRevision !== state.reviewRevision)' in script
    assert 'bindText(byId("result-count"), previousCount)' in script
    assert 'context.generation !== state.generation || context.scanId !== state.scanId' in script
    assert 'data.reviewed !== reviewed' in script
    mutation = script.split('toggle.addEventListener("click", async () => {', 1)[1].split('function findingArticle', 1)[0]
    assert mutation.index('await api(') < mutation.index('updateReviewCopies(findingId, reviewed, true)')
    assert 'pendingReviews.add(key)' in mutation and 'pendingReviews.delete(key)' in mutation
    assert 'reviewSavedFiltered' in mutation and 'reviewSaved' in mutation
    assert 'restartResults(' not in mutation
    assert 'localStorage' not in mutation
    assert 'reviewed-finding' in (STATIC / "style.css").read_text()


def translations():
    source = (STATIC / "app.js").read_text()
    return json.loads(source.split("  const messages = ", 1)[1].split(";\n", 1)[0])


def test_every_static_and_dynamic_translation_has_both_languages():
    document = Document((STATIC / "index.html").read_text())
    messages = translations()
    for key, values in messages.items():
        assert len(values) == 2, key
        assert all(isinstance(value, str) and value for value in values), key
        assert set(re.findall(r"\{([a-z]+)\}", values[0])) == set(re.findall(r"\{([a-z]+)\}", values[1])), key
    static_keys = {
        value for _, attrs in document.tags for name, value in attrs.items()
        if name.startswith("data-i18n")
    }
    assert static_keys <= messages.keys()
    script = (STATIC / "app.js").read_text()
    dynamic_keys = set(re.findall(r'\b(?:msg|t)\("([a-zA-Z.]+)"', script))
    assert dynamic_keys <= messages.keys()
    for category, values in {
        "analysis": ["analyzed", "partial", "not_analyzed", "unknown"],
        "status": ["running", "interrupted", "complete", "complete_with_errors", "processed", "skipped", "error"],
        "severity": ["critical", "high", "medium", "low", "info"],
    }.items():
        assert all(f"{category}.{value}" in messages for value in values)


def test_display_switches_update_in_place_without_requests_or_result_reloads():
    script = (STATIC / "app.js").read_text()
    handlers = script.split('byId("language-select").addEventListener', 1)[1].split("  applyTheme();\n  applyLanguage();", 1)[0]
    for operation in ("loadScans(", "loadSummary(", "loadResults(", "fetch(", "restartResults("):
        assert operation not in handlers
    translation = script.split("function applyLanguage()", 1)[1].split("  const systemTheme", 1)[0]
    assert "document.createTreeWalker" in translation
    assert "new WeakMap()" in script
    assert "replaceChildren" not in translation
    assert 'navigator.language || ""' in script
    assert '["system", "light", "dark"].includes(saved.theme)' in script
    assert 'saved.language === "ru" || saved.language === "en"' in script


def test_analysis_controls_are_available_and_legacy_caveat_is_explicit():
    document = Document((STATIC / "index.html").read_text())
    assert sum(tag == "select" and attrs.get("name") == "analysis_status" for tag, attrs in document.tags) == 2
    script = (STATIC / "app.js").read_text()
    assert 'data.analysis_counts_available === true' in script
    assert 'for (const status of ["analyzed", "partial", "not_analyzed", "unknown"])' in script
    assert 'card.dataset.analysis = status' in script
    assert 'named("analysisReason", item.analysis_reason)' in script


def test_timing_is_separate_from_metrics_and_uses_localized_snapshot_bindings():
    source = (STATIC / "index.html").read_text()
    document = Document(source)
    timing = next(attrs for tag, attrs in document.tags if tag == "section" and attrs.get("id") == "scan-timing")
    assert timing["aria-labelledby"] == "scan-timing-title"
    assert source.index('id="metrics"') < source.index('id="scan-timing"') < source.index('id="analysis-metrics"')
    script = (STATIC / "app.js").read_text()
    rendering = script.split("function renderTiming(", 1)[1].split("function renderSummary(", 1)[0]
    assert 'renderTiming(data.timing)' in script
    assert 'if (state.summary) renderTiming(state.summary.timing, true)' in script
    assert 'snapshot.elapsed_seconds' in rendering
    assert 'snapshot.remaining_seconds' in rendering
    assert 'snapshot.lower_seconds <= snapshot.upper_seconds' in rendering
    assert 'bindText(byId("scan-elapsed")' in rendering
    assert 'bindText(byId("scan-remaining")' in rendering
    assert 'byId("scan-timing-estimate").hidden' in rendering
    for operation in ('fetch(', 'setTimeout(', 'setInterval(', 'Date.now(', 'performance.now(', 'created_at'):
        assert operation not in rendering
    messages = translations()
    for key in ("timingUnavailable", "timingCalculating", "timingComplete", "timingDisabled", "timingStale", "timingNotStarted"):
        assert all("0" not in value for value in messages[key])
    assert 'Number.isFinite(value) && value >= 0' in script
    assert "latest start or resume" in messages["timingCaveat"][0]
    assert "последнего запуска или возобновления" in messages["timingCaveat"][1]


def test_both_themes_use_neutral_grayscale_for_base_interface_colors():
    css = (STATIC / "style.css").read_text()
    neutral_tokens = {
        "canvas", "surface", "text", "muted", "accent", "accent-hover", "secondary-text",
        "surface-hover", "border", "border-strong", "surface-soft", "status-bg", "metric-text",
        "tab-text", "tab-bg", "tab-border", "badge-text", "badge-bg", "code-bg",
    }
    for selector in (":root {", ':root[data-theme="dark"] {'):
        block = css.split(selector, 1)[1].split("}", 1)[0]
        declarations = dict(re.findall(r"--([a-z-]+):\s*([^;]+);", block))
        assert neutral_tokens <= declarations.keys(), (selector, neutral_tokens - declarations.keys())
        for token in sorted(neutral_tokens):
            value = declarations[token].strip()
            assert re.fullmatch(r"#[0-9a-fA-F]{6}", value), (selector, token, value)
            channels = [int(value[index:index + 2], 16) for index in (1, 3, 5)]
            assert channels[0] == channels[1] == channels[2], (selector, token, value)
    # Severity, warnings, errors and match highlights deliberately retain
    # semantic colors; only the ordinary interface must stay neutral.


def test_both_themes_have_readable_normal_text_and_match_highlight():
    css = (STATIC / "style.css").read_text()

    def luminance(value):
        channels = [int(value[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [channel / 12.92 if channel <= .04045 else ((channel + .055) / 1.055) ** 2.4 for channel in channels]
        return sum(channel * factor for channel, factor in zip(linear, (.2126, .7152, .0722)))

    for selector in (":root {", ':root[data-theme="dark"] {'):
        block = css.split(selector, 1)[1].split("}", 1)[0]
        colors = dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-f]{6})(?:;|\s)", block))
        for fg, bg in (("text", "surface"), ("muted", "surface"), ("text", "canvas"), ("mark-text", "mark")):
            a, b = sorted((luminance(colors[fg]), luminance(colors[bg])))
            assert (b + .05) / (a + .05) >= 4.5, (selector, fg, bg)
        for background in ("accent", "accent-hover"):
            assert 1.05 / (luminance(colors[background]) + .05) >= 4.5, (selector, background)
    assert "prefers-reduced-motion: reduce" in css
    assert 'max-width: 680px' in css
