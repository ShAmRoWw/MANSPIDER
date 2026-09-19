"""Token-free local HTTP viewer: origin boundaries, data and bounded queries.

These tests never start the scanner or connect to an SMB host.  An in-process
ASGI client and a small recording store keep the security checks inexpensive.
"""

import ast
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from man_spider.web import create_app


PORT = 18765
ORIGIN = f"http://127.0.0.1:{PORT}"
SCAN_ID = "scan-fixture"


class RecordingStore:
    def __init__(self):
        self.calls = []
        self.content = '<script>alert("untrusted found text")</script>'

    def scans(self):
        self.calls.append(("scans",))
        return {"scans": [{"id": SCAN_ID, "status": "running"}]}

    def summary(self, scan_id):
        self.calls.append(("summary", scan_id))
        return {"id": scan_id, "findings": 3}

    def findings(self, scan_id, **filters):
        self.calls.append(("findings", scan_id, filters))
        return {"items": [{"id": 1, "matched_value": self.content}], "next_after": 1}

    def objects(self, scan_id, **filters):
        self.calls.append(("objects", scan_id, filters))
        return {"items": [{"id": 2, "path": r"\\192.0.2.1\share\report.txt"}], "next_after": 2}

    def object_findings(self, scan_id, object_id, **filters):
        self.calls.append(("object_findings", scan_id, object_id, filters))
        return {"items": [{"id": 1, "object_id": object_id}], "next_after": 1}

    def evidence(self, scan_id, finding_id, **filters):
        self.calls.append(("evidence", scan_id, finding_id, filters))
        return {"text": self.content, "offset": 0, "has_more": False}


@pytest.fixture
def viewer():
    store = RecordingStore()
    app = create_app(store, port=PORT)
    with TestClient(app, base_url=ORIGIN) as client:
        yield client, store


@pytest.mark.parametrize("port", [-1, 0, 65536])
def test_app_requires_a_valid_local_port(port):
    store = RecordingStore()
    with pytest.raises(ValueError, match="port"):
        create_app(store, port=port)
    assert not store.calls


def test_findings_without_filters_only_pass_pagination(viewer):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/findings")
    assert response.status_code == 200
    assert store.calls == [("findings", SCAN_ID, {"limit": 100, "after": 0})]


@pytest.mark.parametrize("value", ["true", "false", "1", "0"])
def test_removed_weak_filter_cannot_be_enabled_through_api(viewer, value):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/findings", params={"hide_weak": value})
    assert response.status_code == 400
    assert not store.calls


@pytest.mark.parametrize("endpoint", ["findings", "objects"])
@pytest.mark.parametrize("status", ["unknown", "not_analyzed", "partial", "analyzed"])
def test_content_analysis_status_filter_reaches_store(viewer, endpoint, status):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/{endpoint}", params={"analysis_status": status})
    assert response.status_code == 200
    assert store.calls[-1][-1]["analysis_status"] == status


@pytest.mark.parametrize("endpoint", ["findings", "objects"])
def test_content_analysis_filter_rejects_processing_status(viewer, endpoint):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/{endpoint}", params={"analysis_status": "processed"})
    assert response.status_code == 400
    assert not store.calls


@pytest.mark.parametrize("path", ["/", "/assets/app.js", "/assets/style.css"])
def test_public_shell_is_local_and_requires_no_login(viewer, path):
    client, store = viewer
    response = client.get(path)
    assert response.status_code == 200
    assert "#token=" not in response.text
    assert "/api/session" not in response.text
    assert "X-Manspider-Session" not in response.text
    assert "set-cookie" not in response.headers
    assert store.calls == []
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize(
    "path",
    [
        "/api/scans",
        f"/api/scans/{SCAN_ID}/summary",
        f"/api/scans/{SCAN_ID}/findings",
        f"/api/scans/{SCAN_ID}/objects",
        f"/api/scans/{SCAN_ID}/objects/2/findings",
        f"/api/scans/{SCAN_ID}/findings/1/evidence",
    ],
)
def test_local_scan_data_is_available_without_tokens_or_cookies(viewer, path):
    client, store = viewer
    assert not client.cookies
    assert "X-Manspider-Session" not in client.headers
    response = client.get(path)
    assert response.status_code == 200
    assert len(store.calls) == 1
    assert not response.cookies
    assert "set-cookie" not in response.headers
    assert "access-control-allow-origin" not in response.headers
    assert "no-store" in response.headers["cache-control"]


@pytest.mark.parametrize(
    "host",
    [
        "attacker.invalid",
        f"attacker.invalid:{PORT}",
        f"127.0.0.1.attacker.invalid:{PORT}",
        f"localhost:{PORT}",
        f"127.0.0.1:{PORT + 1}",
        f"[::1]:{PORT}",
        f"0.0.0.0:{PORT}",
    ],
)
@pytest.mark.parametrize("path", ["/", "/api/scans"])
def test_exact_host_prevents_dns_rebinding(viewer, host, path):
    client, store = viewer
    response = client.get(path, headers={"Host": host})
    assert response.status_code in {400, 403}
    assert store.calls == []


@pytest.mark.parametrize(
    "headers",
    [
        [("Host", f"127.0.0.1:{PORT}"), ("Host", "attacker.invalid")],
        [("Origin", ORIGIN), ("Origin", "https://attacker.invalid")],
        [("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Site", "cross-site")],
    ],
)
def test_duplicate_security_headers_fail_closed(viewer, headers):
    client, store = viewer
    response = client.get("/api/scans", headers=headers)
    assert response.status_code in {400, 403}
    assert store.calls == []


@pytest.mark.parametrize(
    "origin",
    [
        "null",
        "https://attacker.invalid",
        f"http://localhost:{PORT}",
        f"https://127.0.0.1:{PORT}",
        f"http://127.0.0.1:{PORT + 1}",
        ORIGIN + ".attacker.invalid",
    ],
)
@pytest.mark.parametrize("path", ["/", "/api/scans", f"/api/scans/{SCAN_ID}/findings/1/evidence"])
def test_cross_origin_requests_cannot_read_local_results(viewer, origin, path):
    client, store = viewer
    response = client.get(path, headers={"Origin": origin})
    assert response.status_code in {400, 403}
    assert "set-cookie" not in response.headers
    assert store.calls == []


@pytest.mark.parametrize("fetch_site", ["cross-site", "same-site"])
@pytest.mark.parametrize("path", ["/api/scans", f"/api/scans/{SCAN_ID}/objects/2/findings"])
def test_cross_site_fetch_cannot_read_local_results(viewer, fetch_site, path):
    client, store = viewer
    response = client.get(path, headers={"Sec-Fetch-Site": fetch_site})
    assert response.status_code in {400, 403}
    assert store.calls == []


@pytest.mark.parametrize("fetch_site", ["same-origin", "none"])
def test_same_origin_browser_requests_are_allowed_without_login(viewer, fetch_site):
    client, store = viewer
    headers = {"Origin": ORIGIN, "Sec-Fetch-Site": fetch_site}
    response = client.get("/api/scans", headers=headers)
    assert response.status_code == 200
    assert store.calls == [("scans",)]
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize("path", ["/", "/assets/app.js", "/api/scans", "/not-found"])
def test_security_headers_cover_success_and_error_responses(viewer, path):
    client, _store = viewer
    response = client.get(path)
    assert "no-store" in response.headers["cache-control"].lower()
    assert response.headers["x-content-type-options"] == "nosniff"
    policy = response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in policy
    assert "object-src 'none'" in policy
    assert "base-uri 'none'" in policy
    assert "script-src 'self'" in policy
    assert "style-src 'self'" in policy
    assert "connect-src 'self'" in policy
    assert "'unsafe-inline'" not in policy
    assert "'unsafe-eval'" not in policy


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/assets/not-present.js"])
def test_no_public_documentation_or_arbitrary_static_files(viewer, path):
    client, store = viewer
    response = client.get(path)
    assert response.status_code == 404
    assert store.calls == []


@pytest.mark.parametrize(
    "path",
    [
        "/assets/%2e%2e/AGENTS.md",
        "/assets/%2e%2e%2fAGENTS.md",
        "/assets/%2e%2e%5cAGENTS.md",
        "/assets/%2fetc%2fpasswd",
        "/assets/app.js/../../AGENTS.md",
        "/assets/app.js%00",
    ],
)
def test_assets_cannot_escape_fixed_allowlist(viewer, path):
    client, store = viewer
    response = client.get(path)
    assert response.status_code in {400, 404}
    assert "root:x:" not in response.text
    assert "Инструмент никогда" not in response.text
    assert store.calls == []


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
@pytest.mark.parametrize("endpoint", ["", f"/{SCAN_ID}", f"/{SCAN_ID}/findings"])
def test_web_cannot_mutate_or_control_a_scan(viewer, method, endpoint):
    client, store = viewer
    response = getattr(client, method)("/api/scans" + endpoint)
    assert response.status_code in {404, 405}
    assert store.calls == []


@pytest.mark.parametrize("endpoint", ["findings", "objects"])
@pytest.mark.parametrize("query", [{"limit": 0}, {"limit": 201}, {"limit": -1}, {"after": -1}, {"limit": "x"}])
def test_pagination_is_bounded_before_querying_store(viewer, endpoint, query):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/{endpoint}", params=query)
    assert response.status_code in {400, 422}
    assert store.calls == []


@pytest.mark.parametrize("endpoint", ["findings", "objects"])
def test_incremental_pages_forward_cursor_and_limit(viewer, endpoint):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/{endpoint}", params={"limit": 10, "after": 20})
    assert response.status_code == 200
    name, scan_id, filters = store.calls[-1]
    assert (name, scan_id) == (endpoint, SCAN_ID)
    assert filters["limit"] == 10
    assert filters["after"] == 20
    assert response.json()["items"]


def test_api_preserves_found_text_as_json_data(viewer):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/findings")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["items"][0]["matched_value"] == store.content


@pytest.mark.parametrize(
    "endpoint, query",
    [
        ("findings", {"severity": "catastrophic"}),
        ("findings", {"confidence": "certain"}),
        ("findings", {"representation": "network"}),
        ("objects", {"status": "deleted"}),
        ("objects", {"kind": "socket"}),
        ("findings", {"q": "x" * 8192}),
        ("objects", {"q": "x" * 8192}),
        ("findings", {"after": str(2**64)}),
        ("objects", {"after": str(2**64)}),
        ("findings", {"arbitrary_sql": "DROP TABLE findings"}),
        ("objects", {"arbitrary_sql": "DROP TABLE objects"}),
        ("findings", [("limit", "1"), ("limit", "200")]),
        ("objects", [("after", "0"), ("after", "10")]),
    ],
)
def test_invalid_filters_never_reach_store(viewer, endpoint, query):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/{endpoint}", params=query)
    assert response.status_code in {400, 422}
    assert store.calls == []


@pytest.mark.parametrize("query", ["' OR 1=1; --", '<img src=x onerror="alert(1)">', r"\\203.0.113.1\share"])
def test_search_is_passed_as_inert_text(viewer, query):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/findings", params={"q": query})
    assert response.status_code == 200
    assert store.calls[-1][2]["q"] == query


@pytest.mark.parametrize(
    "representation",
    [
        "unknown", "inspect:private-key-material", "inspect:kubernetes-secret-json",
        "inspect:group-policy-preference-password", "inspect:active-directory-ldif-secrets",
        "inspect:active-directory-json-secrets", "inspect:russian-json-credential-value",
        "inspect:russian-legacy-credential-value",
    ],
)
def test_real_inspector_representations_can_be_filtered(viewer, representation):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/findings", params={"representation": representation})
    assert response.status_code == 200
    assert store.calls[-1][2]["representation"] == representation


@pytest.mark.parametrize(
    "path",
    [
        f"/api/scans/{SCAN_ID}/objects/2/findings",
        f"/api/scans/{SCAN_ID}/findings/1/evidence",
    ],
)
def test_detail_and_evidence_still_reject_cross_origin_requests(viewer, path):
    client, store = viewer
    response = client.get(path, headers={"Origin": "https://attacker.invalid"})
    assert response.status_code == 403
    assert store.calls == []


@pytest.mark.parametrize("query", [{"field": "password"}, {"offset": -1}, {"limit": 65537}, {"limit": 0}])
def test_evidence_query_is_bounded(viewer, query):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/findings/1/evidence", params=query)
    assert response.status_code in {400, 422}
    assert store.calls == []


@pytest.mark.parametrize(
    "object_id", ["0", "-1", "1.5", str(2**63), pytest.param("9" * 5000, id="oversized-integer")],
)
def test_object_identifier_is_bounded_before_integer_conversion(viewer, object_id):
    client, store = viewer
    response = client.get(f"/api/scans/{SCAN_ID}/objects/{object_id}/findings")
    assert response.status_code in {400, 404, 414}
    assert store.calls == []


def test_unexpected_errors_do_not_expose_local_secrets(viewer, caplog):
    client, store = viewer

    def broken_store():
        raise RuntimeError("/private/session.sqlite password=ExampleSecret123")

    store.scans = broken_store
    response = client.get("/api/scans")
    assert response.status_code == 500
    assert "no-store" in response.headers["cache-control"]
    for private_text in ("/private/session.sqlite", "ExampleSecret123", "Traceback"):
        assert private_text not in response.text
        assert private_text not in caplog.text


def test_viewer_does_not_import_scanner_or_remote_clients():
    """Keep opening the viewer independent of the SMB scanner and extractors."""

    source = Path("man_spider/web.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = (
        "impacket", "kreuzberg", "requests", "urllib.request", "httpx",
        "man_spider.manspider", "man_spider.preflight", "man_spider.lib.smb",
        "man_spider.lib.spider", "man_spider.lib.spiderling", "man_spider.lib.file",
    )
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
            imports.extend(f"{node.module}.{alias.name}" for alias in node.names)
    assert not [name for name in imports if any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden)]


@pytest.mark.parametrize("method", ["get", "post", "put", "patch", "delete", "options"])
def test_removed_session_endpoint_does_not_create_cookies_or_read_data(viewer, method):
    client, store = viewer
    response = getattr(client, method)("/api/session")
    assert response.status_code == 404
    assert "set-cookie" not in response.headers
    assert not response.cookies
    assert store.calls == []
    assert "access-control-allow-origin" not in response.headers


def test_removed_session_endpoint_does_not_reflect_submitted_values(viewer):
    client, store = viewer
    response = client.post("/api/session", json={"token": "OldSecretMustNotBeReflected"})
    assert response.status_code == 404
    assert "OldSecretMustNotBeReflected" not in response.text
    assert "set-cookie" not in response.headers
    assert store.calls == []


def test_legacy_token_query_is_rejected_as_an_unknown_parameter(viewer):
    client, store = viewer
    response = client.get("/api/scans", params={"token": "UnusedLegacyToken"})
    assert response.status_code == 400
    assert "UnusedLegacyToken" not in response.text
    assert "set-cookie" not in response.headers
    assert store.calls == []


def test_browser_cors_preflight_does_not_allow_an_external_site(viewer):
    client, store = viewer
    response = client.options("/api/scans", headers={
        "Origin": "https://attacker.invalid", "Access-Control-Request-Method": "GET",
    })
    assert response.status_code == 403
    assert "access-control-allow-origin" not in response.headers
    assert store.calls == []


def test_command_line_server_is_loopback_only_and_bounded(monkeypatch, capsys, tmp_path):
    import uvicorn

    import man_spider.web as web

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: calls.append((app, options)))
    assert web.main(["--state", str(tmp_path / "session.sqlite"), "--port", str(PORT)]) == 0
    assert len(calls) == 1
    _app, options = calls[0]
    assert options["host"] == "127.0.0.1"
    assert options["port"] == PORT
    assert options["workers"] == 1
    assert options["reload"] is False
    assert options["proxy_headers"] is False
    assert options["access_log"] is False
    assert options["ws"] == "none"
    assert 1 <= options["limit_concurrency"] <= 16
    output = capsys.readouterr().out
    assert ORIGIN + "/" in output.splitlines()
    assert "#token=" not in output
    assert "?token=" not in output
    assert "токен" not in output.casefold()
    assert "Без авторизации" in output
    assert "пользователи и процессы" in output
    assert "немаскированные находки" in output
    assert not (tmp_path / "session.sqlite").exists()


@pytest.mark.parametrize("arguments", [["--host", "0.0.0.0"], ["--port", "0"], ["--port", "65536"]])
def test_command_line_cannot_bind_public_or_invalid_address(monkeypatch, arguments):
    import uvicorn

    import man_spider.web as web

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *_args, **_kwargs: calls.append(True))
    with pytest.raises(SystemExit) as failure:
        web.main(arguments)
    assert failure.value.code == 2
    assert calls == []
