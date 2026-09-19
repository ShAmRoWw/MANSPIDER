"""Explicit, bounded same-origin annotation writes; no scan-control endpoint."""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from man_spider.web import create_app
from man_spider.web_data import ViewerError


ORIGIN = "http://127.0.0.1:18765"
ENDPOINT = "/api/scans/scan-fixture/findings/finding-fixture/review"
HEADERS = {"Origin": ORIGIN, "X-Manspider-Review": "1", "Content-Type": "application/json"}


class Store:
    def __init__(self):
        self.calls = []
        self.failure = None

    def set_finding_review(self, scan_id, finding_id, reviewed):
        self.calls.append((scan_id, finding_id, reviewed))
        if self.failure:
            raise self.failure
        return {"finding_id": finding_id, "reviewed": reviewed}

    def findings(self, scan_id, **filters):
        self.calls.append((scan_id, filters))
        return {"items": [], "next_after": None}

    def object_findings(self, scan_id, object_id, **filters):
        self.calls.append((scan_id, object_id, filters))
        return {"items": [], "next_after": None}


@pytest.fixture
def viewer():
    store = Store()
    with TestClient(create_app(store, port=18765), base_url=ORIGIN) as client:
        yield client, store


@pytest.mark.parametrize("reviewed", [True, False])
def test_only_explicit_boolean_mark_reaches_store(viewer, reviewed):
    client, store = viewer
    response = client.patch(ENDPOINT, headers=HEADERS, json={"reviewed": reviewed})
    assert response.status_code == 200
    assert response.json() == {"finding_id": "finding-fixture", "reviewed": reviewed}
    assert store.calls == [("scan-fixture", "finding-fixture", reviewed)]
    assert "no-store" in response.headers["cache-control"]
    assert "access-control-allow-origin" not in response.headers
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize("overrides", [
    {"Origin": "https://attacker.invalid"}, {"Origin": "null"},
    {"Origin": ORIGIN + "/"}, {"Origin": None},
    {"X-Manspider-Review": None}, {"X-Manspider-Review": "0"},
    {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"},
    {"Host": "attacker.invalid:18765"},
])
def test_missing_or_cross_origin_write_intent_never_reaches_store(viewer, overrides):
    client, store = viewer
    headers = {key: value for key, value in (HEADERS | overrides).items() if value is not None}
    response = client.patch(ENDPOINT, headers=headers, json={"reviewed": True})
    assert response.status_code in {400, 403}
    assert not store.calls


@pytest.mark.parametrize("header,value", [("Origin", ORIGIN), ("X-Manspider-Review", "1"), ("Content-Type", "application/json")])
def test_duplicate_write_headers_fail_closed(viewer, header, value):
    client, store = viewer
    response = client.patch(ENDPOINT, headers=[*HEADERS.items(), (header, value)], content='{"reviewed": true}')
    assert response.status_code in {400, 403, 415}
    assert not store.calls


@pytest.mark.parametrize("body", [
    '{}', 'null', '[]', 'true', '"reviewed"', '[["reviewed",true]]',
    '{"reviewed": 1}', '{"reviewed": "true"}', '{"reviewed": null}',
    '{"reviewed": []}', '{"reviewed": {}}', '{"reviewed": false, "extra": 1}',
    '{"reviewed": false, "reviewed": true}', '{"reviewed": NaN}',
    '{"reviewed": true', '', b'\xff',
])
def test_invalid_or_ambiguous_payload_is_not_a_review(viewer, body):
    client, store = viewer
    response = client.patch(ENDPOINT, headers=HEADERS, content=body)
    assert response.status_code == 400
    assert not store.calls


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"])
def test_form_and_simple_request_payloads_cannot_write(viewer, content_type):
    client, store = viewer
    response = client.patch(ENDPOINT, headers=HEADERS | {"Content-Type": content_type}, content='{"reviewed": true}')
    assert response.status_code == 415
    assert not store.calls


@pytest.mark.parametrize("chunked", [False, True])
def test_payload_size_is_bounded_even_without_content_length(viewer, chunked):
    client, store = viewer
    payload = b'{"reviewed":true}' + b' ' * 300
    response = client.patch(ENDPOINT, headers=HEADERS, content=iter([payload[:16], payload[16:]]) if chunked else payload)
    assert response.status_code == 413
    assert not store.calls


def test_review_endpoint_accepts_no_arbitrary_path_or_query(viewer):
    client, store = viewer
    response = client.patch(ENDPOINT + "?path=/tmp/arbitrary", headers=HEADERS, json={"reviewed": True})
    assert response.status_code == 400
    response = client.patch(ENDPOINT.replace("finding-fixture", "x" * 129), headers=HEADERS, json={"reviewed": True})
    assert response.status_code == 404
    assert not store.calls


@pytest.mark.parametrize("method", ["get", "post", "put", "delete"])
def test_other_verbs_do_not_change_marks(viewer, method):
    client, store = viewer
    response = client.request(method.upper(), ENDPOINT, headers=HEADERS)
    assert response.status_code == 405
    assert not store.calls


@pytest.mark.parametrize("status", [404, 409, 503])
def test_persistence_failure_is_not_reported_as_success(viewer, status):
    client, store = viewer
    store.failure = ViewerError("review is not saved", status)
    response = client.patch(ENDPOINT, headers=HEADERS, json={"reviewed": True})
    assert response.status_code == status
    assert response.json() == {"detail": "review is not saved"}


@pytest.mark.parametrize("suffix", ["findings", "objects/1/findings"])
@pytest.mark.parametrize("status", ["", "reviewed", "unreviewed"])
def test_review_status_filter_reaches_store(viewer, suffix, status):
    client, store = viewer
    response = client.get("/api/scans/scan-fixture/" + suffix, params={"review_status": status})
    assert response.status_code == 200
    assert store.calls[-1][-1]["review_status"] == status


@pytest.mark.parametrize("status", ["hidden", "all", "true", "1"])
def test_unknown_review_filter_is_rejected(viewer, status):
    client, store = viewer
    response = client.get("/api/scans/scan-fixture/findings", params={"review_status": status})
    assert response.status_code == 400
    assert not store.calls
