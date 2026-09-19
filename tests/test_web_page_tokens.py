"""A page cursor must never silently outlive its file's finding set."""

from contextlib import contextmanager
from dataclasses import replace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from man_spider import state as state_module, web_data
from man_spider.state import FindingRecord, ScanState
from man_spider.web import create_app
from man_spider.web_data import ViewerError, ViewerStore


@pytest.fixture
def scan(tmp_path):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "test")
    records = [FindingRecord("rule:fixture", f"Synthetic-{i:03}", i, i + 1) for i in range(70)]
    obj = state.claim_object(object_key="file|one", kind="file", path="one.txt")
    state.complete_object(obj.object_id, "error", findings=records)
    later = state.claim_object(object_key="file|later", kind="file", path="later.txt")
    state.complete_object(later.object_id, "processed", findings=[FindingRecord("rule:other", "Other")])
    store = ViewerStore([], [state.path])
    scan_id = store.scans()["scans"][0]["id"]
    yield state, store, scan_id, obj.object_id, records
    state.close()


def all_pages(store, scan_id, object_id, **filters):
    result, after, token = [], 0, None
    while True:
        page = store.object_findings(scan_id, object_id, limit=13, after=after, page_token=token, **filters)
        result.extend(hit["finding_id"] for hit in page["items"])
        after, token = page["next_after"], page["page_token"]
        if after is None:
            return result


@pytest.mark.parametrize("mode", ["same", "reverse", "delete_anchor", "change_anchor", "empty"])
@pytest.mark.parametrize("after_zero", [False, True])
def test_replacement_rejects_old_cursor_and_restart_preserves_exact_order(scan, mode, after_zero):
    state, store, scan_id, object_id, records = scan
    first = store.object_findings(scan_id, object_id)
    anchor = first["items"][-1]["value"]
    replacement = {
        "same": records, "reverse": records[::-1], "empty": [],
        "delete_anchor": [record for record in records if record.value != anchor],
        "change_anchor": [replace(record, value="Changed") if record.value == anchor else record for record in records],
    }[mode]
    state.complete_object(object_id, "processed", findings=replacement)
    before = list(state.connection.iterdump())
    with pytest.raises(ViewerError) as error:
        store.object_findings(scan_id, object_id, after=0 if after_zero else first["next_after"],
                              page_token=first["page_token"])
    assert (error.value.status, error.value.code) == (409, "stale_page")
    expected = [row[0] for row in state.connection.execute(
        "SELECT finding_id FROM findings WHERE object_id=? ORDER BY rowid DESC", (object_id,))]
    assert all_pages(store, scan_id, object_id) == expected
    assert list(state.connection.iterdump()) == before


def test_preview_token_continues_without_unrelated_scan_or_review_invalidation(scan):
    state, store, scan_id, object_id, _records = scan
    card = next(item for item in store.findings(scan_id)["items"] if item["object_id"] == object_id)
    first = store.object_findings(scan_id, object_id)
    store.set_finding_review(scan_id, first["items"][0]["finding_id"], True)
    other = state.claim_object(object_key="file|unrelated", kind="file", path="other.txt")
    state.complete_object(other.object_id, "processed", findings=[FindingRecord("rule:other", "More")])
    rest = store.object_findings(scan_id, object_id, after=card["findings_next_after"],
                                page_token=card["findings_page_token"])
    assert len(rest["items"]) == 50
    assert rest["next_after"] is None
    assert rest["page_token"] == first["page_token"] == card["findings_page_token"]
    assert len({hit["finding_id"] for hit in card["findings"] + rest["items"]}) == 70


@pytest.mark.parametrize("status", ["reviewed", "unreviewed"])
def test_cross_store_review_membership_change_is_stale(scan, status):
    state, store, scan_id, object_id, _records = scan
    hits = store.object_findings(scan_id, object_id)["items"]
    for hit in hits[:35]:
        store.set_finding_review(scan_id, hit["finding_id"], True)
    first = store.object_findings(scan_id, object_id, limit=10, review_status=status)
    other_store = ViewerStore([], [state.path])
    other_id = other_store.scans()["scans"][0]["id"]
    other_store.set_finding_review(other_id, first["items"][-1]["finding_id"], status != "reviewed")
    before = list(state.connection.iterdump())
    with pytest.raises(ViewerError) as error:
        store.object_findings(scan_id, object_id, after=first["next_after"], page_token=first["page_token"],
                              review_status=status)
    assert (error.value.status, error.value.code) == (409, "stale_page")
    assert len(all_pages(store, scan_id, object_id, review_status=status)) == 34
    assert list(state.connection.iterdump()) == before


@pytest.mark.parametrize("wrong", ["missing", "filter", "object", "valid_but_unknown"])
def test_missing_or_cross_context_tokens_never_silently_continue(scan, wrong):
    _state, store, scan_id, object_id, _records = scan
    first = store.object_findings(scan_id, object_id)
    token, filters = first["page_token"], {}
    if wrong == "missing":
        token = None
    elif wrong == "filter":
        filters["review_status"] = "unreviewed"
    elif wrong == "object":
        object_id += 1
    else:
        token = "v1." + "0" * 64
    with pytest.raises(ViewerError) as error:
        store.object_findings(scan_id, object_id, after=first["next_after"], page_token=token, **filters)
    assert (error.value.status, error.value.code) == (409, "stale_page")


@pytest.mark.parametrize("token", ["", "x", "v2." + "a" * 64, "v1." + "A" * 64,
                                    "v1." + "a" * 63, "v1." + "a" * 65, "v1." + "\0" * 64,
                                    0, False, [], {}])
def test_malformed_token_rejected_before_opening_database(scan, monkeypatch, token):
    _state, store, scan_id, object_id, _records = scan
    monkeypatch.setattr(store, "_entry", lambda *_: pytest.fail("Malformed token reached storage"))
    with pytest.raises(ViewerError) as error:
        store.object_findings(scan_id, object_id, page_token=token)
    assert error.value.status == 400


def test_http_token_extension_and_machine_readable_stale_response(scan):
    state, store, scan_id, object_id, records = scan
    with TestClient(create_app(store), base_url="http://127.0.0.1:8765") as client:
        url = f"/api/scans/{scan_id}/objects/{object_id}/findings"
        first = client.get(url).json()
        query = {"after": first["next_after"], "page_token": first["page_token"]}
        assert len(client.get(url, params=query).json()["items"]) == 20
        state.complete_object(object_id, "processed", findings=records)
        stale = client.get(url, params=query)
        assert stale.status_code == 409 and stale.json()["code"] == "stale_page"
        assert "no-store" in stale.headers["cache-control"]
        assert client.get(url, params={"after": 1}).json()["code"] == "stale_page"
        assert client.get(url, params={"page_token": "invalid"}).status_code == 400
        assert client.get(url, params=[("page_token", first["page_token"])] * 2).status_code == 400


def test_token_and_page_use_the_same_read_snapshot(scan, monkeypatch):
    state, store, scan_id, object_id, records = scan
    original = store._finding_page_token

    def change_after_version(*args, **kwargs):
        token = original(*args, **kwargs)
        state.complete_object(object_id, "processed", findings=records[::-1])
        return token

    expected = [row[0] for row in state.connection.execute(
        "SELECT finding_id FROM findings WHERE object_id=? ORDER BY rowid DESC", (object_id,))]
    monkeypatch.setattr(store, "_finding_page_token", change_after_version)
    page = store.object_findings(scan_id, object_id)
    assert [row["finding_id"] for row in page["items"]] == expected[:50]
    monkeypatch.setattr(store, "_finding_page_token", original)
    with pytest.raises(ViewerError) as error:
        store.object_findings(scan_id, object_id, after=page["next_after"], page_token=page["page_token"])
    assert error.value.code == "stale_page"


def test_version_does_not_select_evidence_and_obeys_deadline(scan, monkeypatch):
    _state, store, scan_id, object_id, _records = scan
    statements = []
    original = store._connection

    @contextmanager
    def observed(path):
        with original(path) as connection:
            connection.set_trace_callback(statements.append)
            yield connection

    monkeypatch.setattr(store, "_connection", observed)
    store.object_findings(scan_id, object_id)
    version_query = next(query for query in statements if query.startswith("SELECT rowid,finding_id,created_at"))
    assert "context" not in version_query and "value" not in version_query
    with original(store._entry(scan_id)[0]) as connection:
        with pytest.raises(ViewerError) as error:
            store._finding_page_token(connection, scan_id, object_id, "", deadline=web_data.time.monotonic() - 1)
    assert error.value.status == 503


def test_reused_rowids_and_frozen_clock_do_not_hide_order_changes(scan, monkeypatch):
    state, store, scan_id, object_id, records = scan
    monkeypatch.setattr(state_module, "utc_now", lambda: "2000-01-01T00:00:00+00:00")
    with state.transaction():
        state.connection.execute("DELETE FROM objects WHERE object_id!=?", (object_id,))
    state.complete_object(object_id, "processed", findings=records)
    state.complete_object(object_id, "processed", findings=records)
    first = store.object_findings(scan_id, object_id)
    rowids = [row[0] for row in state.connection.execute("SELECT rowid FROM findings ORDER BY rowid")]
    changed = list(records)
    # Neither the top nor the anchor row changes, but an already visible
    # finding trades places with an unseen one. Endpoint/timestamp heuristics
    # alone cannot establish this page's generation.
    changed[0], changed[65] = changed[65], changed[0]
    state.complete_object(object_id, "processed", findings=changed)
    assert rowids == [row[0] for row in state.connection.execute("SELECT rowid FROM findings ORDER BY rowid")]
    with pytest.raises(ViewerError) as error:
        store.object_findings(scan_id, object_id, after=first["next_after"], page_token=first["page_token"])
    assert error.value.code == "stale_page"
