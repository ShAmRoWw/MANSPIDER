"""NUL-safe viewer integration using tiny private local states, never SMB."""

from dataclasses import fields
import hashlib
import json
import sqlite3

import pytest

from man_spider.state import FindingRecord, ScanState
from man_spider.web_data import ViewerError, ViewerStore
import man_spider.web_data as web_data


class _CompatibleConnection:
    """Expose Python 3.10's connection surface without native blobopen."""

    def __init__(self, connection):
        object.__setattr__(self, "_connection", connection)

    def __getattr__(self, name):
        if name == "blobopen":
            raise AttributeError(name)
        return getattr(self._connection, name)

    def __setattr__(self, name, value):
        setattr(self._connection, name, value)


@pytest.fixture(params=("native", "compat"))
def storage_path(request, monkeypatch):
    if request.param == "native":
        if not hasattr(sqlite3.Connection, "blobopen"):
            pytest.skip("Native incremental BLOB API starts with Python 3.11")
    else:
        original = web_data._connect_local_sqlite

        def compatible(*args, **kwargs):
            return _CompatibleConnection(original(*args, **kwargs))

        monkeypatch.setattr(web_data, "_connect_local_sqlite", compatible)
    return request.param


@pytest.fixture
def state(tmp_path, storage_path):
    manifest = ScanState.create(tmp_path / "nul.sqlite3", {
        "semantic": {"scope": {"targets": [{"kind": "smb", "host": "192.0.2.20", "port": 445}]}},
        "authentication": {"username": "FixtureUser", "password": "PrivateConfigNotEvidence"},
    }, "2.0.0")
    yield manifest
    manifest.close()


def _add(state, value, context=None, *, path="example.txt", findings=None):
    decision = state.register_object(
        object_key="file|" + path, kind="file", target="192.0.2.20", share="LocalFixtureOnly",
        path=path, size=123,
    )
    if findings is None:
        findings = [FindingRecord(
            rule_id="rule:nul-fixture", value=value, context=context, representation="raw_text",
            severity="high", confidence="high", tags=("fixture",),
        )]
    state.complete_object(decision.object_id, "processed", findings=findings)
    return decision.object_id


def _view(state):
    state.close()
    store = ViewerStore([], [state.path])
    scans = store.scans()
    assert scans["warnings"] == []
    return store, scans["scans"][0]["id"]


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns


def _assert_hit_fields(hit):
    assert set(hit) == {
        "cursor", "finding_id", "rule_id", "severity", "confidence", "representation", "category",
        "value", "context", "match_start", "match_end", "value_truncated", "context_truncated", "tags",
        "reviewed",
    }
    assert hit["reviewed"] is False


@pytest.mark.parametrize(("value", "context"), [
    ("", ""), ("ordinary", None), ("\0", None), ("Prefix\0AfterNullSecret!", "small"),
    ("\0До\0После🔐\0", "\0before\0after\0"), ("ordinary", "before\0after"),
    ("value\0", ""), ("", "\0"),
])
def test_small_nul_preview_and_evidence_are_exact(state, value, context):
    object_id = _add(state, value, context)
    store, scan_id = _view(state)
    before = _digest(state.path)
    grouped = store.findings(scan_id)["items"][0]["findings"][0]
    detail = store.object_findings(scan_id, object_id)["items"][0]
    assert grouped == detail
    _assert_hit_fields(detail)
    assert detail["value"] == value
    assert detail["context"] == context
    assert detail["value_truncated"] is False
    assert detail["context_truncated"] is False
    for field, expected in (("value", value), ("context", context or "")):
        assert store.evidence(scan_id, detail["finding_id"], field=field) == {
            "text": expected, "total": len(expected), "next_offset": None,
        }
    assert _digest(state.path) == before
    assert "PrivateConfigNotEvidence" not in json.dumps(detail)


@pytest.mark.parametrize("length", [65535, 65536, 65537, 131073])
def test_unicode_nul_preview_boundaries_and_complete_pagination(state, length):
    value = ("🔐я\0" * ((length + 2) // 3))[:length]
    context = value[::-1]
    object_id = _add(state, value, context)
    store, scan_id = _view(state)
    hit = store.object_findings(scan_id, object_id)["items"][0]
    for field, expected in (("value", value), ("context", context)):
        assert hit[field] == expected[:65536]
        assert hit[f"{field}_truncated"] is (length > 65536)
        offset, parts = 0, []
        while True:
            result = store.evidence(scan_id, hit["finding_id"], field=field, offset=offset)
            assert set(result) == {"text", "total", "next_offset"}
            assert result["text"] == expected[offset:offset + 65536]
            assert result["total"] == length
            parts.append(result["text"])
            if result["next_offset"] is None:
                break
            assert result["next_offset"] == offset + 65536
            offset = result["next_offset"]
        assert "".join(parts) == expected


@pytest.mark.parametrize("offset", [0, 1, 2, 4, 7, 8, 9223372036854775806])
@pytest.mark.parametrize("field", ["value", "context"])
def test_nul_evidence_character_offsets_and_beyond_end(state, offset, field):
    expected = "🔐\0Я\0abc"
    object_id = _add(state, expected, expected)
    store, scan_id = _view(state)
    hit = store.object_findings(scan_id, object_id)["items"][0]
    assert store.evidence(scan_id, hit["finding_id"], field=field, offset=offset, limit=2) == {
        "text": expected[offset:offset + 2], "total": len(expected),
        "next_offset": offset + 2 if offset + 2 < len(expected) else None,
    }


@pytest.mark.parametrize(("value", "query", "expected"), [
    ("Prefix\0AfTeR", "after", True), ("Prefix\0AfTeR", "PREFIX", True),
    ("Prefix\0AfTeR", "fixafter", False), ("\0%_\\END", "%_\\end", True),
    ("\0literal", "%", False), ("\0literal", "_", False), ("\0literal", "\\", False),
    ("\0Я", "я", False), ("\0я", "я", True), ("\0Straße", "STRASSE", False),
    ("\0🔐Password", "🔐pASS", True), ("\0İ", "i", False),
])
@pytest.mark.parametrize("field", ["value", "context"])
def test_literal_search_reaches_past_nul_without_changing_unicode_case(state, value, query, expected, field):
    values = {"value": "neutral", "context": "neutral", field: value}
    object_id = _add(state, **values)
    store, scan_id = _view(state)
    rows = store.findings(scan_id, q=query)["items"]
    assert [row["object_id"] for row in rows] == ([object_id] if expected else [])


def test_nul_pages_preserve_all_findings_and_budget_continuations(state, monkeypatch):
    monkeypatch.setattr(web_data, "_PAGE_TEXT_BUDGET", 120)
    records = [FindingRecord(rule_id=f"rule:r{index}", value="\0" + "x" * 160) for index in range(4)]
    object_id = _add(state, "unused", findings=records)
    store, scan_id = _view(state)
    after, ids, page_token = 0, [], None
    while True:
        page = store.object_findings(scan_id, object_id, after=after, page_token=page_token)
        page_token = page["page_token"]
        assert len(page["items"]) == 1
        hit = page["items"][0]
        assert hit["value"] == "\0" + "x" * 160
        _assert_hit_fields(hit)
        ids.append(hit["rule_id"])
        if page["next_after"] is None:
            break
        after = page["next_after"]
    assert len(ids) == len(set(ids)) == 4


@pytest.mark.parametrize("operation", ["findings", "object_findings", "evidence"])
def test_nul_deadline_is_reported_as_retryable_error_not_partial_data(state, monkeypatch, operation):
    object_id = _add(state, "before\0after")
    store, scan_id = _view(state)
    finding_id = store.object_findings(scan_id, object_id)["items"][0]["finding_id"]
    original = web_data.EvidenceTextReader

    class ExpiredReader(original):
        def __init__(self, connection, deadline, **kwargs):
            super().__init__(connection, float("-inf"), **kwargs)

    monkeypatch.setattr(web_data, "EvidenceTextReader", ExpiredReader)
    arguments = {
        "findings": (scan_id,), "object_findings": (scan_id, object_id), "evidence": (scan_id, finding_id),
    }[operation]
    before = _digest(state.path)
    with pytest.raises(ViewerError, match="time limit") as error:
        getattr(store, operation)(*arguments)
    assert error.value.status == 503
    assert _digest(state.path) == before


def test_all_nul_fields_share_one_response_deadline_and_readonly_connection(state, monkeypatch):
    for index in range(3):
        _add(state, "value\0tail", "context\0tail", path=f"{index}.txt")
    store, scan_id = _view(state)
    original = web_data.EvidenceTextReader
    observed = []

    class RecordingReader(original):
        def read(self, *args, **kwargs):
            observed.append((self.deadline, self.connection.execute("PRAGMA query_only").fetchone()[0]))
            return super().read(*args, **kwargs)

    monkeypatch.setattr(web_data, "EvidenceTextReader", RecordingReader)
    before = _digest(state.path)
    assert len(store.findings(scan_id)["items"]) == 3
    assert len(observed) == 6
    assert len({deadline for deadline, _ in observed}) == 1
    assert {read_only for _, read_only in observed} == {1}
    assert _digest(state.path) == before


def test_nul_preview_and_evidence_keep_same_sqlite_snapshot(state, monkeypatch):
    object_id = _add(state, "old\0value")
    store, scan_id = _view(state)
    original = web_data.EvidenceTextReader
    updates = []

    class ConcurrentCommitReader(original):
        def read(self, *args, **kwargs):
            if not updates:
                with sqlite3.connect(state.path) as writer:
                    writer.execute("UPDATE findings SET value=?", ("new\0value",))
                updates.append(True)
            return super().read(*args, **kwargs)

    monkeypatch.setattr(web_data, "EvidenceTextReader", ConcurrentCommitReader)
    old = store.object_findings(scan_id, object_id)["items"][0]
    assert old["value"] == "old\0value"
    assert store.evidence(scan_id, old["finding_id"])["text"] == "new\0value"


def test_real_builtin_kubernetes_inspector_value_survives_viewer(state, tmp_path):
    from man_spider.lib.parser import FileParser
    from man_spider.rules import load_builtin_rules

    expected = "Prefix\0AfterNullSecret!🔐"
    document = json.dumps({"apiVersion": "v1", "kind": "Secret", "stringData": {"password": expected}})
    source = tmp_path / "secret.json"
    source.write_text(document, encoding="utf-8")
    before = _digest(source)
    parser = FileParser([], quiet=True, rules=load_builtin_rules())
    route = parser.route_rules({
        "filename": source.name, "path": str(source), "directory": str(source.parent), "extension": ".json",
        "size": len(document.encode("utf-8")), "share": "Fixture", "mtime": 0,
    })
    result = parser.parse_file(source, data=source.read_bytes(), rule_route=route)
    assert result.error is None
    extracted = [hit for hit in result.findings if hit.representation == "inspect:kubernetes-secret-json"]
    assert [hit.value for hit in extracted] == [expected]
    records = [FindingRecord(**{
        field.name: getattr(hit, field.name) for field in fields(FindingRecord) if hasattr(hit, field.name)
    }) for hit in extracted]
    object_id = _add(state, "unused", findings=records)
    store, scan_id = _view(state)
    hit = store.object_findings(scan_id, object_id)["items"][0]
    assert hit["value"] == expected
    assert store.evidence(scan_id, hit["finding_id"])["text"] == expected
    assert json.loads(hit["context"])["source_value"] == expected
    assert _digest(source) == before


def test_real_http_response_preserves_nul_and_filtered_results(state):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from man_spider.web import create_app

    expected = 'before\0AfterSecret!🔐<script>"'
    object_id = _add(state, expected, "context\0tail")
    store, scan_id = _view(state)
    before = _digest(state.path)
    with TestClient(create_app(store, port=18765), base_url="http://127.0.0.1:18765") as client:
        response = client.get(f"/api/scans/{scan_id}/findings", params={"q": "aftersecret"})
        assert response.status_code == 200
        row = response.json()["items"][0]
        assert row["object_id"] == object_id
        hit = row["findings"][0]
        _assert_hit_fields(hit)
        assert hit["value"] == expected
        assert b"\\u0000" in response.content
        assert b"PrivateConfigNotEvidence" not in response.content
        response = client.get(f"/api/scans/{scan_id}/findings/{hit['finding_id']}/evidence", params={"offset": 6})
        assert response.status_code == 200
        assert response.json() == {"text": expected[6:], "total": len(expected), "next_offset": None}
    assert _digest(state.path) == before
