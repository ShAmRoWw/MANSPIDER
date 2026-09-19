"""Schema 9 contexts preserve exact read-only viewer evidence and cursors."""

from contextlib import closing
import hashlib
import sqlite3
import time

import pytest

from man_spider.state import FindingRecord, ScanState
from man_spider.web_data import ViewerError, ViewerStore
from man_spider.web_text import EvidenceTextReader
import man_spider.web_text as web_text


@pytest.fixture
def scan(tmp_path):
    with closing(ScanState.create(tmp_path / "contexts.sqlite3", {}, "test")) as state:
        yield state


def view(state):
    store = ViewerStore([], [state.path])
    return store, store.scans()["scans"][0]["id"]


def complete(state, key, contexts):
    obj = state.claim_object(object_key=key, kind="file", path=key + ".txt")
    state.complete_object(obj.object_id, "processed", findings=[
        FindingRecord(f"rule:{index}", f"SyntheticOnly-{index}", context=context)
        for index, context in enumerate(contexts)
    ])
    return obj.object_id


def test_shared_long_nul_context_search_preview_evidence_review_and_page_order(scan):
    context = "Before\0" + "я🔐" * 35000 + "CaseSensitiveAsciiTail"
    object_id = complete(scan, "shared", [context] * 25)
    assert scan.connection.execute("SELECT count(*) FROM finding_contexts").fetchone()[0] == 1
    store, scan_id = view(scan)
    card = store.findings(scan_id, q="casesensitiveasciitail")["items"][0]
    assert card["object_id"] == object_id
    assert len(card["findings"]) == 20 and card["findings_truncated"] is True
    first = card["findings"][0]
    assert first["context"] == context[:65536] and first["context_truncated"] is True
    assert "context_id" not in first
    page = store.object_findings(scan_id, object_id, after=card["findings_next_after"],
                                 page_token=card["findings_page_token"])
    assert len(page["items"]) == 5 and page["next_after"] is None
    expected = [row[0] for row in scan.connection.execute(
        "SELECT finding_id FROM findings WHERE object_id=? ORDER BY rowid DESC", (object_id,))]
    assert [row["finding_id"] for row in card["findings"] + page["items"]] == expected
    text, offset = [], 0
    while offset is not None:
        evidence = store.evidence(scan_id, first["finding_id"], field="context", offset=offset, limit=8191)
        text.append(evidence["text"])
        assert evidence["total"] == len(context)
        offset = evidence["next_offset"]
    assert "".join(text) == context
    store.set_finding_review(scan_id, first["finding_id"], True)
    marked = store.object_findings(scan_id, object_id, review_status="reviewed")
    assert [row["finding_id"] for row in marked["items"]] == [first["finding_id"]]
    assert marked["items"][0]["context"] == context[:65536]


@pytest.mark.parametrize("portable", [False, True])
def test_normalized_context_blob_and_python310_reader_preserve_unicode(scan, portable):
    expected = "Prefix\0" + "🔐я" * 9000 + "TAIL"
    object_id = complete(scan, "native", [expected, expected])
    assert scan.connection.execute("SELECT count(*) FROM finding_contexts").fetchone()[0] == 1
    finding_rowid = scan.connection.execute("SELECT rowid FROM findings WHERE object_id=?", (object_id,)).fetchone()[0]

    class SQLOnly:
        def execute(self, query, parameters=()):
            return scan.connection.execute(query, parameters)

    connection = SQLOnly() if portable else scan.connection
    reader = EvidenceTextReader(connection, time.monotonic() + 2, schema_version=9)
    assert reader.read(finding_rowid, "context", offset=4095, limit=8192) == (expected[4095:12287], len(expected))


@pytest.mark.parametrize("encoding", ["UTF-8", "UTF-16le", "UTF-16be"])
@pytest.mark.parametrize("portable", [False, True])
def test_normalized_character_offsets_are_exact_for_every_sqlite_encoding(encoding, portable, monkeypatch):
    monkeypatch.setattr(web_text, "_BYTE_WINDOW", 4096)
    expected = "я" * 2047 + "🔐\0" + "Ж🔐" * 20000 + "END"
    with sqlite3.connect(":memory:") as connection:
        connection.execute(f"PRAGMA encoding='{encoding}'")
        connection.execute("CREATE TABLE findings(run_id TEXT,object_id INTEGER,value TEXT,context TEXT,context_id INTEGER)")
        connection.execute("CREATE TABLE finding_contexts(context_id INTEGER PRIMARY KEY,run_id TEXT,object_id INTEGER,context TEXT)")
        connection.execute("INSERT INTO finding_contexts VALUES(1,'fixture',1,?)", (expected,))
        connection.execute("INSERT INTO findings VALUES('fixture',1,'SyntheticOnly',NULL,1)")

        class SQLOnly:
            def execute(self, query, parameters=()):
                return connection.execute(query, parameters)

        reader = EvidenceTextReader(SQLOnly() if portable else connection, time.monotonic() + 2, schema_version=9)
        for offset in (0, 2047, 2048, 4095, len(expected) - 3, len(expected) + 1):
            text, length = reader.read(1, "context", offset=offset, limit=8192)
            assert text == expected[offset:offset + 8192]
            assert length == len(expected)


@pytest.mark.parametrize("bad_reference", ["missing", "another_object", "inline_and_reference"])
def test_corrupt_normalized_context_fails_closed_for_pages_search_and_evidence(scan, bad_reference):
    object_id = complete(scan, "one", ["FirstOnly", "FirstOnly"])
    other_id = complete(scan, "other", ["SecondOnly", "SecondOnly"])
    assert scan.connection.execute("SELECT count(*) FROM finding_contexts").fetchone()[0] == 2
    finding_id = scan.connection.execute("SELECT finding_id FROM findings WHERE object_id=?", (object_id,)).fetchone()[0]
    scan.connection.execute("DROP TRIGGER findings_context_update")
    scan.connection.execute("PRAGMA foreign_keys=OFF")
    if bad_reference == "missing":
        scan.connection.execute("UPDATE findings SET context_id=999999 WHERE object_id=?", (object_id,))
    elif bad_reference == "another_object":
        context_id = scan.connection.execute("SELECT context_id FROM finding_contexts WHERE object_id=?", (other_id,)).fetchone()[0]
        scan.connection.execute("UPDATE findings SET context_id=? WHERE object_id=?", (context_id, object_id))
    else:
        scan.connection.execute("UPDATE findings SET context='ContradictoryInline' WHERE object_id=?", (object_id,))
    store, scan_id = view(scan)
    for operation in (
        lambda: store.object_findings(scan_id, object_id),
        lambda: store.findings(scan_id, q="Only"),
        lambda: store.evidence(scan_id, finding_id, field="context"),
    ):
        with pytest.raises(ViewerError) as error:
            operation()
        assert error.value.status == 409


@pytest.mark.parametrize("schema", [7, 8])
def test_genuine_legacy_inline_context_without_new_columns_stays_read_only(scan, schema):
    expected = "Legacy\0Exact🔐Text"
    object_id = complete(scan, "legacy", [expected])
    # Produce a real historical table shape; do not rely only on a version flag.
    scan.connection.execute("UPDATE findings SET context=?,context_id=NULL", (expected,))
    for name, in scan.connection.execute("SELECT name FROM sqlite_schema WHERE type='trigger'").fetchall():
        scan.connection.execute(f'DROP TRIGGER "{name}"')
    scan.connection.execute("DROP INDEX IF EXISTS findings_context_idx")
    scan.connection.execute("ALTER TABLE findings DROP COLUMN context_id")
    scan.connection.execute("DROP TABLE finding_contexts")
    if schema == 7:
        for name in ("analysis_status", "analysis_reason", "analysis_read"):
            scan.connection.execute(f"ALTER TABLE objects DROP COLUMN {name}")
    scan.connection.execute("UPDATE runs SET schema_version=?", (schema,))
    scan.connection.execute("DELETE FROM counters WHERE name='data_revision'")
    scan.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = (hashlib.sha256(scan.path.read_bytes()).hexdigest(), scan.path.stat().st_mtime_ns)
    store, scan_id = view(scan)
    item = store.findings(scan_id, q="Exact")["items"][0]["findings"][0]
    assert item["context"] == expected
    assert store.evidence(scan_id, item["finding_id"], field="context")["text"] == expected
    assert store.summary(scan_id)["findings"] == 1
    assert store.object_findings(scan_id, object_id)["items"][0]["context"] == expected
    assert scan.run_row()["schema_version"] == schema
    assert before == (hashlib.sha256(scan.path.read_bytes()).hexdigest(), scan.path.stat().st_mtime_ns)
