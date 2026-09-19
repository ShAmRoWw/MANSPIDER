"""Exact evidence readers use only disposable local SQLite data."""

import hashlib
import sqlite3
import time

import pytest

from man_spider.web_text import EvidenceReadError, EvidenceTextReader
import man_spider.web_text as web_text


class SQLOnly:
    """The same SQLite API available on Python 3.10, without blobopen."""

    def __init__(self, connection):
        self.connection = connection
        self.windows = []

    def execute(self, query, parameters=()):
        if query.startswith("SELECT substr(CAST("):
            self.windows.append(parameters[1])
        return self.connection.execute(query, parameters)


@pytest.mark.parametrize("encoding", ["UTF-8", "UTF-16le", "UTF-16be"])
@pytest.mark.parametrize("portable", [False, True])
def test_character_slices_preserve_nuls_unicode_and_boundaries(encoding, portable, monkeypatch):
    if not portable and not hasattr(sqlite3.Connection, "blobopen"):
        pytest.skip("native incremental BLOB API requires Python 3.11")
    monkeypatch.setattr(web_text, "_BYTE_WINDOW", 4096)
    examples = [
        "", "\0", "Prefix\0AfterNullSecret!", "\0До\0После🔐",
        "a" * 4095 + "🔐\0Конец", "я" * 2047 + "🔐\0Конец",
        "a" * 65535 + "\0🔐TAIL", "🔐я\0" * 23000 + "END",
    ]
    with sqlite3.connect(":memory:") as connection:
        connection.execute(f"PRAGMA encoding='{encoding}'")
        connection.execute("CREATE TABLE findings(value TEXT, context TEXT)")
        reader_connection = SQLOnly(connection) if portable else connection
        reader = EvidenceTextReader(reader_connection, time.monotonic() + 30)
        for expected in examples:
            rowid = connection.execute("INSERT INTO findings VALUES(?,?)", (expected, expected)).lastrowid
            for offset in (0, 1, 4095, 4096, 65535, 65536, len(expected) + 1):
                for limit in (1, 7, 65536):
                    actual, count = reader.read(rowid, "value", offset=offset, limit=limit)
                    assert actual == expected[offset:offset + limit]
                    assert count == len(expected)
            preview, count = reader.read(rowid, "context", full_length=False)
            assert preview == expected[:65536]
            assert (count > 65536) == (len(expected) > 65536)
        if portable:
            assert reader_connection.windows and max(reader_connection.windows) == 4096


@pytest.mark.parametrize("portable", [False, True])
def test_read_only_database_and_original_bytes_remain_unchanged(tmp_path, portable):
    if not portable and not hasattr(sqlite3.Connection, "blobopen"):
        pytest.skip("native incremental BLOB API requires Python 3.11")
    path = tmp_path / "read.sqlite3"
    with sqlite3.connect(path) as writer:
        writer.execute("CREATE TABLE findings(value TEXT, context TEXT)")
        writer.execute("INSERT INTO findings VALUES(?,?)", ("Prefix\0Suffix", "before\0after"))
    before = (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
        connection.execute("PRAGMA query_only=ON")
        reader = EvidenceTextReader(SQLOnly(connection) if portable else connection, time.monotonic() + 1)
        assert reader.read(1, "value") == ("Prefix\0Suffix", 13)
        assert reader.read(1, "context", offset=7) == ("after", 12)
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM findings")
    assert before == (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)


def test_deadline_is_shared_across_repeated_fields(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(web_text.time, "monotonic", lambda: clock[0])
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE findings(value TEXT, context TEXT)")
        connection.execute("INSERT INTO findings VALUES(?,?)", ("a\0b", "c\0d"))
        reader = EvidenceTextReader(SQLOnly(connection), 1.0)
        assert reader.read(1, "value") == ("a\0b", 3)
        clock[0] = 1.0
        with pytest.raises(EvidenceReadError) as error:
            reader.read(1, "context")
        assert error.value.status == 503


def test_native_handle_is_readonly_and_closed_on_preview_and_timeout(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(web_text.time, "monotonic", lambda: clock[0])
    closed = []

    class Blob:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            closed.append(True)

        def read(self, size):
            clock[0] += 0.1
            return b"x\0" * (size // 2)

    class Native:
        def execute(self, query):
            assert query == "PRAGMA encoding"
            return sqlite3.connect(":memory:").execute(query)

        def blobopen(self, table, field, rowid, *, readonly):
            assert (table, field, rowid, readonly) == ("findings", "value", 1, True)
            return Blob()

    reader = EvidenceTextReader(Native(), 1.0)
    assert reader.read(1, "value", limit=3, full_length=False)[0] == "x\0x"
    assert len(closed) == 1
    with pytest.raises(EvidenceReadError) as error:
        reader.read(1, "value", limit=3, full_length=True)
    assert error.value.status == 503
    assert len(closed) == 2


def test_native_failure_is_not_retried_with_sql_fallback():
    class BrokenNative:
        def execute(self, query):
            assert query == "PRAGMA encoding", "native failure must not trigger SQL BLOB fallback"
            return sqlite3.connect(":memory:").execute(query)

        def blobopen(self, *args, **kwargs):
            raise sqlite3.OperationalError("corrupt fixture")

    with pytest.raises(sqlite3.OperationalError, match="corrupt fixture"):
        EvidenceTextReader(BrokenNative(), time.monotonic() + 1).read(1, "value")


@pytest.mark.parametrize("portable", [False, True])
@pytest.mark.parametrize("raw", [b"bad\0\xff", b"x\0\xf0\x9f"])
def test_invalid_encoding_is_explicit_never_replaced_or_ignored(raw, portable):
    if not portable and not hasattr(sqlite3.Connection, "blobopen"):
        pytest.skip("native incremental BLOB API requires Python 3.11")
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE findings(value TEXT)")
        connection.execute("INSERT INTO findings VALUES(?)", (raw,))
        reader = EvidenceTextReader(SQLOnly(connection) if portable else connection, time.monotonic() + 1)
        with pytest.raises(EvidenceReadError, match="invalid encoded text") as error:
            reader.read(1, "value")
        assert error.value.status == 409


@pytest.mark.parametrize("arguments", [
    (0, "value", {}), (True, "value", {}), (1, "not_allowed", {}),
    (1, "value);DELETE FROM findings;--", {}),
    (1, "value", {"offset": -1}), (1, "value", {"offset": True}),
    (1, "value", {"limit": 0}), (1, "value", {"limit": 65537}),
])
def test_invalid_requests_fail_before_any_database_access(arguments):
    rowid, field, options = arguments
    with pytest.raises(ValueError):
        EvidenceTextReader(None, time.monotonic() + 1).read(rowid, field, **options)


def test_portable_missing_row_is_explicit_not_empty_success():
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE findings(value TEXT)")
        with pytest.raises(EvidenceReadError) as error:
            EvidenceTextReader(SQLOnly(connection), time.monotonic() + 1).read(1, "value")
        assert error.value.status == 404


def test_preview_stops_reading_once_truncation_is_known(monkeypatch):
    monkeypatch.setattr(web_text, "_BYTE_WINDOW", 4096)
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE findings(value TEXT)")
        connection.execute("INSERT INTO findings VALUES(?)", ("\0" + "x" * 1_000_000,))
        adapter = SQLOnly(connection)
        preview, count = EvidenceTextReader(adapter, time.monotonic() + 1).read(1, "value", full_length=False)
        assert preview == "\0" + "x" * 65535
        assert 65536 < count < 1_000_001
        assert len(adapter.windows) == 17
