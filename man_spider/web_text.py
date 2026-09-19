"""Exact local evidence slices, including embedded NUL, without DB writes.

Python 3.11+ supplies incremental SQLite BLOB reads. The Python 3.10 fallback
returns bounded byte windows via SQL; SQLite may still materialize the stored
field internally, just as with the viewer's ordinary TEXT substr/length path.
Do not describe that fallback as a hard SQLite heap bound.
"""

import codecs
import time

from man_spider.evidence_storage import evidence_location


_BYTE_WINDOW = 256 * 1024
_FIELDS = {"value", "context"}
_ENCODINGS = {"UTF-8": "utf-8", "UTF-16le": "utf-16-le", "UTF-16be": "utf-16-be"}


class EvidenceReadError(RuntimeError):
    def __init__(self, message, status=409):
        super().__init__(message)
        self.status = status


class EvidenceTextReader:
    """Read already-authorized finding rowids within one read-only snapshot."""

    def __init__(self, connection, deadline, *, schema_version=7):
        self.connection = connection
        self.deadline = deadline
        self.schema_version = schema_version
        self._encoding = None

    def _check_deadline(self):
        if time.monotonic() >= self.deadline:
            raise EvidenceReadError("Evidence reading time limit was reached", 503)

    def _chunks(self, rowid, field):
        table = "findings"
        if field == "context" and self.schema_version >= 9:
            table, field, rowid = evidence_location(self.connection, rowid, field, self.schema_version)
        blobopen = getattr(self.connection, "blobopen", None)
        if callable(blobopen):
            # Never fall back after a native reader error: corruption or a
            # missing object must not silently become a different result.
            with blobopen(table, field, rowid, readonly=True) as blob:
                while True:
                    self._check_deadline()
                    chunk = blob.read(_BYTE_WINDOW)
                    self._check_deadline()
                    yield chunk
                    if not chunk:
                        break
        else:
            # No new dependency or changed minimum Python version. Only the
            # fixed allowlisted field is interpolated; rowid/offset are bound.
            offset = 0
            while True:
                self._check_deadline()
                row = self.connection.execute(
                    f"SELECT substr(CAST({field} AS BLOB),?,?) FROM {table} WHERE rowid=?",
                    (offset + 1, _BYTE_WINDOW, rowid),
                ).fetchone()
                self._check_deadline()
                if row is None:
                    raise EvidenceReadError("Finding is no longer present", 404)
                chunk = b"" if row[0] is None else row[0]
                if not isinstance(chunk, bytes):
                    raise EvidenceReadError("Unsupported evidence storage")
                yield chunk
                if not chunk:
                    break
                offset += len(chunk)

    def read(self, rowid, field, *, offset=0, limit=65536, full_length=True):
        """Return (slice, count), preserving character offsets and every NUL.

        With full_length=False, count may be a lower bound: stop as soon as
        enough characters establish that a preview is truncated. The slice
        itself is exact in both modes. No prefix-only result is returned on
        timeout or decoding error.
        """
        if field not in _FIELDS or type(rowid) is not int or rowid <= 0:
            raise ValueError("Invalid evidence field or rowid")
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 65536:
            raise ValueError("Invalid evidence slice")
        self._check_deadline()
        if self._encoding is None:
            encoding = self.connection.execute("PRAGMA encoding").fetchone()[0]
            if encoding not in _ENCODINGS:
                raise EvidenceReadError("Unsupported results text encoding")
            self._encoding = _ENCODINGS[encoding]
        decoder = codecs.getincrementaldecoder(self._encoding)("strict")
        count, pieces = 0, []
        chunks = self._chunks(rowid, field)
        try:
            for raw in chunks:
                text = decoder.decode(raw, final=not raw)
                left = max(0, offset - count)
                right = min(len(text), offset + limit - count)
                if left < right:
                    pieces.append(text[left:right])
                count += len(text)
                self._check_deadline()
                if not full_length and count > offset + limit:
                    break
        except UnicodeError as exc:
            raise EvidenceReadError("Evidence contains invalid encoded text") from exc
        finally:
            # Close the native read-only handle even after preview early-stop.
            chunks.close()
        return "".join(pieces), count
