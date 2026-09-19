"""Bounded, local, read-only scan queries for the optional results viewer.

This module never attaches a writable ScanState, migrates a database, runs a
scanner, or opens a discovered target. ``processed`` is deliberately not
presented as a count of files whose contents were analyzed.
Explicit specialist review actions write only a separate local sidecar.
"""

from collections import OrderedDict
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
import time

from man_spider.path_safety import UnsafeWritePath, local_directory_descriptor
from man_spider.evidence_storage import configure_evidence_reader, context_join, context_sql
from man_spider.state import StateError, _connect_local_sqlite
from man_spider.web_review import ReviewError, attach_reviews, review_expression, review_path, review_predicate, set_review
from man_spider.web_text import EvidenceReadError, EvidenceTextReader


class ViewerError(RuntimeError):
    def __init__(self, message, status=400, *, code=None):
        super().__init__(message)
        self.status = status
        self.code = code


_CACHE_SECONDS = 3.0
_MAX_SCANS = 512
_MAX_FINDINGS = 20
_MAX_TEXT = 65536
_PAGE_TEXT_BUDGET = 2 * 1024 * 1024
_TIMING_STALE_SECONDS = 30.0
_OBJECT_COLUMNS = "object_id,kind,target,share,path,size,status,reason"
_SUPPORTED_SCHEMAS = {7, 8, 9}
ANALYSIS_STATUSES = {"unknown", "not_analyzed", "partial", "analyzed"}
REVIEW_STATUSES = {"reviewed", "unreviewed"}
_SCHEMA = {
    "runs": {"run_id", "schema_version", "status", "config_json", "created_at", "updated_at", "completed_at"},
    "objects": set(_OBJECT_COLUMNS.split(",")) | {"run_id"},
    "findings": {
        "run_id", "object_id", "rule_id", "severity", "confidence", "representation",
        "category", "tags_json", "value", "context", "match_start", "match_end", "finding_id", "created_at",
    },
    "exclusions": {"run_id", "kind"},
}


def _timing_number(value):
    # Do not coerce booleans, strings, infinity or corrupt checkpoint numbers.
    if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1e12:
        return float(value)
    return None


def _timing_timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _read_timing(connection, run):
    """Read one small local telemetry row; old databases need no migration."""
    result = {
        "elapsed_seconds": None, "remaining_seconds": None,
        "lower_seconds": None, "upper_seconds": None,
        "eta_status": "unavailable", "confidence": None, "updated_at": None,
    }
    payload = None
    if connection.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='checkpoints'").fetchone():
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(checkpoints)")}
        if {"run_id", "name", "value_json"}.issubset(columns):
            row = connection.execute(
                "SELECT substr(value_json,1,8193) AS payload FROM checkpoints WHERE run_id=? AND name='scan_timing'",
                (run["run_id"],),
            ).fetchone()
            if row is not None and isinstance(row["payload"], str) and len(row["payload"]) <= 8192:
                try:
                    payload = json.loads(row["payload"])
                except (ValueError, RecursionError):
                    pass
    if isinstance(payload, dict) and type(payload.get("version")) is int and payload["version"] == 1:
        result["elapsed_seconds"] = _timing_number(payload.get("elapsed_seconds"))
        if _timing_timestamp(payload.get("updated_at")) is not None:
            result["updated_at"] = payload["updated_at"]
        eta = payload.get("eta")
        if isinstance(eta, dict):
            status = eta.get("status")
            if status in ("calculating", "estimated", "unavailable", "complete", "disabled", "not_started"):
                result["eta_status"] = status
            if status == "estimated":
                remaining = _timing_number(eta.get("remaining_seconds"))
                if remaining is not None and remaining > 0:
                    result["remaining_seconds"] = remaining
                    lower = _timing_number(eta.get("lower_seconds"))
                    upper = _timing_number(eta.get("upper_seconds"))
                    if lower is not None and upper is not None and lower <= remaining <= upper:
                        result.update(lower_seconds=lower, upper_seconds=upper)
                    if eta.get("confidence") in ("low", "medium", "high"):
                        result["confidence"] = eta["confidence"]
                else:
                    result["eta_status"] = "unavailable"
    try:
        configuration = json.loads(run["config_json"])
    except (TypeError, ValueError, RecursionError):
        configuration = {}
    if isinstance(configuration, dict) and configuration.get("dynamic_eta") is False:
        result.update(eta_status="disabled", remaining_seconds=None, lower_seconds=None, upper_seconds=None, confidence=None)
    # The durable run state wins over a checkpoint from the last live tick.
    if run["status"] in {"complete", "complete_with_errors"}:
        result.update(eta_status="complete", remaining_seconds=0.0, lower_seconds=None, upper_seconds=None, confidence=None)
    elif run["status"] != "running":
        result.update(eta_status="unavailable", remaining_seconds=None, lower_seconds=None, upper_seconds=None, confidence=None)
    elif result["eta_status"] == "complete":
        result.update(eta_status="unavailable", remaining_seconds=None, lower_seconds=None, upper_seconds=None, confidence=None)
    return result


def _summary_response(result):
    """Age cached telemetry without reopening SQLite or inventing progress."""
    response = deepcopy(result)
    timing = response["timing"]
    if response["scan"]["status"] == "running" and timing["eta_status"] not in {"disabled", "not_started"}:
        updated = _timing_timestamp(timing["updated_at"])
        if updated is not None:
            age = (datetime.now(timezone.utc) - updated).total_seconds()
            if age > _TIMING_STALE_SECONDS or age < -5:
                timing.update(eta_status="stale", remaining_seconds=None, lower_seconds=None, upper_seconds=None, confidence=None)
        elif timing["eta_status"] == "estimated":
            timing.update(eta_status="unavailable", remaining_seconds=None, lower_seconds=None, upper_seconds=None, confidence=None)
    return response


def _literal(value):
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _text_filter(value):
    if not isinstance(value, str) or len(value) > 1024 or "\x00" in value:
        raise ViewerError("Filter must be text of at most 1024 characters")
    return value


def _pagination(limit, after):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ViewerError("limit must be an integer from 1 to 200")
    if isinstance(after, bool) or not isinstance(after, int) or not 0 <= after <= 9223372036854775807:
        raise ViewerError("after must be a non-negative SQLite integer")


def _analysis_filter(value):
    value = _text_filter(value)
    if value and value not in ANALYSIS_STATUSES:
        raise ViewerError("Unknown content-analysis status")
    return value


def _review_filter(value):
    value = _text_filter(value)
    if value and value not in REVIEW_STATUSES:
        raise ViewerError("Unknown finding-review status")
    return value


def _object_projection(analysis_available, alias=""):
    prefix = f"{alias}." if alias else ""
    columns = [prefix + name for name in _OBJECT_COLUMNS.split(",")]
    if analysis_available:
        columns.extend(prefix + name for name in ("analysis_status", "analysis_reason", "analysis_read"))
    else:
        # Schema 7 has no complete analysis observations. In particular,
        # processed/metadata findings are not proof of content analysis.
        columns.extend(("'unknown' AS analysis_status", "NULL AS analysis_reason", "NULL AS analysis_read"))
    return ",".join(columns)


def _targets(configuration):
    """Allowlist display fields; never expose the saved authentication config."""
    if not isinstance(configuration, dict):
        return []
    semantic = configuration.get("semantic", configuration)
    scope = semantic.get("scope", {}) if isinstance(semantic, dict) else {}
    raw = scope.get("targets", []) if isinstance(scope, dict) else []
    if not isinstance(raw, list):
        return []
    result = []
    for target in raw[:10000]:
        if isinstance(target, str):
            result.append(target[:4096])
        elif isinstance(target, dict) and target.get("kind") == "smb":
            host = target.get("host")
            port = target.get("port", 445)
            if isinstance(host, str) and isinstance(port, int):
                result.append(host[:4096] if port == 445 else f"{host[:4096]}:{port}")
        elif isinstance(target, dict) and target.get("kind") == "local":
            if isinstance(target.get("path"), str):
                result.append(target["path"][:4096])
    return result


class ViewerStore:
    """A catalog of explicitly allowed local result databases, not arbitrary paths."""

    def __init__(self, directories, files=(), query_timeout=1.0):
        if not isinstance(query_timeout, (int, float)) or not math.isfinite(query_timeout) or query_timeout <= 0:
            raise ValueError("query_timeout must be finite and positive")
        self.directories = tuple(dict.fromkeys(Path(value).expanduser().absolute() for value in directories))
        self.files = tuple(dict.fromkeys(Path(value).expanduser().absolute() for value in files))
        self.query_timeout = min(float(query_timeout), 10.0)
        self._lock = threading.RLock()
        self._catalog_time = float("-inf")
        self._catalog = {"scans": [], "warnings": []}
        self._entries = {}
        self._summaries = OrderedDict()
        self._summary_keys = {}
        self._summary_flights = {}

    @contextmanager
    def _connection(self, path):
        connection = None
        try:
            connection = _connect_local_sqlite(
                path, read_only=True, timeout=min(self.query_timeout, 0.1), isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            configure_evidence_reader(connection)
            deadline = time.monotonic() + self.query_timeout
            connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            connection.execute("PRAGMA trusted_schema=OFF")
            attach_reviews(connection, path, timeout=min(self.query_timeout, 0.25))
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA cache_size=-2048")
            # A short snapshot makes a response internally consistent. It is
            # closed before the HTTP response is serialized or sent.
            connection.execute("BEGIN")
            self._validate_schema(connection)
            yield connection
        except ViewerError:
            raise
        except EvidenceReadError as exc:
            raise ViewerError(str(exc), exc.status) from exc
        except ReviewError as exc:
            raise ViewerError(str(exc), exc.status) from exc
        except sqlite3.OperationalError as exc:
            if any(word in str(exc).lower() for word in ("locked", "busy", "interrupt")):
                raise ViewerError("Results database is busy or the query time limit was reached", 503) from exc
            raise ViewerError("Unsupported or unreadable results database", 409) from exc
        except (sqlite3.Error, StateError, UnsafeWritePath, OSError) as exc:
            raise ViewerError("Results database is not an accessible, private local scan state", 409) from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _validate_schema(connection):
        tables = {row["name"] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        for table, expected in _SCHEMA.items():
            if table not in tables:
                raise ViewerError("Unsupported results schema; no automatic migration is performed", 409)
            actual = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
            if not expected.issubset(actual):
                raise ViewerError("Unsupported results schema; no automatic migration is performed", 409)

    @staticmethod
    def _description(path, row):
        if row["schema_version"] not in _SUPPORTED_SCHEMAS:
            raise ViewerError("Unsupported results schema version; no automatic migration is performed", 409)
        try:
            configuration = json.loads(row["config_json"])
        except (TypeError, ValueError):
            configuration = {}
        scan_id = hashlib.sha256(f"{path}\0{row['run_id']}".encode()).hexdigest()[:32]
        return {
            "id": scan_id, "run_id": row["run_id"], "status": row["status"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "completed_at": row["completed_at"], "targets": _targets(configuration), "filename": path.name,
            "schema_version": row["schema_version"],
        }

    def _paths(self, warnings, deadline):
        seen = set()
        for path in self.files:
            if path not in seen:
                seen.add(path)
                yield path
        for directory in self.directories:
            try:
                with local_directory_descriptor(directory, purpose="viewer scan directory", create=False) as (fd, _):
                    with os.scandir(fd) as entries:
                        for entry in entries:
                            if time.monotonic() >= deadline:
                                warnings.append("Scan directory discovery time limit reached")
                                return
                            if Path(entry.name).suffix not in {".sqlite", ".sqlite3", ".db"}:
                                continue
                            path = directory / entry.name
                            if path not in seen:
                                seen.add(path)
                                yield path
            except FileNotFoundError:
                continue
            except (UnsafeWritePath, OSError):
                warnings.append(f"Cannot read local scan directory: {directory.name}")

    def scans(self):
        with self._lock:
            now = time.monotonic()
            if now - self._catalog_time < _CACHE_SECONDS:
                return deepcopy(self._catalog)
            scans, warnings, entries = [], [], {}
            # One deadline for discovery as well as a deadline for each query;
            # huge folders cannot cause unbounded database opens per poll.
            deadline = now + max(self.query_timeout, 0.1)
            for count, path in enumerate(self._paths(warnings, deadline)):
                if count >= _MAX_SCANS or len(scans) >= _MAX_SCANS or time.monotonic() >= deadline:
                    warnings.append("Scan discovery limit reached; use a narrower directory or explicit state files")
                    break
                try:
                    with self._connection(path) as connection:
                        rows = connection.execute(
                            "SELECT run_id,schema_version,status,config_json,created_at,updated_at,completed_at "
                            "FROM runs ORDER BY created_at DESC LIMIT ?", (_MAX_SCANS - len(scans),),
                        )
                        for row in rows:
                            description = self._description(path, row)
                            scans.append(description)
                            entries[description["id"]] = (path, description["run_id"])
                except ViewerError as exc:
                    warnings.append(f"{path.name}: {exc}")
            scans.sort(key=lambda scan: (scan["created_at"], scan["id"]), reverse=True)
            self._entries = entries
            self._catalog = {"scans": scans, "warnings": warnings}
            self._catalog_time = time.monotonic()
            return deepcopy(self._catalog)

    def _entry(self, scan_id):
        if not isinstance(scan_id, str) or len(scan_id) != 32:
            raise ViewerError("Unknown scan", 404)
        with self._lock:
            entry = self._entries.get(scan_id)
        # Live views of an already catalogued scan must not reopen every other
        # saved scan merely because the user keeps its results page open.
        if entry is None:
            self.scans()
            with self._lock:
                entry = self._entries.get(scan_id)
        if entry is None:
            raise ViewerError("Unknown scan", 404)
        return entry

    @staticmethod
    def _file_revisions(path):
        parts = []
        for candidate in (path, path.with_name(path.name + "-wal")):
            try:
                stat = candidate.stat(follow_symlinks=False)
                parts.append((stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns))
            except OSError:
                parts.append(None)
        return tuple(parts)

    @staticmethod
    def _revision_value(run_id, main_revision, review_revision):
        return hashlib.sha256(json.dumps((run_id, main_revision, review_revision)).encode()).hexdigest()[:24]

    @classmethod
    def _revision(cls, path, run_id):
        return cls._revision_value(run_id, cls._file_revisions(path), cls._file_revisions(review_path(path)))

    @staticmethod
    def _data_generation(connection, run_id, schema_version):
        # Only schema 9 writers promise transactional generation updates.
        # A legacy database with a coincidentally named counter is not trusted.
        if schema_version < 9 or not connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='counters'"
        ).fetchone():
            return None
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(counters)")}
        if not {"run_id", "name", "value"}.issubset(columns):
            return None
        row = connection.execute(
            "SELECT value FROM counters WHERE run_id=? AND name='data_revision'", (run_id,),
        ).fetchone()
        value = row["value"] if row is not None else None
        return value if type(value) is int and 0 <= value < 2**63 - 1 else None

    @staticmethod
    def _results_revision(result, object_updates, review_revision, generation):
        data = {key: value for key, value in result.items() if key not in {"revision", "results_revision", "timing"}}
        data["object_updates"] = object_updates
        data["review_revision"] = review_revision
        if generation is not None:
            # Unlike MAX(updated_at), a committed generation also notices
            # same-count replacements when the wall clock moves backwards.
            data["data_generation"] = generation
        return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:24]

    def summary(self, scan_id):
        path, run_id = self._entry(scan_id)
        deadline = time.monotonic() + self.query_timeout
        while True:
            main_revision = self._file_revisions(path)
            review_revision = self._file_revisions(review_path(path))
            revision = self._revision_value(run_id, main_revision, review_revision)
            with self._lock:
                cached = self._summaries.get(scan_id)
                key = self._summary_keys.get(scan_id)
                if cached is not None and (
                    revision == cached[1]["revision"] or (
                        time.monotonic() - cached[0] < _CACHE_SECONDS
                        and key is not None and review_revision == key["review"]
                    )
                ):
                    self._summaries.move_to_end(scan_id)
                    return _summary_response(cached[1])
                flight = self._summary_flights.get(scan_id)
                owner = flight is None
                if owner:
                    if time.monotonic() >= deadline:
                        raise ViewerError("Summary calculation is busy; retry shortly", 503)
                    # At most one aggregate snapshot per scan. Do not hold the
                    # catalog lock during SQLite work or another scan's wait.
                    flight = self._summary_flights[scan_id] = threading.Event()
            if owner:
                try:
                    return self._refresh_summary(
                        scan_id, path, run_id, revision, main_revision, review_revision, cached, key,
                    )
                finally:
                    with self._lock:
                        self._summary_flights.pop(scan_id, None)
                        flight.set()
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not flight.wait(remaining):
                raise ViewerError("Summary calculation is busy; retry shortly", 503)
            # Recheck the published cache and revisions after the owner ends.

    def _refresh_summary(self, scan_id, path, run_id, revision, main_revision, review_revision, cached, key):
        # Observe the revision before SQLite takes its snapshot. Reading it
        # afterwards could label an older snapshot with a newer commit's
        # revision and hide that commit from a subsequent live refresh.
        with self._connection(path) as connection:
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise ViewerError("Scan is no longer present", 404)
            scan = self._description(path, row)
            timing = _read_timing(connection, row)
            generation = self._data_generation(connection, run_id, row["schema_version"])
            identity = main_revision[0][:2] if main_revision[0] is not None else None
            observed_main = self._file_revisions(path)
            unchanged_main = (
                key is not None and key["main"] == main_revision
                and observed_main == main_revision
            )
            unchanged_generation = (
                key is not None and generation is not None and key["generation"] == generation
                and key["identity"] == identity and key["schema"] == row["schema_version"]
                and observed_main[0] is not None and observed_main[0][:2] == identity
            )
            if cached is not None and (unchanged_main or unchanged_generation):
                result = deepcopy(cached[1])
                object_updates = key["object_updates"]
            else:
                result, object_updates = self._aggregate_summary(connection, run_id, row["schema_version"])
        result.update(scan=scan, timing=timing, revision=revision)
        result["results_revision"] = self._results_revision(result, object_updates, review_revision, generation)
        with self._lock:
            self._summaries[scan_id] = (time.monotonic(), result)
            self._summary_keys[scan_id] = {
                "main": main_revision, "review": review_revision, "identity": identity,
                "generation": generation, "schema": scan["schema_version"], "object_updates": object_updates,
            }
            self._summaries.move_to_end(scan_id)
            while len(self._summaries) > 32:
                expired_id, _ = self._summaries.popitem(last=False)
                self._summary_keys.pop(expired_id, None)
        return _summary_response(result)

    @staticmethod
    def _aggregate_summary(connection, run_id, schema_version):
        analysis_available = schema_version >= 8
        analysis_expression = "analysis_status" if analysis_available else "'unknown'"
        analysis_counts = dict.fromkeys(sorted(ANALYSIS_STATUSES), 0)
        objects = {}
        object_columns = {column["name"] for column in connection.execute("PRAGMA table_info(objects)")}
        latest_expression = "MAX(updated_at)" if "updated_at" in object_columns else "NULL"
        object_updates = []
        for row in connection.execute(
            f"SELECT kind,status,{analysis_expression} AS analysis_status,COUNT(*) AS count,"
            f"{latest_expression} AS latest_update "
            "FROM objects WHERE run_id=? GROUP BY kind,status,analysis_status", (run_id,),
        ):
            object_updates.append((row["kind"], row["status"], row["analysis_status"], row["latest_update"]))
            by_status = objects.setdefault(row["kind"], {})
            by_status[row["status"]] = by_status.get(row["status"], 0) + row["count"]
            if row["kind"] == "file":
                bucket = row["analysis_status"] if row["analysis_status"] in ANALYSIS_STATUSES else "unknown"
                analysis_counts[bucket] += row["count"]
        counts = connection.execute(
            "SELECT COUNT(*) AS findings,COUNT(DISTINCT f.object_id) AS matched_objects,"
            "COUNT(DISTINCT CASE WHEN o.kind='file' THEN f.object_id END) AS matched_files "
            "FROM findings f LEFT JOIN objects o ON o.object_id=f.object_id AND o.run_id=f.run_id "
            "WHERE f.run_id=?", (run_id,),
        ).fetchone()
        exclusions = {row["kind"]: row["count"] for row in connection.execute(
            "SELECT kind,COUNT(*) AS count FROM exclusions WHERE run_id=? GROUP BY kind", (run_id,),
        )}
        reasons = [dict(row) for row in connection.execute(
            "SELECT kind,status,substr(reason,1,4096) AS reason,COUNT(*) AS count FROM objects "
            "WHERE run_id=? AND reason IS NOT NULL GROUP BY kind,status,reason ORDER BY count DESC LIMIT 100",
            (run_id,),
        )]
        return {
            "objects": objects, "findings": counts["findings"], "matched_files": counts["matched_files"],
            "matched_objects": counts["matched_objects"], "exclusions": exclusions, "reasons": reasons,
            "analysis_counts_available": analysis_available, "analysis_counts": analysis_counts,
        }, object_updates

    def findings(self, scan_id, *, limit=100, after=0, rule="", severity="", confidence="", representation="",
                 target="", share="", path="", extension="", q="", category="",
                 min_size=None, max_size=None, analysis_status="", review_status=""):
        _pagination(limit, after)
        analysis_status = _analysis_filter(analysis_status)
        review_status = _review_filter(review_status)
        for bound in (min_size, max_size):
            if bound is not None and (
                isinstance(bound, bool) or not isinstance(bound, int) or not 0 <= bound <= 9223372036854775807
            ):
                raise ViewerError("Size filters must be non-negative SQLite integers")
        if min_size is not None and max_size is not None and min_size > max_size:
            raise ViewerError("min_size cannot exceed max_size")
        rule, severity, confidence, representation, target, share, path, extension, q, category = (
            _text_filter(value) for value in
            (rule, severity, confidence, representation, target, share, path, extension, q, category)
        )
        db_path, run_id = self._entry(scan_id)
        predicates, parameters = ["o.run_id=?"], [run_id]
        if after:
            predicates.append("o.object_id<?")
            parameters.append(after)
        for operator, bound in ((">=", min_size), ("<=", max_size)):
            if bound is not None:
                predicates.append(f"o.size {operator} ?")
                parameters.append(bound)
        for field, value in (("target", target), ("share", share)):
            if value:
                predicates.append(f"o.{field}=? COLLATE NOCASE")
                parameters.append(value)
        if path:
            predicates.append("o.path LIKE ? ESCAPE '\\'")
            parameters.append(_literal(path))
        if extension:
            extension = "." + extension.lstrip(".")
            predicates.append("substr(o.path,-length(?))=? COLLATE NOCASE")
            parameters.extend((extension, extension))
        matching = ["f.run_id=o.run_id", "f.object_id=o.object_id"]
        if rule:
            matching.append("f.rule_id IN (?,?)")
            parameters.extend((rule, rule if ":" in rule else "rule:" + rule))
        for field, value in (("severity", severity), ("confidence", confidence),
                             ("representation", representation), ("category", category)):
            if value:
                matching.append(f"f.{field}=?")
                parameters.append(value)
        deadline = time.monotonic() + self.query_timeout
        with self._connection(db_path) as connection:
            schema_version = self._check_run(connection, run_id)
            analysis_available = schema_version >= 8
            if q:
                # Literal substring search keeps SQLite's ASCII-only folding
                # and sees text after NUL in inline AND normalized context.
                matching.append(
                    f"(instr(lower(f.value),lower(?))>0 OR instr(lower({context_sql(schema_version)}),lower(?))>0)"
                )
                parameters.extend((q, q))
            predicates.append(
                "EXISTS (SELECT 1 FROM findings f" + (context_join(schema_version) if q else "")
                + " WHERE " + " AND ".join(matching) + review_predicate(review_status) + ")"
            )
            if analysis_status:
                predicates.append("o.kind='file'")
                predicates.append("o.analysis_status=?" if analysis_available else "'unknown'=?")
                parameters.append(analysis_status)
            rows = connection.execute(
                "SELECT " + _object_projection(analysis_available, "o") +
                # The run/status index cannot supply object_id order unless
                # status is fixed. SQLite otherwise scans/sorts the full run
                # before LIMIT. Reverse integer-PK iteration stops as soon as
                # one page matches; existing finding/object indexes handle the
                # correlated predicates. No database/index changes are needed.
                " FROM objects o NOT INDEXED WHERE " + " AND ".join(predicates) +
                " ORDER BY o.object_id DESC LIMIT ?",
                (*parameters, limit + 1),
            ).fetchall()
            items = []
            text_size = 0
            for row in rows[:limit]:
                item = dict(row)
                totals = connection.execute(
                    "SELECT COUNT(*) AS total_findings,MAX(CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 "
                    "WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END) AS severity_rank "
                    "FROM findings f WHERE run_id=? AND object_id=?" + review_predicate(review_status),
                    (run_id, row["object_id"]),
                ).fetchone()
                item["total_findings"] = totals["total_findings"]
                item["max_severity"] = ("unknown", "info", "low", "medium", "high", "critical")[
                    totals["severity_rank"] or 0
                ]
                page = self._finding_page(
                    connection, run_id, row["object_id"], _MAX_FINDINGS, 0,
                    deadline=deadline, review_status=review_status, schema_version=schema_version,
                )
                item["findings"] = page["items"]
                item["findings_truncated"] = page["next_after"] is not None
                item["findings_next_after"] = page["next_after"]
                item["findings_page_token"] = (
                    self._finding_page_token(
                        connection, run_id, row["object_id"], review_status, deadline=deadline,
                    )
                    if page["next_after"] is not None else None
                )
                items.append(item)
                text_size += sum(self._evidence_size(finding) for finding in item["findings"])
                if text_size >= _PAGE_TEXT_BUDGET:
                    break
        return {"items": items, "next_after": items[-1]["object_id"] if len(rows) > len(items) else None}

    @staticmethod
    def _evidence_size(finding):
        # Include tags/metadata, not just evidence: pathological tags should
        # not evade the page budget. Count codepoints; UTF-8 uses <=4 bytes each.
        return sum(len(value) for value in finding.values() if isinstance(value, str)) + sum(
            len(tag) for tag in finding.get("tags", ())
        )

    @staticmethod
    def _finding_page(connection, run_id, object_id, limit, after, *, deadline, review_status="", schema_version=7):
        cursor_clause = " AND f.rowid<?" if after else ""
        parameters = [run_id, object_id]
        if after:
            parameters.append(after)
        context = context_sql(schema_version)
        rows = connection.execute(
            "SELECT f.rowid AS cursor,f.finding_id,f.rule_id,f.severity,f.confidence,f.representation,f.category,"
            "substr(f.tags_json,1,65536) AS tags_json,substr(f.value,1,65536) AS value,"
            f"substr({context},1,65536) AS context,f.match_start,f.match_end,"
            f"instr(f.value,char(0))>0 AS value_has_nul,instr({context},char(0))>0 AS context_has_nul,"
            f"length(f.value)>65536 AS value_truncated,length({context})>65536 AS context_truncated,"
            + review_expression() + " AS reviewed "
            "FROM findings f" + context_join(schema_version)
            + " WHERE f.run_id=? AND f.object_id=?" + review_predicate(review_status)
            + cursor_clause + " ORDER BY f.rowid DESC LIMIT ?",
            (*parameters, limit + 1),
        )
        items, text_size, more = [], 0, False
        reader = None
        for row in rows:
            if len(items) >= limit or text_size >= _PAGE_TEXT_BUDGET:
                more = True
                break
            evidence = dict(row)
            for field in ("value", "context"):
                if evidence.pop(f"{field}_has_nul"):
                    if reader is None:
                        reader = EvidenceTextReader(connection, deadline, schema_version=schema_version)
                    evidence[field], count = reader.read(
                        evidence["cursor"], field, limit=_MAX_TEXT, full_length=False,
                    )
                    evidence[f"{field}_truncated"] = count > _MAX_TEXT
            try:
                tags = json.loads(evidence.pop("tags_json"))
            except (TypeError, ValueError):
                tags = []
            evidence["tags"] = [tag for tag in tags if isinstance(tag, str)] if isinstance(tags, list) else []
            evidence["value_truncated"] = bool(evidence["value_truncated"])
            evidence["context_truncated"] = bool(evidence["context_truncated"])
            evidence["reviewed"] = bool(evidence["reviewed"])
            items.append(evidence)
            text_size += ViewerStore._evidence_size(evidence)
        rows.close()
        return {"items": items, "next_after": items[-1]["cursor"] if more else None}

    @staticmethod
    def _finding_page_token(connection, run_id, object_id, review_status, *, deadline):
        """Version one file's ordered membership in the current read snapshot.

        Rowids are cursors, not durable finding identities: a retry may replace
        every row. Stream only identity metadata, never evidence or a whole
        materialized result list. Include the active review membership, so a
        different tab cannot silently remove the continuation's anchor. This
        is local read work under the same deadline as the page; the scanner's
        schema, writes, and source reads are not changed.
        """
        digest = hashlib.sha256(b"manspider-finding-page-v1\0")
        encode = json.JSONEncoder(separators=(",", ":")).encode
        digest.update(encode((run_id, object_id, review_status)).encode("utf-8"))
        cursor = connection.execute(
            "SELECT rowid,finding_id,created_at FROM findings f WHERE run_id=? AND object_id=?"
            + review_predicate(review_status) + " ORDER BY rowid DESC",
            (run_id, object_id),
        )
        try:
            for index, row in enumerate(cursor):
                if index % 256 == 0 and time.monotonic() >= deadline:
                    raise ViewerError("Finding page version query time limit was reached", 503)
                digest.update(encode(tuple(row)).encode("utf-8"))
        finally:
            cursor.close()
        if time.monotonic() >= deadline:
            raise ViewerError("Finding page version query time limit was reached", 503)
        return "v1." + digest.hexdigest()

    def object_findings(self, scan_id, object_id, *, limit=50, after=0, review_status="", page_token=None):
        _pagination(limit, after)
        review_status = _review_filter(review_status)
        self._object_id(object_id)
        if page_token is not None and (
            not isinstance(page_token, str) or len(page_token) != 67 or not page_token.startswith("v1.")
            or any(character not in "0123456789abcdef" for character in page_token[3:])
        ):
            raise ViewerError("Invalid finding page token")
        path, run_id = self._entry(scan_id)
        deadline = time.monotonic() + self.query_timeout
        with self._connection(path) as connection:
            schema_version = self._check_run(connection, run_id)
            if connection.execute(
                "SELECT 1 FROM objects WHERE run_id=? AND object_id=?", (run_id, object_id),
            ).fetchone() is None:
                raise ViewerError("Unknown object", 404)
            token = self._finding_page_token(connection, run_id, object_id, review_status, deadline=deadline)
            if (after and page_token is None) or (page_token is not None and page_token != token):
                raise ViewerError(
                    "The file's finding pages changed or the page token is missing; restart this file's pages",
                    409, code="stale_page",
                )
            page = self._finding_page(
                connection, run_id, object_id, limit, after, deadline=deadline, review_status=review_status,
                schema_version=schema_version,
            )
            return {**page, "page_token": token}

    def set_finding_review(self, scan_id, finding_id, reviewed):
        if not isinstance(finding_id, str) or not 1 <= len(finding_id) <= 256 or "\x00" in finding_id:
            raise ViewerError("Invalid finding ID")
        if not isinstance(reviewed, bool):
            raise ViewerError("reviewed must be a boolean")
        path, run_id = self._entry(scan_id)
        # Validate against the allowed read-only scan before opening any
        # writable annotation store. Unknown IDs cannot create sidecars.
        with self._connection(path) as connection:
            self._check_run(connection, run_id)
            if connection.execute(
                "SELECT 1 FROM findings WHERE run_id=? AND finding_id=?", (run_id, finding_id),
            ).fetchone() is None:
                raise ViewerError("Unknown finding", 404)
        try:
            set_review(path, run_id, finding_id, reviewed, timeout=min(self.query_timeout, 0.25))
        except ReviewError as exc:
            raise ViewerError(str(exc), exc.status) from exc
        except sqlite3.OperationalError as exc:
            if any(word in str(exc).lower() for word in ("locked", "busy", "interrupt")):
                raise ViewerError("Review database is busy or the query time limit was reached", 503) from exc
            raise ViewerError("Unsupported or unreadable review database", 409) from exc
        except (sqlite3.Error, StateError, UnsafeWritePath, OSError) as exc:
            raise ViewerError("Review database is not an accessible, private local file", 409) from exc
        # The sidecar revision invalidates review membership independently.
        # Retain unchanged main-database aggregates for the next summary.
        return {"finding_id": finding_id, "reviewed": reviewed}

    @staticmethod
    def _object_id(object_id):
        if isinstance(object_id, bool) or not isinstance(object_id, int) or not 1 <= object_id <= 9223372036854775807:
            raise ViewerError("object_id must be a positive SQLite integer")

    def evidence(self, scan_id, finding_id, *, field="value", offset=0, limit=65536):
        if field not in {"value", "context"}:
            raise ViewerError("Evidence field must be value or context")
        if not isinstance(finding_id, str) or not 1 <= len(finding_id) <= 256 or "\x00" in finding_id:
            raise ViewerError("Invalid finding ID")
        if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset < 9223372036854775807:
            raise ViewerError("offset must be a non-negative SQLite integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_TEXT:
            raise ViewerError("Evidence limit must be from 1 to 65536 characters")
        path, run_id = self._entry(scan_id)
        deadline = time.monotonic() + self.query_timeout
        with self._connection(path) as connection:
            schema_version = self._check_run(connection, run_id)
            # field is a fixed allowlist, never an arbitrary SQL identifier.
            expression = context_sql(schema_version) if field == "context" else "f.value"
            row = connection.execute(
                f"SELECT f.rowid AS rowid,substr({expression},?,?) AS text,length({expression}) AS total,"
                f"instr({expression},char(0))>0 AS has_nul "
                "FROM findings f" + (context_join(schema_version) if field == "context" else "")
                + " WHERE f.run_id=? AND f.finding_id=?", (offset + 1, limit, run_id, finding_id),
            ).fetchone()
            if row is None:
                raise ViewerError("Unknown finding", 404)
            if row["has_nul"]:
                value, total = EvidenceTextReader(connection, deadline, schema_version=schema_version).read(
                    row["rowid"], field, offset=offset, limit=limit,
                )
                return {"text": value, "total": total,
                        "next_offset": offset + limit if offset + limit < total else None}
            total = row["total"] or 0
            return {"text": row["text"] or "", "total": total,
                    "next_offset": offset + limit if offset + limit < total else None}

    @staticmethod
    def _check_run(connection, run_id):
        row = connection.execute("SELECT schema_version FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise ViewerError("Scan is no longer present", 404)
        if row["schema_version"] not in _SUPPORTED_SCHEMAS:
            raise ViewerError("Unsupported results schema version; no automatic migration is performed", 409)
        return row["schema_version"]

    def objects(self, scan_id, *, limit=100, after=0, status="", kind="file", q="", analysis_status=""):
        _pagination(limit, after)
        analysis_status = _analysis_filter(analysis_status)
        status, kind, q = (_text_filter(value) for value in (status, kind, q))
        path, run_id = self._entry(scan_id)
        predicates, parameters = ["run_id=?"], [run_id]
        if after:
            predicates.append("object_id<?")
            parameters.append(after)
        for field, value in (("status", status), ("kind", kind)):
            if value:
                predicates.append(f"{field}=?")
                parameters.append(value)
        if q:
            predicates.append("(path LIKE ? ESCAPE '\\' OR reason LIKE ? ESCAPE '\\')")
            parameters.extend((_literal(q), _literal(q)))
        with self._connection(path) as connection:
            analysis_available = self._check_run(connection, run_id) >= 8
            if analysis_status:
                predicates.append("kind='file'")
                predicates.append("analysis_status=?" if analysis_available else "'unknown'=?")
                parameters.append(analysis_status)
            # With an exact status the existing (run_id,status) index has rowid
            # as its final ordering key. Without status, prefer reverse PK to
            # avoid sorting every object in the run for a single page.
            index_hint = "" if status else " NOT INDEXED"
            rows = connection.execute(
                f"SELECT {_object_projection(analysis_available)} FROM objects{index_hint} WHERE " + " AND ".join(predicates) +
                " ORDER BY object_id DESC LIMIT ?", (*parameters, limit + 1),
            ).fetchall()
        return {"items": [dict(row) for row in rows[:limit]],
                "next_after": rows[limit - 1]["object_id"] if len(rows) > limit else None}
