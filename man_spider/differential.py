"""Bounded-memory semantic comparison of MANSPIDER persistent scan states."""

from __future__ import annotations

import heapq
import sqlite3
from collections import Counter
from dataclasses import dataclass
from itertools import groupby
from pathlib import Path
from typing import Iterable, Iterator

from man_spider.path_safety import UnsafeWritePath, require_local_path
from man_spider.evidence_storage import configure_evidence_reader, context_join, context_sql
from man_spider.state import StateError, _connect_local_sqlite


REQUIRED_TABLES = {"runs", "objects", "findings", "exclusions"}
TERMINAL_RUN_STATUSES = {"complete", "complete_with_errors"}
# Keep this explicit: newer schemas may add detection semantics that this
# comparator does not yet understand, even if the selected columns exist.
SUPPORTED_SCHEMA_VERSIONS = frozenset(range(2, 10))
ANALYSIS_COLUMN_TYPES = {
    "analysis_status": "TEXT",
    "analysis_reason": "TEXT",
    "analysis_read": "INTEGER",
}
ANALYSIS_STATUSES = {"unknown", "not_analyzed", "partial", "analyzed"}

OBJECT_QUERY = """
    SELECT object_key, kind, target, share, path, size, mtime,
           file_id, status, reason, changed
    FROM objects WHERE run_id=?
    ORDER BY object_key, kind, target, share, path, size, mtime,
             file_id, status, reason, changed
"""
FINDING_QUERY = """
    SELECT o.object_key, o.target, o.share, o.path,
           f.rule_id, f.representation, f.rule_source,
           f.rule_schema_version, f.rule_pack_id,
           f.rule_pack_version, f.severity, f.confidence,
           f.category, f.tags_json, f.match_start, f.match_end,
           f.value, f.context
    FROM findings AS f
    JOIN objects AS o
      ON o.run_id=f.run_id AND o.object_id=f.object_id
    WHERE f.run_id=?
    ORDER BY o.object_key, o.target, o.share, o.path,
             f.rule_id, f.representation, f.rule_source,
             f.rule_schema_version, f.rule_pack_id,
             f.rule_pack_version, f.severity, f.confidence,
             f.category, f.tags_json, f.match_start, f.match_end,
             f.value, f.context
"""
EXCLUSION_QUERY = """
    SELECT object_key, kind, target, share, path, reason
    FROM exclusions WHERE run_id=?
    ORDER BY object_key, kind, target, share, path, reason
"""
FILE_ANALYSIS_QUERY = """
    SELECT object_key, target, share, path,
           analysis_status, analysis_reason, analysis_read
    FROM objects WHERE run_id=? AND kind='file'
    ORDER BY object_key, target, share, path,
             analysis_status, analysis_reason, analysis_read
"""
LEGACY_FILE_ANALYSIS_QUERY = """
    SELECT object_key, target, share, path,
           'unknown' AS analysis_status, NULL AS analysis_reason,
           NULL AS analysis_read
    FROM objects WHERE run_id=? AND kind='file'
    ORDER BY object_key, target, share, path,
             analysis_status, analysis_reason, analysis_read
"""


class StateComparisonError(RuntimeError):
    """Raised when a state cannot be read or does not have the expected schema."""


@dataclass
class _StateReader:
    path: Path
    connection: sqlite3.Connection
    run_id: str
    status: str
    schema_version: int

    def close(self) -> None:
        self.connection.close()


@dataclass(frozen=True)
class CategoryDifference:
    reference_total: int
    candidate_total: int
    reference_only_count: int
    candidate_only_count: int
    reference_only: Counter
    candidate_only: Counter

    @property
    def equal(self) -> bool:
        return self.reference_only_count == 0 and self.candidate_only_count == 0


@dataclass(frozen=True)
class SemanticComparison:
    categories: dict[str, CategoryDifference]

    @property
    def equal(self) -> bool:
        return all(difference.equal for difference in self.categories.values())


def _open_state(path: Path, *, check_integrity: bool) -> _StateReader:
    try:
        resolved = require_local_path(path, purpose="differential SQLite state").resolve()
    except UnsafeWritePath as exc:
        raise StateComparisonError(str(exc)) from exc
    if not resolved.is_file():
        raise StateComparisonError(f"State database does not exist: {resolved}")
    connection = None
    try:
        connection = _connect_local_sqlite(resolved, read_only=True)
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.row_factory = sqlite3.Row
        configure_evidence_reader(connection)
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        missing = REQUIRED_TABLES - tables
        if missing:
            raise StateComparisonError(f"State {resolved} is missing tables: {', '.join(sorted(missing))}")
        if check_integrity:
            result = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise StateComparisonError(f"State {resolved} failed SQLite integrity_check: {result}")
        runs = connection.execute("SELECT run_id, status, schema_version FROM runs").fetchall()
        if len(runs) != 1:
            raise StateComparisonError(f"State {resolved} contains {len(runs)} runs; exactly one is required")
        schema_version = runs[0]["schema_version"]
        if type(schema_version) is not int or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise StateComparisonError(f"State {resolved} has unsupported schema version: {schema_version!r}")
        if schema_version >= 8:
            columns = {row["name"]: row for row in connection.execute("PRAGMA table_info(objects)")}
            for name, expected_type in ANALYSIS_COLUMN_TYPES.items():
                column = columns.get(name)
                if column is None:
                    raise StateComparisonError(f"State {resolved} schema 8 is missing required column: {name}")
                if column["type"].upper() != expected_type or (name == "analysis_status" and not column["notnull"]):
                    raise StateComparisonError(f"State {resolved} schema 8 has malformed analysis column: {name}")
        if schema_version >= 9:
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(findings)")}
            contexts = {row["name"] for row in connection.execute("PRAGMA table_info(finding_contexts)")}
            if "context_id" not in columns or not {"context_id", "run_id", "object_id", "context"}.issubset(contexts):
                raise StateComparisonError(f"State {resolved} schema 9 is missing finding context storage")
        return _StateReader(resolved, connection, runs[0]["run_id"], runs[0]["status"], schema_version)
    except StateComparisonError:
        if connection is not None:
            connection.close()
        raise
    except (sqlite3.Error, StateError) as exc:
        if connection is not None:
            connection.close()
        raise StateComparisonError(f"Unable to read state {resolved}: {exc}") from exc


def _open_states(paths: Iterable[str | Path], *, check_integrity: bool) -> list[_StateReader]:
    state_paths = tuple(Path(path) for path in paths)
    if not state_paths:
        raise StateComparisonError("At least one state database is required")
    readers = []
    try:
        for path in state_paths:
            readers.append(_open_state(path, check_integrity=check_integrity))
        return readers
    except BaseException:
        for reader in readers:
            reader.close()
        raise


def _sort_key(item: tuple) -> tuple:
    """Make nullable fixed-schema SQLite rows safely comparable in Python."""

    return tuple((0, "") if value is None else (1, value) for value in item)


def _merged_rows(readers: list[_StateReader], query: str) -> Iterator[tuple]:
    def rows(reader):
        statement = query
        if query == FINDING_QUERY and reader.schema_version >= 9:
            statement = query.replace("f.context", context_sql(reader.schema_version)).replace(
                "FROM findings AS f", "FROM findings AS f " + context_join(reader.schema_version)
            )
        for row in reader.connection.execute(statement, (reader.run_id,)):
            yield tuple(row)
    streams = (rows(reader) for reader in readers)
    return heapq.merge(*streams, key=_sort_key)


def _file_analysis_rows(reader: _StateReader) -> Iterator[tuple]:
    query = FILE_ANALYSIS_QUERY if reader.schema_version >= 8 else LEGACY_FILE_ANALYSIS_QUERY
    for row in reader.connection.execute(query, (reader.run_id,)):
        item = tuple(row)
        status, reason, content_read = item[-3:]
        if (
            not isinstance(status, str)
            or status not in ANALYSIS_STATUSES
            or (reason is not None and not isinstance(reason, str))
            or (content_read is not None and (type(content_read) is not int or content_read not in (0, 1)))
        ):
            raise StateComparisonError(f"State {reader.path} has malformed file analysis evidence for {item[0]!r}")
        yield item


def _grouped_file_analysis(readers: list[_StateReader]) -> Iterator[tuple[tuple, int]]:
    streams = (_file_analysis_rows(reader) for reader in readers)
    for item, duplicates in groupby(heapq.merge(*streams, key=_sort_key)):
        # File multiplicity remains exact, including overlapping shards.
        yield item, sum(1 for _duplicate in duplicates)


def _grouped_rows(
    readers: list[_StateReader],
    query: str,
    *,
    merge_target_objects: bool = False,
) -> Iterator[tuple[tuple, int]]:
    for item, duplicates in groupby(_merged_rows(readers, query)):
        count = sum(1 for _duplicate in duplicates)
        # This helper is called with ``merge_target_objects`` only for the
        # object stream.  Do not depend on Python preserving the identity of
        # an otherwise equal SQL string supplied by a caller.
        if merge_target_objects and item[1] == "target":
            count = 1
        yield item, count


def _record_example(examples: Counter, item: tuple, count: int, limit: int) -> None:
    if len(examples) < limit:
        examples[item] = count


def _compare_rows(
    reference_rows: Iterator[tuple[tuple, int]],
    candidate_rows: Iterator[tuple[tuple, int]],
    *,
    example_limit: int,
) -> CategoryDifference:
    reference_item = next(reference_rows, None)
    candidate_item = next(candidate_rows, None)
    reference_total = 0
    candidate_total = 0
    reference_only_count = 0
    candidate_only_count = 0
    reference_only = Counter()
    candidate_only = Counter()

    while reference_item is not None or candidate_item is not None:
        if candidate_item is None or (
            reference_item is not None and _sort_key(reference_item[0]) < _sort_key(candidate_item[0])
        ):
            item, count = reference_item
            reference_total += count
            reference_only_count += count
            _record_example(reference_only, item, count, example_limit)
            reference_item = next(reference_rows, None)
            continue
        if reference_item is None or _sort_key(candidate_item[0]) < _sort_key(reference_item[0]):
            item, count = candidate_item
            candidate_total += count
            candidate_only_count += count
            _record_example(candidate_only, item, count, example_limit)
            candidate_item = next(candidate_rows, None)
            continue

        item = reference_item[0]
        reference_count = reference_item[1]
        candidate_count = candidate_item[1]
        reference_total += reference_count
        candidate_total += candidate_count
        if reference_count > candidate_count:
            difference = reference_count - candidate_count
            reference_only_count += difference
            _record_example(reference_only, item, difference, example_limit)
        elif candidate_count > reference_count:
            difference = candidate_count - reference_count
            candidate_only_count += difference
            _record_example(candidate_only, item, difference, example_limit)
        reference_item = next(reference_rows, None)
        candidate_item = next(candidate_rows, None)

    return CategoryDifference(
        reference_total=reference_total,
        candidate_total=candidate_total,
        reference_only_count=reference_only_count,
        candidate_only_count=candidate_only_count,
        reference_only=reference_only,
        candidate_only=candidate_only,
    )


def _aggregate_run_status(readers: list[_StateReader]) -> str:
    statuses = Counter(reader.status for reader in readers)
    unique = set(statuses)
    if unique == {"complete"}:
        return "complete"
    if unique and unique <= TERMINAL_RUN_STATUSES:
        return "complete_with_errors" if "complete_with_errors" in unique else "complete"
    return ",".join(f"{status}:{statuses[status]}" for status in sorted(unique))


def _compare_run_status(reference: list[_StateReader], candidate: list[_StateReader]) -> CategoryDifference:
    reference_status = _aggregate_run_status(reference)
    candidate_status = _aggregate_run_status(candidate)
    same = reference_status == candidate_status
    return CategoryDifference(
        reference_total=1,
        candidate_total=1,
        reference_only_count=0 if same else 1,
        candidate_only_count=0 if same else 1,
        reference_only=Counter() if same else Counter({(reference_status,): 1}),
        candidate_only=Counter() if same else Counter({(candidate_status,): 1}),
    )


def compare_scan_states(
    reference_paths: Iterable[str | Path],
    candidate_paths: Iterable[str | Path],
    *,
    merge_reference_shards: bool = False,
    merge_candidate_shards: bool = False,
    check_integrity: bool = True,
    example_limit: int = 3,
) -> SemanticComparison:
    """Compare complete semantic results while keeping memory use bounded.

    Run IDs, timestamps, retry attempts, and exclusion visit counts are
    execution history rather than detection semantics and are intentionally
    ignored. Object identity/metadata/status/reason/changed, file content
    analysis evidence, every complete finding field, exclusions, and the
    aggregate terminal run status are exact. Pre-schema-8 file analysis is
    explicitly unknown, with no inferred reason/read or database migration.

    ``merge_*_shards`` coalesces identical target lifecycle objects because
    each independently executed shard owns its own target row. All other row
    multiplicity is retained, so overlapping shard work is reported.
    """

    if example_limit < 0:
        raise ValueError("example_limit must be zero or greater")
    reference = _open_states(reference_paths, check_integrity=check_integrity)
    try:
        candidate = _open_states(candidate_paths, check_integrity=check_integrity)
        try:
            categories = {"run_status": _compare_run_status(reference, candidate)}
            for name, query in (
                ("objects", OBJECT_QUERY),
                ("findings", FINDING_QUERY),
                ("exclusions", EXCLUSION_QUERY),
            ):
                categories[name] = _compare_rows(
                    _grouped_rows(
                        reference,
                        query,
                        merge_target_objects=merge_reference_shards and name == "objects",
                    ),
                    _grouped_rows(
                        candidate,
                        query,
                        merge_target_objects=merge_candidate_shards and name == "objects",
                    ),
                    example_limit=example_limit,
                )
            categories["file_analysis"] = _compare_rows(
                _grouped_file_analysis(reference),
                _grouped_file_analysis(candidate),
                example_limit=example_limit,
            )
            return SemanticComparison(categories)
        except sqlite3.Error as exc:
            raise StateComparisonError(f"Unable to compare state rows: {exc}") from exc
        finally:
            for reader in candidate:
                reader.close()
    finally:
        for reader in reference:
            reader.close()
