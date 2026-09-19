import hashlib
import sqlite3
from contextlib import closing
from types import SimpleNamespace

import pytest

from man_spider.differential import StateComparisonError, _grouped_file_analysis, compare_scan_states
from man_spider.lib.util import Target
from man_spider.state import ScanState, smb_object_key, target_object_key
from tests.optional_fixtures import require_private_directory


UNKNOWN = ("unknown", None, None)
ANALYZED = ("analyzed", "content_checked", 1)
ANALYSIS_COLUMNS = ("analysis_status", "analysis_reason", "analysis_read")


def build_state(path, evidence=UNKNOWN, *, filenames=("secret.txt",), nonfile_evidence=UNKNOWN):
    target = Target("server.test")
    with closing(ScanState.create(path, {}, "test")) as state:
        decision = state.claim_object(
            object_key=target_object_key(target), kind="target", target=str(target), path=str(target)
        )
        state.complete_object(
            decision.object_id,
            "processed",
            analysis_status=nonfile_evidence[0],
            analysis_reason=nonfile_evidence[1],
            analysis_read=nonfile_evidence[2],
        )
        for filename in filenames:
            decision = state.claim_object(
                object_key=smb_object_key(target, "Secrets", filename),
                kind="file",
                target=str(target),
                share="Secrets",
                path=filename,
                size=12,
                mtime=100,
            )
            state.complete_object(
                decision.object_id,
                "processed",
                analysis_status=evidence[0],
                analysis_reason=evidence[1],
                analysis_read=evidence[2],
            )
        state.set_run_status("complete")


def make_legacy(path, version, *, remove_columns=True):
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE runs SET schema_version=?", (version,))
        if remove_columns:
            for name in ANALYSIS_COLUMNS:
                connection.execute(f"ALTER TABLE objects DROP COLUMN {name}")


def snapshot(path):
    return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns


@pytest.mark.parametrize(
    "evidence",
    [
        UNKNOWN,
        ("unknown", "unavailable", None),
        ("not_analyzed", "metadata_only", 0),
        ("partial", "parser_error", 1),
        ANALYZED,
        ("analyzed", "reason\0suffix", 1),
    ],
)
def test_same_file_analysis_is_exact(tmp_path, evidence):
    reference, candidate = tmp_path / "reference.sqlite3", tmp_path / "candidate.sqlite3"
    build_state(reference, evidence)
    build_state(candidate, evidence)
    comparison = compare_scan_states([reference], [candidate])
    assert comparison.equal
    assert comparison.categories["file_analysis"].reference_total == 1
    assert comparison.categories["file_analysis"].candidate_total == 1


@pytest.mark.parametrize(
    "reference_evidence,candidate_evidence",
    [
        (UNKNOWN, ("not_analyzed", None, None)),
        (("partial", None, 1), ("analyzed", None, 1)),
        (ANALYZED, ("analyzed", "parser_checked", 1)),
        (UNKNOWN, ("unknown", "", None)),
        (("partial", "reason\0first", 1), ("partial", "reason\0second", 1)),
        (UNKNOWN, ("unknown", None, 0)),
        (("partial", None, 0), ("partial", None, 1)),
        (("analyzed", "content_checked", None), ANALYZED),
    ],
)
def test_each_analysis_field_is_compared_exactly(tmp_path, reference_evidence, candidate_evidence):
    reference, candidate = tmp_path / "reference.sqlite3", tmp_path / "candidate.sqlite3"
    build_state(reference, reference_evidence)
    build_state(candidate, candidate_evidence)
    comparison = compare_scan_states([reference], [candidate])
    assert not comparison.equal
    assert all(result.equal for name, result in comparison.categories.items() if name != "file_analysis")
    difference = comparison.categories["file_analysis"]
    assert difference.reference_only_count == difference.candidate_only_count == 1
    assert next(iter(difference.reference_only))[-3:] == reference_evidence
    assert next(iter(difference.candidate_only))[-3:] == candidate_evidence


def test_analysis_category_contains_only_files(tmp_path):
    reference, candidate = tmp_path / "reference.sqlite3", tmp_path / "candidate.sqlite3"
    build_state(reference, filenames=(), nonfile_evidence=UNKNOWN)
    build_state(candidate, filenames=(), nonfile_evidence=ANALYZED)
    comparison = compare_scan_states([reference], [candidate])
    assert comparison.equal
    assert comparison.categories["file_analysis"].reference_total == 0
    assert comparison.categories["file_analysis"].candidate_total == 0


@pytest.mark.parametrize("version", range(2, 8))
@pytest.mark.parametrize("remove_columns", [False, True])
def test_legacy_analysis_maps_to_unknown_without_migration(tmp_path, version, remove_columns):
    legacy, current = tmp_path / "legacy.sqlite3", tmp_path / "current.sqlite3"
    build_state(legacy, ANALYZED)
    make_legacy(legacy, version, remove_columns=remove_columns)
    build_state(current, UNKNOWN)
    before = snapshot(legacy), snapshot(current)
    assert compare_scan_states([legacy], [current]).equal
    assert compare_scan_states([current], [legacy]).equal
    assert before == (snapshot(legacy), snapshot(current))
    with sqlite3.connect(f"file:{legacy}?mode=ro", uri=True) as connection:
        assert connection.execute("SELECT schema_version FROM runs").fetchone()[0] == version
        columns = {row[1] for row in connection.execute("PRAGMA table_info(objects)")}
        assert ("analysis_status" not in columns) is remove_columns


@pytest.mark.parametrize("version", range(2, 8))
def test_legacy_analysis_is_not_equal_to_known_evidence(tmp_path, version):
    legacy, current = tmp_path / "legacy.sqlite3", tmp_path / "current.sqlite3"
    build_state(legacy)
    make_legacy(legacy, version)
    build_state(current, ANALYZED)
    comparison = compare_scan_states([legacy], [current])
    assert not comparison.equal
    difference = comparison.categories["file_analysis"]
    assert next(iter(difference.reference_only))[-3:] == UNKNOWN
    assert next(iter(difference.candidate_only))[-3:] == ANALYZED


@pytest.mark.parametrize("column", ANALYSIS_COLUMNS)
@pytest.mark.parametrize("check_integrity", [False, True])
def test_schema8_missing_analysis_column_fails_even_without_files(tmp_path, column, check_integrity):
    malformed, valid = tmp_path / "malformed.sqlite3", tmp_path / "valid.sqlite3"
    build_state(malformed, filenames=())
    build_state(valid, filenames=())
    with sqlite3.connect(malformed) as connection:
        connection.execute(f"ALTER TABLE objects DROP COLUMN {column}")
    before = snapshot(malformed)
    with pytest.raises(StateComparisonError, match=f"missing required column: {column}"):
        compare_scan_states([valid], [malformed], check_integrity=check_integrity)
    assert snapshot(malformed) == before


@pytest.mark.parametrize(
    "column,declaration",
    [
        ("analysis_status", "INTEGER NOT NULL DEFAULT 0"),
        ("analysis_status", "TEXT"),
        ("analysis_reason", "BLOB"),
        ("analysis_read", "TEXT"),
    ],
)
def test_schema8_malformed_analysis_declaration_is_explicit_error(tmp_path, column, declaration):
    malformed, valid = tmp_path / "malformed.sqlite3", tmp_path / "valid.sqlite3"
    build_state(malformed)
    build_state(valid)
    with sqlite3.connect(malformed) as connection:
        connection.execute(f"ALTER TABLE objects RENAME COLUMN {column} TO old_{column}")
        connection.execute(f"ALTER TABLE objects ADD COLUMN {column} {declaration}")
    with pytest.raises(StateComparisonError, match=f"malformed analysis column: {column}"):
        compare_scan_states([valid], [malformed])


@pytest.mark.parametrize(
    "column,value",
    [
        ("analysis_status", "complete"),
        ("analysis_status", b"analyzed"),
        ("analysis_reason", b"content_checked"),
        ("analysis_read", 2),
        ("analysis_read", "yes"),
        ("analysis_read", b"1"),
    ],
)
def test_schema8_invalid_analysis_value_is_not_silently_compared(tmp_path, column, value):
    malformed, valid = tmp_path / "malformed.sqlite3", tmp_path / "valid.sqlite3"
    build_state(malformed)
    build_state(valid)
    with sqlite3.connect(malformed) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(f"UPDATE objects SET {column}=? WHERE kind='file'", (value,))
    before = snapshot(malformed)
    with pytest.raises(StateComparisonError, match="malformed file analysis evidence"):
        compare_scan_states([valid], [malformed], check_integrity=False)
    assert snapshot(malformed) == before


@pytest.mark.parametrize("version", [1, 10, -1, 8.5, "future"])
def test_unsupported_schema_is_not_guessed(tmp_path, version):
    malformed, valid = tmp_path / "malformed.sqlite3", tmp_path / "valid.sqlite3"
    build_state(malformed)
    build_state(valid)
    with sqlite3.connect(malformed) as connection:
        connection.execute("UPDATE runs SET schema_version=?", (version,))
    with pytest.raises(StateComparisonError, match="unsupported schema version"):
        compare_scan_states([valid], [malformed])


def test_schema_without_version_is_explicit_error(tmp_path):
    malformed, valid = tmp_path / "malformed.sqlite3", tmp_path / "valid.sqlite3"
    build_state(malformed)
    build_state(valid)
    with sqlite3.connect(malformed) as connection:
        connection.execute("ALTER TABLE runs DROP COLUMN schema_version")
    with pytest.raises(StateComparisonError, match="schema_version"):
        compare_scan_states([valid], [malformed])


@pytest.mark.parametrize("side", ["reference", "candidate"])
def test_analysis_does_not_coalesce_overlapping_shard_files(tmp_path, side):
    reference, first, second = (tmp_path / name for name in ("reference.sqlite3", "first.sqlite3", "second.sqlite3"))
    build_state(reference, ANALYZED)
    build_state(first, ANALYZED)
    build_state(second, ANALYZED)
    if side == "candidate":
        comparison = compare_scan_states([reference], [first, second], merge_candidate_shards=True)
    else:
        comparison = compare_scan_states([first, second], [reference], merge_reference_shards=True)
    assert not comparison.equal
    difference = comparison.categories["file_analysis"]
    assert getattr(difference, f"{side}_total") == 2
    assert getattr(difference, f"{side}_only_count") == 1
    assert len(getattr(difference, f"{side}_only")) == 1


@pytest.mark.parametrize("side", ["reference", "candidate"])
def test_analysis_merges_disjoint_legacy_and_current_shards(tmp_path, side):
    reference, first, second = (tmp_path / name for name in ("reference.sqlite3", "first.sqlite3", "second.sqlite3"))
    build_state(reference, filenames=("one.txt", "two.txt"))
    build_state(first, filenames=("one.txt",))
    build_state(second, filenames=("two.txt",))
    make_legacy(first, 7)
    if side == "candidate":
        comparison = compare_scan_states([reference], [first, second], merge_candidate_shards=True)
    else:
        comparison = compare_scan_states([first, second], [reference], merge_reference_shards=True)
    assert comparison.equal
    assert comparison.categories["file_analysis"].reference_total == 2
    assert comparison.categories["file_analysis"].candidate_total == 2


@pytest.mark.parametrize("side", ["reference", "candidate"])
def test_shard_merge_retains_duplicate_target_exclusions(tmp_path, side):
    reference, first, second = (tmp_path / name for name in ("reference.sqlite3", "first.sqlite3", "second.sqlite3"))
    for path in (reference, first, second):
        build_state(path, filenames=())
        with sqlite3.connect(path) as connection:
            connection.execute(
                """
                INSERT INTO exclusions(run_id, object_key, kind, reason, first_seen_at, last_seen_at)
                SELECT run_id, 'excluded-target', 'target', 'scope_policy', 'start', 'end' FROM runs
                """
            )
    if side == "candidate":
        comparison = compare_scan_states([reference], [first, second], merge_candidate_shards=True)
    else:
        comparison = compare_scan_states([first, second], [reference], merge_reference_shards=True)
    assert comparison.categories["objects"].equal
    assert not comparison.equal
    assert getattr(comparison.categories["exclusions"], f"{side}_only_count") == 1


@pytest.mark.parametrize("example_limit", [0, 1, 3])
def test_analysis_mismatch_examples_remain_bounded(tmp_path, example_limit):
    reference, candidate = tmp_path / "reference.sqlite3", tmp_path / "candidate.sqlite3"
    filenames = tuple(f"secret-{index:04d}.txt" for index in range(64))
    build_state(reference, UNKNOWN, filenames=filenames)
    build_state(candidate, ANALYZED, filenames=filenames)
    comparison = compare_scan_states([reference], [candidate], example_limit=example_limit)
    difference = comparison.categories["file_analysis"]
    assert difference.reference_only_count == difference.candidate_only_count == 64
    assert len(difference.reference_only) == len(difference.candidate_only) == example_limit


def test_analysis_merge_does_not_materialize_file_streams():
    consumed = [0, 0]

    class StreamingConnection:
        def __init__(self, index):
            self.index = index

        def execute(self, _query, _parameters):
            for number in range(100_000):
                consumed[self.index] += 1
                key = f"{number * 2 + self.index:07d}"
                yield (key, "server", "Secrets", f"{key}.txt", *ANALYZED)

    readers = [
        SimpleNamespace(schema_version=8, connection=StreamingConnection(index), run_id="run", path=f"shard-{index}")
        for index in range(2)
    ]
    rows = _grouped_file_analysis(readers)
    assert next(rows)[0][0] == "0000000"
    assert next(rows)[0][0] == "0000001"
    assert 0 < max(consumed) < 10
    rows.close()


def test_sqlite_projection_error_is_comparison_error_not_traceback(tmp_path, capsys):
    require_private_directory("tools")
    from tools.compare_scan_states import main

    malformed, valid = tmp_path / "malformed.sqlite3", tmp_path / "valid.sqlite3"
    build_state(malformed)
    build_state(valid)
    with sqlite3.connect(malformed) as connection:
        connection.execute("ALTER TABLE findings DROP COLUMN rule_pack_version")
    assert main([str(valid), str(malformed)]) == 2
    output = capsys.readouterr()
    assert "State comparison failed:" in output.err
    assert "rule_pack_version" in output.err
    assert "semantic comparison: exact" not in output.out


def test_cli_analysis_mismatch_and_corrupt_schema_have_distinct_exit_codes(tmp_path, capsys):
    require_private_directory("tools")
    from tools.compare_scan_states import main

    reference, candidate = tmp_path / "reference.sqlite3", tmp_path / "candidate.sqlite3"
    build_state(reference, UNKNOWN)
    build_state(candidate, ANALYZED)
    before = snapshot(reference), snapshot(candidate)
    assert main([str(reference), str(reference)]) == 0
    assert "file_analysis: equal" in capsys.readouterr().out
    assert main([str(reference), str(candidate), "--examples", "0"]) == 1
    output = capsys.readouterr().out
    assert "file_analysis: DIFFERENT" in output
    assert "semantic comparison: DIFFERENT" in output
    assert before == (snapshot(reference), snapshot(candidate))
    with sqlite3.connect(candidate) as connection:
        connection.execute("ALTER TABLE objects DROP COLUMN analysis_read")
    assert main([str(reference), str(candidate)]) == 2
    output = capsys.readouterr()
    assert "analysis_read" in output.err
    assert "semantic comparison: exact" not in output.out
