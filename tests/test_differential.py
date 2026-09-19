from man_spider.differential import compare_scan_states
from man_spider.lib.util import Target
from man_spider.state import FindingRecord, ScanState, smb_object_key, target_object_key
from tests.optional_fixtures import require_private_directory


def build_state(path, files, *, context_suffix="", include_target=True):
    target = Target("server.test")
    state = ScanState.create(path, {}, "test")
    if include_target:
        target_decision = state.claim_object(
            object_key=target_object_key(target),
            kind="target",
            target=str(target),
            path=str(target),
        )
        state.complete_object(target_decision.object_id, "processed")
    for filename in files:
        decision = state.claim_object(
            object_key=smb_object_key(target, "Secrets", filename),
            kind="file",
            target=str(target),
            share="Secrets",
            path=filename,
            size=12,
            mtime=100,
            file_id=f"id:{filename}",
        )
        state.complete_object(
            decision.object_id,
            "processed",
            findings=(
                FindingRecord(
                    rule_id="rule:fixture",
                    value="SECRET_VALUE",
                    start=0,
                    end=12,
                    context=f"SECRET_VALUE{context_suffix}",
                    representation="text",
                    rule_source="fixture",
                    rule_schema_version=3,
                    rule_pack_id="fixture.pack",
                    rule_pack_version="1",
                    severity="high",
                    confidence="high",
                    category="secret.fixture",
                    tags=("secret", "fixture"),
                ),
            ),
        )
    state.set_run_status("complete")
    state.close()


def test_semantic_comparison_ignores_run_ids_and_timestamps(tmp_path):
    reference = tmp_path / "reference.sqlite3"
    candidate = tmp_path / "candidate.sqlite3"
    build_state(reference, ["one.txt", "two.txt"])
    build_state(candidate, ["one.txt", "two.txt"])

    comparison = compare_scan_states([reference], [candidate])

    assert comparison.equal is True
    assert all(difference.equal for difference in comparison.categories.values())


def test_semantic_comparison_detects_context_difference_with_equal_counts(tmp_path):
    reference = tmp_path / "reference.sqlite3"
    candidate = tmp_path / "candidate.sqlite3"
    build_state(reference, ["secret.txt"])
    build_state(candidate, ["secret.txt"], context_suffix=" changed")

    comparison = compare_scan_states([reference], [candidate])

    assert comparison.equal is False
    assert comparison.categories["objects"].equal is True
    assert comparison.categories["findings"].reference_only_count == 1
    assert comparison.categories["findings"].candidate_only_count == 1


def test_shard_merge_coalesces_only_duplicate_target_lifecycle(tmp_path):
    reference = tmp_path / "reference.sqlite3"
    first = tmp_path / "first.sqlite3"
    second = tmp_path / "second.sqlite3"
    build_state(reference, ["one.txt", "two.txt"])
    build_state(first, ["one.txt"])
    build_state(second, ["two.txt"])

    unmerged = compare_scan_states([reference], [first, second])
    merged = compare_scan_states([reference], [first, second], merge_candidate_shards=True)

    assert unmerged.equal is False
    assert unmerged.categories["objects"].candidate_only_count == 1
    assert merged.equal is True


def test_comparison_cli_uses_distinct_exit_codes(tmp_path, capsys):
    require_private_directory("tools")
    from tools.compare_scan_states import main

    reference = tmp_path / "reference.sqlite3"
    equal = tmp_path / "equal.sqlite3"
    different = tmp_path / "different.sqlite3"
    build_state(reference, ["secret.txt"])
    build_state(equal, ["secret.txt"])
    build_state(different, ["secret.txt"], context_suffix=" changed")

    assert main([str(reference), str(equal)]) == 0
    assert "semantic comparison: exact" in capsys.readouterr().out
    assert main([str(reference), str(different), "--examples", "1"]) == 1
    assert "semantic comparison: DIFFERENT" in capsys.readouterr().out
