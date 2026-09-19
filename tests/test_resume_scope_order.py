import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from man_spider.cli import parse_options
from man_spider.state import ResumeMismatchError, ScanState, configuration_fingerprint, normalized_scan_configuration


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Configuration/resume compatibility must not connect or resolve targets")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.fixture
def configuration(tmp_path):
    options = parse_options(
        ["192.0.2.1", "192.0.2.2:1445", str(tmp_path), "-f", "secret", "-u", "fixture", "-p", "unused"]
    )
    result = normalized_scan_configuration(options)
    # Distinct members make every non-target array's order observable.
    for field in ("shares", "excluded_shares", "directories", "excluded_directories"):
        result["semantic"]["scope"][field] = ["one", "two"]
    for field in ("filenames", "extensions", "excluded_extensions", "content"):
        result["semantic"]["filters"][field] = ["one", "two"]
    result["semantic"]["filters"]["rules"] = [
        {"id": "one", "match": {"patterns": ["first", "second"]}},
        {"id": "two", "rule_pack_version": "1"},
    ]
    for field in ("read_formats", "skip_formats", "blocked_content_extensions"):
        result["semantic"]["policy"][field] = ["one", "two"]
    return result


def legacy_fingerprint(configuration):
    payload = json.dumps(
        configuration.get("semantic", configuration), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def create_interrupted(tmp_path, configuration):
    path = tmp_path / "state.sqlite3"
    state = ScanState.create(path, configuration, "2.0.0")
    state.set_run_status("interrupted")
    row = dict(state.run_row())
    state.close()
    assert row["config_fingerprint"] == legacy_fingerprint(configuration)
    return path, row


def reordered(configuration):
    requested = copy.deepcopy(configuration)
    requested["semantic"]["scope"]["targets"].reverse()
    return requested


def assert_resume_persisted(path, requested):
    before = copy.deepcopy(requested)
    state = ScanState.resume(path, requested, "2.0.1")
    try:
        row = dict(state.run_row())
        assert row["status"] == "running"
        assert row["scanner_version"] == "2.0.1"
        assert row["config_fingerprint"] == legacy_fingerprint(requested)
        assert row["config_fingerprint"] == configuration_fingerprint(json.loads(row["config_json"]))
        assert json.loads(row["config_json"]) == requested
        assert requested == before
        return row
    finally:
        state.close()


def assert_resume_rejected(path, requested, original_row):
    before = copy.deepcopy(requested)
    with pytest.raises(ResumeMismatchError, match="scope, filters, rules, or policy"):
        ScanState.resume(path, requested, "2.0.1")
    state = ScanState.attach(path, original_row["run_id"])
    try:
        assert dict(state.run_row()) == original_row
        assert requested == before
    finally:
        state.close()


def test_legacy_fingerprint_reordered_resume_and_repeated_restarts(tmp_path, configuration):
    original = copy.deepcopy(configuration)
    path, old_row = create_interrupted(tmp_path, configuration)
    requested = reordered(configuration)
    assert configuration_fingerprint(requested) != old_row["config_fingerprint"]
    new_row = assert_resume_persisted(path, requested)
    assert new_row["run_id"] == old_row["run_id"]
    assert new_row["created_at"] == old_row["created_at"]
    assert new_row["config_fingerprint"] != old_row["config_fingerprint"]
    assert_resume_persisted(path, requested)
    assert_resume_persisted(path, configuration)
    assert configuration == original


def test_identical_duplicate_targets_remain_compatible_when_reordered(tmp_path, configuration):
    targets = configuration["semantic"]["scope"]["targets"]
    targets.append(copy.deepcopy(targets[0]))
    path, _row = create_interrupted(tmp_path, configuration)
    assert_resume_persisted(path, reordered(configuration))


@pytest.mark.parametrize("mutation", ["remove", "duplicate", "host", "port", "kind", "path", "host_case"])
def test_reordered_resume_rejects_real_target_changes(tmp_path, configuration, mutation):
    if mutation == "host_case":
        for target in configuration["semantic"]["scope"]["targets"]:
            if target["kind"] == "smb":
                target["host"] = "example.invalid"
    path, row = create_interrupted(tmp_path, configuration)
    requested = reordered(configuration)
    targets = requested["semantic"]["scope"]["targets"]
    smb = next(target for target in targets if target["kind"] == "smb")
    local = next(target for target in targets if target["kind"] == "local")
    if mutation == "remove":
        targets.pop()
    elif mutation == "duplicate":
        targets.append(copy.deepcopy(targets[0]))
    elif mutation == "host":
        smb["host"] = "192.0.2.99"
    elif mutation == "host_case":
        smb["host"] = "EXAMPLE.invalid"
    elif mutation == "port":
        smb["port"] += 1
    elif mutation == "kind":
        smb["kind"] = "local"
    elif mutation == "path":
        local["path"] += "-different"
    assert_resume_rejected(path, requested, row)


@pytest.mark.parametrize(
    "section, field",
    [
        ("scope", "shares"),
        ("scope", "excluded_shares"),
        ("scope", "directories"),
        ("scope", "excluded_directories"),
        ("filters", "filenames"),
        ("filters", "extensions"),
        ("filters", "excluded_extensions"),
        ("filters", "content"),
        ("filters", "rules"),
        ("policy", "read_formats"),
        ("policy", "skip_formats"),
        ("policy", "blocked_content_extensions"),
    ],
)
@pytest.mark.parametrize("mutation", ["reverse", "append"])
def test_reordered_resume_preserves_all_other_ordered_arrays(tmp_path, configuration, section, field, mutation):
    path, row = create_interrupted(tmp_path, configuration)
    requested = reordered(configuration)
    values = requested["semantic"][section][field]
    if mutation == "reverse":
        values.reverse()
    else:
        values.append(copy.deepcopy(values[0]))
    assert_resume_rejected(path, requested, row)


@pytest.mark.parametrize(
    "section, field, replacement",
    [
        ("filters", "modified_after", "2026-01-01T00:00:00"),
        ("filters", "modified_before", "2026-01-01T00:00:00"),
        ("filters", "logic", "OR"),
        ("policy", "content_format_resolution", "different"),
        ("policy", "maxdepth", 99),
        ("policy", "max_filesize", 1024),
        ("policy", "download_matches", True),
        ("policy", "allow_external_dfs", True),
        ("policy", "object_retries", 99),
        ("policy", "large_domain_mode", "different"),
        ("policy", "large_domain_target_threshold", 99),
        ("policy", "large_domain_share_threshold", 99),
        ("policy", "effective_large_domain", True),
        ("policy", "scope_estimate", {"shares": 2}),
        ("policy", "non_text_policy", "different"),
    ],
)
def test_reordered_resume_rejects_other_semantic_changes(tmp_path, configuration, section, field, replacement):
    assert configuration["semantic"][section][field] != replacement
    path, row = create_interrupted(tmp_path, configuration)
    requested = reordered(configuration)
    requested["semantic"][section][field] = replacement
    assert_resume_rejected(path, requested, row)


@pytest.mark.parametrize("mutation", ["pattern_order", "pack_version", "new_semantic_field"])
def test_reordered_resume_does_not_hide_nested_or_new_semantic_changes(tmp_path, configuration, mutation):
    path, row = create_interrupted(tmp_path, configuration)
    requested = reordered(configuration)
    if mutation == "pattern_order":
        requested["semantic"]["filters"]["rules"][0]["match"]["patterns"].reverse()
    elif mutation == "pack_version":
        requested["semantic"]["filters"]["rules"][1]["rule_pack_version"] = "2"
    else:
        requested["semantic"]["future_policy"] = ["one", "two"]
    assert_resume_rejected(path, requested, row)


def test_reordered_resume_does_not_equate_boolean_and_integer(tmp_path, configuration):
    configuration["semantic"]["policy"]["maxdepth"] = 1
    path, row = create_interrupted(tmp_path, configuration)
    requested = reordered(configuration)
    requested["semantic"]["policy"]["maxdepth"] = True
    assert_resume_rejected(path, requested, row)


@pytest.mark.parametrize(
    "section, field, replacement",
    [
        ("authentication", "password", "replacement-unused"),
        ("authentication", "username", "different"),
        ("authentication", "domain", "different.invalid"),
        ("authentication", "hash", "unused-hash"),
        ("execution", "threads", 1),
        ("execution", "resume_strategy", "refresh"),
        ("execution", "rule_files", ["different-local-path"]),
    ],
)
def test_reordered_resume_retains_existing_nonsemantic_change_policy(
    tmp_path, configuration, section, field, replacement
):
    path, _row = create_interrupted(tmp_path, configuration)
    requested = reordered(configuration)
    requested[section][field] = replacement
    assert_resume_persisted(path, requested)
    assert_resume_persisted(path, requested)


def test_inconsistent_stored_fingerprint_cannot_use_target_order_fallback(tmp_path, configuration):
    path, row = create_interrupted(tmp_path, configuration)
    state = ScanState.attach(path, row["run_id"])
    try:
        state.connection.execute("UPDATE runs SET config_fingerprint=?", ("0" * 64,))
        inconsistent = dict(state.run_row())
    finally:
        state.close()
    assert_resume_rejected(path, reordered(configuration), inconsistent)


def test_download_policy_mismatch_still_explains_required_flag(tmp_path, configuration):
    configuration["semantic"]["policy"]["download_matches"] = True
    path, _row = create_interrupted(tmp_path, configuration)
    requested = reordered(configuration)
    requested["semantic"]["policy"]["download_matches"] = False
    with pytest.raises(ResumeMismatchError, match="--download is now required"):
        ScanState.resume(path, requested, "2.0.0")


def test_bare_semantic_legacy_configuration_supports_order_only_resume(tmp_path, configuration):
    bare = configuration["semantic"]
    path, _row = create_interrupted(tmp_path, bare)
    requested = copy.deepcopy(bare)
    requested["scope"]["targets"].reverse()
    assert_resume_persisted(path, requested)


def test_resume_never_changes_actual_target_objects_or_queue_order(tmp_path):
    options = parse_options(["192.0.2.0/29", str(tmp_path), "-f", "secret", "-u", "fixture", "-p", "unused"])
    original_targets = tuple(options.targets)
    original_ids = tuple(map(id, options.targets))
    configuration = normalized_scan_configuration(options)
    path, _row = create_interrupted(tmp_path, configuration)
    options.targets.reverse()
    expected_targets = tuple(options.targets)
    expected_ids = tuple(map(id, options.targets))
    assert_resume_persisted(path, normalized_scan_configuration(options))
    assert tuple(options.targets) == expected_targets == original_targets[::-1]
    assert tuple(map(id, options.targets)) == expected_ids == original_ids[::-1]


def test_same_cidr_across_python_hash_seeds_resumes_without_network(tmp_path):
    script = (
        "import json, sys; "
        "sys.addaudithook(lambda event, args: "
        "(_ for _ in ()).throw(AssertionError('Unexpected network access')) "
        "if event in ('socket.connect', 'socket.getaddrinfo', 'socket.gethostbyname') else None); "
        "from man_spider.cli import parse_options; "
        "from man_spider.state import normalized_scan_configuration; "
        "print(json.dumps(normalized_scan_configuration(parse_options("
        "['192.0.2.0/29', '-f', 'secret', '-u', 'fixture', '-p', 'unused']))))"
    )
    configurations = []
    for seed in (1, 2, 3):
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            env=dict(os.environ, PYTHONHASHSEED=str(seed)),
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        configurations.append(json.loads(completed.stdout))
    orders = [configuration["semantic"]["scope"]["targets"] for configuration in configurations]
    assert any(order != orders[0] for order in orders[1:])
    assert len({configuration_fingerprint(configuration) for configuration in configurations}) > 1
    path, _row = create_interrupted(tmp_path, configurations[0])
    for configuration in configurations[1:] + configurations:
        assert_resume_persisted(path, configuration)
