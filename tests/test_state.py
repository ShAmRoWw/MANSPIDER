import json
import secrets
import sqlite3
import stat
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from man_spider.state import (
    SCHEMA_VERSION,
    FindingRecord,
    ResumeMismatchError,
    ScanLease,
    ScanState,
    StateError,
    StateExistsError,
    local_object_key,
    normalized_scan_configuration,
    smb_object_key,
)
from man_spider.lib.util import Target


def scan_options(tmp_path, **overrides):
    values = {
        "targets": [tmp_path],
        "sharenames": [],
        "exclude_sharenames": ["ipc$", "c$", "admin$", "print$"],
        "dirnames": [],
        "exclude_dirnames": [],
        "filenames": ["secret"],
        "extensions": [".txt"],
        "exclude_extensions": [],
        "content": ["Password"],
        "modified_after": datetime(2026, 1, 1),
        "modified_before": None,
        "or_logic": False,
        "maxdepth": 10,
        "max_filesize": 10 * 1024 * 1024,
        "no_download": False,
        "username": "runuser",
        "password": "FixturePassword123!",
        "domain": "test.local",
        "hash": "",
        "kerberos": False,
        "aes_key": None,
        "dc_ip": None,
        "max_failed_logons": None,
        "threads": 5,
        "quiet": False,
        "verbose": False,
        "loot_dir": str(tmp_path / "loot"),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def create_state(tmp_path, **overrides):
    options = scan_options(tmp_path, **overrides)
    configuration = normalized_scan_configuration(options)
    state = ScanState.create(tmp_path / "scan.sqlite3", configuration, "2.0.0")
    return state, configuration


def test_create_persists_full_unmasked_configuration_in_private_state_file(tmp_path):
    state, _configuration = create_state(tmp_path)
    row = state.run_row()
    persisted = json.loads(row["config_json"])

    assert persisted["authentication"]["password"] == "FixturePassword123!"
    assert persisted["authentication"]["username"] == "runuser"
    assert stat.S_IMODE(state.path.stat().st_mode) == 0o600
    assert row["status"] == "running"
    state.close()


def test_new_state_directories_are_private_without_changing_existing_parent(tmp_path):
    existing_mode = stat.S_IMODE(tmp_path.stat().st_mode)
    options = scan_options(tmp_path)
    state = ScanState.create(
        tmp_path / "new" / "nested" / "scan.sqlite3",
        normalized_scan_configuration(options),
        "2.0.0",
    )

    assert stat.S_IMODE((tmp_path / "new").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "new" / "nested").stat().st_mode) == 0o700
    assert stat.S_IMODE(tmp_path.stat().st_mode) == existing_mode
    state.close()


def test_new_scan_never_overwrites_an_existing_database(tmp_path):
    state, configuration = create_state(tmp_path)
    state.close()

    with pytest.raises(StateExistsError):
        ScanState.create(tmp_path / "scan.sqlite3", configuration, "2.0.0")


def test_state_uses_memory_for_sqlite_temporary_storage(tmp_path):
    state, _configuration = create_state(tmp_path)
    assert state.connection.execute("PRAGMA temp_store").fetchone()[0] == 2
    state.close()


def test_state_rejects_shared_nonsticky_ancestor_before_creating_database(tmp_path):
    shared = Path("/tmp") / f"manspider-state-untrusted-{secrets.token_hex(12)}"
    private = shared / "private"
    configuration = normalized_scan_configuration(scan_options(tmp_path))
    try:
        shared.mkdir(mode=0o700)
        private.mkdir(mode=0o700)
        shared.chmod(0o777)

        with pytest.raises(StateError, match="ancestor is writable"):
            ScanState.create(private / "scan.sqlite3", configuration, "2.0.0")

        assert not (private / "scan.sqlite3").exists()
    finally:
        shared.chmod(0o700)
        private.rmdir()
        shared.rmdir()


@pytest.mark.parametrize("suffix", ("-journal", "-wal", "-shm"))
def test_new_state_rejects_sqlite_sidecar_symlink_without_touching_target(tmp_path, suffix):
    state_path = tmp_path / "scan.sqlite3"
    protected = tmp_path / "protected.bin"
    protected.write_bytes(b"UNCHANGED")
    state_path.with_name(f"{state_path.name}{suffix}").symlink_to(protected)
    configuration = normalized_scan_configuration(scan_options(tmp_path))

    with pytest.raises(StateError, match="sidecar already exists"):
        ScanState.create(state_path, configuration, "2.0.0")

    assert protected.read_bytes() == b"UNCHANGED"
    assert not state_path.exists()


@pytest.mark.parametrize("initially_allowed", [False, True])
def test_external_dfs_policy_cannot_change_silently_on_resume(tmp_path, initially_allowed):
    state, configuration = create_state(tmp_path, allow_external_dfs=initially_allowed)
    assert configuration["semantic"]["policy"]["allow_external_dfs"] is initially_allowed
    state.close()
    changed = normalized_scan_configuration(scan_options(tmp_path, allow_external_dfs=not initially_allowed))

    with pytest.raises(ResumeMismatchError):
        ScanState.resume(tmp_path / "scan.sqlite3", changed, "2.0.0")


def test_processed_unchanged_object_is_not_read_again_on_resume(tmp_path):
    state, configuration = create_state(tmp_path)
    decision = state.register_object(
        object_key="file|local|secret.txt",
        kind="file",
        path="secret.txt",
        size=12,
        mtime=100,
    )
    state.begin_object(decision.object_id)
    state.complete_object(
        decision.object_id,
        "processed",
        findings=[FindingRecord("content:Password", "Password", 0, 8, "Password")],
    )
    finding_id = state.findings_for(decision.object_id)[0]["finding_id"]
    state.set_run_status("interrupted")
    state.close()

    resumed = ScanState.resume(tmp_path / "scan.sqlite3", configuration, "2.0.0")
    unchanged = resumed.register_object(
        object_key="file|local|secret.txt",
        kind="file",
        path="secret.txt",
        size=12,
        mtime=100,
    )

    assert unchanged.should_process is False
    assert unchanged.prior_status == "processed"
    assert resumed.findings_for(unchanged.object_id)[0]["finding_id"] == finding_id
    resumed.close()


def test_changed_object_is_reprocessed_and_old_findings_are_removed(tmp_path):
    state, _configuration = create_state(tmp_path)
    decision = state.register_object(object_key="file|one", kind="file", size=10, mtime=100)
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "processed", findings=[FindingRecord("rule", "old", 1, 4)])

    changed = state.register_object(object_key="file|one", kind="file", size=11, mtime=101)

    assert changed.should_process is True
    assert changed.changed is True
    assert changed.prior_status == "processed"
    assert state.object_row(changed.object_id)["status"] == "pending"
    assert state.findings_for(changed.object_id) == []
    state.begin_object(changed.object_id)
    state.complete_object(changed.object_id, "processed", changed=False)
    assert state.object_row(changed.object_id)["changed"] == 1
    state.close()


def test_completed_changed_read_accepts_post_read_identity_for_resume(tmp_path):
    state, configuration = create_state(tmp_path)
    decision = state.register_object(
        object_key="file|accepted-change",
        kind="file",
        size=10,
        mtime=100,
        file_id="file-id",
    )
    state.begin_object(decision.object_id)
    finding = FindingRecord("content:secret", "FIRST_SECRET", 0, 12, "FIRST_SECRET")
    state.complete_object(
        decision.object_id,
        "processed",
        changed=True,
        findings=[finding],
        post_read_identity=(12, 101, "file-id"),
    )
    finding_id = state.findings_for(decision.object_id)[0]["finding_id"]
    state.set_run_status("interrupted")
    state.close()

    resumed = ScanState.resume(tmp_path / "scan.sqlite3", configuration, "2.0.0")
    accepted = resumed.register_object(
        object_key="file|accepted-change",
        kind="file",
        size=12,
        mtime=101,
        file_id="file-id",
    )

    assert accepted.should_process is False
    assert accepted.changed is True
    assert accepted.prior_status == "processed"
    assert resumed.object_row(accepted.object_id)["attempts"] == 1
    assert resumed.findings_for(accepted.object_id)[0]["finding_id"] == finding_id

    changed_again = resumed.register_object(
        object_key="file|accepted-change",
        kind="file",
        size=13,
        mtime=102,
        file_id="file-id",
    )
    assert changed_again.should_process is True
    assert resumed.findings_for(changed_again.object_id) == []
    resumed.close()


def test_in_progress_object_is_reprocessed_from_the_beginning(tmp_path):
    state, configuration = create_state(tmp_path)
    decision = state.register_object(object_key="file|one", kind="file", size=10, mtime=100)
    state.begin_object(decision.object_id)
    state.close()

    resumed = ScanState.resume(tmp_path / "scan.sqlite3", configuration, "2.0.0")
    repeated = resumed.register_object(object_key="file|one", kind="file", size=10, mtime=100)
    assert repeated.should_process is True
    assert repeated.prior_status == "in_progress"
    resumed.close()


def test_claim_object_rolls_back_manifest_counters_and_attempt_together(monkeypatch, tmp_path):
    state, _configuration = create_state(tmp_path)

    def fail_begin(_object_id, _now):
        raise StateError("simulated durable begin failure")

    monkeypatch.setattr(state, "_begin_object", fail_begin)
    with pytest.raises(StateError, match="simulated durable begin failure"):
        state.claim_object(
            object_key="file|atomic",
            kind="file",
            path="atomic.txt",
            discovery_counter="files_discovered",
        )

    assert state.connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
    assert state.connection.execute("SELECT COUNT(*) FROM counters WHERE name<>'data_revision'").fetchone()[0] == 0
    assert state.connection.execute("SELECT value FROM counters WHERE name='data_revision'").fetchone()[0] == 0
    state.close()


def test_skipped_object_is_not_reconsidered_with_unchanged_policy(tmp_path):
    state, _configuration = create_state(tmp_path)
    decision = state.register_object(object_key="file|one", kind="file", size=10, mtime=100)
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "skipped", reason="format policy")

    repeated = state.register_object(object_key="file|one", kind="file", size=10, mtime=100)
    assert repeated.should_process is False
    assert repeated.prior_status == "skipped"
    state.close()


def test_error_retry_obeys_retry_limit(tmp_path):
    state, _configuration = create_state(tmp_path)
    decision = state.register_object(object_key="file|one", kind="file", size=10, mtime=100, retry_limit=2)
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "error", reason="temporary")

    retry = state.register_object(object_key="file|one", kind="file", size=10, mtime=100, retry_limit=2)
    assert retry.should_process is True
    state.begin_object(retry.object_id)
    state.complete_object(retry.object_id, "error", reason="permanent")
    exhausted = state.register_object(object_key="file|one", kind="file", size=10, mtime=100, retry_limit=2)
    assert exhausted.should_process is False
    state.close()


def test_findings_and_processed_status_are_committed_atomically(tmp_path):
    state, _configuration = create_state(tmp_path)
    decision = state.register_object(object_key="file|one", kind="file", size=10, mtime=100)
    state.begin_object(decision.object_id)
    duplicate = FindingRecord("rule", "same", 1, 5)

    with pytest.raises(StateError, match="Persistent-state transaction failed") as failure:
        state.complete_object(
            decision.object_id,
            "processed",
            findings=[duplicate, duplicate],
            checkpoint_name="target:one",
            checkpoint_value={"path": "one"},
        )
    assert isinstance(failure.value.__cause__, sqlite3.IntegrityError)

    assert state.object_row(decision.object_id)["status"] == "in_progress"
    assert state.findings_for(decision.object_id) == []
    assert state.get_checkpoint("target:one") is None
    state.close()


def test_transaction_rolls_back_on_base_exception(tmp_path):
    state, _configuration = create_state(tmp_path)

    with pytest.raises(KeyboardInterrupt):
        with state.transaction():
            state.connection.execute(
                "INSERT INTO counters(run_id, name, value) VALUES (?, 'interrupted-write', 1)",
                (state.run_id,),
            )
            raise KeyboardInterrupt

    assert state.connection.execute("SELECT COUNT(*) FROM counters WHERE name<>'data_revision'").fetchone()[0] == 0
    assert state.connection.execute("SELECT value FROM counters WHERE name='data_revision'").fetchone()[0] == 0
    state.close()


def test_scan_lease_prevents_concurrent_writer_and_releases_cleanly(tmp_path):
    state_path = tmp_path / "nested" / "scan.sqlite3"
    first = ScanLease.acquire(state_path)
    try:
        assert first.lock_path.is_file()
        assert stat.S_IMODE(first.lock_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(first.lock_path.parent.stat().st_mode) == 0o700
        with pytest.raises(StateError, match="already in use or cannot be locked"):
            ScanLease.acquire(state_path)
    finally:
        first.release()

    second = ScanLease.acquire(state_path)
    second.release()


def test_scan_lease_never_follows_a_preplanted_lock_symlink(tmp_path):
    state_path = tmp_path / "scan.sqlite3"
    protected = tmp_path / "protected.bin"
    protected.write_bytes(b"UNCHANGED")
    lock_path = state_path.with_name(f"{state_path.name}.lock")
    lock_path.symlink_to(protected)

    with pytest.raises(StateError, match="symlink component|Unable to prepare scan-state lease"):
        ScanLease.acquire(state_path)

    assert protected.read_bytes() == b"UNCHANGED"


def test_finding_identity_is_stable_and_not_duplicated(tmp_path):
    state, _configuration = create_state(tmp_path)
    decision = state.register_object(object_key="file|one", kind="file", size=10, mtime=100)
    finding = FindingRecord("rule", "same", 1, 5)
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "processed", findings=[finding])
    first_id = state.findings_for(decision.object_id)[0]["finding_id"]

    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "processed", findings=[finding])
    rows = state.findings_for(decision.object_id)
    assert len(rows) == 1
    assert rows[0]["finding_id"] == first_id
    state.close()


def test_structural_equal_values_at_distinct_pointers_survive_reprocessing(tmp_path):
    state, _configuration = create_state(tmp_path)
    decision = state.register_object(object_key="file|secret", kind="file", path="secret.json")
    findings = [
        FindingRecord(
            "rule:kubernetes-secret-json",
            "SameSecret!",
            0,
            200,
            json.dumps({"pointer": pointer}),
            representation="inspect:kubernetes-secret-json",
        )
        for pointer in ("/items/0/data/password", "/items/1/data/password", "/items/1/stringData/other")
    ]
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "processed", findings=findings)
    rows = state.findings_for(decision.object_id)
    ids = {row["finding_id"] for row in rows}
    assert len(ids) == 3
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "processed", findings=reversed(findings))
    assert {row["finding_id"] for row in state.findings_for(decision.object_id)} == ids
    assert {(row["value"], row["context"]) for row in state.report_findings()} == {
        (row["value"], row["context"]) for row in rows
    }
    state.close()


def test_finding_rule_provenance_is_persisted_without_masking(tmp_path):
    state, _configuration = create_state(tmp_path)
    decision = state.register_object(object_key="file|provenance", kind="file", path="secret.conf")
    state.begin_object(decision.object_id)
    state.complete_object(
        decision.object_id,
        "processed",
        findings=[
            FindingRecord(
                "rule:credential",
                "SECRET_VALUE",
                4,
                16,
                "key=SECRET_VALUE",
                representation="text",
                rule_source="/rules/custom.json",
                rule_schema_version=2,
                rule_pack_id="custom.credentials",
                rule_pack_version="3.1.4",
                severity="critical",
                confidence="high",
                category="credential.password",
                tags=("configuration", "database"),
            )
        ],
    )

    row = state.findings_for(decision.object_id)[0]
    assert row["representation"] == "text"
    assert row["rule_source"] == "/rules/custom.json"
    assert row["rule_schema_version"] == 2
    assert row["rule_pack_id"] == "custom.credentials"
    assert row["rule_pack_version"] == "3.1.4"
    assert row["severity"] == "critical"
    assert row["confidence"] == "high"
    assert row["category"] == "credential.password"
    assert json.loads(row["tags_json"]) == ["configuration", "database"]
    assert row["value"] == "SECRET_VALUE"
    assert row["context"] == "key=SECRET_VALUE"
    state.close()


def test_resume_rejects_changed_scope_filters_or_policy(tmp_path):
    state, _configuration = create_state(tmp_path)
    state.close()
    changed = normalized_scan_configuration(scan_options(tmp_path, content=["DifferentRule"]))

    with pytest.raises(ResumeMismatchError):
        ScanState.resume(tmp_path / "scan.sqlite3", changed, "2.0.0")


def test_resume_fingerprint_includes_normalized_pack_version_and_overrides(tmp_path):
    rule = {
        "schema_version": 2,
        "id": "credential",
        "description": "",
        "match": {"condition": "all", "predicates": []},
        "actions": [{"type": "report", "representation": "metadata"}],
        "rule_source": "builtin:test",
        "rule_pack_id": "test.pack",
        "rule_pack_version": "1",
    }
    state, _configuration = create_state(tmp_path, rules=[rule])
    state.close()
    changed_rule = dict(rule, rule_pack_version="2", rule_source="/rules/override.json")
    changed = normalized_scan_configuration(scan_options(tmp_path, rules=[changed_rule]))

    with pytest.raises(ResumeMismatchError):
        ScanState.resume(tmp_path / "scan.sqlite3", changed, "2.0.0")


def test_normalized_configuration_persists_derived_rule_representation_plan(tmp_path):
    rules = [
        {
            "schema_version": 2,
            "id": "multi-representation",
            "description": "",
            "match": {"condition": "all", "predicates": []},
            "actions": [
                {"type": "report", "representation": "metadata"},
                {"type": "scan", "representation": "raw", "pattern": "SECRET", "flags": []},
            ],
            "rule_source": "/rules/example.json",
            "rule_pack_id": "example",
            "rule_pack_version": "1",
        }
    ]

    configuration = normalized_scan_configuration(scan_options(tmp_path, rules=rules))

    assert configuration["execution"]["rule_representation_plan"] == {
        "metadata": ["multi-representation"],
        "raw": ["multi-representation"],
    }


def test_schema_two_state_is_migrated_to_rule_provenance_without_losing_findings(tmp_path):
    state, configuration = create_state(tmp_path)
    decision = state.register_object(object_key="file|legacy", kind="file", path="legacy.txt")
    state.begin_object(decision.object_id)
    state.complete_object(
        decision.object_id,
        "processed",
        findings=[FindingRecord("metadata:active-include", "legacy.txt", context="legacy finding")],
    )
    for column in (
        "tags_json",
        "category",
        "confidence",
        "severity",
        "rule_pack_version",
        "rule_pack_id",
        "rule_schema_version",
        "rule_source",
        "representation",
    ):
        state.connection.execute(f"ALTER TABLE findings DROP COLUMN {column}")
    state.connection.execute("UPDATE runs SET schema_version=2")
    state.set_run_status("interrupted")
    state.close()

    resumed = ScanState.resume(tmp_path / "scan.sqlite3", configuration, "2.0.0")
    row = resumed.findings_for(decision.object_id)[0]

    assert resumed.run_row()["schema_version"] == SCHEMA_VERSION
    assert row["value"] == "legacy.txt"
    assert row["context"] == "legacy finding"
    assert row["representation"] == "metadata"
    assert row["rule_source"] == "cli"
    assert row["rule_schema_version"] is None
    assert row["rule_pack_id"] is None
    assert row["rule_pack_version"] is None
    assert row["severity"] == "medium"
    assert row["confidence"] == "medium"
    assert row["category"] == "uncategorized"
    assert json.loads(row["tags_json"]) == []
    resumed.close()


def test_schema_six_state_drops_retired_reviews_during_migration(tmp_path):
    state, configuration = create_state(tmp_path)
    assert (
        state.connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='reviews'"
        ).fetchone()[0]
        == 0
    )
    decision = state.register_object(object_key="file|legacy-review", kind="file", path="legacy.txt")
    state.begin_object(decision.object_id)
    state.complete_object(
        decision.object_id,
        "processed",
        findings=[FindingRecord("rule", "SECRET_VALUE")],
    )
    finding_id = state.findings_for(decision.object_id)[0]["finding_id"]
    state.connection.executescript(
        """
        CREATE TABLE reviews (
            run_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            status TEXT NOT NULL,
            note TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(run_id, finding_id)
        );
        CREATE INDEX reviews_run_idx ON reviews(run_id);
        """
    )
    state.connection.execute(
        "INSERT INTO reviews VALUES (?, ?, 'accepted', 'obsolete', ?)",
        (state.run_id, finding_id, "2026-09-09T00:00:00+00:00"),
    )
    state.connection.execute("UPDATE runs SET schema_version=6")
    state.set_run_status("interrupted")
    state.close()

    resumed = ScanState.resume(tmp_path / "scan.sqlite3", configuration, "2.0.0")
    assert resumed.run_row()["schema_version"] == SCHEMA_VERSION
    assert (
        resumed.connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='reviews'"
        ).fetchone()[0]
        == 0
    )
    assert "review_status" not in resumed.report_findings()[0].keys()
    resumed.close()


def test_resume_allows_execution_and_credentials_to_change(tmp_path):
    state, _configuration = create_state(tmp_path)
    state.close()
    changed = normalized_scan_configuration(
        scan_options(tmp_path, threads=12, password="new-password", quiet=True, verbose=True, no_eta=True)
    )

    resumed = ScanState.resume(tmp_path / "scan.sqlite3", changed, "2.1.0")
    assert resumed.run_row()["status"] == "running"
    assert resumed.run_row()["scanner_version"] == "2.1.0"
    assert changed["execution"]["dynamic_eta"] is False
    resumed.close()


def test_checkpoints_counters_and_final_run_status(tmp_path):
    state, _configuration = create_state(tmp_path)
    assert state.increment_counter("excluded") == 1
    assert state.increment_counter("excluded", 2) == 3
    state.set_checkpoint("target", {"index": 4})
    assert state.get_checkpoint("target") == {"index": 4}

    object_decision = state.register_object(object_key="file|bad", kind="file")
    state.begin_object(object_decision.object_id)
    state.complete_object(
        object_decision.object_id,
        "error",
        reason="denied",
        checkpoint_name="target:one",
        checkpoint_value={"path": "bad", "status": "error"},
    )
    assert state.get_checkpoint("target:one") == {"path": "bad", "status": "error"}
    assert state.finish() == "complete_with_errors"
    assert state.run_row()["status"] == "complete_with_errors"
    assert state.summary()["error"] == 1
    state.close()


@pytest.mark.parametrize(
    ("kind", "share", "reason"),
    [
        ("share", "Restricted$", "SMB SessionError: STATUS_ACCESS_DENIED"),
        ("directory", "Data", "FileListError: STATUS_NETWORK_ACCESS_DENIED"),
        ("file", "Data", "[network_access_denied] unable to retrieve required file"),
        ("share_enumeration", None, "CSessionError: STATUS_ACCESS_DENIED"),
    ],
)
def test_network_access_denied_errors_remain_visible_without_degrading_run_status(
    tmp_path,
    kind,
    share,
    reason,
):
    state, _configuration = create_state(tmp_path)
    decision = state.register_object(
        object_key=f"{kind}|fileserver.test|{share or '-'}|restricted",
        kind=kind,
        target="fileserver.test",
        share=share,
        path="restricted",
    )
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "error", reason=reason)

    assert state.finish() == "complete"
    assert state.run_row()["status"] == "complete"
    assert state.summary()["error"] == 1
    assert state.object_row(decision.object_id)["status"] == "error"
    assert state.object_row(decision.object_id)["reason"] == reason
    state.close()


@pytest.mark.parametrize(
    ("kind", "share", "reason"),
    [
        ("directory", None, "STATUS_ACCESS_DENIED while traversing a local path"),
        ("target", None, "SMB SessionError: STATUS_ACCESS_DENIED"),
        ("file", "Data", "required representation failed"),
        ("share", "Data", "SMB transport disconnected"),
    ],
)
def test_non_resource_or_non_access_errors_still_degrade_run_status(tmp_path, kind, share, reason):
    state, _configuration = create_state(tmp_path)
    decision = state.register_object(
        object_key=f"{kind}|fileserver.test|{share or '-'}|failed",
        kind=kind,
        target="fileserver.test",
        share=share,
        path="failed",
    )
    state.begin_object(decision.object_id)
    state.complete_object(decision.object_id, "error", reason=reason)

    assert state.finish() == "complete_with_errors"
    assert state.run_row()["status"] == "complete_with_errors"
    state.close()


def test_network_access_denied_does_not_hide_another_object_error(tmp_path):
    state, _configuration = create_state(tmp_path)
    denied = state.register_object(
        object_key="directory|fileserver.test|Data|restricted",
        kind="directory",
        target="fileserver.test",
        share="Data",
        path="restricted",
    )
    failed = state.register_object(
        object_key="file|fileserver.test|Data|broken.docx",
        kind="file",
        target="fileserver.test",
        share="Data",
        path="broken.docx",
    )
    state.begin_object(denied.object_id)
    state.complete_object(denied.object_id, "error", reason="STATUS_ACCESS_DENIED")
    state.begin_object(failed.object_id)
    state.complete_object(failed.object_id, "error", reason="document extraction failed")

    assert state.finish() == "complete_with_errors"
    assert state.summary()["error"] == 2
    state.close()


@pytest.mark.parametrize("status", ["pending", "in_progress"])
def test_finish_refuses_nonterminal_objects_and_leaves_run_resumable(tmp_path, status):
    state, _configuration = create_state(tmp_path)
    decision = state.register_object(object_key="file|unfinished", kind="file")
    if status == "in_progress":
        state.begin_object(decision.object_id)

    with pytest.raises(StateError, match=rf"{status}=1"):
        state.finish()

    row = state.run_row()
    assert row["status"] == "interrupted"
    assert f"{status}=1" in row["error_reason"]
    assert state.object_row(decision.object_id)["status"] == status
    state.close()


def test_exclusions_are_unique_but_repeated_observations_are_retained(tmp_path):
    state, _configuration = create_state(tmp_path)

    assert (
        state.record_exclusion(
            object_key="file|excluded",
            kind="file",
            target="server",
            share="share",
            path="folder/excluded.log",
            reason="excluded extension: log",
        )
        is True
    )
    assert (
        state.record_exclusion(
            object_key="file|excluded",
            kind="file",
            target="server",
            share="share",
            path="folder/excluded.log",
            reason="excluded extension: log",
        )
        is False
    )

    row = state.connection.execute("SELECT * FROM exclusions").fetchone()
    assert row["occurrences"] == 2
    assert row["reason"] == "excluded extension: log"
    assert state.summary()["excluded"] == 1
    assert state.progress_snapshot()["counters"]["excluded"] == 1
    state.close()


def test_object_keys_are_stable_and_smb_keys_are_case_insensitive(tmp_path):
    assert local_object_key(tmp_path / "one" / ".." / "file.txt") == local_object_key(tmp_path / "file.txt")
    assert smb_object_key(Target("SERVER", 1445), "Public", r"Folder/File.TXT") == smb_object_key(
        Target("server", 1445), "public", r"folder\file.txt"
    )


def test_derived_policy_can_be_finalized_only_before_traversal(tmp_path):
    state, _configuration = create_state(tmp_path)
    options = scan_options(tmp_path)
    options.large_domain = True
    options.scope_estimate = {"large_domain": True, "reason": "fixture"}
    options.blocked_content_extensions = [".bin", ".zip"]
    finalized = normalized_scan_configuration(options)

    state.update_configuration(finalized)
    persisted = ScanState.read_configuration(state.path)
    assert persisted["semantic"]["policy"]["effective_large_domain"] is True
    assert persisted["semantic"]["policy"]["blocked_content_extensions"] == [".bin", ".zip"]

    state.register_object(object_key="file|one", kind="file")
    with pytest.raises(StateError, match="after traversal has started"):
        state.update_configuration(finalized)
    state.close()


def test_processed_container_is_revisited_but_exhausted_error_is_not(tmp_path):
    state, _configuration = create_state(tmp_path)
    processed = state.register_object(
        object_key="target|one",
        kind="target",
        retry_limit=2,
        always_process=True,
    )
    state.begin_object(processed.object_id)
    state.complete_object(processed.object_id, "processed")
    revisit = state.register_object(
        object_key="target|one",
        kind="target",
        retry_limit=2,
        always_process=True,
    )
    assert revisit.should_process is True

    failed = state.register_object(
        object_key="directory|bad",
        kind="directory",
        retry_limit=1,
        always_process=True,
    )
    state.begin_object(failed.object_id)
    state.complete_object(failed.object_id, "error", reason="denied")
    exhausted = state.register_object(
        object_key="directory|bad",
        kind="directory",
        retry_limit=1,
        always_process=True,
    )
    assert exhausted.should_process is False
    state.close()


def test_resumable_objects_returns_only_unfinished_and_retriable_work(tmp_path):
    state, _configuration = create_state(tmp_path)
    processed = state.claim_object(
        object_key="file|processed",
        kind="file",
        target="one",
    )
    state.complete_object(processed.object_id, "processed")
    pending = state.register_object(
        object_key="file|pending",
        kind="file",
        target="one",
    )
    retriable = state.claim_object(
        object_key="file|retriable",
        kind="file",
        target="one",
    )
    state.complete_object(retriable.object_id, "error", reason="temporary")
    exhausted = state.claim_object(
        object_key="file|exhausted",
        kind="file",
        target="one",
        retry_limit=2,
    )
    state.complete_object(exhausted.object_id, "error", reason="temporary")
    exhausted = state.claim_object(
        object_key="file|exhausted",
        kind="file",
        target="one",
        retry_limit=2,
    )
    state.complete_object(exhausted.object_id, "error", reason="permanent")

    rows = state.resumable_objects(targets=["one"], retry_limit=2)

    assert {row["object_key"] for row in rows} == {
        "file|pending",
        "file|retriable",
    }
    assert pending.object_id in {row["object_id"] for row in rows}
    assert not state.resumable_objects(targets=[], retry_limit=2)
    state.close()


def test_supervisor_marks_only_a_running_latest_run_interrupted(tmp_path):
    state, _configuration = create_state(tmp_path)
    run_id = state.run_id
    state.close()

    assert ScanState.interrupt_latest(tmp_path / "scan.sqlite3", reason="signal fixture") is True
    attached = ScanState.attach(tmp_path / "scan.sqlite3", run_id)
    assert attached.run_row()["status"] == "interrupted"
    assert attached.run_row()["error_reason"] == "signal fixture"
    # Verify a terminal run is not overwritten by a later supervisor update.
    attached.set_run_status("complete")
    attached.close()
    assert ScanState.interrupt_latest(tmp_path / "scan.sqlite3") is False
