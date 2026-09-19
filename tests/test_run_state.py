import json
import sqlite3

import man_spider.manspider as manspider_module
from man_spider.cli import parse_options
from man_spider.manspider import (
    EXIT_COMPLETE_WITH_ERRORS,
    EXIT_CREDENTIALS_INVALID,
    EXIT_STATE_ERROR,
    go,
)
from man_spider.state import ScanLease, ScanState


class SuccessfulSpider:
    starts = 0

    def __init__(self, options):
        self.options = options

    def start(self):
        type(self).starts += 1


def run_row(path):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute("SELECT * FROM runs").fetchone()
    finally:
        connection.close()


def local_options(tmp_path, state_arguments):
    return parse_options([str(tmp_path), "-f", "secret", "--yes", *state_arguments])


def test_run_creates_state_before_scan_and_finishes_it(monkeypatch, tmp_path):
    state_path = tmp_path / "scan.sqlite3"
    options = local_options(tmp_path, ["--state-file", str(state_path)])
    SuccessfulSpider.starts = 0
    monkeypatch.setattr(manspider_module, "MANSPIDER", SuccessfulSpider)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    assert go(options, command=["manspider", str(tmp_path)]) == 0
    row = run_row(state_path)
    assert row["status"] == "complete"
    assert options.state_run_id == row["run_id"]
    assert SuccessfulSpider.starts == 1
    assert not state_path.with_suffix(".json").exists()


def test_preflight_failure_is_persisted_and_main_scan_does_not_start(monkeypatch, tmp_path):
    state_path = tmp_path / "preflight.sqlite3"
    options = local_options(tmp_path, ["--state-file", str(state_path)])
    SuccessfulSpider.starts = 0
    messages = []
    monkeypatch.setattr(manspider_module, "MANSPIDER", SuccessfulSpider)
    monkeypatch.setattr(manspider_module.log, "info", lambda message: messages.append(str(message)))
    monkeypatch.setattr(
        manspider_module,
        "credential_preflight",
        lambda _options: EXIT_CREDENTIALS_INVALID,
    )

    assert go(options, command=["manspider", str(tmp_path)]) == EXIT_CREDENTIALS_INVALID
    row = run_row(state_path)
    assert row["status"] == "preflight_failed"
    assert "exit code 3" in row["error_reason"]
    assert SuccessfulSpider.starts == 0
    assert any("Progress: run=preflight_failed; targets=0/1" in message for message in messages)


def test_runtime_failure_leaves_a_resumable_interrupted_run(monkeypatch, tmp_path):
    class FailingSpider(SuccessfulSpider):
        def start(self):
            raise RuntimeError("scanner fixture failed")

    state_path = tmp_path / "interrupted.sqlite3"
    json_path = tmp_path / "interrupted.json"
    options = local_options(
        tmp_path,
        ["--state-file", str(state_path), "--json-file", str(json_path)],
    )
    monkeypatch.setattr(manspider_module, "MANSPIDER", FailingSpider)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    assert go(options, command=["manspider", str(tmp_path)]) == 1
    row = run_row(state_path)
    assert row["status"] == "interrupted"
    assert row["error_reason"] == "scanner fixture failed"
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["run_status"] == "interrupted"
    assert report["error_reason"] == "scanner fixture failed"


def test_systemic_state_failure_stops_scan_with_resumable_state_exit(monkeypatch, tmp_path):
    class StateFailingSpider(SuccessfulSpider):
        def start(self):
            raise manspider_module.StateError("findings commit fixture failed")

    state_path = tmp_path / "state-error.sqlite3"
    options = local_options(tmp_path, ["--state-file", str(state_path)])
    monkeypatch.setattr(manspider_module, "MANSPIDER", StateFailingSpider)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    assert go(options, command=["manspider", str(tmp_path)]) == EXIT_STATE_ERROR
    row = run_row(state_path)
    assert row["status"] == "interrupted"
    assert row["error_reason"] == "findings commit fixture failed"


def test_nonterminal_manifest_prevents_successful_run_finalization(monkeypatch, tmp_path):
    class IncompleteSpider(SuccessfulSpider):
        def start(self):
            state = ScanState.attach(self.options.state_path, self.options.state_run_id)
            try:
                state.claim_object(object_key="file|unfinished", kind="file")
            finally:
                state.close()

    state_path = tmp_path / "unfinished.sqlite3"
    options = local_options(tmp_path, ["--state-file", str(state_path)])
    monkeypatch.setattr(manspider_module, "MANSPIDER", IncompleteSpider)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    assert go(options, command=["manspider", str(tmp_path)]) == EXIT_STATE_ERROR
    row = run_row(state_path)
    assert row["status"] == "interrupted"
    assert "in_progress=1" in row["error_reason"]


def test_existing_state_requires_explicit_resume(monkeypatch, tmp_path):
    state_path = tmp_path / "existing.sqlite3"
    state_path.write_bytes(b"do not overwrite")
    options = local_options(tmp_path, ["--state-file", str(state_path)])
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    assert go(options, command=["manspider", str(tmp_path)]) == EXIT_STATE_ERROR
    assert state_path.read_bytes() == b"do not overwrite"


def test_concurrent_scan_of_same_state_fails_before_preflight(monkeypatch, tmp_path):
    state_path = tmp_path / "leased.sqlite3"
    options = local_options(tmp_path, ["--state-file", str(state_path)])
    preflight_calls = []
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: preflight_calls.append(True) or 0)

    lease = ScanLease.acquire(state_path)
    try:
        assert go(options, command=["manspider", str(tmp_path)]) == EXIT_STATE_ERROR
    finally:
        lease.release()

    assert preflight_calls == []
    assert not state_path.exists()


def test_raw_sqlite_failure_is_classified_as_a_state_error(monkeypatch, tmp_path):
    state_path = tmp_path / "sqlite-failure.sqlite3"
    options = local_options(tmp_path, ["--state-file", str(state_path)])
    monkeypatch.setattr(
        manspider_module.ScanState,
        "create",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("disk I/O fixture")),
    )

    assert go(options, command=["manspider", str(tmp_path)]) == EXIT_STATE_ERROR


def test_resume_reuses_the_same_run(monkeypatch, tmp_path):
    state_path = tmp_path / "resume.sqlite3"
    SuccessfulSpider.starts = 0
    monkeypatch.setattr(manspider_module, "MANSPIDER", SuccessfulSpider)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    first = local_options(tmp_path, ["--state-file", str(state_path)])
    assert go(first, command=["manspider", str(tmp_path)]) == 0
    first_run_id = run_row(state_path)["run_id"]

    resumed = local_options(tmp_path, ["--resume", str(state_path)])
    assert go(resumed, command=["manspider", str(tmp_path)]) == 0
    row = run_row(state_path)
    assert row["run_id"] == first_run_id
    assert row["status"] == "complete"
    assert SuccessfulSpider.starts == 2


def test_local_object_errors_are_reported_only_after_scanner_finishes(monkeypatch, tmp_path):
    class SpiderWithLocalError(SuccessfulSpider):
        def start(self):
            state = ScanState.attach(self.options.state_path, self.options.state_run_id)
            try:
                decision = state.register_object(object_key="file|failed", kind="file")
                state.begin_object(decision.object_id)
                state.complete_object(decision.object_id, "error", reason="fixture error")
            finally:
                state.close()
            type(self).starts += 1

    state_path = tmp_path / "errors.sqlite3"
    options = local_options(tmp_path, ["--state-file", str(state_path)])
    SpiderWithLocalError.starts = 0
    monkeypatch.setattr(manspider_module, "MANSPIDER", SpiderWithLocalError)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    assert go(options, command=["manspider", str(tmp_path)]) == EXIT_COMPLETE_WITH_ERRORS
    assert run_row(state_path)["status"] == "complete_with_errors"
    assert SpiderWithLocalError.starts == 1


def test_smb_access_denied_object_error_is_reported_without_nonzero_run_status(monkeypatch, tmp_path):
    class SpiderWithDeniedShare(SuccessfulSpider):
        def start(self):
            state = ScanState.attach(self.options.state_path, self.options.state_run_id)
            try:
                decision = state.register_object(
                    object_key="share|fileserver.test|restricted$",
                    kind="share",
                    target="fileserver.test",
                    share="restricted$",
                    path="restricted$",
                )
                state.begin_object(decision.object_id)
                state.complete_object(
                    decision.object_id,
                    "error",
                    reason="[network_access_denied] SMB SessionError: STATUS_ACCESS_DENIED",
                )
            finally:
                state.close()
            type(self).starts += 1

    state_path = tmp_path / "access-denied.sqlite3"
    options = local_options(tmp_path, ["--state-file", str(state_path)])
    SpiderWithDeniedShare.starts = 0
    monkeypatch.setattr(manspider_module, "MANSPIDER", SpiderWithDeniedShare)
    monkeypatch.setattr(manspider_module, "credential_preflight", lambda _options: 0)

    assert go(options, command=["manspider", str(tmp_path)]) == 0
    assert run_row(state_path)["status"] == "complete"
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status, reason FROM objects WHERE kind='share'").fetchone() == (
            "error",
            "[network_access_denied] SMB SessionError: STATUS_ACCESS_DENIED",
        )
    assert SpiderWithDeniedShare.starts == 1
