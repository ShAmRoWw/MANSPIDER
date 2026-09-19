"""Passive analysis coverage observations; no SMB server or heavy extractor."""

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from man_spider.lib.errors import FileRetrievalError, ReadOnlySMBViolation
from man_spider.lib.file import RemoteFile
from man_spider.lib.parser import FileParser
from man_spider.lib.parser.parser import ParseResult
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.state import ScanState, local_object_key


parser_module = importlib.import_module("man_spider.lib.parser.parser")


def content_rule(name, representation="raw", pattern="SECRET"):
    return {"id": name, "match": {}, "actions": [
        {"type": "scan", "representation": representation, "pattern": pattern},
    ]}


def metadata_rule(name="metadata"):
    return {"id": name, "match": {}, "actions": [{"type": "report"}]}


def make_parser(*rules, cli=(), blocked=()):
    return FileParser(list(cli), quiet=True, blocked_extensions=list(blocked), rules=list(rules))


def route(parser, filename="candidate.txt"):
    return parser.route_rules({
        "filename": filename, "path": filename, "extension": Path(filename).suffix,
        "size": 6, "mtime": 1, "share": "Data", "directory": "",
    })


@pytest.fixture
def make_worker(tmp_path):
    states = []
    def build(parser, *, selected=True, no_download=True):
        state = ScanState.create(tmp_path / f"state-{len(states)}.sqlite3", {}, "analysis-test")
        states.append(state)
        worker = Spiderling.__new__(Spiderling)
        worker.target = tmp_path
        worker.parent = SimpleNamespace(
            parser=parser, state_path=str(state.path), state_run_id=state.run_id,
            unclassified_report_enabled=False, no_download=no_download, quiet=True,
            modified_after=None, modified_before=None, max_filesize=1024, tmp_dir=tmp_path,
            scope_matcher=SimpleNamespace(final_include=lambda **_kwargs: selected),
        )
        worker.scan_state = state
        worker.local_object_ids = {}
        worker.local_initial_metadata = {}
        worker.local_rule_routes = {}
        worker.file_analysis_observations = {}
        worker.pending_state_completions = []
        worker.completed_files_since_progress = 0
        worker.fast_resume = False
        worker.emit_findings = lambda *_args, **_kwargs: None
        return worker, state
    yield build
    for state in states:
        state.close()


def local_candidate(worker, state, tmp_path, content=b"ordinary", name="candidate.txt"):
    file = tmp_path / name
    file.write_bytes(content)
    stat = file.stat()
    decision = state.claim_object(
        object_key=local_object_key(file), kind="file", path=str(file), target=str(tmp_path), size=len(content),
    )
    worker.local_object_ids[local_object_key(file)] = decision.object_id
    worker.local_initial_metadata[local_object_key(file)] = (stat.st_size, stat.st_mtime_ns, stat.st_dev, stat.st_ino)
    worker.local_rule_routes[local_object_key(file)] = route(worker.parent.parser, name)
    return file, decision.object_id


def remote_candidate(worker, state, tmp_path, *, content=b"ordinary", name="candidate.txt", retrieve=True):
    remote = RemoteFile(name, "Data", Target("192.0.2.10"), size=len(content), mtime=1, tmp_dir=tmp_path)
    remote.rule_route = route(worker.parent.parser, name)
    decision = state.claim_object(
        object_key=f"smb|{name}", kind="file", path=name, target="192.0.2.10", share="Data", size=len(content),
    )
    remote.object_id = decision.object_id
    calls = []
    def retrieve_file(share, path, callback):
        calls.append((share, path))
        callback(content)
        return len(content), 1, None
    if retrieve:
        remote.get(SimpleNamespace(retrieve_file=retrieve_file))
        remote.retrieved = True
    return remote, decision.object_id, calls


def completed_row(worker, state, object_id):
    assert state.object_row(object_id)["status"] == "in_progress"
    assert state.object_row(object_id)["analysis_status"] == "unknown"
    worker.flush_state_completions()
    return state.object_row(object_id)


def assert_analysis(row, status, read):
    assert row["analysis_status"] == status
    assert row["analysis_read"] == read


def test_parser_zero_matches_counts_completed_work():
    parser = make_parser(content_rule("missing"))
    result = parser.parse_file("candidate.txt", data=b"ordinary")
    assert not result.findings
    assert (result.analysis_selected, result.analysis_completed, result.analysis_read) == (1, 1, True)


@pytest.mark.parametrize("selected", [True, False])
def test_local_completed_analysis_without_findings_or_include_match(make_worker, tmp_path, selected):
    worker, state = make_worker(make_parser(cli=("SECRET",)), selected=selected)
    file, object_id = local_candidate(worker, state, tmp_path)
    worker.process_file(file)
    row = completed_row(worker, state, object_id)
    assert row["status"] == "processed"
    assert_analysis(row, "analyzed", True)
    assert row["analysis_reason"] is None
    if not selected:
        assert not state.findings_for(object_id)
        assert "after content analysis" in row["reason"]
    assert not worker.file_analysis_observations


def test_remote_completed_analysis_does_not_make_more_remote_reads(make_worker, tmp_path):
    worker, state = make_worker(make_parser(content_rule("missing")))
    remote, object_id, calls = remote_candidate(worker, state, tmp_path)
    worker.process_file(remote)
    row = completed_row(worker, state, object_id)
    assert_analysis(row, "analyzed", True)
    assert not state.findings_for(object_id)
    assert calls == [("Data", "candidate.txt")]
    assert remote._content is None


@pytest.mark.parametrize("remote", [False, True])
def test_metadata_only_does_not_claim_analysis(make_worker, tmp_path, remote):
    worker, state = make_worker(make_parser(metadata_rule()))
    if remote:
        file, object_id, calls = remote_candidate(worker, state, tmp_path, retrieve=False)
    else:
        file, object_id = local_candidate(worker, state, tmp_path)
    worker.process_file(file)
    row = completed_row(worker, state, object_id)
    assert_analysis(row, "not_analyzed", False)
    assert len(state.findings_for(object_id)) == 1


def test_downloaded_metadata_file_is_read_but_not_analyzed(make_worker, tmp_path):
    worker, state = make_worker(make_parser(metadata_rule()), no_download=False)
    remote, object_id, calls = remote_candidate(worker, state, tmp_path)
    worker.save_file = lambda file: file.cleanup() or True
    worker.process_file(remote)
    row = completed_row(worker, state, object_id)
    assert_analysis(row, "not_analyzed", True)
    assert calls == [("Data", "candidate.txt")]


def test_failed_loot_save_does_not_erase_successful_analysis(make_worker, tmp_path):
    worker, state = make_worker(make_parser(content_rule("secret")), no_download=False)
    remote, object_id, _ = remote_candidate(worker, state, tmp_path, content=b"SECRET")
    worker.save_file = lambda _file: False
    worker.process_file(remote)
    row = completed_row(worker, state, object_id)
    assert row["status"] == "error"
    assert_analysis(row, "analyzed", True)
    assert len(state.findings_for(object_id)) == 1


@pytest.mark.parametrize("remote", [False, True])
def test_partial_analysis_counts_successful_zero_match_rule(make_worker, tmp_path, remote):
    parser = make_parser(content_rule("raw"), content_rule("unsupported", "ocr"))
    worker, state = make_worker(parser)
    if remote:
        file, object_id, _ = remote_candidate(worker, state, tmp_path)
    else:
        file, object_id = local_candidate(worker, state, tmp_path)
    worker.process_file(file)
    row = completed_row(worker, state, object_id)
    assert row["status"] == "error"
    assert_analysis(row, "partial", True)
    assert row["analysis_reason"] == "partial_analysis"
    assert "OCR representation does not support" in row["reason"]
    assert not state.findings_for(object_id)


def test_extracted_bytes_with_all_rule_evaluations_failed_are_not_analyzed(make_worker, tmp_path, monkeypatch):
    parser = make_parser(content_rule("first"), content_rule("second"))
    def failure(*_args):
        raise RuntimeError("rule failed")
    monkeypatch.setattr(parser, "_evaluate_content_rule", failure)
    worker, state = make_worker(parser)
    file, object_id = local_candidate(worker, state, tmp_path)
    worker.process_file(file)
    row = completed_row(worker, state, object_id)
    assert_analysis(row, "not_analyzed", True)
    assert row["analysis_reason"] == "analysis_failed"
    assert "rule failed" in row["reason"]


def test_one_of_two_rules_same_representation_fails_with_other_zero_match():
    parser = make_parser(content_rule("first"), content_rule("second"))
    original = parser._evaluate_content_rule
    def evaluate(rule, content):
        if rule.rule_id == "rule:second":
            raise RuntimeError("second failed")
        return original(rule, content)
    parser._evaluate_content_rule = evaluate
    result = parser.parse_file("candidate.txt", data=b"ordinary")
    assert not result.findings
    assert (result.analysis_selected, result.analysis_completed) == (2, 1)


def test_format_policy_disables_all_selected_content_without_reading():
    parser = make_parser(content_rule("raw"), blocked=(".txt",))
    def forbidden():
        pytest.fail("Policy-blocked content was read")
    result = parser.parse_file("candidate.txt", data_loader=forbidden)
    assert result.skipped_reason
    assert (result.analysis_selected, result.analysis_completed, result.analysis_read) == (1, 0, False)


@pytest.mark.parametrize("downloaded", [False, True])
def test_pipeline_format_policy_is_independent_of_download(make_worker, tmp_path, downloaded):
    worker, state = make_worker(make_parser(content_rule("raw")))
    remote, object_id, _ = remote_candidate(worker, state, tmp_path, retrieve=downloaded)
    remote.skip_content = True
    worker.process_file(remote)
    row = completed_row(worker, state, object_id)
    assert_analysis(row, "not_analyzed", downloaded)
    assert row["analysis_reason"] == "format_policy"


def test_size_policy_records_not_analyzed_without_read(make_worker, tmp_path):
    worker, state = make_worker(make_parser(content_rule("raw")))
    file, object_id = local_candidate(worker, state, tmp_path)
    worker.parent.max_filesize = 1
    assert worker.complete_oversized_file(file, file.stat().st_size, {}, worker.rule_route(file))
    row = completed_row(worker, state, object_id)
    assert_analysis(row, "not_analyzed", False)
    assert row["analysis_reason"] == "size_policy"


def test_failed_data_loader_does_not_claim_executed_rules():
    parser = make_parser(content_rule("raw"))
    def failure():
        raise OSError("read failed")
    result = parser.parse_file("candidate.txt", data_loader=failure)
    assert (result.analysis_selected, result.analysis_completed, result.analysis_read) == (1, 0, None)


@pytest.mark.parametrize("partial_bytes", [b"", b"partial"])
def test_failed_remote_retrieval_reports_observed_bytes(make_worker, tmp_path, partial_bytes):
    worker, state = make_worker(make_parser(content_rule("raw")))
    remote, object_id, _ = remote_candidate(worker, state, tmp_path, retrieve=False)
    def failure(_share, _name, callback):
        if partial_bytes:
            callback(partial_bytes)
        raise OSError("transport lost")
    client = SimpleNamespace(retrieve_file=failure, handle_impacket_error=lambda *_args: None)
    with pytest.raises(FileRetrievalError):
        remote.get(client)
    remote.cleanup()
    worker.complete_file(remote, "error", reason="transport lost", content_read=False, content_status="retrieval_failed")
    row = completed_row(worker, state, object_id)
    assert_analysis(row, "not_analyzed", bool(partial_bytes))


def test_empty_successful_remote_read_is_observed(make_worker, tmp_path):
    worker, state = make_worker(make_parser(content_rule("raw")))
    remote, object_id, _ = remote_candidate(worker, state, tmp_path, content=b"")
    worker.process_file(remote)
    assert_analysis(completed_row(worker, state, object_id), "analyzed", True)


def test_zero_match_inspector_is_successfully_completed():
    parser = make_parser({"id": "key", "match": {}, "actions": [
        {"type": "inspect", "detector": "private-key-material"},
    ]})
    parser._run_inspector = lambda *_args: ()
    result = parser.parse_file("candidate.key", data=b"ordinary")
    assert not result.findings
    assert (result.analysis_selected, result.analysis_completed, result.analysis_read) == (1, 1, True)


@pytest.mark.parametrize("success", [False, True])
def test_structured_precomputed_outcome_counts_without_extra_extraction(success):
    parser = make_parser(content_rule("structured", "structured"))
    def forbidden():
        pytest.fail("Precomputed representation caused another content read")
    result = parser.parse_file(
        "candidate.docx", data_loader=forbidden,
        precomputed_representations={"structured": (success, "ordinary" if success else RuntimeError("batch failure"))},
    )
    assert (result.analysis_selected, result.analysis_completed) == (1, int(success))


def test_legacy_parser_result_remains_unknown_instead_of_guessing_processed(make_worker, tmp_path):
    parser = make_parser(content_rule("raw"))
    parser.parse_file = lambda *_args, **_kwargs: ParseResult(extracted=True)
    worker, state = make_worker(parser)
    file, object_id = local_candidate(worker, state, tmp_path)
    worker.process_file(file)
    row = completed_row(worker, state, object_id)
    assert_analysis(row, "unknown", None)


def test_unexpected_parser_exception_after_read_is_unknown_but_bytes_known(make_worker, tmp_path):
    parser = make_parser(content_rule("raw"))
    def failure(*_args, data_loader, **_kwargs):
        data_loader()
        raise RuntimeError("custom parser failed after reading")
    parser.parse_file = failure
    worker, state = make_worker(parser)
    file, object_id = local_candidate(worker, state, tmp_path)
    worker.process_file(file)
    assert_analysis(completed_row(worker, state, object_id), "unknown", True)


def test_local_open_failure_is_not_analyzed_and_not_read(make_worker, tmp_path, monkeypatch):
    worker, state = make_worker(make_parser(content_rule("raw")))
    file, object_id = local_candidate(worker, state, tmp_path)
    def denied(*_args, **_kwargs):
        raise PermissionError("denied before opening")
    monkeypatch.setattr("man_spider.lib.spiderling.local_file_descriptor", denied)
    worker.process_file(file)
    assert_analysis(completed_row(worker, state, object_id), "not_analyzed", False)


def test_metadata_failure_terminal_record_has_independent_analysis_observation(make_worker):
    worker, state = make_worker(make_parser(content_rule("raw")))
    worker.record_error_object(object_key="file|missing", kind="file", path="missing", reason="metadata unavailable")
    worker.flush_state_completions()
    row = state.connection.execute("SELECT * FROM objects WHERE kind='file'").fetchone()
    assert_analysis(row, "not_analyzed", False)
    assert row["analysis_reason"] == "metadata_unavailable"


def test_safety_violation_does_not_commit_terminal_analysis(make_worker, tmp_path):
    parser = make_parser(content_rule("raw"))
    def violation(*_args, **_kwargs):
        raise ReadOnlySMBViolation("blocked unsafe operation")
    parser.parse_file = violation
    worker, state = make_worker(parser)
    remote, object_id, _ = remote_candidate(worker, state, tmp_path)
    with pytest.raises(ReadOnlySMBViolation):
        worker.process_file(remote)
    assert not worker.pending_state_completions
    assert state.object_row(object_id)["status"] == "in_progress"
    assert state.object_row(object_id)["analysis_status"] == "unknown"
