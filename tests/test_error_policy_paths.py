"""Resource names must not turn real transport failures into access refusals."""

import pytest
from impacket import nt_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.srvs import DCERPCSessionError
from impacket.smb import SessionError as SMB1SessionError
from impacket.smbconnection import SessionError

from man_spider.error_policy import NETWORK_ACCESS_DENIED_MARKER, is_network_access_denied
from man_spider.lib.errors import FileRetrievalError, network_error_reason
from man_spider.lib.file import RemoteFile
from man_spider.lib.util import Target
from man_spider.state import ScanState, directory_object_key, smb_object_key


MISLEADING_FILENAMES = (
    "STATUS_ACCESS_DENIED.txt",
    "report STATUS_ACCESS_DENIED notes.txt",
    "STATUS_ACCESS_DENIED notes.txt",
    "NT_STATUS_ACCESS_DENIED.txt",
    "ERROR_ACCESS_DENIED.txt",
    "ERRnoaccess.txt",
    "[network_access_denied].txt",
    "report [network_access_denied] notes.txt",
    r"STATUS_ACCESS_DENIED\ordinary.txt",
    'embedded": [network_access_denied] filename.txt',
)


class FailingTransport:
    def __init__(self, error):
        self.error = error
        self.attempts = 0

    def retrieve_file(self, share, path, callback):
        self.attempts += 1
        raise self.error

    def handle_impacket_error(self, *args):
        pass


def retrieve_error(tmp_path, filename, error):
    remote = RemoteFile(filename, "Data", Target("192.0.2.1"), size=3, tmp_dir=tmp_path / "spool")
    transport = FailingTransport(error)
    try:
        with pytest.raises(FileRetrievalError) as raised:
            remote.get(transport)
        assert transport.attempts == 1
        assert remote._content is None
        return raised.value
    finally:
        remote.cleanup()


def finish_with_file_error(tmp_path, filename, reason):
    state = ScanState.create(tmp_path / "scan.sqlite3", {}, "2.0.0")
    try:
        decision = state.register_object(
            object_key=f"file|misleading-name|{filename}",
            kind="file",
            target="192.0.2.1",
            share="Data",
            path=filename,
        )
        state.begin_object(decision.object_id)
        state.complete_object(decision.object_id, "error", reason=reason)
        result = state.finish()
        assert state.summary()["error"] == 1
        assert state.object_row(decision.object_id)["reason"] == reason
        return result
    finally:
        state.close()


@pytest.mark.parametrize("filename", MISLEADING_FILENAMES)
@pytest.mark.parametrize("persist_formatted_reason", [False, True], ids=["raw-reason", "formatted-reason"])
def test_remote_read_failure_is_not_hidden_by_access_denied_words_in_its_path(
    tmp_path, filename, persist_formatted_reason
):
    error = retrieve_error(tmp_path, filename, OSError("connection reset during read"))
    reason = network_error_reason(error) if persist_formatted_reason else str(error)

    assert finish_with_file_error(tmp_path, filename, reason) == "complete_with_errors"
    assert not is_network_access_denied(error)
    assert not reason.startswith(NETWORK_ACCESS_DENIED_MARKER)


@pytest.mark.parametrize("filename", MISLEADING_FILENAMES[:9])
def test_real_access_refusal_remains_non_fatal_with_misleading_filenames(tmp_path, filename):
    error = retrieve_error(tmp_path, filename, SessionError(nt_errors.STATUS_ACCESS_DENIED))

    assert is_network_access_denied(error)
    assert finish_with_file_error(tmp_path, filename, str(error)) == "complete"
    assert network_error_reason(error).startswith(NETWORK_ACCESS_DENIED_MARKER)


@pytest.mark.parametrize(
    "reason",
    [
        "STATUS_ACCESS_DENIED",
        "NT_STATUS_ACCESS_DENIED",
        "STATUS_ACCESS_DISABLED_BY_POLICY_PATH",
        "SMB SessionError: STATUS_ACCESS_DENIED",
        "FileListError: STATUS_NETWORK_ACCESS_DENIED",
        "CSessionError: STATUS_ACCESS_DENIED",
        "FileListError: [network_access_denied] persisted refusal",
        str(SessionError(nt_errors.STATUS_ACCESS_DENIED)),
        str(SMB1SessionError("fixture", SMB1SessionError.ERRDOS, SMB1SessionError.ERRnoaccess)),
        str(SMB1SessionError("fixture", 2, SMB1SessionError.ERRaccess)),
        str(DCERPCException(error_code=5)),
        str(DCERPCSessionError(error_code=5)),
    ],
)
def test_known_legacy_serialized_refusals_are_preserved(reason):
    assert is_network_access_denied(reason)


@pytest.mark.parametrize(
    "reason",
    [
        "STATUS_ACCESS_DENIED.txt",
        "STATUS_ACCESS_DENIED notes.txt",
        "[network_access_denied].txt",
        'OSError: "STATUS_ACCESS_DENIED": connection reset',
        'FileListError: failed to list "folder STATUS_ACCESS_DENIED": connection reset',
        'FileRetrievalError: "STATUS_ACCESS_DENIED notes.txt": read failed',
        'Error retrieving file "STATUS_ACCESS_DENIED.txt": OSError: connection reset',
        'Error retrieving file "ordinary.txt": OSError: failed to open "file": STATUS_ACCESS_DENIED',
        'Error retrieving file "embedded": [network_access_denied] filename.txt": OSError: reset',
        "SMB SessionError: STATUS_SHARING_VIOLATION - filename STATUS_ACCESS_DENIED.txt",
        "SMB SessionError: code: 0xc0000043 - STATUS_ACCESS_DENIED",
        "SMB SessionError: class: ERRDOS, code: ERRbadfile(STATUS_ACCESS_DENIED.txt)",
        "prefix[network_access_denied]suffix",
        "prefixSTATUS_ACCESS_DENIEDsuffix",
    ],
)
def test_quoted_paths_substrings_and_non_refusal_statuses_are_not_authorization(reason):
    assert not is_network_access_denied(reason)


def test_typed_non_refusal_status_takes_precedence_over_misleading_exception_text():
    class MisleadingStatus(SessionError):
        def __str__(self):
            return "STATUS_ACCESS_DENIED"

    assert not is_network_access_denied(MisleadingStatus(nt_errors.STATUS_SHARING_VIOLATION))


@pytest.mark.parametrize("error", [DCERPCException(error_code=5), DCERPCSessionError(error_code=5)])
def test_typed_rpc_access_denied_remains_recognized(error):
    assert is_network_access_denied(error)


def test_typed_cause_is_preserved_even_when_a_path_cannot_be_unambiguously_parsed(tmp_path):
    error = retrieve_error(tmp_path, MISLEADING_FILENAMES[-1], SessionError(nt_errors.STATUS_ACCESS_DENIED))

    assert is_network_access_denied(error)
    assert network_error_reason(error).startswith(NETWORK_ACCESS_DENIED_MARKER)


@pytest.mark.parametrize(
    "parent_path",
    [
        "STATUS_ACCESS_DENIED",
        "folder STATUS_ACCESS_DENIED notes",
        "folder: STATUS_ACCESS_DENIED",
        'folder": [network_access_denied] fake',
        "folder: code",
    ],
)
@pytest.mark.parametrize("denied", [False, True], ids=["transport-error", "access-denied"])
def test_blocked_descendants_classify_original_parent_reason_not_its_name(tmp_path, parent_path, denied):
    target = Target("192.0.2.1")
    key = directory_object_key(target, "Data", parent_path)
    ancestor_reason = "STATUS_ACCESS_DENIED" if denied else "OSError: connection reset"
    state = ScanState.create(tmp_path / "blocked.sqlite3", {}, "2.0.0")
    try:
        parent = state.register_object(
            object_key=key, kind="directory", target=str(target), share="Data", path=parent_path,
        )
        state.begin_object(parent.object_id)
        state.complete_object(parent.object_id, "error", reason=ancestor_reason)
        child_path = parent_path + r"\child.txt"
        child = state.register_object(
            object_key=smb_object_key(target, "Data", child_path),
            kind="file", target=str(target), share="Data", path=child_path,
        )
        for _ in range(3):
            state.begin_object(child.object_id)

        assert state.settle_blocked_objects() == 1
        reason = state.object_row(child.object_id)["reason"]
        assert reason.startswith("Blocked by ancestor ")
        assert is_network_access_denied(reason) is denied
        if denied:
            assert reason.startswith("Blocked by ancestor [network_access_denied] ")
        assert child.object_id in {row["object_id"] for row in state.resumable_objects(retry_limit=0)}
        assert state.finish() == ("complete" if denied else "complete_with_errors")
    finally:
        state.close()


@pytest.mark.parametrize("parent_path", MISLEADING_FILENAMES)
@pytest.mark.parametrize(
    "cause,denied",
    [
        ("OSError: connection reset", False),
        ("BrokenPipeError: transport closed", False),
        ("STATUS_ACCESS_DENIED", True),
        (str(SessionError(nt_errors.STATUS_ACCESS_DENIED)), True),
    ],
)
def test_legacy_ancestor_wrapper_uses_diagnostic_tail_not_status_words_in_key(parent_path, cause, denied):
    key = directory_object_key(Target("server"), "Data", parent_path)

    assert is_network_access_denied(f"Blocked by ancestor {key}: {cause}") is denied
