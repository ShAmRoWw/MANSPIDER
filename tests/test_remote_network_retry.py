"""Full reads retry only failures with proven remote SMB provenance."""

import pytest
from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.smbconnection import SessionError

import man_spider.lib.file as file_module
from man_spider.lib.errors import (
    DFSReferralBlocked,
    FileChangedDuringRead,
    FileRetrievalError,
    NETWORK_UNAVAILABLE_MARKER,
    ReadOnlySMBViolation,
    is_network_unavailable,
    mark_network_unavailable,
)
from man_spider.lib.file import RemoteFile
from man_spider.lib.util import Target


PAYLOAD = b"password=complete-new-snapshot"


class ScriptedClient:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []
        self.errors = []

    def retrieve_file(self, share, name, callback):
        self.requests.append((share, name))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            callback(b"discard-this-partial-snapshot")
            raise outcome
        callback(outcome)
        return (len(outcome), 123, None)

    def handle_impacket_error(self, *args):
        self.errors.append(args)


def network_failure():
    return mark_network_unavailable(ConnectionResetError("synthetic SMB read reset"))


@pytest.fixture
def remote(tmp_path):
    value = RemoteFile("folder/secret.txt", "share", Target("server"),
                       size=len(PAYLOAD), mtime=123, tmp_dir=tmp_path)
    yield value
    value.cleanup()


@pytest.fixture
def spools(monkeypatch):
    values = []
    original = file_module._LazyDirectorySpool

    def create(**kwargs):
        spool = original(**kwargs)
        values.append(spool)
        return spool

    monkeypatch.setattr(file_module, "_LazyDirectorySpool", create)
    return values


@pytest.mark.parametrize("spill_to_disk", [False, True])
def test_one_network_retry_discards_partial_spool(remote, spools, spill_to_disk):
    if spill_to_disk:
        remote.memory_spool_limit = 8
    client = ScriptedClient([network_failure(), PAYLOAD])
    remote.get(client)
    assert client.requests == [("share", "folder/secret.txt")] * 2
    assert remote.content_bytes() == PAYLOAD
    assert remote.retrieved_size == len(PAYLOAD)
    assert remote.post_read_identity == (len(PAYLOAD), 123, None)
    assert remote.post_read_verification_finalized is True
    assert remote.content_read is True
    assert len(spools) == 2
    assert spools[0].closed
    assert not spools[1].closed
    assert client.errors == []


def test_second_network_failure_surfaces_durable_marker(remote, spools):
    second = network_failure()
    client = ScriptedClient([network_failure(), second, PAYLOAD])
    with pytest.raises(FileRetrievalError) as caught:
        remote.get(client)
    assert str(caught.value).startswith(NETWORK_UNAVAILABLE_MARKER)
    assert is_network_unavailable(caught.value)
    assert caught.value.__cause__ is second
    assert len(client.requests) == 2
    assert len(client.errors) == 1
    assert remote._content is None
    assert remote.retrieved_size is None
    assert remote.post_read_identity is None
    assert not remote.post_read_verification_finalized
    assert len(spools) == 2 and all(spool.closed for spool in spools)


@pytest.mark.parametrize("network_position", range(4))
def test_changed_snapshot_and_network_budgets_allow_at_most_five_reads(remote, network_position):
    outcomes = [FileChangedDuringRead("incomplete snapshot") for _ in range(3)]
    outcomes.insert(network_position, network_failure())
    outcomes.append(PAYLOAD)
    client = ScriptedClient(outcomes)
    remote.get(client)
    assert len(client.requests) == 5
    assert remote.content_bytes() == PAYLOAD
    assert remote.changed


@pytest.mark.parametrize("network_position", range(4))
def test_persistent_changed_snapshot_still_exhausts_budget(remote, spools, network_position):
    outcomes = [FileChangedDuringRead("incomplete snapshot") for _ in range(4)]
    outcomes.insert(network_position, network_failure())
    client = ScriptedClient(outcomes + [PAYLOAD])
    with pytest.raises(FileRetrievalError, match="remained incomplete") as caught:
        remote.get(client)
    assert len(client.requests) == 5
    assert not is_network_unavailable(caught.value)
    assert not str(caught.value).startswith(NETWORK_UNAVAILABLE_MARKER)
    assert remote._content is None
    assert all(spool.closed for spool in spools)


def test_network_retry_cannot_fall_back_to_pre_failure_snapshot(remote, spools):
    client = ScriptedClient([
        b"stale-complete-but-changed-snapshot",
        network_failure(),
        FileChangedDuringRead("incomplete snapshot"),
        FileChangedDuringRead("incomplete snapshot"),
        FileChangedDuringRead("incomplete snapshot"),
    ])
    with pytest.raises(FileRetrievalError, match="remained incomplete"):
        remote.get(client)
    assert len(client.requests) == 5
    assert remote._content is None
    assert remote.retrieved_size is None
    assert len(spools) == 5 and all(spool.closed for spool in spools)


@pytest.mark.parametrize("failure", [
    TimeoutError("local temporary spool timed out"),
    BrokenPipeError("local pipe closed"),
    PermissionError("local temporary directory denied"),
    SessionError(STATUS_ACCESS_DENIED),
])
def test_unmarked_local_errors_and_server_refusals_are_not_retried(remote, spools, failure):
    client = ScriptedClient([failure, PAYLOAD])
    with pytest.raises(FileRetrievalError) as caught:
        remote.get(client)
    assert len(client.requests) == 1
    assert caught.value.__cause__ is failure
    assert not is_network_unavailable(caught.value)
    assert not str(caught.value).startswith(NETWORK_UNAVAILABLE_MARKER)
    assert remote._content is None
    assert len(spools) == 1 and spools[0].closed


@pytest.mark.parametrize("failure", [
    ReadOnlySMBViolation("forbidden remote operation"),
    DFSReferralBlocked("target outside scope"),
    KeyboardInterrupt(),
    SystemExit(130),
])
def test_safety_and_cancellation_propagate_without_retry(remote, spools, failure):
    client = ScriptedClient([mark_network_unavailable(failure), PAYLOAD])
    with pytest.raises(type(failure)) as caught:
        remote.get(client)
    assert caught.value is failure
    assert len(client.requests) == 1
    assert client.errors == []
    assert len(spools) == 1 and spools[0].closed


def test_last_local_error_does_not_inherit_previous_network_marker(remote):
    failure = TimeoutError("local spool timeout on second attempt")
    client = ScriptedClient([network_failure(), failure, PAYLOAD])
    with pytest.raises(FileRetrievalError) as caught:
        remote.get(client)
    assert len(client.requests) == 2
    assert caught.value.__cause__ is failure
    assert not is_network_unavailable(caught.value)
    assert not str(caught.value).startswith(NETWORK_UNAVAILABLE_MARKER)


def test_each_explicit_get_has_one_network_retry_budget(remote):
    client = ScriptedClient([network_failure(), PAYLOAD, network_failure(), PAYLOAD])
    remote.get(client)
    remote.get(client)
    assert len(client.requests) == 4
    assert remote.content_bytes() == PAYLOAD
