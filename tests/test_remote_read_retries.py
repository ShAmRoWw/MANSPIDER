import logging

import pytest
from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.smbconnection import SessionError

import man_spider.lib.file as file_module
from man_spider.lib.errors import FileChangedDuringRead, FileRetrievalError
from man_spider.lib.file import RemoteFile
from man_spider.lib.util import Target


class Snapshots:
    def __init__(self, snapshots):
        self.snapshots = iter(snapshots)
        self.attempts = 0

    def retrieve_file(self, share, path, callback):
        self.attempts += 1
        payload, result = next(self.snapshots)
        callback(payload)
        if isinstance(result, BaseException):
            raise result
        return result

    def handle_impacket_error(self, *args):
        pass


def remote(tmp_path, size=3):
    return RemoteFile("secret.txt", "share", Target("server"), size=size, mtime=10, tmp_dir=tmp_path)


def test_stable_snapshot_is_read_once(tmp_path):
    source = Snapshots([(b"abc", (3, 10, None))])
    file = remote(tmp_path)
    try:
        file.get(source)
        assert source.attempts == 1
        assert file.content_bytes() == b"abc"
        assert file.changed is False
    finally:
        file.cleanup()


def test_one_change_retries_against_new_identity_not_stale_listing(tmp_path):
    source = Snapshots([(b"new", (3, 11, None)), (b"new", (3, 11, None))])
    file = remote(tmp_path)
    try:
        file.get(source)
        assert source.attempts == 2
        assert file.content_bytes() == b"new"
        assert file.post_read_identity == (3, 11, None)
        assert file.changed is True
    finally:
        file.cleanup()


def test_continuously_changing_file_stops_after_three_retries(tmp_path, caplog):
    source = Snapshots([(f"s{n:02}".encode(), (3, 11 + n, None)) for n in range(5)])
    file = remote(tmp_path)
    try:
        with caplog.at_level(logging.WARNING):
            file.get(source)
        assert source.attempts == 4
        assert file.content_bytes() == b"s03"
        assert file.post_read_identity == (3, 14, None)
        assert file.changed is True
        assert "still unstable after 3 retries" in caplog.text
    finally:
        file.cleanup()


@pytest.mark.parametrize("spill", [False, True])
def test_incomplete_reads_are_bounded_and_every_spool_closed(tmp_path, monkeypatch, spill):
    spools = []
    original = file_module._LazyDirectorySpool

    def track_spool(**kwargs):
        spool = original(**kwargs)
        spools.append(spool)
        return spool

    monkeypatch.setattr(file_module, "_LazyDirectorySpool", track_spool)
    source = Snapshots([(b"partial", FileChangedDuringRead("early EOF"))] * 5)
    file = remote(tmp_path, size=10)
    if spill:
        file.memory_spool_limit = 1
    with pytest.raises(FileRetrievalError, match="incomplete after 4 attempts"):
        file.get(source)
    assert source.attempts == 4
    assert len(spools) == 4
    assert all(spool.closed for spool in spools)
    assert file._content is None
    assert file.retrieved_size is None
    assert list(tmp_path.iterdir()) == []


def test_partial_attempt_never_prefixes_the_retried_snapshot(tmp_path):
    source = Snapshots([(b"stale-prefix", FileChangedDuringRead("early EOF")), (b"new", (3, 10, None))])
    file = remote(tmp_path)
    try:
        file.get(source)
        assert source.attempts == 2
        assert file.content_bytes() == b"new"
        assert file.retrieved_size == 3
    finally:
        file.cleanup()


def test_last_complete_snapshot_survives_exhausted_incomplete_retries(tmp_path, caplog):
    source = Snapshots([(b"new", (3, 11, None))] + [(b"incomplete", FileChangedDuringRead("early EOF"))] * 4)
    file = remote(tmp_path)
    try:
        with caplog.at_level(logging.WARNING):
            file.get(source)
        assert source.attempts == 4
        assert file.content_bytes() == b"new"
        assert file.post_read_identity == (3, 11, None)
        assert file.changed is True
        assert "last complete snapshot retained" in caplog.text
    finally:
        file.cleanup()


@pytest.mark.parametrize("error", [OSError("access denied"), KeyboardInterrupt()])
def test_non_change_errors_do_not_trigger_repeated_reads(tmp_path, error):
    source = Snapshots([(b"partial", error)])
    file = remote(tmp_path)
    with pytest.raises(FileRetrievalError if isinstance(error, Exception) else KeyboardInterrupt):
        file.get(source)
    assert source.attempts == 1
    assert file._content is None


def test_smb_access_denied_retrieval_is_durably_tagged(tmp_path):
    source = Snapshots([(b"", SessionError(STATUS_ACCESS_DENIED))])
    file = remote(tmp_path)

    with pytest.raises(FileRetrievalError, match=r"\[network_access_denied\].*STATUS_ACCESS_DENIED"):
        file.get(source)

    assert source.attempts == 1
    assert file._content is None


def test_real_empty_file_growth_is_detected_but_unspecified_size_is_not_stale(tmp_path):
    source = Snapshots([(b"new", (3, 10, None)), (b"new", (3, 10, None))])
    file = remote(tmp_path, size=0)
    try:
        file.get(source)
        assert source.attempts == 2
        assert file.changed is True
    finally:
        file.cleanup()


def test_listing_fallback_detects_same_size_change_before_parsing(tmp_path):
    from types import SimpleNamespace

    class Source(Snapshots):
        listings = 0

        def ls(self, share, directory):
            self.listings += 1
            return [
                SimpleNamespace(
                    is_directory=lambda: False,
                    get_longname=lambda: "secret.txt",
                    get_filesize=lambda: 3,
                    get_mtime_epoch=lambda: 11,
                )
            ]

    source = Source([(b"new", None), (b"new", None)])
    file = remote(tmp_path)
    try:
        file.get(source)
        assert source.attempts == source.listings == 2
        assert file.post_read_identity == (3, 11, None)
        assert file.changed is True
    finally:
        file.cleanup()


def test_listing_fallback_and_early_eof_share_one_retry_budget(tmp_path):
    from types import SimpleNamespace

    class Source(Snapshots):
        def ls(self, share, directory):
            return [
                SimpleNamespace(
                    is_directory=lambda: False,
                    get_longname=lambda: "secret.txt",
                    get_filesize=lambda: 3,
                    get_mtime_epoch=lambda: 10 + self.attempts,
                )
            ]

    source = Source(
        [
            (b"partial", FileChangedDuringRead("early EOF")),
            (b"new", None),
            (b"new", None),
            (b"new", None),
            (b"new", None),
        ]
    )
    file = remote(tmp_path)
    try:
        file.get(source)
        assert source.attempts == 4
        assert file.content_bytes() == b"new"
        assert file.post_read_identity == (3, 14, None)
    finally:
        file.cleanup()


def test_unavailable_metadata_reads_once_and_never_verifies_after_parser(tmp_path, caplog):
    from types import SimpleNamespace
    from man_spider.lib.spiderling import Spiderling

    class Source(Snapshots):
        listings = 0

        def ls(self, share, directory):
            self.listings += 1
            if self.listings > 1:
                pytest.fail("verification must not be deferred until after parsing")
            raise OSError("directory listing denied")

    source = Source([(b"abc", None)])
    file = remote(tmp_path)
    worker = Spiderling.__new__(Spiderling)
    worker.smb_client = source
    worker.target = Target("server")
    worker.parent = SimpleNamespace(state_path=None)
    try:
        with caplog.at_level(logging.WARNING):
            file.get(source)
            worker.verify_remote_files("share", "", [file])
        assert source.attempts == source.listings == 1
        assert file.content_bytes() == b"abc"
        assert file.post_read_identity is None
        assert file.post_read_verification_finalized is True
        assert file.post_read_verification_failed is True
        assert file.changed is True
        assert "post-read metadata unavailable" in caplog.text
        assert "retained as unverified" in caplog.text
    finally:
        file.cleanup()


def test_unavailable_metadata_does_not_hide_an_observed_size_change(tmp_path):
    class Source(Snapshots):
        listings = 0

        def ls(self, share, directory):
            self.listings += 1
            raise OSError("directory listing denied")

    source = Source([(b"abcd", None), (b"abcd", None)])
    file = remote(tmp_path)
    try:
        file.get(source)
        assert source.attempts == source.listings == 2
        assert file.content_bytes() == b"abcd"
        assert file.changed is True
        assert file.post_read_verification_failed is True
    finally:
        file.cleanup()


def test_malformed_wrapper_identity_does_not_leak_current_spool(tmp_path, monkeypatch):
    original = file_module._LazyDirectorySpool
    spools = []

    def track_spool(**kwargs):
        spool = original(**kwargs)
        spools.append(spool)
        return spool

    monkeypatch.setattr(file_module, "_LazyDirectorySpool", track_spool)
    source = Snapshots([(b"abc", (3,))])
    file = remote(tmp_path)
    with pytest.raises(FileRetrievalError):
        file.get(source)
    assert source.attempts == 1
    assert len(spools) == 1 and spools[0].closed
    assert file._content is None
