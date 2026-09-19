import errno
import os
import pickle
import stat
from contextlib import contextmanager

import pytest

import man_spider.lib.file as file_module
from man_spider.lib.errors import FileRetrievalError
from man_spider.lib.file import RemoteFile
from man_spider.lib.localfs import loot_storage_file, prepare_loot_root
from man_spider.lib.util import Target


class RetrievalClient:
    def __init__(self, payload=b"complete secret=value", *, failure=None):
        self.payload = payload
        self.failure = failure
        self.requests = []
        self.errors = []

    def retrieve_file(self, share, name, callback):
        self.requests.append((share, name))
        callback(self.payload[:3])
        callback(self.payload[3:])
        if self.failure is not None:
            raise self.failure
        return (len(self.payload), 12345, None)

    def handle_impacket_error(self, *args):
        self.errors.append(args)


def make_remote(tmp_path, **kwargs):
    return RemoteFile("folder/secret.txt", "share", Target("server"), tmp_dir=tmp_path, **kwargs)


def test_in_memory_lifecycle_has_no_local_metadata_syscalls(monkeypatch, tmp_path):
    calls = []

    def unexpected_syscall(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("bytes-only retrieval must not touch temporary filesystem paths")

    client = RetrievalClient()
    with monkeypatch.context() as patch:
        patch.setattr(os, "mkdir", unexpected_syscall)
        patch.setattr(os, "stat", unexpected_syscall)
        patch.setattr(os, "unlink", unexpected_syscall)
        remote = make_remote(tmp_path)
        assert remote.retrieved_size is None
        remote.get(client)
        assert remote.content_bytes() == client.payload
        assert remote.retrieved_size == len(client.payload)
        assert remote.post_read_identity == (len(client.payload), 12345, None)
        remote.cleanup()
        remote.cleanup()
        assert remote.retrieved_size is None
    assert calls == []
    assert client.requests == [("share", "folder/secret.txt")]
    assert client.errors == []


def test_legacy_lifecycle_fixture_confirms_five_avoided_syscall_attempts(monkeypatch, tmp_path):
    """Model the previous Path operations with real Path methods and fake OS calls."""

    calls = {"mkdir": 0, "stat": 0, "unlink": 0}

    def mkdir(*args, **kwargs):
        calls["mkdir"] += 1
        raise FileExistsError(errno.EEXIST, "directory already exists")

    def metadata(*args, **kwargs):
        calls["stat"] += 1
        return os.stat_result((stat.S_IFDIR | 0o700, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    def unlink(*args, **kwargs):
        calls["unlink"] += 1
        raise FileNotFoundError(errno.ENOENT, "named temporary file never existed")

    with monkeypatch.context() as patch:
        patch.setattr(os, "mkdir", mkdir)
        patch.setattr(os, "stat", metadata)
        patch.setattr(os, "unlink", unlink)
        tmp_path.mkdir(parents=True, exist_ok=True)
        for _ in range(3):
            (tmp_path / "legacy-name.txt").unlink(missing_ok=True)
    assert calls == {"mkdir": 1, "stat": 1, "unlink": 3}


def test_missing_temporary_directory_stays_absent_for_bytes_only_retrieval(tmp_path):
    directory = tmp_path / "missing" / "nested"
    remote = make_remote(directory)
    client = RetrievalClient()
    remote.get(client)
    assert remote.content_bytes() == client.payload
    remote.cleanup()
    assert not directory.exists()


def test_unexposed_remote_file_pickle_retains_lazy_lifecycle(tmp_path):
    directory = tmp_path / "missing"
    remote = make_remote(directory)
    restored = pickle.loads(pickle.dumps(remote))
    assert restored.__dict__ == remote.__dict__
    assert restored._tmp_filename is None
    restored.cleanup()
    restored.get(RetrievalClient())
    restored.cleanup()
    assert not directory.exists()


def test_rollover_directory_failure_closes_spool_and_preserves_retrieval_error(monkeypatch, tmp_path):
    remote = make_remote(tmp_path / "missing")
    remote.memory_spool_limit = 8
    client = RetrievalClient()
    spools = []
    original = file_module._LazyDirectorySpool

    def spool(**kwargs):
        value = original(**kwargs)
        spools.append(value)
        return value

    @contextmanager
    def denied(*args, **kwargs):
        raise PermissionError("temporary directory denied")
        yield

    monkeypatch.setattr(file_module, "_LazyDirectorySpool", spool)
    monkeypatch.setattr(file_module, "local_directory_descriptor", denied)
    with pytest.raises(FileRetrievalError, match="temporary directory denied"):
        remote.get(client)
    assert len(spools) == 1 and spools[0].closed
    assert len(client.requests) == 1
    assert len(client.errors) == 1
    assert remote._content is None
    remote.cleanup()


@pytest.mark.parametrize("force_fileno", (False, True))
def test_missing_temporary_directory_is_created_for_rollover(tmp_path, force_fileno):
    directory = tmp_path / "missing" / "nested"
    remote = make_remote(directory)
    remote.memory_spool_limit = 1024 if force_fileno else 8
    client = RetrievalClient()
    remote.get(client)
    if force_fileno:
        assert not directory.exists()
        remote._content.fileno()
    assert directory.is_dir()
    assert remote._content._rolled is True
    assert remote.content_bytes() == client.payload
    assert remote.retrieved_size == len(client.payload)
    assert client.requests == [("share", "folder/secret.txt")]
    remote.cleanup()
    remote.cleanup()
    assert list(directory.iterdir()) == []


def test_rollover_prepares_directory_only_once(monkeypatch, tmp_path):
    remote = make_remote(tmp_path)
    remote.get(RetrievalClient())
    calls = []
    original_directory_descriptor = file_module.local_directory_descriptor

    @contextmanager
    def directory_descriptor(path, *args, **kwargs):
        calls.append(path)
        with original_directory_descriptor(path, *args, **kwargs) as value:
            yield value

    monkeypatch.setattr(file_module, "local_directory_descriptor", directory_descriptor)
    remote._content.fileno()
    remote._content.fileno()
    remote._content.rollover()
    assert calls == [tmp_path]
    remote.cleanup()


def test_cleanup_never_reclaims_a_path_after_its_owned_inode_was_removed(tmp_path):
    remote = make_remote(tmp_path / "missing")
    retained_path = remote.tmp_filename
    assert retained_path.suffix == ".txt"
    assert retained_path == remote.tmp_filename
    retained_path.write_bytes(b"custom extractor bytes")
    assert remote.retrieved_size == len(b"custom extractor bytes")
    assert remote.content_bytes() == b"custom extractor bytes"
    remote.cleanup()
    assert not retained_path.exists()
    retained_path.write_bytes(b"custom extractor writes through retained Path")
    remote.cleanup()
    assert retained_path.read_bytes() == b"custom extractor writes through retained Path"


def test_assigned_public_path_is_limited_to_the_owned_spool_directory(tmp_path):
    root = tmp_path / "owned"
    remote = make_remote(root)
    outside = tmp_path / "outside" / "input.bin"
    with pytest.raises(FileRetrievalError, match="directly below"):
        remote.tmp_filename = outside
    assert not outside.exists()

    override = root / "input.bin"
    remote.tmp_filename = override
    remote.tmp_filename.write_bytes(b"preexisting downloaded bytes")
    assert remote.content_bytes() == b"preexisting downloaded bytes"
    assert remote.materialize() == override
    client = RetrievalClient()
    remote.memory_spool_limit = 8
    remote.get(client)
    assert not override.exists()
    assert remote.content_bytes() == client.payload
    assert remote._content._rolled is True
    remote.cleanup()


@pytest.mark.parametrize("spill", (False, True))
def test_materialization_preserves_all_bytes_and_spool_cursor(tmp_path, spill):
    remote = make_remote(tmp_path / "missing")
    if spill:
        remote.memory_spool_limit = 8
    client = RetrievalClient(bytes(range(256)))
    remote.get(client)
    remote._content.seek(7)
    path = remote.materialize()
    assert path.read_bytes() == client.payload
    assert remote.materialize() == path
    assert remote._content.tell() == 7
    assert remote.content_bytes() == client.payload
    assert remote._content.tell() == 7
    assert len(client.requests) == 1
    remote.cleanup()
    assert not path.exists()


@pytest.mark.parametrize("materialized", (False, True))
def test_arbitrary_save_is_disabled_and_guarded_copy_preserves_bytes(tmp_path, materialized):
    remote = make_remote(tmp_path / "temporary")
    client = RetrievalClient(bytes(range(256)))
    remote.get(client)
    remote._content.seek(11)
    path = remote.materialize() if materialized else None
    destination = tmp_path / "loot.bin"
    with pytest.raises(FileRetrievalError, match=r"save_to\(\) is disabled"):
        remote.save_to(destination)
    with destination.open("wb") as output:
        with pytest.raises(OSError, match="guarded local loot writer"):
            remote.copy_to(output)
    root = prepare_loot_root(tmp_path / "loot")
    destination = root / "server" / "share" / "loot.bin"
    with loot_storage_file(root, destination) as output:
        remote.copy_to(output)
    assert destination.read_bytes() == client.payload
    assert remote._content.tell() == 11
    assert len(client.requests) == 1
    if path is not None:
        assert path.exists()
    else:
        assert remote._tmp_filename is None
        assert not (tmp_path / "temporary").exists()
    remote.cleanup()
    assert destination.read_bytes() == client.payload


@pytest.mark.parametrize("failure", (OSError("network disconnected"), KeyboardInterrupt(), SystemExit(1)))
@pytest.mark.parametrize("spill", (False, True))
def test_failed_retrieval_closes_spool_without_leaving_temporary_files(monkeypatch, tmp_path, failure, spill):
    remote = make_remote(tmp_path)
    if spill:
        remote.memory_spool_limit = 8
    spools = []
    original_init = file_module._LazyDirectorySpool.__init__

    def initialize(spool, **kwargs):
        original_init(spool, **kwargs)
        spools.append(spool)

    monkeypatch.setattr(file_module._LazyDirectorySpool, "__init__", initialize)
    client = RetrievalClient(failure=failure)
    expected = FileRetrievalError if isinstance(failure, Exception) else type(failure)
    with pytest.raises(expected):
        remote.get(client)
    assert len(spools) == 1
    assert spools[0].closed
    assert remote._content is None
    assert remote.retrieved_size is None
    assert len(client.requests) == 1
    assert len(client.errors) == int(isinstance(failure, Exception))
    remote.cleanup()
    assert list(tmp_path.iterdir()) == []


def test_failed_materialization_removes_partial_named_file_and_preserves_spool(monkeypatch, tmp_path):
    remote = make_remote(tmp_path)
    client = RetrievalClient()
    remote.get(client)
    remote._content.seek(9)

    def interrupted_copy(source, destination):
        destination.write(source.read(3))
        raise KeyboardInterrupt

    monkeypatch.setattr(file_module.shutil, "copyfileobj", interrupted_copy)
    with pytest.raises(KeyboardInterrupt):
        remote.materialize()
    assert remote._content.tell() == 9
    assert remote.content_bytes() == client.payload
    assert list(tmp_path.iterdir()) == []
    remote.cleanup()


def test_failed_owned_cleanup_never_deletes_a_later_replacement(monkeypatch, tmp_path):
    remote = make_remote(tmp_path)
    path = remote.tmp_filename
    path.write_bytes(b"temporary")
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_bytes(b"preserve")
    original_unlink = file_module.os.unlink

    def denied(candidate, *args, **kwargs):
        if candidate == path.name:
            raise PermissionError("fixture denied")
        return original_unlink(candidate, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(file_module.os, "unlink", denied)
        with pytest.raises(PermissionError, match="fixture denied"):
            remote.cleanup()
    assert path.exists()
    remote.cleanup()
    assert path.exists()
    assert unrelated.read_bytes() == b"preserve"


def test_materialize_without_retrieved_or_external_content_reports_error_without_disk_work(tmp_path):
    directory = tmp_path / "missing"
    remote = make_remote(directory)
    with pytest.raises(FileRetrievalError, match="Retrieved content is unavailable"):
        remote.materialize()
    assert not directory.exists()


def test_tmp_filename_setter_never_claims_or_deletes_a_preexisting_file(tmp_path):
    root = tmp_path / "owned"
    root.mkdir()
    victim = root / "victim.txt"
    victim.write_bytes(b"PRESERVE")
    remote = make_remote(root)

    with pytest.raises(FileRetrievalError, match="reserve private temporary file"):
        remote.tmp_filename = victim
    remote.cleanup()

    assert victim.read_bytes() == b"PRESERVE"


def test_cleanup_preserves_a_replaced_or_hardlinked_temp_inode(tmp_path):
    root = tmp_path / "owned"
    remote = make_remote(root)
    path = remote.tmp_filename
    path.write_bytes(b"OWNED")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"PRESERVE")
    path.unlink()
    path.hardlink_to(outside)

    with pytest.raises(FileRetrievalError, match="changed before cleanup"):
        remote.cleanup()

    assert outside.read_bytes() == b"PRESERVE"
    assert path.read_bytes() == b"PRESERVE"


def test_remote_controlled_suffix_cannot_create_an_ads_or_device_name(tmp_path):
    remote = RemoteFile(r"folder\image.pdf::$DATA", "share", Target("server"), tmp_dir=tmp_path)
    path = remote.tmp_filename
    try:
        assert path.parent == tmp_path
        assert path.suffix == ".bin"
        assert ":" not in path.name
    finally:
        remote.cleanup()


def test_successive_retrievals_replace_spool_and_do_not_reuse_old_bytes(tmp_path):
    remote = make_remote(tmp_path)
    first = RetrievalClient(b"first complete bytes")
    second = RetrievalClient(b"second complete bytes")
    remote.get(first)
    previous_spool = remote._content
    remote.get(second)
    assert previous_spool.closed
    assert remote.content_bytes() == second.payload
    assert remote.retrieved_size == len(second.payload)
    assert len(first.requests) == len(second.requests) == 1
    remote.cleanup()
