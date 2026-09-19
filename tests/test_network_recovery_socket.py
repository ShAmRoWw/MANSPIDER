"""Real loopback SMB reads with a forced client TCP disconnect mid-file."""

import socket

import pytest

from man_spider.lib.errors import FileRetrievalError, NETWORK_UNAVAILABLE_MARKER
from man_spider.lib.file import RemoteFile
from man_spider.lib.smb import SMBClient
from man_spider.lib.util import Target
from test_smb_integration import SMBTestServer, get_free_port


@pytest.mark.parametrize("failed_connections", [1, 2])
def test_real_tcp_break_restarts_once_without_changing_source(tmp_path, monkeypatch, failed_connections):
    share = tmp_path / "share"
    share.mkdir()
    source = share / "secret.txt"
    payload = b"password=synthetic-fixture\n" * 4
    source.write_bytes(payload)
    before = source.stat()
    server = SMBTestServer(str(share), get_free_port())
    client = SMBClient("127.0.0.1", "", "", "", "", port=server.port)
    remote = RemoteFile("secret.txt", "testshare", Target("127.0.0.1", server.port),
                        size=len(payload), tmp_dir=tmp_path / "spool")
    offsets = []
    installs = []
    original_install = client._install_connection

    def instrument(connection):
        original_install(connection)
        installs.append(connection)
        number = len(installs)
        native = connection.getSMBServer()
        native._Connection["MaxReadSize"] = 16
        original_read = native.read

        def read(tree, file, offset, size):
            offsets.append((number, offset))
            result = original_read(tree, file, offset, size)
            if number <= failed_connections and offset == 0:
                # The first chunk really arrived over TCP. Shut down only our
                # captured socket; the next guarded SMB exchange detects loss.
                native.get_socket().shutdown(socket.SHUT_RDWR)
            return result

        monkeypatch.setattr(native, "read", read)

    monkeypatch.setattr(client, "_install_connection", instrument)
    server.start()
    try:
        assert client.login(first_try=False) is True
        if failed_connections == 1:
            remote.get(client)
            assert remote.content_bytes() == payload
            assert remote.retrieved_size == len(payload)
            assert client._network_recovery.failures == 0
        else:
            with pytest.raises(FileRetrievalError, match=NETWORK_UNAVAILABLE_MARKER.replace("[", r"\[")):
                remote.get(client)
            assert remote._content is None
            assert remote.retrieved_size is None
        assert len(installs) == 2
        assert [number for number, offset in offsets if offset == 0] == [1, 2]
        assert remote.content_read is True
    finally:
        remote.cleanup()
        client.close()
        server.stop()
    assert source.read_bytes() == payload
    after = source.stat()
    assert (after.st_size, after.st_mtime_ns, after.st_mode) == (before.st_size, before.st_mtime_ns, before.st_mode)
    assert [path.name for path in share.iterdir()] == ["secret.txt"]
