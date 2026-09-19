"""
SMB integration test using impacket's SimpleSMBServer.

This test:
1. Spins up a local SMB server on a high port (no root needed)
2. Populates it with test files
3. Verifies we can connect and list files via SMB client
4. Runs MANSPIDER against the server and verifies content extraction
"""

import shutil
import socket
import threading
import time
from argparse import Namespace
from pathlib import Path

import pytest
from impacket import smb as smb_protocol
from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection
from impacket.smbserver import SimpleSMBServer
from impacket.smb3structs import SMB2_DIALECT_002

from man_spider.lib.smb import SMBClient
from man_spider.lib.file import RemoteFile
from man_spider.lib.util import Target
from tests.optional_fixtures import require_private_directory


def get_free_port() -> int:
    """Find a free port to use for the SMB server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SMBTestServer:
    """Simple wrapper around impacket's SimpleSMBServer for testing."""

    def __init__(self, share_path: str, port: int, *, smb2_support: bool = True):
        self.share_path = share_path
        self.port = port
        self.smb2_support = smb2_support
        self.server = None
        self.thread = None

    def start(self):
        """Start the SMB server in a background thread."""
        self.server = SimpleSMBServer(
            listenAddress="127.0.0.1",
            listenPort=self.port,
        )
        self.server.setSMB2Support(self.smb2_support)
        self.server.addShare("testshare", self.share_path, "Test Share")

        self.thread = threading.Thread(target=self.server.start, daemon=True)
        self.thread.start()
        time.sleep(0.5)  # Give server time to start

    def stop(self):
        """Stop the SMB server."""
        if self.server:
            self.server.stop()


@pytest.fixture(scope="module")
def smb_server(tmp_path_factory):
    """
    Fixture that spins up an SMB server with test files.

    Uses module scope so the server is started once and shared across all tests.

    Yields:
        tuple: (SMBTestServer instance, Path to share directory)
    """
    require_private_directory("testdata")
    # Create share directory
    tmp_path = tmp_path_factory.mktemp("smb")
    share_path = tmp_path / "share"
    share_path.mkdir()

    # Copy a subset of test files to the share
    testdata = Path(__file__).parent.parent / "testdata"
    test_files = ["test.docx", "test.pdf", "test-utf8.txt"]

    for filename in test_files:
        src = testdata / filename
        if src.exists():
            shutil.copy(src, share_path / filename)

    # Start server on a free port
    port = get_free_port()
    server = SMBTestServer(str(share_path), port=port)
    server.start()

    yield server, share_path

    # Cleanup
    server.stop()


@pytest.fixture(scope="module")
def smb1_server(tmp_path_factory):
    """Expose a real SMB1-only endpoint for the compatibility fallback."""

    share_path = tmp_path_factory.mktemp("smb1") / "share"
    share_path.mkdir()
    (share_path / "legacy-secret.txt").write_bytes(b"Password123 from the SMB1 compatibility fixture\n")
    server = SMBTestServer(str(share_path), port=get_free_port(), smb2_support=False)
    server.start()

    yield server, share_path

    server.stop()


class TestSMBServer:
    """Tests for the SMB server infrastructure."""

    def test_server_starts_and_has_files(self, smb_server):
        """Verify the SMB server starts and has files."""
        server, share_path = smb_server

        # Verify server is running (thread is alive)
        assert server.thread is not None
        assert server.thread.is_alive()

        # Verify test files exist in share
        assert (share_path / "test.docx").exists()
        assert (share_path / "test.pdf").exists()
        assert (share_path / "test-utf8.txt").exists()

    def test_client_can_connect_and_list_shares(self, smb_server):
        """Verify we can connect to the SMB server and list shares."""
        server, share_path = smb_server

        # Connect to the server
        conn = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=server.port, timeout=5)
        conn.login("", "")  # Anonymous login

        # List shares
        shares = conn.listShares()
        share_names = [share["shi1_netname"].rstrip("\x00").lower() for share in shares]

        assert "testshare" in share_names

        conn.close()

    def test_client_can_list_files(self, smb_server):
        """Verify we can list files in the share."""
        server, share_path = smb_server

        # Connect to the server
        conn = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=server.port, timeout=5)
        conn.login("", "")  # Anonymous login

        # List files in share
        conn.connectTree("testshare")
        files = conn.listPath("testshare", "*")
        filenames = [f.get_longname() for f in files if f.get_longname() not in (".", "..")]

        assert "test.docx" in filenames
        assert "test.pdf" in filenames
        assert "test-utf8.txt" in filenames

        conn.close()

    def test_smb2_retrieval_returns_post_read_identity_from_close(self, smb_server):
        server, share_path = smb_server
        client = SMBClient("127.0.0.1", "", "", "", "", port=server.port)
        assert client.login(first_try=False) is True
        assert client.conn.getDialect() == SMB2_DIALECT_002
        payload = bytearray()
        try:
            with client.pin_share("testshare"):
                identity = client.retrieve_file("testshare", "test-utf8.txt", payload.extend)
        finally:
            client.close()

        assert bytes(payload) == (share_path / "test-utf8.txt").read_bytes()
        assert identity is not None
        assert identity[0] == len(payload)
        assert isinstance(identity[1], float)
        assert identity[2] is None

    def test_smb1_retrieval_opens_read_only_without_oplock(self, smb1_server, monkeypatch):
        server, share_path = smb1_server
        client = SMBClient("127.0.0.1", "", "", "", "", port=server.port)
        assert client.login(first_try=False) is True
        assert client.conn.getDialect() == SMB_DIALECT
        native = object.__getattribute__(client, "_SMBClient__connection").getSMBServer()
        original_send = native.sendSMB
        opens = []

        def observe_send(packet):
            if packet["Command"] == smb_protocol.SMB.SMB_COM_NT_CREATE_ANDX:
                parsed = smb_protocol.NewSMBPacket(data=packet.getData())
                command = smb_protocol.SMBCommand(parsed["Data"][0])
                fields = smb_protocol.SMBNtCreateAndX_Parameters(command["Parameters"])
                opens.append(
                    (fields["CreateFlags"], fields["AccessMask"], fields["ShareAccess"], fields["Disposition"])
                )
            return original_send(packet)

        monkeypatch.setattr(native, "sendSMB", observe_send)
        payload = bytearray()
        try:
            with client.pin_share("testshare"):
                identity = client.retrieve_file("testshare", "legacy-secret.txt", payload.extend)
        finally:
            client.close()

        assert identity is not None
        assert identity[0] == len(payload)
        assert opens == [(0, 0x20089, 7, 1)]
        assert bytes(payload) == (share_path / "legacy-secret.txt").read_bytes()

    def test_smb1_file_truncated_after_size_query_has_bounded_recovery(self, smb1_server, monkeypatch):
        server, share_path = smb1_server
        path = share_path / "truncate-during-read.txt"
        path.write_bytes(b"original-content")
        client = SMBClient("127.0.0.1", "", "", "", "", port=server.port)
        assert client.login(first_try=False) is True
        native = object.__getattribute__(client, "_SMBClient__connection").getSMBServer()
        original_query = native.query_file_info
        initial_queries = []

        def truncate_once(tree, handle, info_class=smb_protocol.SMB_QUERY_FILE_STANDARD_INFO):
            result = original_query(tree, handle, info_class)
            if info_class == smb_protocol.SMB_QUERY_FILE_STANDARD_INFO:
                initial_queries.append(1)
                if len(initial_queries) == 1:
                    # Modify only this test's local fixture, never via SMB.
                    path.write_bytes(b"")
            return result

        monkeypatch.setattr(native, "query_file_info", truncate_once)
        remote = RemoteFile(path.name, "testshare", Target("127.0.0.1", server.port), size=len(b"original-content"))
        try:
            remote.get(client)
            assert remote.content_bytes() == b""
            assert remote.changed is True
            assert 2 <= len(initial_queries) <= 4
        finally:
            remote.cleanup()
            client.close()
            path.unlink()


def create_test_options(targets, loot_dir, **kwargs) -> Namespace:
    """Create an options Namespace matching MANSPIDER's expected structure."""
    defaults = {
        "targets": targets,
        "username": "",
        "password": "",
        "domain": "",
        "hash": "",
        "loot_dir": str(loot_dir),
        "maxdepth": 10,
        "threads": 1,
        "filenames": [],
        "extensions": [],
        "exclude_extensions": [],
        "content": [],
        "sharenames": [],
        "exclude_sharenames": [],
        "dirnames": [],
        "exclude_dirnames": [],
        "quiet": True,
        "no_download": False,
        "max_failed_logons": None,
        "or_logic": False,
        "max_filesize": 10 * 1024 * 1024,  # 10MB
        "verbose": False,
        "modified_after": None,
        "modified_before": None,
        "kerberos": False,
        "aes_key": None,
        "dc_ip": None,
        "rules": [],
    }
    defaults.update(kwargs)
    return Namespace(**defaults)


@pytest.fixture(scope="module")
def smb_server_full(tmp_path_factory):
    """
    Fixture that spins up an SMB server with ALL test files.

    Uses module scope so the server is started once and shared across all tests.
    """
    require_private_directory("testdata")
    # Create share directory
    tmp_path = tmp_path_factory.mktemp("smb_full")
    share_path = tmp_path / "share"
    share_path.mkdir()

    # Copy ALL test files to the share
    testdata = Path(__file__).parent.parent / "testdata"
    for f in testdata.iterdir():
        if f.is_file():
            shutil.copy(f, share_path / f.name)

    nested = share_path / "unmatched-parent" / "matching-child"
    nested.mkdir(parents=True)
    (nested / "nested-secret.txt").write_text("Password123", encoding="utf-8")

    # Start server on a free port
    port = get_free_port()
    server = SMBTestServer(str(share_path), port=port)
    server.start()

    yield server, share_path

    # Cleanup
    server.stop()


class TestMANSPIDER:
    """Integration tests that run MANSPIDER against the SMB server."""

    # Base names to search for in loot filenames (MANSPIDER removes hyphens and adds prefix)
    # Format: original filename -> pattern to search for in loot filename
    EXPECTED_TEXT_PATTERNS = [
        "testascii",  # test-ascii.txt
        "testutf8.txt",  # test-utf8.txt (exact, no hyphen version)
        "testutf8bom",  # test-utf8-bom.txt
        "testutf16le",  # test-utf16le.txt
        "testutf16be",  # test-utf16be.txt
        "testutf16bom",  # test-utf16-bom.txt
        "testlatin1",  # test-latin1.txt
        "testcp1252",  # test-cp1252.txt
    ]

    EXPECTED_DOCUMENT_PATTERNS = [
        "test.docx",
        "test.pdf",
        "test.xlsx",
        "test.doc",
        "test.xls",
    ]

    EXPECTED_BINARY_PATTERNS = [
        "testbinarysmall",  # test-binary-small.bin
        "testbinarymedium",  # test-binary-medium.bin
        "testbinarylarge",  # test-binary-large.bin
        "testbinarystart",  # test-binary-start.bin
        "testbinaryend",  # test-binary-end.bin
    ]

    def test_live_scan_collects_passive_per_host_smb_metrics(self, smb_server, tmp_path):
        from man_spider.lib.spider import MANSPIDER

        server, _share_path = smb_server
        options = create_test_options(
            targets=[Target("127.0.0.1", server.port)],
            loot_dir=tmp_path / "metrics-loot",
            content=["Password123"],
            extensions=[".txt"],
            sharenames=["testshare"],
            exclude_sharenames=["IPC$"],
            no_download=True,
        )
        scanner = MANSPIDER(options)

        scanner.start()
        report = scanner.smb_metrics.report(
            run_id="integration",
            run_status="complete",
            state_path=tmp_path / "scan.sqlite3",
        )

        assert report["automatic_throttling"] is False
        assert report["totals"]["hosts"] == 1
        host = report["hosts"][0]
        assert host["host"] == "127.0.0.1"
        assert host["port"] == server.port
        assert host["operation_details"]["directory_list"]["attempts"] >= 1
        assert host["operation_details"]["file_read"]["bytes_transferred"] > 0
        assert host["sessions_opened"] == host["sessions_closed"] == 1

    def test_smb1_pipeline_finds_content_and_preserves_remote_file(self, smb1_server, tmp_path):
        from man_spider.lib.spider import MANSPIDER

        server, share_path = smb1_server
        source = share_path / "legacy-secret.txt"
        before = (source.read_bytes(), source.stat().st_mode, source.stat().st_mtime_ns)
        loot_dir = tmp_path / "smb1-loot"
        options = create_test_options(
            targets=[Target("127.0.0.1", server.port)],
            loot_dir=loot_dir,
            content=["Password123"],
            extensions=[".txt"],
            sharenames=["testshare"],
            exclude_sharenames=["IPC$"],
        )

        MANSPIDER(options).start()

        copies = list(loot_dir.rglob("legacy-secret.txt"))
        assert len(copies) == 1
        assert copies[0].read_bytes() == before[0]
        assert (source.read_bytes(), source.stat().st_mode, source.stat().st_mtime_ns) == before

    def _find_matching_files(self, loot_dir, patterns, extension):
        """Check if loot files contain expected patterns."""
        loot_files = [f.name.lower() for f in loot_dir.rglob(f"*{extension}")]
        found = set()
        for pattern in patterns:
            pattern_lower = pattern.lower()
            for loot_file in loot_files:
                normalized_pattern = "".join(character for character in pattern_lower if character.isalnum())
                normalized_filename = "".join(character for character in loot_file if character.isalnum())
                if pattern_lower in loot_file or normalized_pattern in normalized_filename:
                    found.add(pattern)
                    break
        return found

    def test_manspider_finds_password_in_all_text_files(self, smb_server_full, tmp_path):
        """MANSPIDER finds Password123 in ALL text encoding variants."""
        from man_spider.lib.spider import MANSPIDER

        server, share_path = smb_server_full
        loot_dir = tmp_path / "loot"
        loot_dir.mkdir()

        target = Target("127.0.0.1", server.port)

        options = create_test_options(
            targets=[target],
            loot_dir=loot_dir,
            content=["Password123"],
            extensions=[".txt"],
            exclude_sharenames=["IPC$"],  # Exclude IPC$ to avoid local file access
        )

        spider = MANSPIDER(options)
        spider.start()

        # Check that ALL expected text files were found
        found = self._find_matching_files(loot_dir, self.EXPECTED_TEXT_PATTERNS, ".txt")
        missing = set(self.EXPECTED_TEXT_PATTERNS) - found
        assert not missing, f"Missing text patterns: {missing}. Found: {list(loot_dir.rglob('*.txt'))}"

    def test_manspider_finds_password_in_all_document_files(self, smb_server_full, tmp_path):
        """MANSPIDER finds Password123 in ALL document formats (docx, pdf, xlsx, doc, xls)."""
        from man_spider.lib.spider import MANSPIDER

        server, share_path = smb_server_full
        loot_dir = tmp_path / "loot"
        loot_dir.mkdir()

        target = Target("127.0.0.1", server.port)

        options = create_test_options(
            targets=[target],
            loot_dir=loot_dir,
            content=["Password123"],
            extensions=[".docx", ".pdf", ".xlsx", ".doc", ".xls"],
            exclude_sharenames=["IPC$"],
        )

        spider = MANSPIDER(options)
        spider.start()

        # Check that ALL expected document files were found
        all_found = set()
        for ext in [".docx", ".pdf", ".xlsx", ".doc", ".xls"]:
            patterns = [p for p in self.EXPECTED_DOCUMENT_PATTERNS if p.endswith(ext)]
            all_found.update(self._find_matching_files(loot_dir, patterns, ext))

        missing = set(self.EXPECTED_DOCUMENT_PATTERNS) - all_found
        assert not missing, f"Missing document patterns: {missing}. Found: {list(loot_dir.rglob('*'))}"

    def test_directory_include_does_not_prune_an_unmatched_parent(self, smb_server_full, tmp_path):
        from man_spider.lib.spider import MANSPIDER

        server, _share_path = smb_server_full
        loot_dir = tmp_path / "loot"
        loot_dir.mkdir()
        options = create_test_options(
            targets=[Target("127.0.0.1", server.port)],
            loot_dir=loot_dir,
            content=["Password123"],
            extensions=[".txt"],
            dirnames=["matching-child"],
            exclude_sharenames=["IPC$"],
        )

        MANSPIDER(options).start()

        found = self._find_matching_files(loot_dir, ["nestedsecret"], ".txt")
        assert found == {"nestedsecret"}
        assert (
            loot_dir
            / f"127.0.0.1_port-{server.port}"
            / "TESTSHARE"
            / "unmatched-parent"
            / "matching-child"
            / "nested-secret.txt"
        ).is_file()

    def test_remote_scan_does_not_modify_server_files_or_metadata(self, smb_server_full, tmp_path):
        from man_spider.lib.spider import MANSPIDER

        server, share_path = smb_server_full

        def snapshot():
            return {
                str(path.relative_to(share_path)): (
                    path.read_bytes(),
                    stat.S_IMODE(path.stat().st_mode),
                    path.stat().st_mtime_ns,
                )
                for path in share_path.rglob("*")
                if path.is_file()
            }

        import stat

        before = snapshot()
        options = create_test_options(
            targets=[Target("127.0.0.1", server.port)],
            loot_dir=tmp_path / "readonly-loot",
            content=["Password123"],
            extensions=[".txt"],
            exclude_sharenames=["IPC$"],
        )
        MANSPIDER(options).start()
        after = snapshot()

        assert after == before

    def test_manspider_finds_password_in_all_binary_files(self, smb_server_full, tmp_path):
        """MANSPIDER finds Password123 in ALL binary files with embedded text."""
        from man_spider.lib.spider import MANSPIDER

        server, share_path = smb_server_full
        loot_dir = tmp_path / "loot"
        loot_dir.mkdir()

        target = Target("127.0.0.1", server.port)

        options = create_test_options(
            targets=[target],
            loot_dir=loot_dir,
            content=["Password123"],
            extensions=[".bin"],
            exclude_sharenames=["IPC$"],
        )

        spider = MANSPIDER(options)
        spider.start()

        # Check that ALL expected binary files were found
        found = self._find_matching_files(loot_dir, self.EXPECTED_BINARY_PATTERNS, ".bin")
        missing = set(self.EXPECTED_BINARY_PATTERNS) - found
        assert not missing, f"Missing binary patterns: {missing}. Found: {list(loot_dir.rglob('*.bin'))}"

    def test_native_rule_respects_download_policy_and_preserves_remote_bytes(self, smb_server_full, tmp_path):
        from man_spider.lib.spider import MANSPIDER

        server, share_path = smb_server_full
        target = Target("127.0.0.1", server.port)
        rules = [
            {
                "id": "native-rule-loot",
                "match": {
                    "condition": "all",
                    "predicates": [{"field": "filename", "operator": "exact", "value": "test-utf8.txt"}],
                },
                "actions": [
                    {
                        "type": "scan",
                        "representation": "text",
                        "pattern": "Password123",
                        "flags": [],
                    }
                ],
            }
        ]

        enabled_loot = tmp_path / "enabled-loot"
        enabled_options = create_test_options(
            targets=[target],
            loot_dir=enabled_loot,
            rules=rules,
            exclude_sharenames=["IPC$"],
        )
        MANSPIDER(enabled_options).start()

        destination = enabled_loot / f"127.0.0.1_port-{server.port}" / "TESTSHARE" / "test-utf8.txt"
        assert destination.read_bytes() == (share_path / "test-utf8.txt").read_bytes()
        assert [path for path in enabled_loot.rglob("*") if path.is_file()] == [destination]

        disabled_loot = tmp_path / "disabled-loot"
        disabled_options = create_test_options(
            targets=[target],
            loot_dir=disabled_loot,
            rules=rules,
            no_download=True,
            exclude_sharenames=["IPC$"],
        )
        MANSPIDER(disabled_options).start()

        assert not any(path.is_file() for path in disabled_loot.rglob("*"))
