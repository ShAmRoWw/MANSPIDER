import multiprocessing
import struct
import threading
from time import sleep

import pytest
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_PATH_NOT_COVERED
from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SessionError
from impacket.smb3structs import (
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_302,
    SMB2_DIALECT_311,
)

import man_spider.lib.smb as smb_module
from man_spider.lib.errors import FileListError, NETWORK_ACCESS_DENIED_MARKER
from man_spider.lib.smb import SMBClient


@pytest.fixture(autouse=True)
def directory_routing_transport(monkeypatch):
    # These connection doubles model routing/tree lifetimes, not wire encoding.
    # The real read-only adapter is covered by test_smb_directory and loopback tests.
    monkeypatch.setattr(smb_module, "read_only_list_path", lambda connection, share, path: connection.listPath(share, path))


def dfs_referral_response(request_path, network_address, version=3, ttl=600, consumed_path=None):
    consumed_path = request_path if consumed_path is None else consumed_path
    network_path = network_address.encode("utf-16-le") + b"\x00\x00"
    if version == 1:
        fixed = struct.pack("<HHHH", version, 8 + len(network_path), 0, 0)
        header = struct.pack("<HHI", len(consumed_path.encode("utf-16-le")), 1, 2)
        return header + fixed + network_path

    dfs_path = request_path.encode("utf-16-le") + b"\x00\x00"
    alternate_path = dfs_path
    if version == 2:
        fixed_size = 22
        fixed = struct.pack(
            "<HHHHIIHHH",
            version,
            fixed_size,
            0,
            0,
            0,
            ttl,
            fixed_size,
            fixed_size + len(dfs_path),
            fixed_size + len(dfs_path) + len(alternate_path),
        )
    else:
        fixed_size = 34
        fixed = struct.pack(
            "<HHHHIHHH16s",
            version,
            fixed_size,
            0,
            0,
            ttl,
            fixed_size,
            fixed_size + len(dfs_path),
            fixed_size + len(dfs_path) + len(alternate_path),
            b"\x00" * 16,
        )
    header = struct.pack("<HHI", len(consumed_path.encode("utf-16-le")), 1, 2)
    return header + fixed + dfs_path + alternate_path + network_path


def dfs_referral_response_many(request_path, network_addresses, ttl=600):
    fixed_size = 34
    table_size = fixed_size * len(network_addresses)
    strings = bytearray()
    entries = []
    for index, network_address in enumerate(network_addresses):
        entry_offset = 8 + index * fixed_size
        dfs_path = request_path.encode("utf-16-le") + b"\x00\x00"
        alternate_path = dfs_path
        network_path = network_address.encode("utf-16-le") + b"\x00\x00"
        dfs_absolute = 8 + table_size + len(strings)
        alternate_absolute = dfs_absolute + len(dfs_path)
        network_absolute = alternate_absolute + len(alternate_path)
        entries.append(
            struct.pack(
                "<HHHHIHHH16s",
                3,
                fixed_size,
                0,
                0,
                ttl,
                dfs_absolute - entry_offset,
                alternate_absolute - entry_offset,
                network_absolute - entry_offset,
                b"\x00" * 16,
            )
        )
        strings.extend(dfs_path)
        strings.extend(alternate_path)
        strings.extend(network_path)
    header = struct.pack("<HHI", len(request_path.encode("utf-16-le")), len(entries), 2)
    return header + b"".join(entries) + bytes(strings)


class ReferenceCountedConnection:
    """Small SMB2/3 model matching Impacket's high-level tree lifecycle."""

    def __init__(self, dialect=0x0311):
        self.dialect = dialect
        self.references = {}
        self.events = []
        self.closed = False
        self._Connection = {"MaxReadSize": 64 * 1024}
        self._open_payloads = {}
        self._open_errors = {}

    def getDialect(self):
        return self.dialect

    def getSMBServer(self):
        return self

    @staticmethod
    def isSnapshotRequest(_path):
        return False

    def connectTree(self, share):
        if self.references.get(share, 0) == 0:
            self.events.append(("tree-connect", share))
        self.references[share] = self.references.get(share, 0) + 1
        return share

    def disconnectTree(self, tree_id):
        self.references[tree_id] -= 1
        if self.references[tree_id] == 0:
            self.events.append(("tree-disconnect", tree_id))
            self.references.pop(tree_id)

    def listPath(self, share, _path):
        tree_id = self.connectTree(share)
        try:
            return ()
        finally:
            self.disconnectTree(tree_id)

    def getFile(self, share, _filename, callback, share_access_mode):
        assert share_access_mode == smb_module.NON_BLOCKING_READ_SHARE_ACCESS
        tree_id = self.connectTree(share)
        try:
            callback(b"payload")
        finally:
            self.disconnectTree(tree_id)

    def create(self, tree_id, filename, **kwargs):
        chunks = []
        error = None
        try:
            self.getFile(tree_id, filename, chunks.append, kwargs["shareMode"])
        except Exception as exc:
            if not chunks:
                raise
            error = exc
        file_id = (tree_id, filename)
        self._open_payloads[file_id] = b"".join(chunks)
        if error is not None:
            self._open_errors[file_id] = error
        return file_id

    def queryInfo(self, _tree_id, file_id):
        info = smb_module._impacket_smb.SMBQueryFileStandardInfo()
        info["AllocationSize"] = info["EndOfFile"] = len(self._open_payloads[file_id])
        info["Directory"] = 0
        return info.getData()

    def read(self, _tree_id, file_id, offset, size):
        return self._open_payloads[file_id][offset : offset + size]

    def close(self, *args):
        if len(args) == 2:
            _tree_id, file_id = args
            self._open_payloads.pop(file_id, None)
            error = self._open_errors.pop(file_id, None)
            if error is not None:
                raise error
            return
        self.closed = True
        self.events.append(("session-close", None))


def client_with_connection(connection):
    client = SMBClient("server", "user", "password", "domain", "")
    client._install_connection(connection)
    return client


def hold_host_session_slot(slot_directory, ready):
    client = SMBClient(
        "crash-safe-server",
        "user",
        "password",
        "domain",
        "",
        session_slot_directory=slot_directory,
        max_sessions_per_host=1,
    )
    client._claim_transport()
    ready.set()
    while True:
        sleep(1)


def test_share_pin_reuses_one_tree_for_list_and_retrieval_calls():
    connection = ReferenceCountedConnection()
    client = client_with_connection(connection)
    payload = bytearray()

    with client.pin_share("Secrets"):
        assert list(client.ls("Secrets", "")) == []
        assert list(client.ls("Secrets", "folder")) == []
        client.retrieve_file("Secrets", "passwords.txt", payload.extend)

    assert payload == b"payload"
    assert connection.events == [
        ("tree-connect", "Secrets"),
        ("tree-disconnect", "Secrets"),
    ]
    assert connection.references == {}


def test_access_denied_listing_error_gets_durable_status_marker():
    class AccessDeniedConnection(ReferenceCountedConnection):
        def listPath(self, _share, _path):
            raise SessionError(STATUS_ACCESS_DENIED)

    client = client_with_connection(AccessDeniedConnection())
    try:
        with pytest.raises(FileListError) as caught:
            list(client.ls("Restricted$", "private"))
    finally:
        client.close()

    reason = str(caught.value)
    assert reason.startswith(NETWORK_ACCESS_DENIED_MARKER)
    assert "STATUS_ACCESS_DENIED" in reason


def test_passive_metrics_observe_existing_calls_without_adding_smb_operations():
    connection = ReferenceCountedConnection()
    client = client_with_connection(connection)
    snapshots = []
    client.enable_metrics(snapshots.append, flush_interval_seconds=3600)
    payload = bytearray()

    with client.pin_share("Secrets"):
        assert list(client.ls("Secrets", "")) == []
        client.retrieve_file("Secrets", "passwords.txt", payload.extend)
    client.close()

    assert payload == b"payload"
    assert connection.events == [
        ("tree-connect", "Secrets"),
        ("tree-disconnect", "Secrets"),
        ("session-close", None),
    ]
    assert len(snapshots) == 1
    assert snapshots[0]["operations"]["directory_list"]["attempts"] == 1
    assert snapshots[0]["operations"]["file_read"]["bytes"] == len(payload)


def test_nested_share_pin_releases_only_the_outer_reference():
    connection = ReferenceCountedConnection()
    client = client_with_connection(connection)

    with client.pin_share("Secrets"):
        with client.pin_share("secrets"):
            assert list(client.ls("Secrets", "")) == []
        assert connection.references == {"Secrets": 1}

    assert connection.events == [
        ("tree-connect", "Secrets"),
        ("tree-disconnect", "Secrets"),
    ]


def test_overlapping_share_pins_release_when_the_last_context_exits():
    connection = ReferenceCountedConnection()
    client = client_with_connection(connection)
    first = client.pin_share("Secrets")
    second = client.pin_share("secrets")

    first.__enter__()
    second.__enter__()
    first.__exit__(None, None, None)
    assert connection.references == {"Secrets": 1}
    second.__exit__(None, None, None)

    assert connection.references == {}
    assert connection.events == [
        ("tree-connect", "Secrets"),
        ("tree-disconnect", "Secrets"),
    ]


def test_active_share_is_repinned_after_connection_rebuild():
    first = ReferenceCountedConnection()
    second = ReferenceCountedConnection()
    client = client_with_connection(first)

    with client.pin_share("Secrets"):
        assert list(client.ls("Secrets", "")) == []
        client._install_connection(second)
        assert first.closed is True
        assert list(client.ls("Secrets", "")) == []

    assert first.events == [("tree-connect", "Secrets"), ("session-close", None)]
    assert second.events == [
        ("tree-connect", "Secrets"),
        ("tree-disconnect", "Secrets"),
    ]


def test_smb1_keeps_existing_unpinned_high_level_behavior():
    connection = ReferenceCountedConnection(dialect=SMB_DIALECT)
    client = client_with_connection(connection)

    with client.pin_share("Legacy"):
        assert list(client.ls("Legacy", "")) == []
        assert list(client.ls("Legacy", "folder")) == []

    assert connection.events == [
        ("tree-connect", "Legacy"),
        ("tree-disconnect", "Legacy"),
        ("tree-connect", "Legacy"),
        ("tree-disconnect", "Legacy"),
    ]


@pytest.mark.parametrize(
    "dialect",
    (
        SMB2_DIALECT_002,
        SMB2_DIALECT_21,
        SMB2_DIALECT_30,
        SMB2_DIALECT_302,
        SMB2_DIALECT_311,
    ),
)
def test_every_smb2_and_smb3_dialect_uses_the_reference_counted_pin(dialect):
    connection = ReferenceCountedConnection(dialect=dialect)
    client = client_with_connection(connection)

    with client.pin_share("DialectFixture"):
        assert list(client.ls("DialectFixture", "")) == []

    assert connection.events == [
        ("tree-connect", "DialectFixture"),
        ("tree-disconnect", "DialectFixture"),
    ]


def test_dfs_listing_keeps_the_relative_path_expected_by_impacket():
    class DfsConnection(ReferenceCountedConnection):
        def __init__(self):
            super().__init__()
            self.patterns = []

        def listPath(self, share, path):
            self.patterns.append(path)
            return super().listPath(share, path)

    connection = DfsConnection()
    client = client_with_connection(connection)

    with client.pin_share("Secrets"):
        assert list(client.ls("Secrets", "folder")) == []

    assert connection.patterns == [r"folder\*"]


@pytest.mark.parametrize("version", (1, 2, 3, 4))
def test_dfs_referral_parser_accepts_storage_referral_versions(version):
    request_path = r"\files.test.local\namespace\link"
    payload = dfs_referral_response(request_path, r"\files.test.local\target\folder", version=version)

    referrals = SMBClient._parse_dfs_referrals(payload, request_path)

    assert referrals[0].namespace_prefix == "link"
    assert referrals[0].network_address == r"\files.test.local\target\folder"
    assert referrals[0].ttl == (0 if version == 1 else 600)


def test_dfs_referral_parser_accepts_a_share_root_referral():
    request_path = r"\files.test.local\namespace\folder\file.txt"
    payload = dfs_referral_response(
        request_path,
        r"\files.test.local\target\prefix",
        consumed_path=r"\files.test.local\namespace",
    )

    referrals = SMBClient._parse_dfs_referrals(payload, request_path)

    assert referrals[0].namespace_prefix == ""


def test_dfs_referral_parser_rejects_a_partial_component_path_consumed():
    request_path = r"\files.test.local\namespace\folder"
    payload = dfs_referral_response(
        request_path,
        r"\files.test.local\target",
        consumed_path=r"\files.test.local\namespace\fold",
    )

    with pytest.raises(ValueError, match="inside a path component"):
        SMBClient._parse_dfs_referrals(payload, request_path)


def test_dfs_referral_parser_rejects_invalid_path_consumed():
    request_path = r"\files.test.local\namespace\link"
    payload = bytearray(dfs_referral_response(request_path, r"\files.test.local\target"))
    struct.pack_into("<H", payload, 0, 3)

    with pytest.raises(ValueError, match="PathConsumed"):
        SMBClient._parse_dfs_referrals(bytes(payload), request_path)


def test_dfs_referral_parser_rejects_a_string_offset_inside_entry_table():
    request_path = r"\files.test.local\namespace\link"
    payload = bytearray(dfs_referral_response(request_path, r"\files.test.local\target"))
    struct.pack_into("<H", payload, 8 + 16, 2)

    with pytest.raises(ValueError, match="overlaps the entry table"):
        SMBClient._parse_dfs_referrals(bytes(payload), request_path)


def test_dfs_referral_parser_preserves_multiple_storage_target_order():
    request_path = r"\files.test.local\namespace\link"
    payload = dfs_referral_response_many(
        request_path,
        (r"\first.test.local\target", r"\second.test.local\target\prefix"),
    )

    referrals = SMBClient._parse_dfs_referrals(payload, request_path)

    assert [referral.network_address for referral in referrals] == [
        r"\first.test.local\target",
        r"\second.test.local\target\prefix",
    ]


def test_dfs_referral_parser_does_not_read_an_unterminated_string_into_the_next_target():
    request_path = r"\files.test.local\namespace\link"
    first_address = r"\first.test.local\target"
    payload = bytearray(
        dfs_referral_response_many(
            request_path,
            (first_address, r"\second.test.local\target"),
        )
    )
    first_terminator = payload.index(first_address.encode("utf-16-le")) + len(first_address.encode("utf-16-le"))
    payload[first_terminator : first_terminator + 2] = b"XX"

    with pytest.raises(ValueError, match="unterminated DFS referral string"):
        SMBClient._parse_dfs_referrals(bytes(payload), request_path)


def test_dfs_path_translation_uses_components_when_casefold_changes_length():
    route = smb_module._DFSRoute(
        "namespace",
        "Straße",
        "target",
        "prefix",
        float("inf"),
    )

    assert SMBClient._translate_dfs_path(route, r"STRASSE\secret.txt") == r"prefix\secret.txt"


def test_same_server_dfs_referral_reuses_session_and_translates_paths():
    request_path = r"\server\dfsroot\fixtures"

    class Entry:
        @staticmethod
        def get_longname():
            return "test.txt"

    class SameServerDFSConnection(ReferenceCountedConnection):
        _Connection = {"ServerName": "rootserver"}

        def __init__(self):
            super().__init__()
            self.listed = []
            self.retrieved = []
            self.referral_requests = []

        @staticmethod
        def getServerName():
            return "ROOTSERVER"

        def getSMBServer(self):
            return self

        def ioctl(self, _tree_id, _file_id, _control_code, _flags, request, *_limits):
            requested_path = request[2:-2].decode("utf-16-le")
            self.referral_requests.append(requested_path)
            return dfs_referral_response(requested_path, r"\ROOTSERVER\target")

        def listPath(self, share, path):
            tree_id = self.connectTree(share)
            try:
                self.listed.append((share, path))
                if share.casefold() == "dfsroot" and path.casefold() == r"fixtures\*":
                    raise SessionError(STATUS_PATH_NOT_COVERED)
                if share.casefold() == "target" and path == r"\*":
                    return (Entry(),)
                return ()
            finally:
                self.disconnectTree(tree_id)

        def getFile(self, share, filename, callback, share_access_mode):
            assert share_access_mode == smb_module.NON_BLOCKING_READ_SHARE_ACCESS
            tree_id = self.connectTree(share)
            try:
                self.retrieved.append((share, filename))
                callback(b"payload")
            finally:
                self.disconnectTree(tree_id)

    connection = SameServerDFSConnection()
    client = client_with_connection(connection)
    payload = bytearray()

    with client.pin_share("dfsroot"):
        entries = list(client.ls("dfsroot", "fixtures"))
        client.retrieve_file("dfsroot", r"fixtures\test.txt", payload.extend)
    client.close()

    assert [entry.get_longname() for entry in entries] == ["test.txt"]
    assert bytes(payload) == b"payload"
    assert connection.referral_requests == [request_path]
    assert ("target", r"\*") in connection.listed
    assert connection.retrieved == [("target", "test.txt")]
    assert ("tree-connect", "target") in connection.events
    assert connection.closed is True


def test_direct_file_retrieval_resolves_dfs_without_prior_directory_listing():
    class DirectDFSConnection(ReferenceCountedConnection):
        _Connection = {"ServerName": "server"}

        def getSMBServer(self):
            return self

        def ioctl(self, _tree_id, _file_id, _control_code, _flags, request, *_limits):
            request_path = request[2:-2].decode("utf-16-le")
            return dfs_referral_response(
                request_path,
                r"\server\target",
                consumed_path=r"\server\dfsroot\link",
            )

        def getFile(self, share, filename, callback, share_access_mode):
            assert share_access_mode == smb_module.NON_BLOCKING_READ_SHARE_ACCESS
            tree_id = self.connectTree(share)
            try:
                if share == "dfsroot":
                    raise SessionError(STATUS_PATH_NOT_COVERED)
                assert (share, filename) == ("target", "secret.txt")
                callback(b"secret")
            finally:
                self.disconnectTree(tree_id)

    client = client_with_connection(DirectDFSConnection())
    payload = bytearray()

    with client.pin_share("dfsroot"):
        client.retrieve_file("dfsroot", r"link\secret.txt", payload.extend)
    client.close()

    assert bytes(payload) == b"secret"


def test_zero_ttl_dfs_referral_is_requeried_but_still_completes_current_operation():
    class ZeroTTLDFSConnection(ReferenceCountedConnection):
        _Connection = {"ServerName": "server"}

        def __init__(self):
            super().__init__()
            self.referral_requests = 0

        def getSMBServer(self):
            return self

        def ioctl(self, _tree_id, _file_id, _control_code, _flags, request, *_limits):
            self.referral_requests += 1
            request_path = request[2:-2].decode("utf-16-le")
            return dfs_referral_response(request_path, r"\server\target", ttl=0)

        def listPath(self, share, path):
            tree_id = self.connectTree(share)
            try:
                if share == "dfsroot":
                    raise SessionError(STATUS_PATH_NOT_COVERED)
                return ()
            finally:
                self.disconnectTree(tree_id)

    connection = ZeroTTLDFSConnection()
    client = client_with_connection(connection)

    with client.pin_share("dfsroot"):
        assert list(client.ls("dfsroot", "link")) == []
        assert list(client.ls("dfsroot", "link")) == []
    client.close()

    assert connection.referral_requests == 2
    assert connection.references == {}


def test_dfs_alternate_storage_target_is_used_after_first_target_fails(monkeypatch):
    class Entry:
        @staticmethod
        def get_longname():
            return "available.txt"

    class AlternateTargetConnection(ReferenceCountedConnection):
        def listPath(self, share, path):
            tree_id = self.connectTree(share)
            try:
                if share == "dfsroot":
                    raise SessionError(STATUS_PATH_NOT_COVERED)
                if share == "unavailable":
                    raise OSError("target unavailable")
                if share == "available":
                    return (Entry(),)
                return ()
            finally:
                self.disconnectTree(tree_id)

    connection = AlternateTargetConnection()
    client = client_with_connection(connection)
    monkeypatch.setattr(
        client,
        "_dfs_route_candidates",
        lambda _share, _path: [
            smb_module._DFSRoute("dfsroot", "link", "unavailable", "", float("inf")),
            smb_module._DFSRoute("dfsroot", "link", "available", "", float("inf")),
        ],
    )

    with client.pin_share("dfsroot"):
        entries = list(client.ls("dfsroot", "link"))
    client.close()

    assert [entry.get_longname() for entry in entries] == ["available.txt"]
    assert connection.references == {}


def test_dfs_retrieval_never_retries_after_a_callback_received_bytes(monkeypatch):
    class PartialTargetConnection(ReferenceCountedConnection):
        def __init__(self):
            super().__init__()
            self.attempts = []

        def getFile(self, share, filename, callback, share_access_mode):
            assert share_access_mode == smb_module.NON_BLOCKING_READ_SHARE_ACCESS
            tree_id = self.connectTree(share)
            try:
                self.attempts.append((share, filename))
                if share == "dfsroot":
                    raise SessionError(STATUS_PATH_NOT_COVERED)
                if share == "partial":
                    callback(b"partial")
                    raise OSError("connection lost")
                callback(b"duplicate")
            finally:
                self.disconnectTree(tree_id)

    connection = PartialTargetConnection()
    client = client_with_connection(connection)
    monkeypatch.setattr(
        client,
        "_dfs_route_candidates",
        lambda _share, _path: [
            smb_module._DFSRoute("dfsroot", "link", "partial", "", float("inf")),
            smb_module._DFSRoute("dfsroot", "link", "unused", "", float("inf")),
        ],
    )
    payload = bytearray()

    with client.pin_share("dfsroot"):
        with pytest.raises(OSError, match="connection lost"):
            client.retrieve_file("dfsroot", r"link\secret.txt", payload.extend)
    client.close()

    assert bytes(payload) == b"partial"
    assert connection.attempts == [("dfsroot", r"link\secret.txt"), ("partial", "secret.txt")]


def test_cross_server_dfs_referral_switches_transport_and_preserves_namespace(monkeypatch):
    class Entry:
        @staticmethod
        def get_longname():
            return "external.txt"

    class CrossServerDFSConnection(ReferenceCountedConnection):
        _Connection = {"ServerName": "rootserver"}

        @staticmethod
        def getServerName():
            return "ROOTSERVER"

        def getSMBServer(self):
            return self

        @staticmethod
        def ioctl(_tree_id, _file_id, _control_code, _flags, request, *_limits):
            requested_path = request[2:-2].decode("utf-16-le")
            return dfs_referral_response(requested_path, r"\other-server\target")

        def listPath(self, share, path):
            tree_id = self.connectTree(share)
            try:
                if share.casefold() == "dfsroot" and path.casefold() == r"link\*":
                    raise SessionError(STATUS_PATH_NOT_COVERED)
                return ()
            finally:
                self.disconnectTree(tree_id)

    class TargetConnection(ReferenceCountedConnection):
        def __init__(self):
            super().__init__()
            self.listed = []

        def listPath(self, share, path):
            tree_id = self.connectTree(share)
            try:
                self.listed.append((share, path))
                return (Entry(),)
            finally:
                self.disconnectTree(tree_id)

    root_connection = CrossServerDFSConnection()
    restored_root_connection = ReferenceCountedConnection()
    target_connection = TargetConnection()
    client = client_with_connection(root_connection)
    client.allow_external_dfs = True
    created = []

    def create_target(server, port):
        target = SMBClient(
            server,
            "user",
            "password",
            "domain",
            "",
            port=port,
            transport_group=client._transport_group,
        )
        target._install_connection(target_connection)
        created.append(target)
        return target

    monkeypatch.setattr(client, "_create_dfs_client", create_target)

    with client.pin_share("dfsroot"):
        entries = list(client.ls("dfsroot", "link"))

    assert [entry.get_longname() for entry in entries] == ["external.txt"]
    assert target_connection.listed == [("target", r"\*")]
    assert root_connection.closed is True
    assert client.conn is None
    assert client._transport_group.active_client is created[0]

    def restore_root(refresh=False, first_try=True):
        assert refresh is False
        assert first_try is False
        client._install_connection(restored_root_connection)
        return True

    monkeypatch.setattr(client, "login", restore_root)
    with client.pin_share("local"):
        assert list(client.ls("local", "")) == []

    assert target_connection.closed is True
    assert object.__getattribute__(client, "_SMBClient__connection") is restored_root_connection
    assert client._transport_group.active_client is client
    client.close()
    assert restored_root_connection.closed is True


def test_external_dfs_target_receives_selected_credentials_and_reports_rejection(monkeypatch):
    rejected = []
    parent = SMBClient(
        "rootserver",
        "runuser",
        "secret",
        "TEST.LOCAL",
        "0123456789abcdef",
        use_kerberos=True,
        aes_key="aes-key",
        dc_ip="192.0.2.10",
        dfs_auth_failure_callback=rejected.append,
        allow_external_dfs=True,
    )
    observed = {}

    def reject_login(client, refresh=False, first_try=True):
        observed.update(
            username=client.username,
            password=client.password,
            domain=client.domain,
            nthash=client.nthash,
            use_kerberos=client.use_kerberos,
            aes_key=client.aes_key,
            dc_ip=client.dc_ip,
            port=client.port,
            refresh=refresh,
            first_try=first_try,
        )
        return False

    monkeypatch.setattr(SMBClient, "login", reject_login)

    child = parent._create_dfs_client("other-server", 445)

    assert observed == {
        "username": "runuser",
        "password": "secret",
        "domain": "TEST.LOCAL",
        "nthash": "0123456789abcdef",
        "use_kerberos": True,
        "aes_key": "aes-key",
        "dc_ip": "192.0.2.10",
        "port": 445,
        "refresh": False,
        "first_try": True,
    }
    assert rejected == ["other-server"]
    assert child._transport_group is parent._transport_group
    assert child.allow_external_dfs is True


def test_login_treats_silent_guest_mapping_as_rejected_credentials(monkeypatch):
    connections = []

    class GuestMappingConnection:
        def __init__(self, *_args, **_kwargs):
            self.username = None
            self.closed = False
            connections.append(self)

        def login(self, username, _password, **_kwargs):
            self.username = username

        def isGuestSession(self):
            return int(self.username in ("runuser", "Guest"))

        def close(self):
            self.closed = True

    monkeypatch.setattr(smb_module, "SMBConnection", GuestMappingConnection)
    client = SMBClient("server", "runuser", "wrong", "TEST", "")

    assert client.login() is False
    assert client.username == "Guest"
    assert len(connections) == 2
    assert connections[0].closed is True
    assert connections[1].closed is False
    client.close()
    assert connections[1].closed is True


def test_login_splits_impacket_lm_nt_hash_pair(monkeypatch):
    calls = []

    class HashConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, username, password, **kwargs):
            calls.append((username, password, kwargs))

        @staticmethod
        def isGuestSession():
            return 0

        def close(self):
            pass

    monkeypatch.setattr(smb_module, "SMBConnection", HashConnection)
    lmhash = "11111111111111111111111111111111"
    nthash = "22222222222222222222222222222222"
    client = SMBClient("server", "runuser", "", "TEST", f"{lmhash}:{nthash}")

    assert client.login() is True
    assert client.lmhash == lmhash
    assert client.nthash == nthash
    assert calls == [
        (
            "runuser",
            "",
            {
                "lmhash": lmhash,
                "nthash": nthash,
                "domain": "TEST",
            },
        )
    ]
    assert client._supplied_credentials[3] == f"{lmhash}:{nthash}"


def test_pinned_share_finishes_guest_then_null_fallback_after_access_denied(monkeypatch):
    class GuestDeniedConnection(ReferenceCountedConnection):
        def connectTree(self, _share):
            raise SessionError(STATUS_ACCESS_DENIED)

    guest_connection = GuestDeniedConnection()
    null_connection = ReferenceCountedConnection()
    client = SMBClient("server", "Guest", "", "", "")
    client._install_connection(guest_connection)
    login_calls = []

    def login(refresh=False, first_try=True):
        login_calls.append((refresh, first_try, client.username))
        client._install_connection(null_connection)
        return True

    monkeypatch.setattr(client, "login", login)

    with client.pin_share("target"):
        assert list(client.ls("target", "")) == []

    assert login_calls == [(True, False, "")]
    assert guest_connection.closed is True
    assert null_connection.events == [
        ("tree-connect", "target"),
        ("tree-disconnect", "target"),
    ]


def test_host_slot_serializes_same_endpoint_sessions(tmp_path):
    first = SMBClient(
        "same-server",
        "user",
        "password",
        "domain",
        "",
        session_slot_directory=tmp_path,
        max_sessions_per_host=1,
    )
    second = SMBClient(
        "SAME-SERVER",
        "user",
        "password",
        "domain",
        "",
        session_slot_directory=tmp_path,
        max_sessions_per_host=1,
    )
    acquired = threading.Event()

    first._claim_transport()

    def claim_second():
        second._claim_transport()
        acquired.set()

    thread = threading.Thread(target=claim_second)
    thread.start()
    assert acquired.wait(0.05) is False
    first._suspend_transport()
    assert acquired.wait(1) is True
    second._suspend_transport()
    thread.join(timeout=1)
    assert thread.is_alive() is False


def test_host_slot_is_released_after_a_worker_process_is_terminated(tmp_path):
    process_context = multiprocessing.get_context("spawn")
    ready = process_context.Event()
    holder = process_context.Process(target=hold_host_session_slot, args=(tmp_path, ready))
    contender = SMBClient(
        "crash-safe-server",
        "user",
        "password",
        "domain",
        "",
        session_slot_directory=tmp_path,
        max_sessions_per_host=1,
    )
    acquired = threading.Event()
    thread = None
    holder.start()
    try:
        assert ready.wait(3) is True

        def claim_contender():
            contender._claim_transport()
            acquired.set()

        thread = threading.Thread(target=claim_contender)
        thread.start()
        assert acquired.wait(0.05) is False
        holder.terminate()
        holder.join(timeout=3)
        assert holder.is_alive() is False
        assert acquired.wait(2) is True
    finally:
        if holder.is_alive():
            holder.terminate()
            holder.join(timeout=3)
        contender._suspend_transport()
        if thread is not None:
            thread.join(timeout=2)


def test_postquery_close_failure_uses_normal_close_without_losing_bytes(monkeypatch):
    payload = b"complete payload"

    class LowLevelConnection:
        _Connection = {"MaxReadSize": 4}

        def __init__(self):
            self.events = []
            self.create_arguments = []

        @staticmethod
        def isSnapshotRequest(_path):
            return False

        def connectTree(self, share):
            self.events.append(("tree-connect", share))
            return 7

        def create(self, _tree_id, path, *args, **_kwargs):
            self.events.append(("create", path))
            self.create_arguments.append((args, _kwargs))
            return b"file-id"

        @staticmethod
        def queryInfo(_tree_id, _file_id):
            return object()

        @staticmethod
        def read(_tree_id, _file_id, offset, size):
            return payload[offset : offset + size]

        def close(self, tree_id, file_id):
            self.events.append(("normal-close", (tree_id, file_id)))

        def disconnectTree(self, tree_id):
            self.events.append(("tree-disconnect", tree_id))

    connection = LowLevelConnection()
    client = SMBClient("server", "user", "password", "domain", "")
    monkeypatch.setattr(
        smb_module._impacket_smb,
        "SMBQueryFileStandardInfo",
        lambda _response: {"EndOfFile": len(payload)},
    )
    monkeypatch.setattr(
        client,
        "_close_smb2_file_with_identity",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("post-query unsupported")),
    )
    received = bytearray()

    identity = client._retrieve_smb2_file(connection, "Secrets", "folder/secret.txt", received.extend)

    assert identity is None
    assert bytes(received) == payload
    assert connection.create_arguments == [
        (
            (),
            {
                "desiredAccess": smb_module.FILE_READ_DATA,
                "shareMode": smb_module.NON_BLOCKING_READ_SHARE_ACCESS,
                "creationOptions": smb_module.FILE_NON_DIRECTORY_FILE,
                "creationDisposition": smb_module.FILE_OPEN,
                "fileAttributes": 0,
                "impersonationLevel": smb_module.SMB2_IL_IMPERSONATION,
                "securityFlags": 0,
                "oplockLevel": smb_module.SMB2_OPLOCK_LEVEL_NONE,
                "createContexts": None,
            },
        )
    ]
    assert connection.events == [
        ("tree-connect", "Secrets"),
        ("create", r"folder\secret.txt"),
        ("normal-close", (7, b"file-id")),
        ("tree-disconnect", 7),
    ]


@pytest.mark.parametrize(
    "position,unsafe_value",
    (
        (0, 0x00000003),  # desired access
        (1, 0x00000001),  # share mode
        (2, 0x00000000),  # create options
        (3, 0x00000003),  # create disposition (OPEN_IF)
        (4, 0x00000020),  # file attributes
        (5, 0x00000003),  # impersonation
        (6, 0x00000001),  # security flags
        (7, 0x00000001),  # oplock
    ),
)
def test_smb2_runtime_guard_rejects_every_unpinned_open_parameter_before_dispatch(position, unsafe_value):
    class Transport:
        create_calls = 0
        connectTree = queryInfo = read = close = disconnectTree = isSnapshotRequest = staticmethod(lambda *_args: None)

        def create(self, *_args, **_kwargs):
            self.create_calls += 1

    raw = Transport()
    guarded = smb_module._ReadOnlySMB2FileTransport(raw)
    arguments = [
        smb_module.FILE_READ_DATA,
        smb_module.NON_BLOCKING_READ_SHARE_ACCESS,
        smb_module.FILE_NON_DIRECTORY_FILE,
        smb_module.FILE_OPEN,
        0,
        smb_module.SMB2_IL_IMPERSONATION,
        0,
        smb_module.SMB2_OPLOCK_LEVEL_NONE,
    ]
    arguments[position] = unsafe_value

    with pytest.raises(smb_module.ReadOnlySMBViolation, match="pinned read-only open"):
        guarded.create(7, "secret.txt", *arguments, createContexts=None)

    assert raw.create_calls == 0


@pytest.mark.parametrize("contexts", ([], [object()], [object(), object()]))
def test_smb2_runtime_guard_rejects_unknown_create_contexts_before_dispatch(contexts):
    class Transport:
        create_calls = 0
        connectTree = queryInfo = read = close = disconnectTree = isSnapshotRequest = staticmethod(lambda *_args: None)

        def create(self, *_args, **_kwargs):
            self.create_calls += 1

    raw = Transport()
    guarded = smb_module._ReadOnlySMB2FileTransport(raw)

    with pytest.raises(smb_module.ReadOnlySMBViolation, match="CREATE context"):
        guarded.create(
            7,
            "secret.txt",
            smb_module.FILE_READ_DATA,
            smb_module.NON_BLOCKING_READ_SHARE_ACCESS,
            smb_module.FILE_NON_DIRECTORY_FILE,
            smb_module.FILE_OPEN,
            0,
            smb_module.SMB2_IL_IMPERSONATION,
            0,
            smb_module.SMB2_OPLOCK_LEVEL_NONE,
            createContexts=contexts,
        )

    assert raw.create_calls == 0


def test_smb2_file_capability_does_not_expose_mutating_transport_methods():
    class Transport:
        connectTree = create = queryInfo = read = close = disconnectTree = isSnapshotRequest = staticmethod(
            lambda *_args, **_kwargs: None
        )

        @staticmethod
        def write(*_args):
            pytest.fail("raw write must not be reachable through the file capability")

    guarded = smb_module._ReadOnlySMB2FileTransport(Transport())

    assert not hasattr(guarded, "write")
    with pytest.raises(AttributeError):
        guarded.write(7, b"file-id", 0, b"mutation")
    assert not hasattr(guarded, "sendSMB")
    assert not hasattr(guarded, "SMB_PACKET")


def test_smb2_postquery_close_reparses_packet_factory_output_before_dispatch():
    from impacket.smb3structs import SMB2Packet, SMB2_WRITE

    class EvilPacket(dict):
        def getData(self):
            packet = SMB2Packet()
            packet["Command"] = SMB2_WRITE
            packet["TreeID"] = 7
            packet["Data"] = b"\x00" * 48
            return packet.getData()

    class Transport:
        send_calls = 0
        _Connection = {"MaxReadSize": 4096}
        connectTree = queryInfo = read = close = disconnectTree = isSnapshotRequest = staticmethod(lambda *_args: None)
        create = staticmethod(lambda *_args, **_kwargs: b"F" * 16)
        SMB_PACKET = staticmethod(EvilPacket)

        def sendSMB(self, _packet):
            self.send_calls += 1

    raw = Transport()
    guarded = smb_module._ReadOnlySMB2FileTransport(raw)
    file_id = guarded.create(
        7,
        "secret.txt",
        smb_module.FILE_READ_DATA,
        smb_module.NON_BLOCKING_READ_SHARE_ACCESS,
        smb_module.FILE_NON_DIRECTORY_FILE,
        smb_module.FILE_OPEN,
        0,
        smb_module.SMB2_IL_IMPERSONATION,
        0,
        smb_module.SMB2_OPLOCK_LEVEL_NONE,
        createContexts=None,
    )

    with pytest.raises(smb_module.ReadOnlySMBViolation, match="canonical post-query CLOSE"):
        guarded.close_with_postquery(7, file_id)
    assert raw.send_calls == 0


def test_smb2_postquery_close_rejects_untracked_handle_before_packet_creation():
    class Transport:
        packet_calls = 0
        connectTree = create = queryInfo = read = close = disconnectTree = isSnapshotRequest = staticmethod(
            lambda *_args, **_kwargs: None
        )

        def SMB_PACKET(self):
            self.packet_calls += 1

    raw = Transport()
    guarded = smb_module._ReadOnlySMB2FileTransport(raw)
    with pytest.raises(smb_module.ReadOnlySMBViolation, match="opened by the read-only capability"):
        guarded.close_with_postquery(7, b"F" * 16)
    assert raw.packet_calls == 0


def test_public_connection_view_cannot_bypass_read_only_transport_guards():
    raw = ReferenceCountedConnection()
    raw.deleteFile = lambda *_args: pytest.fail("raw delete must not be publicly reachable")
    raw.putFile = lambda *_args: pytest.fail("raw upload must not be publicly reachable")
    client = client_with_connection(raw)

    assert client.conn.getDialect() == 0x0311
    for forbidden in ("getSMBServer", "create", "write", "deleteFile", "putFile", "rename"):
        assert not hasattr(client.conn, forbidden)
        with pytest.raises(AttributeError):
            getattr(client.conn, forbidden)
    with pytest.raises(AttributeError):
        client.conn = raw


def test_close_releases_a_pin_before_closing_the_session():
    connection = ReferenceCountedConnection()
    client = client_with_connection(connection)

    with client.pin_share("Secrets"):
        client.close()

    assert connection.events == [
        ("tree-connect", "Secrets"),
        ("tree-disconnect", "Secrets"),
        ("session-close", None),
    ]
    assert client.conn is None
