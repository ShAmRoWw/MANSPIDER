"""Real Impacket wildcard negotiation failures, never string-only retries."""

import ast
import socket
import struct
import threading
from contextlib import contextmanager

import pytest
from impacket import nmb, smbconnection
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE
from impacket.smbconnection import SessionError

from man_spider.lib.errors import ReadOnlySMBViolation, is_network_unavailable
from man_spider.lib import smb as smb_module
from man_spider.lib.smb import SMBClient
from man_spider.lib.smb_transport import close_failed_negotiation, is_transport_error, transport_state
from man_spider.metrics import classify_smb_error
from test_network_recovery import recovery
from test_smb_transport_failure import MemoryConnection, installed
from test_read_only import _identity_only_smb_connection_references


@contextmanager
def closed_negotiation_peer(*, reset=False):
    """Consume only our wildcard NEGOTIATE, then FIN/RST our loopback socket."""

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.1)
    stop = threading.Event()
    packets, failures = [], []

    def read_exact(peer, size):
        result = bytearray()
        while len(result) < size:
            chunk = peer.recv(size - len(result))
            if not chunk:
                raise AssertionError("Client closed before its NEGOTIATE")
            result.extend(chunk)
        return bytes(result)

    def serve():
        while not stop.is_set():
            try:
                peer, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with peer:
                    peer.settimeout(2)
                    header = read_exact(peer, 4)
                    body = read_exact(peer, int.from_bytes(header[1:], "big"))
                    assert body[:5] == b"\xffSMBr", body[:8]
                    packets.append(body)
                    if reset:
                        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    else:
                        peer.shutdown(socket.SHUT_WR)
            except BaseException as exc:
                failures.append(exc)

    worker = threading.Thread(target=serve, name="test-owned-negotiation")
    worker.start()
    try:
        yield listener.getsockname()[1], packets
    finally:
        stop.set()
        listener.close()
        worker.join(timeout=3)
        assert not worker.is_alive()
        assert not failures


@pytest.mark.parametrize("reset", [False, True], ids=["fin", "rst"])
def test_real_closed_negotiation_has_transport_provenance(reset):
    with closed_negotiation_peer(reset=reset) as (port, packets):
        with pytest.raises(Exception) as caught:
            smbconnection.SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=2)
        assert str(caught.value) == "No answer!"
        assert len(packets) == 2  # Dependency's own bounded wildcard attempts.
        assert is_transport_error(caught.value)
        assert not is_network_unavailable(caught.value)  # Classifier is pure.
        assert classify_smb_error(caught.value) == "disconnect"


@pytest.mark.parametrize("reset", [False, True], ids=["fin", "rst"])
def test_login_bounds_and_marks_real_exhausted_negotiation(reset):
    with closed_negotiation_peer(reset=reset) as (port, packets):
        client = SMBClient("127.0.0.1", "user", "synthetic", "domain", "", port=port)
        client._network_recovery, clock = recovery()
        try:
            assert client.login(first_try=False) is None
            assert len(packets) == 4  # Two constructors, each at most two packets.
            assert client._network_recovery.failures == 2
            assert clock.now == pytest.approx(1)
            assert is_network_unavailable(client.last_connection_error)
            assert client.conn is None
        finally:
            client.close()


def test_failed_constructor_sockets_are_closed_even_while_tracebacks_are_retained(monkeypatch):
    sockets, errors = [], []
    original = smb_module.SMBConnection

    def capture_failed_constructor(*args, **kwargs):
        try:
            return original(*args, **kwargs)
        except Exception as error:
            tb = error.__traceback__
            while tb.tb_next is not None:
                tb = tb.tb_next
            sockets.append(tb.tb_frame.f_locals["self"].getNMBServer().get_socket())
            errors.append(error)
            raise

    monkeypatch.setattr(smb_module, "SMBConnection", capture_failed_constructor)
    with closed_negotiation_peer() as (port, packets):
        client = SMBClient("127.0.0.1", "user", "synthetic", "domain", "", port=port)
        client._network_recovery, _clock = recovery()
        try:
            assert client.login(first_try=False) is None
            assert len(packets) == 4 and len(errors) == len(sockets) == 2
            assert all(peer.fileno() == -1 for peer in sockets)
            assert all(error.__traceback__ is not None for error in errors)
            assert is_network_unavailable(client.last_connection_error)
        finally:
            client.close()
            for peer in sockets:
                peer.close()  # Bound the diagnostic leak even before the fix.


def test_failed_negotiation_raw_cleanup_is_idempotent_and_preserves_provenance():
    with closed_negotiation_peer() as (port, packets):
        with pytest.raises(Exception) as caught:
            smbconnection.SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=2)
        error = caught.value
        tb = error.__traceback__
        while tb.tb_next is not None:
            tb = tb.tb_next
        peer = tb.tb_frame.f_locals["self"].getNMBServer().get_socket()
        try:
            assert peer.fileno() >= 0
            assert close_failed_negotiation(error)
            assert peer.fileno() == -1
            assert close_failed_negotiation(error)
            assert is_transport_error(error)
            assert not is_network_unavailable(error)
            assert len(packets) == 2
        finally:
            peer.close()


def test_actual_new_negotiation_failure_is_not_confused_with_historical_access_denial():
    with closed_negotiation_peer() as (port, _packets):
        client = SMBClient("127.0.0.1", "user", "synthetic", "domain", "", port=port)
        client._network_recovery, _clock = recovery()
        try:
            try:
                raise SessionError(STATUS_ACCESS_DENIED)
            except SessionError as previous:
                assert client.login(first_try=False) is None
                assert client.last_connection_error.__context__ is previous
                assert is_network_unavailable(client.last_connection_error)
                assert classify_smb_error(client.last_connection_error) == "disconnect"
        finally:
            client.close()


def test_plain_local_matching_text_is_not_transport_provenance():
    for error in (Exception("No answer!"), RuntimeError("No answer!")):
        try:
            raise error
        except Exception:
            assert not is_transport_error(error)
            assert not close_failed_negotiation(error)
            assert classify_smb_error(error) == "other"


def test_same_module_and_function_names_cannot_fake_dependency_origin():
    namespace = {"__name__": "impacket.smbconnection"}
    exec("def negotiateSessionWildcard():\n    raise Exception('No answer!')", namespace)
    with pytest.raises(Exception) as caught:
        namespace["negotiateSessionWildcard"]()
    assert not is_transport_error(caught.value)
    assert not close_failed_negotiation(caught.value)
    assert classify_smb_error(caught.value) == "other"


@pytest.mark.parametrize(
    "error",
    [
        Exception("No answer!"),
        SessionError(STATUS_ACCESS_DENIED),
        SessionError(STATUS_LOGON_FAILURE),
        ReadOnlySMBViolation("No answer!"),
    ],
)
def test_nested_local_or_status_error_in_real_negotiation_is_not_reclassified(monkeypatch, error):
    class LocalSession:
        def __init__(self, *_args, **_kwargs):
            raise error

    monkeypatch.setattr(nmb, "NetBIOSTCPSession", LocalSession)
    with pytest.raises(type(error)) as caught:
        smbconnection.SMBConnection("fixture", "fixture", timeout=2)
    assert caught.value is error
    assert not is_transport_error(error)
    assert not close_failed_negotiation(error)


def test_local_callback_no_answer_does_not_poison_or_retry_connection():
    connection = MemoryConnection()
    client = installed(connection)
    error = Exception("No answer!")

    def callback(_content):
        raise error

    try:
        with pytest.raises(Exception) as caught:
            client.retrieve_file("share", "secret.txt", callback)
        assert caught.value is error
        assert not is_network_unavailable(error)
        assert not transport_state(connection).failed
        assert connection.events.count("create") == 1
        assert client._network_recovery.failures == 0
    finally:
        client.close()


_IDENTITY_IMPORT_SOURCE = """
from impacket.smbconnection import SMBConnection
code = SMBConnection.negotiateSessionWildcard.__code__
def guard(connection):
    return type(connection) is not SMBConnection
"""


def test_static_identity_import_guard_accepts_only_the_exact_read_only_use():
    assert _identity_only_smb_connection_references(ast.parse(_IDENTITY_IMPORT_SOURCE))


@pytest.mark.parametrize(
    "replacement",
    [
        "SMBConnection()",
        "SMBConnection",
        "helper(SMBConnection)",
        "SMBConnection.negotiateSessionWildcard()",
        'getattr(SMBConnection, "close")',
    ],
)
def test_static_identity_import_guard_rejects_construction_alias_and_calls(replacement):
    source = _IDENTITY_IMPORT_SOURCE.replace("SMBConnection.negotiateSessionWildcard.__code__", replacement)
    assert not _identity_only_smb_connection_references(ast.parse(source))


def test_static_identity_import_guard_rejects_renamed_capability_import():
    source = _IDENTITY_IMPORT_SOURCE.replace("import SMBConnection", "import SMBConnection as Constructor")
    assert not _identity_only_smb_connection_references(ast.parse(source))


@pytest.mark.parametrize(
    "code,expected",
    [
        (STATUS_ACCESS_DENIED, "access_denied"),
        (STATUS_LOGON_FAILURE, "authentication"),
    ],
)
def test_metrics_typed_refusal_stays_authoritative_with_negotiation_text(code, expected):
    error = SessionError(code)
    error.args = ("No answer!",)
    assert classify_smb_error(error) == expected
