"""Read-only directory enumeration with ownership-bound, exact-once cleanup.

Keep Impacket's installed listing implementation (including pagination and
snapshot paths), but give it only the capabilities needed for enumeration.
Cleanup errors are deferred until enumeration has unwound so a failed CLOSE
cannot suppress disconnect or replace an earlier listing error.
"""

import struct
import sys
from functools import wraps

from impacket import smb, smb3
from impacket.smbconnection import SessionError

from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib.smb_transport import transport_state


class _PinnedContext:
    __slots__ = ("_payload",)

    def __init__(self, payload):
        self._payload = payload

    def getData(self):
        return self._payload


def _snapshot_contexts(contexts):
    if contexts is None:
        return None
    if not isinstance(contexts, (list, tuple)) or len(contexts) != 1:
        raise ReadOnlySMBViolation("SMB directory open contains unsupported CREATE contexts")
    try:
        payload = bytes(contexts[0].getData())
        header = struct.unpack_from("<IHHHHI", payload)
    except (AttributeError, TypeError, ValueError, struct.error) as exc:
        raise ReadOnlySMBViolation("SMB directory snapshot context is malformed") from exc
    if (
        len(payload) != 32
        or header != (0, 16, 4, 0, 24, 8)
        or payload[16:20] != b"TWrp"
        or payload[20:24] != b"\x00" * 4
    ):
        raise ReadOnlySMBViolation("SMB directory open permits only a time-warp CREATE context")
    return (_PinnedContext(payload),)


def _require_methods(connection, names):
    missing = [name for name in names if not callable(getattr(connection, name, None))]
    if missing:
        raise ReadOnlySMBViolation(f"SMB directory transport lacks required capabilities: {', '.join(missing)}")


def _guard_operation(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        # Impacket also parses directory records outside this adapter. Its
        # finally block can call us while a parser's safety violation is
        # unwinding, before read_only_list_path gets to catch that exception.
        active_error = sys.exc_info()[1]
        if isinstance(active_error, ReadOnlySMBViolation):
            self._read_only_violation = active_error
        if self._read_only_violation is not None:
            raise self._read_only_violation
        try:
            return method(self, *args, **kwargs)
        except ReadOnlySMBViolation as exc:
            self._read_only_violation = exc
            raise

    return guarded


class _DirectoryLifetime:
    def __init__(self, connection):
        self._connection = connection
        self._transport_state = transport_state(connection)
        self._tree = None
        self._cleanup_errors = []
        self._read_only_violation = None

    def _remember_tree(self, tree):
        if type(tree) is not int or not 0 <= tree <= 0xFFFFFFFF:
            raise ReadOnlySMBViolation("SMB directory transport returned an invalid tree identifier")
        self._tree = tree
        return tree

    def _require_tree(self, tree):
        if self._tree is None or type(tree) is not int or tree != self._tree:
            raise ReadOnlySMBViolation("SMB directory operation does not own this tree reference")

    def _disconnect(self, tree, method):
        self._require_tree(tree)
        # Release this invocation's reference once. A failed response does not
        # authorize retrying against an identifier which may have been reused.
        self._tree = None
        try:
            self._transport_state.call(method, tree)
        except BaseException as exc:
            self._cleanup_errors.append(exc)
            if isinstance(exc, ReadOnlySMBViolation):
                self._read_only_violation = exc

    def finish(self):
        raise NotImplementedError


class _SMB2DirectoryTransport(_DirectoryLifetime):
    def __init__(self, connection):
        _require_methods(
            connection,
            ("connectTree", "create", "queryDirectory", "close", "disconnectTree", "isSnapshotRequest"),
        )
        super().__init__(connection)
        self._file = None

    @_guard_operation
    def isSnapshotRequest(self, path):
        return self._connection.isSnapshotRequest(path)

    @_guard_operation
    def timestampForSnapshot(self, path):
        _require_methods(self._connection, ("timestampForSnapshot",))
        return self._connection.timestampForSnapshot(path)

    @_guard_operation
    def connectTree(self, share):
        if self._tree is not None:
            raise ReadOnlySMBViolation("SMB directory enumeration already owns a tree reference")
        return self._remember_tree(self._transport_state.call(self._connection.connectTree, share))

    @_guard_operation
    def create(
        self,
        tree,
        path,
        desired_access,
        share_mode,
        creation_options,
        creation_disposition,
        file_attributes,
        impersonation_level=2,
        security_flags=0,
        oplock_level=0,
        createContexts=None,
    ):
        self._require_tree(tree)
        observed = (
            desired_access,
            share_mode,
            creation_options,
            creation_disposition,
            file_attributes,
            impersonation_level,
            security_flags,
            oplock_level,
        )
        # READ_DATA/LIST_DIRECTORY | READ_ATTRIBUTES, unrestricted sharing,
        # DIRECTORY | SYNCHRONOUS_IO_NONALERT, OPEN existing, no oplock.
        if any(type(value) is not int for value in observed) or observed != (0x81, 7, 0x21, 1, 0, 2, 0, 0):
            raise ReadOnlySMBViolation("SMB directory CREATE differs from the pinned read-only open")
        if self._file is not None:
            raise ReadOnlySMBViolation("SMB directory enumeration already owns an open handle")
        contexts = _snapshot_contexts(createContexts)
        file_id = self._transport_state.call(
            self._connection.create,
            tree,
            path,
            desiredAccess=desired_access,
            shareMode=share_mode,
            creationOptions=creation_options,
            creationDisposition=creation_disposition,
            fileAttributes=file_attributes,
            impersonationLevel=impersonation_level,
            securityFlags=security_flags,
            oplockLevel=oplock_level,
            createContexts=contexts,
        )
        if not isinstance(file_id, bytes) or len(file_id) != 16:
            raise ReadOnlySMBViolation("SMB directory transport returned an invalid file identifier")
        self._file = file_id
        return file_id

    def _require_file(self, tree, file_id):
        self._require_tree(tree)
        if self._file is None or not isinstance(file_id, bytes) or file_id != self._file:
            raise ReadOnlySMBViolation("SMB directory operation does not own this read-only handle")

    @_guard_operation
    def queryDirectory(self, tree, file_id, pattern, *, maxBufferSize, informationClass):
        self._require_file(tree, file_id)
        if (
            type(maxBufferSize) is not int
            or maxBufferSize != 65535
            or type(informationClass) is not int
            or informationClass != 2
        ):
            raise ReadOnlySMBViolation("SMB directory query differs from the pinned enumeration request")
        return self._transport_state.call(
            self._connection.queryDirectory,
            tree,
            file_id,
            pattern,
            maxBufferSize=maxBufferSize,
            informationClass=informationClass,
        )

    @_guard_operation
    def close(self, tree, file_id):
        self._require_file(tree, file_id)
        self._file = None
        try:
            self._transport_state.call(self._connection.close, tree, file_id)
        except BaseException as exc:
            self._cleanup_errors.append(exc)
            if isinstance(exc, ReadOnlySMBViolation):
                self._read_only_violation = exc

    @_guard_operation
    def disconnectTree(self, tree):
        self._disconnect(tree, self._connection.disconnectTree)

    def finish(self):
        if self._read_only_violation is not None or self._transport_state.failed:
            return
        if self._file is not None:
            self.close(self._tree, self._file)
        if self._tree is not None and self._read_only_violation is None and not self._transport_state.failed:
            self.disconnectTree(self._tree)


class _SMB1DirectoryTransport(_DirectoryLifetime):
    def __init__(self, connection):
        _require_methods(
            connection,
            ("get_flags", "get_remote_name", "tree_connect_andx", "send_trans2", "recvSMB", "disconnect_tree"),
        )
        super().__init__(connection)
        _, flags2 = connection.get_flags()
        if type(flags2) is not int:
            raise ReadOnlySMBViolation("SMB1 directory transport returned invalid encoding flags")
        # Unbound SMB.list_path reads these two private dialect attributes;
        # provide their captured values, never a raw-connection escape hatch.
        self._SMB__flags2 = flags2
        self._SMB__remote_name = connection.get_remote_name()

    @_guard_operation
    def tree_connect_andx(self, path, password):
        if self._tree is not None:
            raise ReadOnlySMBViolation("SMB1 directory enumeration already owns a tree reference")
        return self._remember_tree(self._transport_state.call(self._connection.tree_connect_andx, path, password))

    @_guard_operation
    def send_trans2(self, tree, setup, name, parameters, data):
        self._require_tree(tree)
        if type(setup) is not int or setup not in (1, 2) or name != "\x00" or data not in (b"", ""):
            raise ReadOnlySMBViolation("SMB1 directory transport permits only FIND_FIRST2/FIND_NEXT2")
        expected_type = smb.SMBFindFirst2_Parameters if setup == 1 else smb.SMBFindNext2_Parameters
        try:
            if type(parameters) is not expected_type:
                raise TypeError("unexpected FIND parameter object")
            payload = bytes(parameters.getData())
            if setup == 1:
                observed = struct.unpack_from("<HHHHI", payload)
                valid = observed == (0x37, 512, 6, 0x104, 0)
            else:
                _sid, count, information, _resume, flags = struct.unpack_from("<HHHIH", payload)
                valid = (count, information, flags) == (1024, 0x104, 6)
        except (AttributeError, TypeError, ValueError, struct.error) as exc:
            raise ReadOnlySMBViolation("SMB1 directory FIND parameters are malformed") from exc
        if not valid:
            raise ReadOnlySMBViolation("SMB1 directory FIND differs from the pinned read-only request")
        # Preserve the installed encoder's bytes, including filename encoding,
        # instead of giving the dependency a mutable parameter object again.
        return self._transport_state.call(self._connection.send_trans2, tree, setup, name, payload, data)

    @_guard_operation
    def recvSMB(self):
        if self._tree is None:
            raise ReadOnlySMBViolation("SMB1 directory receive has no owned tree")
        return self._transport_state.call(self._connection.recvSMB)

    @_guard_operation
    def disconnect_tree(self, tree):
        self._disconnect(tree, self._connection.disconnect_tree)

    def finish(self):
        # SMB1 has no pinned/reference-counted tree. TREE_DISCONNECT also
        # releases an unfinished search if pagination failed before EOS.
        if self._tree is not None and self._read_only_violation is None and not self._transport_state.failed:
            self.disconnect_tree(self._tree)


def read_only_list_path(connection, share, nt_path):
    """List using a captured transport; flag failed cleanup for its owner.

    ``smb_cleanup_failed`` tells SMBClient to retire the captured session,
    since a failed CLOSE can leave a handle alive behind a separately pinned
    SMB2 tree. No handle is retried or transferred to a newer connection.
    """

    _require_methods(connection, ("getDialect", "getSMBServer"))
    dialect = connection.getDialect()
    raw = connection.getSMBServer()
    if dialect == smb.SMB_DIALECT:
        adapter = _SMB1DirectoryTransport(raw)
        implementation = smb.SMB.list_path
    elif type(dialect) is int and dialect in (0x202, 0x210, 0x300, 0x302, 0x311):
        adapter = _SMB2DirectoryTransport(raw)
        implementation = smb3.SMB3.listPath
    else:
        raise ReadOnlySMBViolation("SMB directory transport negotiated an unsupported dialect")

    primary_error = None
    result = None
    try:
        result = implementation(adapter, share, nt_path)
    except BaseException as exc:
        primary_error = exc
        if isinstance(exc, ReadOnlySMBViolation):
            adapter._read_only_violation = exc
    finally:
        try:
            adapter.finish()
        except BaseException as exc:
            adapter._cleanup_errors.append(exc)
    error = adapter._read_only_violation
    if error is None:
        # A user cancellation during cleanup must not disappear behind an
        # earlier ordinary listing error. Still complete owned cleanup first.
        error = next(
            (
                exc
                for exc in (primary_error, *adapter._cleanup_errors)
                if isinstance(exc, (KeyboardInterrupt, SystemExit))
            ),
            primary_error,
        )
    if error is None and adapter._cleanup_errors:
        error = adapter._cleanup_errors[0]
    if error is not None:
        # Preserve SMBConnection.listPath's public error type and status code.
        if isinstance(error, (smb.SessionError, smb3.SessionError)):
            translated = SessionError(error.get_error_code(), error.get_error_packet())
            translated.__cause__ = error
            error = translated
        if adapter._cleanup_errors:
            error.smb_cleanup_failed = True
        raise error
    return result
