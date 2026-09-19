import ast
import inspect
import logging
from pathlib import Path

import pytest

from impacket import smb as impacket_smb

from man_spider.lib.smb import NON_BLOCKING_READ_SHARE_ACCESS


REMOTE_MODULES = (
    Path("man_spider/preflight.py"),
    Path("man_spider/lib/file.py"),
    Path("man_spider/lib/smb.py"),
    Path("man_spider/lib/smb_rpc.py"),
    Path("man_spider/lib/smb_directory.py"),
)

READ_ONLY_SMB_CALLS = {
    "close",
    "close_with_postquery",
    "connectTree",
    "disconnectTree",
    "forget_closed_file",
    "getSMBServer",
    "getDialect",
    "getServerDNSDomainName",
    "getServerName",
    "isGuestSession",
    "kerberosLogin",
    "listPath",
    "login",
    # Low-level SMB2 path used to request post-read attributes in the already
    # required CLOSE response. The structural assertions below pin its access,
    # disposition, and packet command to read-only values.
    "SMB_PACKET",
    "create",
    "isSnapshotRequest",
    # Read-only DFS namespace lookup. A separate structural assertion pins the
    # only IOCTL to FSCTL_DFS_GET_REFERRALS.
    "ioctl",
    "queryInfo",
    "read",
    "recvSMB",
    "sendSMB",
    "timestampForSnapshot",
    # Explicit SMB1 read-only open and bounded READ replace getFile(), whose
    # dependency default requests exclusive/batch oplocks.
    "get_flags",
    "tree_connect_andx",
    "nt_create_andx",
    "query_file_info",
    "read_andx",
    "disconnect_tree",
}

MODULE_SMB_CALLS = {
    # Additional methods belong only to these explicitly constrained
    # capabilities. In particular, writeFile is not a general exception.
    "man_spider/lib/smb_rpc.py": {"getRemoteName", "getRemoteHost", "openFile", "closeFile", "readFile"},
    "man_spider/lib/smb_directory.py": {"queryDirectory", "send_trans2", "get_remote_name"},
}


def _is_smb_connection_receiver(node):
    return (isinstance(node, ast.Name) and node.id in {"conn", "connection"}) or (
        isinstance(node, ast.Attribute)
        and node.attr in {"conn", "__connection", "_connection", "_enumeration_connection"}
    )


def _operation_calls(tree, name=None):
    """Inspect direct calls and bound methods passed through .call guards.

    Unwrap any .call receiver for detection, not just the trusted guard: an
    arbitrary wrapper must not hide forbidden operations from the audit.
    Return the original call so ownership and source-order checks stay exact.
    """

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        method, arguments = node.func, node.args
        if method.attr == "call" and arguments and isinstance(arguments[0], ast.Attribute):
            method, arguments = arguments[0], arguments[1:]
        if name is None or method.attr == name:
            yield node, method, arguments


def _owned_srvsvc_write(filename, node, tree):
    """Recognize one exact pipe-write site, not arbitrary writes in an RPC file."""

    if filename.as_posix() != "man_spider/lib/smb_rpc.py":
        return False
    operation = next((item for item in _operation_calls(node, "writeFile") if item[0] is node), None)
    if operation is None:
        return False
    _, method, arguments = operation
    if node.func is not method and ast.unparse(node.func) != "self._transport_state.call":
        return False
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    current = node
    owner_function = owner_class = None
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.FunctionDef) and owner_function is None:
            owner_function = current
        if isinstance(current, ast.ClassDef) and owner_class is None:
            owner_class = current
    if (
        owner_function is None
        or owner_function.name != "send"
        or owner_class is None
        or owner_class.name != "_ShareEnumerationTransport"
        or ast.unparse(method.value) != "self._enumeration_connection"
        or [ast.unparse(argument) for argument in arguments]
        != ["self._enumeration_tree", "self._enumeration_handle", "payload"]
        or len(node.keywords) != 1
        or node.keywords[0].arg != "offset"
        or not isinstance(node.keywords[0].value, ast.Constant)
        or node.keywords[0].value.value != 0
    ):
        return False
    assignments = [
        statement for statement in ast.walk(owner_function)
        if isinstance(statement, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "payload" for target in statement.targets)
    ]
    return (
        len(assignments) == 1
        and assignments[0].lineno < node.lineno
        and ast.unparse(assignments[0].value) == "_validate_share_rpc_message(data)"
    )


def test_runtime_smb_calls_are_limited_to_read_only_operations():
    """Keep direct and guarded Impacket calls behind the same strict allowlist."""

    observed = set()
    for filename in REMOTE_MODULES:
        tree = ast.parse(filename.read_text(encoding="utf-8"), filename=str(filename))
        for node, method, _arguments in _operation_calls(tree):
            if _is_smb_connection_receiver(method.value):
                if _owned_srvsvc_write(filename, node, tree):
                    continue
                assert method.attr in READ_ONLY_SMB_CALLS | MODULE_SMB_CALLS.get(filename.as_posix(), set()), (
                    filename, node.lineno, method.attr
                )
                observed.add(method.attr)

    assert observed
    assert {"connectTree", "disconnectTree", "create", "read", "openFile", "closeFile", "queryDirectory"} <= observed


def test_low_level_smb2_retrieval_can_only_open_for_read_and_send_close():
    tree = ast.parse(Path("man_spider/lib/smb.py").read_text(encoding="utf-8"))
    creates = [
        (node, arguments)
        for node, method, arguments in _operation_calls(tree, "create")
        if isinstance(method.value, ast.Name) and method.value.id == "connection"
    ]
    assert len(creates) == 1
    create, arguments = creates[0]
    assert isinstance(arguments[2], ast.Name) and arguments[2].id == "FILE_READ_DATA"
    assert isinstance(arguments[3], ast.Name) and arguments[3].id == "NON_BLOCKING_READ_SHARE_ACCESS"
    assert isinstance(arguments[4], ast.Name) and arguments[4].id == "FILE_NON_DIRECTORY_FILE"
    assert isinstance(arguments[5], ast.Name) and arguments[5].id == "FILE_OPEN"
    assert isinstance(arguments[6], ast.Constant) and arguments[6].value == 0
    assert isinstance(arguments[7], ast.Name) and arguments[7].id == "SMB2_IL_IMPERSONATION"
    assert isinstance(arguments[8], ast.Constant) and arguments[8].value == 0
    assert isinstance(arguments[9], ast.Name) and arguments[9].id == "SMB2_OPLOCK_LEVEL_NONE"
    assert len(create.keywords) == 1
    assert create.keywords[0].arg == "createContexts"

    share_access_assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "NON_BLOCKING_READ_SHARE_ACCESS" for target in node.targets
        )
    ]
    assert len(share_access_assignments) == 1
    assert ast.unparse(share_access_assignments[0].value) == ("FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE")

    high_level_reads = [
        node
        for node, method, _arguments in _operation_calls(tree, "getFile")
        if _is_smb_connection_receiver(method.value)
    ]
    # Unknown wrappers must fail closed rather than delegating open semantics
    # to Impacket's high-level retrieval helper.
    assert high_level_reads == []

    packet_commands = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and target.value.id == "packet"
            and isinstance(target.slice, ast.Constant)
            and target.slice.value == "Command"
        ):
            packet_commands.append(node.value)
    assert len(packet_commands) == 1
    assert all(isinstance(command, ast.Name) and command.id == "SMB2_CLOSE" for command in packet_commands)


def test_dfs_ioctl_can_only_request_referrals():
    tree = ast.parse(Path("man_spider/lib/smb.py").read_text(encoding="utf-8"))
    calls = [
        arguments
        for _node, method, arguments in _operation_calls(tree, "ioctl")
        if (
            (isinstance(method.value, ast.Name) and method.value.id == "connection")
            or (isinstance(method.value, ast.Attribute) and method.value.attr == "__connection")
        )
    ]

    assert len(calls) == 1
    arguments = calls[0]
    assert isinstance(arguments[1], ast.Constant) and arguments[1].value is None
    assert ast.unparse(arguments[2]) == "self._FSCTL_DFS_GET_REFERRALS"
    assert ast.unparse(arguments[3]) == "self._IOCTL_IS_FSCTL"


def test_entire_package_has_no_smb_file_mutation_calls_or_hidden_getattr_aliases():
    forbidden = {
        "createDirectory",
        "deleteDirectory",
        "deleteFile",
        "putFile",
        "rename",
        "set_file_info",
        "setInfo",
        "setPathInformation",
        "storeFile",
        "truncate",
        "writeFile",
        "write_andx",
    }
    violations = []
    for filename in Path("man_spider").rglob("*.py"):
        tree = ast.parse(filename.read_text(encoding="utf-8"), filename=str(filename))
        for node, method, _arguments in _operation_calls(tree):
            if method.attr in forbidden and not _owned_srvsvc_write(filename, node, tree):
                violations.append((str(filename), node.lineno, method.attr))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in forbidden
            ):
                violations.append((str(filename), node.lineno, f"getattr:{node.args[1].value}"))
    assert violations == []


def test_rpc_write_exception_requires_fixed_own_pipe_and_validated_rpc_payload():
    filename = Path("man_spider/lib/smb_rpc.py")
    tree = ast.parse(filename.read_text(encoding="utf-8"))
    writes = [
        node for node, _method, _arguments in _operation_calls(tree, "writeFile")
    ]
    assert len(writes) == 1
    assert _owned_srvsvc_write(filename, writes[0], tree)
    # The same call shape must never exempt another module from the ban.
    assert not _owned_srvsvc_write(Path("man_spider/lib/file.py"), writes[0], tree)
    opens = [
        (node, arguments) for node, _method, arguments in _operation_calls(tree, "openFile")
    ]
    assert len(opens) == 1
    open_call, open_arguments = opens[0]
    assert [ast.unparse(argument) for argument in open_arguments] == ["self._enumeration_tree", repr(r"\srvsvc")]
    assert {keyword.arg: ast.literal_eval(keyword.value) for keyword in open_call.keywords} == {
        "desiredAccess": 3, "shareMode": 1, "creationOption": 0x40, "creationDisposition": 1,
        "fileAttributes": 0x80, "impersonationLevel": 2, "securityFlags": 0, "oplockLevel": 0,
        "createContexts": None,
    }
    connects = [
        arguments for _node, _method, arguments in _operation_calls(tree, "connectTree")
    ]
    assert len(connects) == 1
    assert len(connects[0]) == 1
    assert ast.literal_eval(connects[0][0]) == "IPC$"


@pytest.mark.parametrize("wrapper", ["self._transport_state.call", "transport_state(connection).call", "other.call"])
@pytest.mark.parametrize("method", ["writeFile", "deleteFile", "setInfo", "putFile", "rename"])
def test_guarded_mutating_methods_are_visible_and_never_gain_rpc_exception(wrapper, method):
    tree = ast.parse(f"{wrapper}(connection.{method}, tree_id, handle, payload)")
    operations = list(_operation_calls(tree, method))
    assert len(operations) == 1
    node, function, arguments = operations[0]
    assert _is_smb_connection_receiver(function.value)
    assert [ast.unparse(argument) for argument in arguments] == ["tree_id", "handle", "payload"]
    assert method not in READ_ONLY_SMB_CALLS | MODULE_SMB_CALLS["man_spider/lib/smb_rpc.py"]
    assert not _owned_srvsvc_write(Path("man_spider/lib/smb_rpc.py"), node, tree)


@pytest.mark.parametrize(
    "replacement",
    [
        ("self._enumeration_connection.writeFile", "connection.writeFile"),
        ("self._enumeration_handle, payload, offset=0", "other_handle, payload, offset=0"),
        ("payload, offset=0", "payload, offset=1"),
        ("payload = _validate_share_rpc_message(data)", "payload = data"),
        ("self._transport_state.call", "other.call"),
    ],
)
def test_guarded_srvsvc_exception_rejects_changed_owner_handle_offset_payload_or_guard(replacement):
    filename = Path("man_spider/lib/smb_rpc.py")
    source = filename.read_text(encoding="utf-8")
    before, after = replacement
    assert before in source
    tree = ast.parse(source.replace(before, after))
    writes = list(_operation_calls(tree, "writeFile"))
    assert len(writes) == 1
    assert not _owned_srvsvc_write(filename, writes[0][0], tree)


def _identity_only_smb_connection_references(tree):
    """The failure-state module may inspect identity, not construct/alias SMB."""

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "impacket.smbconnection":
            if any(alias.name == "SMBConnection" and alias.asname is not None for alias in node.names):
                return False
    references = [node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "SMBConnection"]
    if len(references) != 2:
        return False
    for node in references:
        parent = parents.get(node)
        if (
            isinstance(parent, ast.Attribute)
            and parent.value is node
            and parent.attr == "negotiateSessionWildcard"
        ):
            outer = parents.get(parent)
            if isinstance(outer, ast.Attribute) and outer.value is parent and outer.attr == "__code__":
                continue
        if (
            isinstance(parent, ast.Compare)
            and len(parent.ops) == len(parent.comparators) == 1
            and isinstance(parent.ops[0], ast.IsNot)
            and parent.comparators[0] is node
            and ast.unparse(parent.left) == "type(connection)"
        ):
            continue
        return False
    return True


def test_only_guarded_transport_modules_import_impacket_smb_connection():
    importers = set()
    for filename in Path("man_spider").rglob("*.py"):
        tree = ast.parse(filename.read_text(encoding="utf-8"), filename=str(filename))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "impacket.smbconnection":
                # Importing exception types does not expose a transport.  This
                # boundary is specifically intended to keep construction of
                # the mutable SMBConnection capability inside guarded modules.
                if any(alias.name == "SMBConnection" for alias in node.names):
                    importers.add(filename.as_posix())
    assert importers == {
        "man_spider/lib/smb.py", "man_spider/preflight.py", "man_spider/lib/smb_transport.py",
    }
    # The extra import is solely an identity/provenance check and does not
    # make this module another mutable-connection construction boundary.
    transport_tree = ast.parse(Path("man_spider/lib/smb_transport.py").read_text(encoding="utf-8"))
    assert _identity_only_smb_connection_references(transport_tree)


def test_package_has_no_path_based_directory_creation_or_recursive_removal():
    violations = []
    for filename in Path("man_spider").rglob("*.py"):
        tree = ast.parse(filename.read_text(encoding="utf-8"), filename=str(filename))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr in {"makedirs", "mkdtemp", "rmtree"}:
                violations.append((str(filename), node.lineno, node.func.attr))
                continue
            if node.func.attr != "mkdir":
                continue
            if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "os"):
                violations.append((str(filename), node.lineno, "path-based mkdir"))
                continue
            if not any(keyword.arg == "dir_fd" for keyword in node.keywords):
                violations.append((str(filename), node.lineno, "os.mkdir without dir_fd"))
    assert violations == []


def test_package_has_no_dormant_multiprocessing_manager_or_legacy_processpool():
    """A dormant Manager used to create implicit files below ambient TMPDIR."""

    assert not Path("man_spider/lib/processpool.py").exists()
    violations = []
    for filename in Path("man_spider").rglob("*.py"):
        tree = ast.parse(filename.read_text(encoding="utf-8"), filename=str(filename))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr == "Manager":
                violations.append((str(filename), node.lineno))
    assert violations == []


def test_manspider_loggers_never_propagate_to_embedding_root_handlers():
    """Embedding code must not redirect scanner records to an arbitrary sink."""

    import man_spider.lib.logger  # noqa: F401

    assert logging.getLogger("manspider").propagate is False
    # Children may propagate to the package logger so they reach its queue,
    # but propagation stops there and cannot reach the process root logger.
    assert logging.getLogger("manspider.worker").parent is logging.getLogger("manspider")


def test_installed_impacket_smb1_fallback_opens_existing_file_with_read_only_access(monkeypatch):
    """Audit the dependency path used when an SMB1 server is encountered."""

    protocol = object.__new__(impacket_smb.SMB)
    protocol._SMB__remote_name = "server"
    observed = {}
    protocol.tree_connect_andx = lambda _service, _password: 11

    def nt_create(_tree_id, _filename, **kwargs):
        observed.update(kwargs)
        return 22

    protocol.nt_create_andx = nt_create
    protocol.query_file_info = lambda _tree_id, _file_id: object()
    protocol._SMB__nonraw_retr_file = lambda *_args: None
    protocol.close = lambda _tree_id, _file_id: None
    protocol.disconnect_tree = lambda _tree_id: None
    monkeypatch.setattr(
        impacket_smb,
        "SMBQueryFileStandardInfo",
        lambda _response: {"EndOfFile": 0},
    )

    impacket_smb.SMB.retr_file(
        protocol,
        "share",
        "existing.txt",
        lambda _data: None,
        shareAccessMode=NON_BLOCKING_READ_SHARE_ACCESS,
    )

    expected_access = (
        impacket_smb.READ_CONTROL
        | impacket_smb.FILE_READ_ATTRIBUTES
        | impacket_smb.FILE_READ_EA
        | impacket_smb.FILE_READ_DATA
    )
    mutation_access = (
        impacket_smb.FILE_WRITE_DATA
        | impacket_smb.FILE_APPEND_DATA
        | impacket_smb.FILE_WRITE_EA
        | impacket_smb.FILE_WRITE_ATTRIBUTES
        | impacket_smb.DELETE
        | impacket_smb.WRITE_DAC
        | impacket_smb.WRITE_OWNER
    )
    assert observed == {
        "shareAccessMode": NON_BLOCKING_READ_SHARE_ACCESS,
        "accessMask": expected_access,
    }
    assert expected_access & mutation_access == 0
    disposition = inspect.signature(impacket_smb.SMB.nt_create_andx).parameters["disposition"]
    assert disposition.default == impacket_smb.FILE_OPEN
