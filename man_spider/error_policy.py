"""Shared error classification that is safe to import from state-only tools."""

from contextlib import suppress
import re

from impacket import nt_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smb import SessionError


NETWORK_ACCESS_DENIED_MARKER = "[network_access_denied]"
# Emitted only for transport failures proved at a guarded remote I/O boundary.
# Kept here so state-only readers need not import the lib package's scanner.
NETWORK_UNAVAILABLE_MARKER = "[network-unavailable]"
# Durable classification for deliberately blocked DFS traversal, not an I/O failure.
DFS_SCOPE_BLOCKED_MARKER = "[dfs_scope_policy]"
_ACCESS_DENIED_STATUS_NAMES = (
    "STATUS_ACCESS_DENIED",
    "STATUS_NETWORK_ACCESS_DENIED",
    "STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT",
    "STATUS_ACCESS_DISABLED_BY_POLICY_OTHER",
    "STATUS_ACCESS_DISABLED_BY_POLICY_PATH",
    "STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER",
    "STATUS_CTX_WINSTATION_ACCESS_DENIED",
    "STATUS_VHD_PARENT_VHD_ACCESS_DENIED",
)
_ACCESS_DENIED_STATUS_CODES = frozenset(
    value for name in _ACCESS_DENIED_STATUS_NAMES if isinstance((value := getattr(nt_errors, name, None)), int)
)
_ACCESS_DENIED_TEXT_MARKERS = (
    *[name.casefold() for name in _ACCESS_DENIED_STATUS_NAMES],
    "status_access_disabled_by_policy",
    "nt_status_access_denied",
    "rpc_s_access_denied",
    "error_access_denied",
    "errnoaccess",
    "erraccess",
)
_SMB1_ERRSRV_CLASS = 0x02
_ACCESS_DENIED_TEXT_RE = re.compile(
    r"\A(?:" + "|".join(re.escape(marker) for marker in _ACCESS_DENIED_TEXT_MARKERS) + r")(?=$| - |:|\()"
)
_LEGACY_ERROR_PREFIX_RE = re.compile(
    r"\A(?:(?:[a-z][a-z0-9_]{1,15} )?sessionerror|csessionerror|dcerpcsessionerror|"
    r"dcerpc runtime error|filelisterror|fileretrievalerror|runtimeerror|oserror):\s*"
)
_LEGACY_STATUS_CODE_RE = re.compile(r"\Acode:\s*(0x[0-9a-f]{1,8}|[0-9]{1,10})\s*-\s*")
_LEGACY_SMB1_DENIAL_RE = re.compile(
    r"\Aclass:\s*(?:errdos,\s*code:\s*errnoaccess|errsrv,\s*code:\s*erraccess)(?=$|\()"
)
_LEGACY_RETRIEVAL_RE = re.compile(r'\Aerror retrieving file "[^"\r\n]*": ([^"\r\n]*)\Z')
_ANCESTOR_BLOCKED_PREFIX = "blocked by ancestor "
_LEGACY_ANCESTOR_KEY_RE = re.compile(
    r"\A(?:target|share|directory)\|smb\|[^|\r\n]+\|[0-9]{1,5}(?=\||: |$)"
)


def _legacy_access_denied(text: str) -> bool:
    """Accept anchored status syntax, never tokens found inside resource names.

    Old manifests contain strings rather than typed exceptions. Keep their
    known error wrappers, but reject ambiguous quoted retrieval messages.
    A string deliberately forged as an entire valid diagnostic is inherently
    indistinguishable from one without preserving structured error metadata.
    """

    text = text.casefold().strip()
    for _ in range(8):
        if text == NETWORK_ACCESS_DENIED_MARKER or text.startswith(NETWORK_ACCESS_DENIED_MARKER + " "):
            return True
        if text.startswith(_ANCESTOR_BLOCKED_PREFIX):
            blocked = text[len(_ANCESTOR_BLOCKED_PREFIX):]
            # New records classify the original ancestor reason before adding
            # any resource key. Keep the established prefix used by resume.
            if blocked.startswith(NETWORK_ACCESS_DENIED_MARKER + " "):
                return True
            if _LEGACY_ANCESTOR_KEY_RE.match(blocked) is None:
                return False
            # Legacy keys may contain spaces, quotes and colons. Never search
            # them for status words: only inspect the final diagnostic field.
            prefix, separator, text = blocked.rpartition(": ")
            if not separator:
                return False
            if prefix.endswith(": code") and re.match(r"(?:0x[0-9a-f]{1,8}|[0-9]{1,10})\s*-", text):
                text = f"code: {text}"
            elif prefix.endswith((": errdos, code", ": errsrv, code")):
                text = f"class: {prefix.rsplit(': ', 1)[1]}: {text}"
            continue
        retrieval = _LEGACY_RETRIEVAL_RE.fullmatch(text)
        if retrieval is not None:
            text = retrieval.group(1).strip()
            continue
        prefix = _LEGACY_ERROR_PREFIX_RE.match(text)
        if prefix is None:
            break
        text = text[prefix.end():]

    status = _LEGACY_STATUS_CODE_RE.match(text)
    if status is not None:
        numeric = status.group(1)
        code = int(numeric, 16 if numeric.startswith("0x") else 10)
        if code not in _ACCESS_DENIED_STATUS_CODES and code != 5:
            return False
        return _ACCESS_DENIED_TEXT_RE.match(text[status.end():]) is not None
    return _ACCESS_DENIED_TEXT_RE.match(text) is not None or _LEGACY_SMB1_DENIAL_RE.match(text) is not None


def is_network_access_denied(error, *, include_context: bool = True) -> bool:
    """Recognize an SMB authorization refusal without treating local I/O as one."""

    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))

        typed_status = False
        for accessor in ("getErrorCode", "get_error_code"):
            getter = getattr(current, accessor, None)
            if getter is not None:
                with suppress(Exception):
                    code = getter()
                    typed_status = typed_status or isinstance(code, int)
                    if code in _ACCESS_DENIED_STATUS_CODES or (isinstance(current, DCERPCException) and code == 5):
                        return True

        if isinstance(current, SessionError):
            with suppress(Exception):
                error_class = current.get_error_class()
                error_code = current.get_error_code()
                if (error_class == SessionError.ERRDOS and error_code == SessionError.ERRnoaccess) or (
                    error_class == _SMB1_ERRSRV_CLASS and error_code == SessionError.ERRaccess
                ):
                    return True

        if not typed_status and _legacy_access_denied(str(current)):
            return True

        if include_context and isinstance(current, BaseException):
            pending.extend((current.__cause__, current.__context__))
    return False
