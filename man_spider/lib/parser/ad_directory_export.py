"""Passive inspection of credential-valued attributes in local AD exports.

RFC 2849 folding and attribute ownership are handled structurally. LDIF URL
values are never resolved. Binary attributes are retained as opaque Base64;
this module does not decrypt LAPS/gMSA blobs or perform directory operations.
Ambiguous duplicate JSON keys or excessive derived evidence are explicit
representation errors, never silent last-wins decoding or partial findings.
"""

import base64
import binascii
import codecs
import json
import re
import sys


_LAPS_PLAIN = "ms-mcs-admpwd"
_LAPS_JSON = "mslaps-password"
_UNICODE_PASSWORD = "unicodepwd"
_BITLOCKER_PASSWORD = "msfve-recoverypassword"
_OPAQUE_ATTRIBUTES = frozenset(
    {
        "mslaps-encryptedpassword",
        "mslaps-encryptedpasswordhistory",
        "mslaps-encrypteddsrmpassword",
        "mslaps-encrypteddsrmpasswordhistory",
        "msds-managedpassword",
        "supplementalcredentials",
        "msfve-keypackage",
    }
)
_KNOWN_ATTRIBUTES = _OPAQUE_ATTRIBUTES | {_LAPS_PLAIN, _LAPS_JSON, _UNICODE_PASSWORD, _BITLOCKER_PASSWORD}
_ATTRIBUTE_BYTES = tuple(
    attribute.encode(encoding)
    for attribute in sorted(_KNOWN_ATTRIBUTES)
    for encoding in ("ascii", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")
)
_FOLD_BYTES = tuple(
    "\n ".encode(encoding) for encoding in ("ascii", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")
)
_BITLOCKER_FORMAT = re.compile(r"[0-9]{6}(?:[- ]?[0-9]{6}){7}")
_ATTRIBUTE_LINE = re.compile(rb"([A-Za-z][A-Za-z0-9-]*)(?:;[A-Za-z0-9-]+)*:([:<]?)( *)(.*)\Z")
_REFERENCE = re.compile(r"(?:\$\{[^{}\r\n]+\}|\$\([^()\r\n]+\)|\{\{[^{}\r\n]+\}\}|<%[^%\r\n]+%>)")
_MASKED = re.compile(r"(?:\[redacted\]|<redacted>|redacted|masked|\*{3,})", re.IGNORECASE)
_MIN_EVIDENCE_BUDGET = 1024 * 1024
_MAX_EVIDENCE_BUDGET = 32 * 1024 * 1024
_EVIDENCE_INPUT_MULTIPLIER = 16


class _DuplicateJSONKey(ValueError):
    """A parsed object must not hide a previous value with the same key."""


class _EvidenceFindings(list):
    """Bound repeated DN/path/context expansion without truncating secrets."""

    def __init__(self, data_length):
        super().__init__()
        self._size = 0
        self._budget = min(_MAX_EVIDENCE_BUDGET, max(_MIN_EVIDENCE_BUDGET, data_length * _EVIDENCE_INPUT_MULTIPLIER))

    def append(self, finding):
        self._size += sys.getsizeof(finding) + sys.getsizeof(finding[0]) + sys.getsizeof(finding[3])
        if self._size > self._budget:
            raise ValueError(
                f"AD export derived evidence exceeds context budget of {self._budget} bytes; "
                "inspection is incomplete, no partial or truncated AD findings were returned"
            )
        super().append(finding)


def _invalid_constant(value):
    raise ValueError(f"non-JSON numeric constant {value}")


def _json_loads(value):
    def unique_object(pairs):
        obj = {}
        for key, item in pairs:
            if key in obj:
                raise _DuplicateJSONKey("duplicate JSON object key during AD export inspection")
            obj[key] = item
        return obj

    return json.loads(value, parse_constant=_invalid_constant, object_pairs_hook=unique_object)


def _utf8(value):
    try:
        return value.decode("utf-8")
    except UnicodeError:
        return None


def _literal(value):
    # Unlike lexical script/config rules, this inspector owns a schema-defined
    # exported password value, not executable code. Bare $word and %word% can
    # be literal passwords; reject only explicit template forms and masking.
    if not isinstance(value, str) or "\x00" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    stripped = value.strip()
    return bool(stripped) and not (_REFERENCE.fullmatch(stripped) or _MASKED.fullmatch(stripped))


def _base64(value):
    """Accept RFC-shaped Base64, without whitespace or speculative repairs."""
    if not isinstance(value, (str, bytes)):
        return None
    try:
        encoded = value.encode("ascii") if isinstance(value, str) else value
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeError, ValueError, binascii.Error):
        return None
    if not decoded or base64.b64encode(decoded) != encoded:
        return None
    return decoded


def _numeric_bytes(value):
    if isinstance(value, list) and value and all(type(n) is int and 0 <= n <= 255 for n in value):
        return bytes(value)
    return None


def _material(attribute, source_value, *, encoding, decoded_bytes=None):
    """Return semantic value and classification details, never a guessed decode."""
    if attribute in _OPAQUE_ATTRIBUTES:
        # LDIF ':' is literal text, not an implicit Base64 encoding declaration.
        # For a binary attribute require an explicit encoded/byte-array value.
        if encoding == "plain":
            return None
        raw = decoded_bytes if decoded_bytes is not None else _base64(source_value)
        if not raw:
            return None
        canonical = base64.b64encode(raw).decode("ascii")
        return canonical, {
            "value_kind": "opaque-secret-bytes",
            "decoded_base64": canonical,
            "decoded_bytes_length": len(raw),
            "decoded_utf8": None,
            "evidence": "known exported credential attribute; binary format and live credential validity not verified",
        }

    if attribute == _UNICODE_PASSWORD:
        if encoding == "plain":
            return None
        raw = decoded_bytes if decoded_bytes is not None else _base64(source_value)
        if not raw or len(raw) % 2:
            return None
        try:
            quoted = raw.decode("utf-16-le")
        except UnicodeError:
            return None
        if len(quoted) < 3 or not quoted.startswith('"') or not quoted.endswith('"'):
            return None
        secret = quoted[1:-1]
        if not _literal(secret):
            return None
        return secret, {
            "value_kind": "unicode-password-write-value",
            "decoded_utf8": secret,
            "evidence": "quoted UTF-16 password write/import value; unicodePwd is not returned by ordinary LDAP searches",
        }

    if decoded_bytes is not None:
        decoded = _utf8(decoded_bytes)
    else:
        decoded = source_value
    if attribute == _LAPS_PLAIN:
        if not _literal(decoded):
            return None
        return decoded, {
            "value_kind": "plaintext-password",
            "decoded_utf8": decoded,
            "evidence": "literal exported legacy LAPS password; current credential validity not verified",
        }
    if attribute == _BITLOCKER_PASSWORD:
        if not isinstance(decoded, str) or not _BITLOCKER_FORMAT.fullmatch(decoded):
            return None
        digits = decoded.replace("-", "").replace(" ", "")
        groups = [digits[index : index + 6] for index in range(0, 48, 6)]
        if any(int(group) > 720885 or int(group) % 11 for group in groups):
            return None
        canonical = "-".join(groups)
        return canonical, {
            "value_kind": "bitlocker-recovery-password",
            "decoded_utf8": canonical,
            "evidence": "owned BitLocker recovery attribute with valid eight-group numeric format; volume and live key validity not verified",
        }
    if attribute == _LAPS_JSON:
        try:
            payload = _json_loads(decoded) if isinstance(decoded, str) else decoded
        except _DuplicateJSONKey:
            # A duplicate p/member is ambiguous evidence, unlike a malformed
            # unrelated sibling. It must not become a silent no-match.
            raise
        except (ValueError, UnicodeError, RecursionError):
            return None
        if not isinstance(payload, dict) or not _literal(payload.get("p")):
            return None
        details = {
            "value_kind": "laps-json-password",
            "decoded_utf8": payload["p"],
            "evidence": "password owned by an msLAPS-Password JSON attribute; current credential validity not verified",
        }
        for field, name in (("n", "laps_account"), ("t", "laps_update_time")):
            if isinstance(payload.get(field), str):
                try:
                    payload[field].encode("utf-8")
                except UnicodeError:
                    continue
                details[name] = payload[field]
        return payload["p"], details
    return None


def _evidence(material, data_length, **context):
    value, details = material
    context.update(details)
    context["span"] = "complete source document; value is structurally extracted"
    # Escaping is lossless and protects serialization even if unrelated source
    # properties contain lone surrogates. No source/decoded value is masked.
    return value, 0, data_length, json.dumps(context, ensure_ascii=True)


def _physical_lines(data):
    """LF/CRLF only, unlike splitlines() which also splits valid LDIF bytes."""
    offset = 0
    while offset < len(data):
        end = data.find(b"\n", offset)
        if end < 0:
            yield data[offset:]
            return
        line = data[offset:end]
        yield line[:-1] if line.endswith(b"\r") else line
        offset = end + 1


def _logical_lines(data):
    # LDIF is UTF-8. BOM-marked UTF-16/32 exports are an explicit compatibility
    # path; unmarked invalid value bytes are isolated to the affected sibling.
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        data = data.decode("utf-32").encode("utf-8")
    elif data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        data = data.decode("utf-16").encode("utf-8")
    elif data.startswith(codecs.BOM_UTF8):
        data = data[len(codecs.BOM_UTF8) :]
    parts = []
    first_line = 0
    for line_number, line in enumerate(_physical_lines(data), 1):
        if line.startswith(b" "):
            if parts:
                parts.append(line[1:])
            # RFC 2849 does not permit folding an empty line; an orphan cannot
            # become an independent credential attribute by stripping its space.
            continue
        if parts:
            yield first_line, b"".join(parts)
            parts = []
        if line:
            first_line = line_number
            parts = [line]
        else:
            yield line_number, b""
    if parts:
        yield first_line, b"".join(parts)


def inspect_active_directory_ldif_secrets(data):
    """Inspect inline LDIF attributes, without resolving URLs or changing AD."""
    # .ldf is also a SQL Server transaction-log suffix. Reject unrelated binary
    # bytes before decoding BOM-marked exports, without a second read or sniff.
    # These are necessary, not sufficient, markers: actual findings still need
    # structurally owned attribute lines and correctly represented values.
    lower = data.lower()
    # Folding may split the attribute name itself, not only its value. In that
    # case the unfolded structural pass must decide relevance instead of this
    # raw-byte guard. UTF-16/32 BOM compatibility has the same requirement.
    if not any(attribute in lower for attribute in _ATTRIBUTE_BYTES) and not any(fold in data for fold in _FOLD_BYTES):
        return ()
    findings = _EvidenceFindings(len(data))
    record_dn = None
    record_number = 1
    for line_number, line in _logical_lines(data):
        if not line:
            record_dn = None
            record_number += 1
            continue
        if line.startswith(b"#"):
            continue
        match = _ATTRIBUTE_LINE.fullmatch(line)
        if not match:
            continue
        original_name, marker, _fill, raw_source = match.groups()
        attribute = original_name.decode("ascii").lower()
        if attribute not in _KNOWN_ATTRIBUTES and attribute != "dn":
            continue
        if attribute == "dn":
            # A second dn begins a new ownership context even in an export
            # missing its blank record delimiter.
            record_dn = None
        if marker == b"<":
            continue  # Includes file:// and UNC references: never read/fetch.
        source_value = _utf8(raw_source)
        if source_value is None:
            continue
        decoded = _base64(raw_source) if marker == b":" else raw_source
        if decoded is None:
            continue
        if attribute == "dn":
            record_dn = _utf8(decoded)
            continue
        encoding = "base64" if marker == b":" else "plain"
        material = _material(attribute, source_value, encoding=encoding, decoded_bytes=decoded)
        if material is not None:
            findings.append(
                _evidence(
                    material,
                    len(data),
                    format="ldif",
                    attribute=original_name.decode("ascii"),
                    line=line_number,
                    record=record_number,
                    record_dn=record_dn,
                    encoding=encoding,
                    source_value=source_value,
                    source_attribute_line=line.decode("utf-8"),
                )
            )
    return tuple(findings)


def _pointer_key(key):
    return key.replace("~", "~0").replace("/", "~1")


def _attribute_name(key):
    # LDAP attribute descriptions use ASCII names. Unicode casefold aliases
    # such as long-s must not impersonate a literal exported schema attribute.
    return key.lower() if key.isascii() else ""


def _children(value):
    if isinstance(value, dict):
        for key, child in value.items():
            # Known-attribute payloads are interpreted only by their owner.
            if _attribute_name(key) not in _KNOWN_ATTRIBUTES and isinstance(child, (dict, list)):
                yield child, _pointer_key(key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                yield child, str(index)


def _objects(document, *, lazy_pointers=False):
    # Keep only one path-segment stack. A generator for every ancestor must
    # never capture its full pointer: long keys otherwise amplify a small,
    # deep document quadratically even when it contains no valid findings.
    pending = [iter(((document, None),))]
    segments = []
    while pending:
        try:
            value, segment = next(pending[-1])
        except StopIteration:
            pending.pop()
            if segments:
                segments.pop()
            continue
        if segment is not None:
            segments.append(segment)
        if isinstance(value, dict):
            # The inspector consumes this temporary path view synchronously
            # before advancing the iterator. Render a full pointer only for
            # actual evidence, not for every public/malformed ancestor object.
            yield value, segments if lazy_pointers else ("/" + "/".join(segments) if segments else "")
        pending.append(_children(value))


def _attribute_values(attribute, value, pointer):
    binary = attribute in _OPAQUE_ATTRIBUTES or attribute == _UNICODE_PASSWORD
    if binary:
        raw = _numeric_bytes(value)
        if raw is not None:
            yield value, pointer, "byte-array", raw
            return
    if isinstance(value, list):
        for index, item in enumerate(value):
            raw = _numeric_bytes(item) if binary else None
            yield item, f"{pointer}/{index}", "byte-array" if raw is not None else "json", raw
    else:
        yield value, pointer, "json", None


def inspect_active_directory_json_secrets(data):
    """Inspect exact AD attribute properties in JSON objects and arrays."""
    if b"\\" not in data and b"\x00" not in data:
        lower = data.lower()
        if not any(attribute.encode("ascii") in lower for attribute in _KNOWN_ATTRIBUTES):
            return ()
    try:
        document = _json_loads(data)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"invalid JSON during AD export inspection: {exc}") from exc
    findings = _EvidenceFindings(len(data))
    for obj, segments in _objects(document, lazy_pointers=True):
        # DN is context only, and is never borrowed from a parent/sibling object.
        record_dn = next(
            (
                value
                for key, value in obj.items()
                if _attribute_name(key) in {"dn", "distinguishedname"} and isinstance(value, str)
            ),
            None,
        )
        for key, value in obj.items():
            attribute = _attribute_name(key)
            if attribute not in _KNOWN_ATTRIBUTES:
                continue
            for source, value_suffix, encoding, raw in _attribute_values(attribute, value, ""):
                material = _material(attribute, source, encoding=encoding, decoded_bytes=raw)
                if material is None:
                    continue
                pointer = "/" + "/".join(segments) if segments else ""
                value_pointer = f"{pointer}/{_pointer_key(key)}{value_suffix}"
                findings.append(
                    _evidence(
                        material,
                        len(data),
                        format="json",
                        attribute=key,
                        pointer=value_pointer,
                        record_dn=record_dn,
                        encoding="base64"
                        if attribute in _OPAQUE_ATTRIBUTES | {_UNICODE_PASSWORD} and raw is None
                        else encoding,
                        source_value=source,
                    )
                )
    return tuple(findings)
