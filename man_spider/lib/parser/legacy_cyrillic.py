"""Explicit candidate interpretations of legacy Cyrillic credential assignments.

This does not select or replace the normal text decoder. Three strict,
single-byte codecs are considered independently, without file/network access.
Quoted language escapes remain literal text; no expression is evaluated.
"""

import base64
import codecs
import json
import re
import sys

from .localized_credentials import literal_secret, sensitive_field


_ENCODINGS = ("cp1251", "cp866", "koi8-r")
_CYRILLIC = re.compile(r"[А-Яа-яЁё]")
_BOMS = (codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE, codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)
_BINARY_SIGNATURES = (
    b"MZ",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"BZh",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"%PDF-",
    b"\x7fELF",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
)
_CONTROL_BYTES = bytes(value for value in range(32) if value not in (9, 10, 13)) + b"\x7f"
_MIN_EVIDENCE_BUDGET = 1024 * 1024
_MAX_EVIDENCE_BUDGET = 32 * 1024 * 1024
_EVIDENCE_INPUT_MULTIPLIER = 16
_MAX_VALUE_NESTING = 64
_LEADING_VARIABLE = re.compile(r"\$[^\W\d]\w*\Z")
_UNQUOTED_REFERENCE = re.compile(
    r"(?:(?:[\w]{1,64}\.){0,4}[\w]{1,64}\([^\x00\r\n()]{0,128}\)|"
    r"Read-Host(?:[ \t][^\r\n]{0,128})?|Get-Credential(?:[ \t][^\r\n]{0,128})?)",
    re.IGNORECASE,
)


def _legacy_input(data):
    if not data or data.isascii() or b"\x00" in data or data.startswith(_BOMS + _BINARY_SIGNATURES):
        return False
    controls = len(data) - len(data.translate(None, _CONTROL_BYTES))
    if controls > max(4, len(data) // 100):
        return False
    try:
        data.decode("utf-8")
    except UnicodeError:
        return True
    return False


def _lines(data):
    offset = 0
    while offset < len(data):
        end = data.find(b"\n", offset)
        if end < 0:
            end = len(data)
        content_end = end - 1 if end > offset and data[end - 1] == 13 else end
        yield offset, data[offset:content_end]
        offset = end + 1


def _quoted_end(text, start):
    quote = text[start]
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
        elif text[index] == quote:
            return index + 1
        else:
            index += 1
    return None


def _boundaries(text):
    # Object commas/braces outside quoted strings may start the next property.
    # Password-looking text inside a different field's string cannot own it.
    yield 0
    index = 0
    while index < len(text):
        char = text[index]
        if char in "\"'":
            end = _quoted_end(text, index)
            if end is None:
                return
            index = end
        elif char == "#":
            return
        else:
            if char in "{,":
                yield index + 1
            index += 1


def _assignment(text, start, *, object_context=False):
    while start < len(text) and text[start] in " \t":
        start += 1
    if start == len(text) or text[start] in "#;":
        return None
    key_start = start
    quoted_label = text[start] in "\"'"
    if quoted_label:
        end = _quoted_end(text, start)
        if end is None:
            return None
        label = text[start + 1 : end - 1]
        separator = end
        while separator < len(text) and text[separator] in " \t":
            separator += 1
    else:
        separator = start
        while separator < min(len(text), start + 193) and text[separator] not in ":=":
            separator += 1
        label = text[start:separator].strip()
    # One syntactically valid PowerShell-style leading variable marker may
    # identify an assignment; retain it in source_key and source byte offsets.
    # Quoted JSON-like property names and dynamic/compound expressions are not
    # rewritten into a different owner.
    lookup_label = label[1:] if not quoted_label and _LEADING_VARIABLE.fullmatch(label) else label
    if separator == len(text) or text[separator] not in ":=" or not sensitive_field(lookup_label):
        return None
    operator_length = 2 if text.startswith((":=", "=>"), separator) else 1
    value_start = separator + operator_length
    # Comparisons and unsupported repeated delimiters are not assignments.
    # A literal beginning with one of these characters remains valid in quotes.
    if value_start < len(text) and text[value_start] in ":=>":
        return None
    while value_start < len(text) and text[value_start] in " \t":
        value_start += 1
    if value_start == len(text):
        return None
    if text[value_start] in "\"'":
        end = _quoted_end(text, value_start)
        if end is None:
            return None
        value = text[value_start + 1 : end - 1]
        tail = end
        while tail < len(text) and text[tail] in " \t":
            tail += 1
        if tail < len(text) and text[tail] not in ",};#":
            return None
    else:
        end = value_start
        if object_context and text[value_start] in "{[(":
            return None  # An object/list/expression is not a scalar literal.
        nesting = []
        while end < len(text):
            if text[end] == "#" and end > value_start and text[end - 1] in " \t":
                break
            if object_context:
                char = text[end]
                if char in "{[(":
                    if len(nesting) >= _MAX_VALUE_NESTING:
                        raise ValueError(f"legacy Cyrillic value nesting exceeds {_MAX_VALUE_NESTING} delimiters")
                    nesting.append({"{": "}", "[": "]", "(": ")"}[char])
                elif nesting and char == nesting[-1]:
                    nesting.pop()
                elif not nesting and char in ",};":
                    break
                elif char in "\"'":
                    return None
            end += 1
        while end > value_start and text[end - 1] in " \t":
            end -= 1
        value = text[value_start:end]
        if _UNQUOTED_REFERENCE.fullmatch(value):
            return None
    if not (_CYRILLIC.search(label) or _CYRILLIC.search(value)) or not literal_secret(value):
        return None
    return key_start, end, label, value


def inspect_russian_legacy_credentials(data):
    """Return every distinct credible codec interpretation, not an encoding guess."""
    if not _legacy_input(data):
        return ()
    budget = min(_MAX_EVIDENCE_BUDGET, max(_MIN_EVIDENCE_BUDGET, len(data) * _EVIDENCE_INPUT_MULTIPLIER))
    evidence_size = 0
    candidates = {}

    def account(size):
        nonlocal evidence_size
        evidence_size += size
        if evidence_size > budget:
            raise ValueError(
                f"legacy Cyrillic derived evidence exceeds context budget of {budget} bytes; "
                "inspection is incomplete, no partial or truncated legacy findings were returned"
            )

    for line_number, (line_offset, source_line) in enumerate(_lines(data), 1):
        if b":" not in source_line and b"=" not in source_line:
            continue
        for encoding in _ENCODINGS:
            try:
                text = source_line.decode(encoding)
            except UnicodeError:
                continue
            first = len(text) - len(text.lstrip(" \t"))
            object_line = text[first : first + 1] in ("{", "[")
            for boundary in _boundaries(text):
                candidate = _assignment(text, boundary, object_context=object_line or boundary > first)
                if candidate is None:
                    continue
                start, end, label, value = candidate
                key = (line_offset + start, line_offset + end, label, value)
                if key not in candidates:
                    account(sys.getsizeof(key) + sys.getsizeof(label) + sys.getsizeof(value) + 256)
                    candidates[key] = (line_number, [])
                candidates[key][1].append(encoding)

    findings = []
    for (start, end, label, value), (line_number, encodings) in sorted(candidates.items()):
        source = data[start:end]
        context = json.dumps(
            {
                "format": "legacy-cyrillic-assignment",
                "line": line_number,
                "source_start": start,
                "source_end": end,
                "source_fragment_base64": base64.b64encode(source).decode("ascii"),
                "source_key": label,
                "decoded_value": value,
                "encoding_candidates": list(dict.fromkeys(encodings)),
                "value_kind": "legacy-encoding-credential-candidate",
                "evidence": "strict single-byte decoding candidate; exact source encoding and live credential validity are not established",
                "span": "exact matched source bytes; quote delimiters excluded from value, language escapes are not interpreted",
            },
            ensure_ascii=True,
        )
        finding = (value, start, end, context)
        account(sys.getsizeof(finding) + sys.getsizeof(value) + sys.getsizeof(context))
        findings.append(finding)
    return tuple(findings)
