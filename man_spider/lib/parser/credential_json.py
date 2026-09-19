"""Passive structural inspection of JSON Kubernetes Secret resources.

This is deliberately not a regex join across a JSON document: resource type,
entry ownership, base64 validity, and stringData precedence are checked first.
"""

import base64
import binascii
import json
import re

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_ssh_public_key


_REFERENCE = re.compile(
    r"(?:\$\{[^{}\r\n]{1,256}\}|\$\([^()\r\n]{1,256}\)|"
    r"\{\{[^{}\r\n]{1,256}\}\}|<%[^%\r\n]{1,256}%>|\$[A-Za-z_][A-Za-z0-9_]{0,127})"
)
_PUBLIC_NAMES = {"username", "user", "login"}
_BOOTSTRAP_PUBLIC_NAMES = {"description", "expiration", "auth-extra-groups", "token-id"}
_PEM_PUBLIC_LABELS = (b"CERTIFICATE", b"PUBLIC KEY", b"RSA PUBLIC KEY")
_ASCII_WHITESPACE = b" \t\r\n"
_NON_WHITESPACE = re.compile(rb"[^ \t\r\n]")


def _public_der(data, *, certificate_only=False):
    """Reject trailing bytes before asking a crypto parser about public data."""
    if len(data) < 2 or data[0] != 0x30:
        return False
    length = data[1]
    header_size = 2
    if length & 0x80:
        octets = length & 0x7F
        if not 1 <= octets <= 8 or len(data) < 2 + octets:
            return False
        length = int.from_bytes(data[2 : 2 + octets], "big")
        header_size += octets
    if header_size + length != len(data):
        return False
    loaders = (
        (x509.load_der_x509_certificate,)
        if certificate_only
        else (
            x509.load_der_x509_certificate,
            load_der_public_key,
        )
    )
    for loader in loaders:
        try:
            loader(data)
            return True
        except (ValueError, UnsupportedAlgorithm):
            pass
    return False


def _public_pem_only(data):
    """Every non-whitespace byte must belong to a valid public PEM block."""
    position = 0
    found = False
    while position < len(data):
        next_block = _NON_WHITESPACE.search(data, position)
        if next_block is None:
            break
        position = next_block.start()
        label = next(
            (label for label in _PEM_PUBLIC_LABELS if data.startswith(b"-----BEGIN " + label + b"-----", position)),
            None,
        )
        if label is None:
            return False
        body_start = position + len(b"-----BEGIN " + label + b"-----")
        footer = b"-----END " + label + b"-----"
        body_end = data.find(footer, body_start)
        if body_end < 0:
            return False
        try:
            decoded = base64.b64decode(data[body_start:body_end].translate(None, _ASCII_WHITESPACE), validate=True)
        except (binascii.Error, ValueError):
            return False
        if not _public_der(decoded, certificate_only=label == b"CERTIFICATE"):
            return False
        found = True
        position = body_end + len(footer)
    return found


def _public_material(data):
    stripped = data.strip(_ASCII_WHITESPACE)
    if stripped.startswith(b"-----BEGIN "):
        return _public_pem_only(stripped)
    if stripped.startswith((b"ssh-", b"ecdsa-", b"sk-ssh-", b"sk-ecdsa-")):
        # A loader accepts arbitrary trailing comments/lines. Preserve those
        # candidates: they may contain credentials unrelated to the public key.
        if b"\n" in stripped or b"\r" in stripped or len(stripped.split(None, 2)) != 2:
            return False
        try:
            load_ssh_public_key(stripped)
            return True
        except (ValueError, UnsupportedAlgorithm):
            return False
    # Do not strip binary DER: a valid ASN.1 value may end in whitespace bytes.
    return _public_der(data)


def _children(items, pointer, implicit_secret):
    for index, item in enumerate(items):
        if isinstance(item, (dict, list)):
            yield item, f"{pointer}/{index}", implicit_secret


def _resources(document):
    # An iterator per nesting level, not a tuple and pointer per sibling. JSON
    # decoding already owns the document; traversal needs only O(depth) memory.
    pending = [iter(((document, "", False),))]
    while pending:
        try:
            value, pointer, implicit_secret = next(pending[-1])
        except StopIteration:
            pending.pop()
            continue
        if isinstance(value, list):
            pending.append(_children(value, pointer, False))
            continue
        if not isinstance(value, dict) or value.get("apiVersion", "v1") != "v1":
            continue
        kind = value.get("kind", "Secret" if implicit_secret else None)
        if not isinstance(kind, str):
            continue
        if kind == "Secret":
            yield value, pointer
        elif kind in {"List", "SecretList"} and isinstance(value.get("items"), list):
            pending.append(_children(value["items"], f"{pointer}/items", kind == "SecretList"))


def _public_entry_name(resource_type, key):
    if key.casefold() in _PUBLIC_NAMES:
        return True
    if resource_type == "kubernetes.io/service-account-token":
        return key == "namespace"
    if resource_type == "bootstrap.kubernetes.io/token":
        return key in _BOOTSTRAP_PUBLIC_NAMES or key.startswith("usage-bootstrap-")
    return False


def _invalid_json_constant(value):
    raise ValueError(f"non-JSON numeric constant {value}")


def inspect_kubernetes_secret_json(data):
    # A valid unescaped JSON kind is a necessary condition. Escaped keys/values
    # and UTF-16/32 retain the real parser path instead of being silently skipped.
    if b"\\" not in data and b"\x00" not in data:
        if b'"kind"' not in data or not any(value in data for value in (b'"Secret"', b'"SecretList"')):
            return ()
    try:
        document = json.loads(data, parse_constant=_invalid_json_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"invalid JSON during Kubernetes Secret inspection: {exc}") from exc

    findings = []
    for resource, pointer in _resources(document):
        entries = {}
        encoded = resource.get("data")
        plaintext = resource.get("stringData")
        if isinstance(encoded, dict):
            entries.update((key, (value, "data")) for key, value in encoded.items())
        if isinstance(plaintext, dict):
            # Kubernetes merges stringData into data, with stringData winning.
            entries.update((key, (value, "stringData")) for key, value in plaintext.items())
        for key, (source_value, field) in entries.items():
            if not isinstance(source_value, str) or not source_value or _public_entry_name(resource.get("type"), key):
                continue
            try:
                key.encode("utf-8")
            except UnicodeEncodeError:
                continue
            if field == "data":
                try:
                    # Kubernetes' Go base64 decoder ignores CR/LF, but not
                    # arbitrary spaces or other invalid alphabet characters.
                    value_bytes = base64.b64decode(source_value.replace("\r", "").replace("\n", ""), validate=True)
                except (binascii.Error, ValueError):
                    continue
            else:
                try:
                    value_bytes = source_value.encode("utf-8")
                except UnicodeEncodeError:
                    # A malformed sibling must not hide valid Secret entries.
                    continue
            if not value_bytes or _public_material(value_bytes):
                continue
            try:
                text = value_bytes.decode("utf-8")
            except UnicodeError:
                text = None
            if text is not None and (not text.strip() or _REFERENCE.fullmatch(text.strip())):
                continue
            entry_pointer = f"{pointer}/{field}/{key.replace('~', '~0').replace('/', '~1')}"
            context = json.dumps(
                {
                    "resource_kind": "Secret",
                    "pointer": entry_pointer,
                    "encoding": "base64" if field == "data" else "plain",
                    "source_value": source_value,
                    "decoded_utf8": text,
                    "evidence": "configured Secret material; not live credential validation",
                    "span": "complete source document; value is structurally extracted",
                },
                ensure_ascii=False,
            )
            # Inspectors return semantic values with a source-container span.
            # Binary values stay unmasked base64 instead of lossy decoding.
            findings.append((text if text is not None else source_value, 0, len(data), context))
    return tuple(findings)
