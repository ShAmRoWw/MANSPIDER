"""Passive, entity-free inspection of saved Group Policy Preferences passwords.

The published MS-GPPREF AES key is format material, not a customer credential.
Nothing here contacts a domain controller, resolves an XML entity, or executes
the preference. Ciphertext remains evidence when decryption cannot be proven.
Depth or derived-evidence budget exhaustion is an explicit representation error,
never an implicit cap on passwords or a silently incomplete set of findings.
"""

import base64
import binascii
import json
import re
import sys
from xml.parsers import expat

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


GPP_AES_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
_PASSWORD_HINT = re.compile(rb"cpassword", re.IGNORECASE)
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")
_FAMILIES = {
    "Groups": {"User"},
    "NTServices": {"NTService"},
    "ScheduledTasks": {"Task", "TaskV2", "ImmediateTask", "ImmediateTaskV2"},
    "Drives": {"Drive"},
    "DataSources": {"DataSource"},
    "Printers": {"SharedPrinter"},
}
_MAX_XML_DEPTH = 512
_MIN_EVIDENCE_BUDGET = 1024 * 1024
_MAX_EVIDENCE_BUDGET = 32 * 1024 * 1024
_EVIDENCE_INPUT_MULTIPLIER = 16


def _ciphertext(value):
    # XML normalizes whitespace in attributes. Retain the original parsed
    # attribute separately, but allow explicitly wrapped Base64 for decoding.
    compact = value.translate(str.maketrans("", "", " \t\r\n"))
    if not _BASE64.fullmatch(compact) or len(compact.rstrip("=")) % 4 == 1:
        return None
    try:
        encoded = compact + "=" * (-len(compact) % 4)
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not raw or len(raw) % 16 or base64.b64encode(raw).decode().rstrip("=") != compact.rstrip("="):
        return None
    return raw


def _decrypt(raw):
    decryptor = Cipher(algorithms.AES(GPP_AES_KEY), modes.CBC(bytes(16))).decryptor()
    padded = decryptor.update(raw) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-16-le")


def inspect_group_policy_preference_password(data):
    # UTF-16 attributes contain NULs between letters and must reach the parser.
    if b"\x00" not in data and not _PASSWORD_HINT.search(data):
        return ()
    parser = expat.ParserCreate(namespace_separator="}")
    findings = []
    frames = []
    evidence_size = 0
    evidence_budget = min(_MAX_EVIDENCE_BUDGET, max(_MIN_EVIDENCE_BUDGET, len(data) * _EVIDENCE_INPUT_MULTIPLIER))

    def reject_declaration(*_args):
        raise ValueError("DTD and entity declarations are disabled during GPP inspection")

    def start(name, attributes):
        nonlocal evidence_size
        if len(frames) >= _MAX_XML_DEPTH:
            raise ValueError(f"GPP XML nesting exceeds {_MAX_XML_DEPTH} elements")
        if frames:
            frames[-1]["children"] += 1
            index = frames[-1]["children"]
        else:
            index = 1
        # Match real XML names, not substrings, comments, CDATA, foreign
        # namespace attributes, or password-looking text in another attribute.
        family = frames[-2]["name"] if len(frames) >= 2 else None
        owner = frames[-1] if frames else None
        if name == "Properties" and family in _FAMILIES and owner["name"] in _FAMILIES[family]:
            for attribute, source_value in attributes.items():
                if not attribute.isascii() or attribute.lower() != "cpassword":
                    continue
                raw = _ciphertext(source_value)
                if raw is None:
                    continue
                try:
                    decoded = _decrypt(raw)
                    if not decoded:
                        continue
                    value, kind, error = decoded, "plaintext-password", None
                except (ValueError, UnicodeError) as exc:
                    value, kind, error = source_value, "encrypted-password-candidate", type(exc).__name__
                path = "/" + "/".join(
                    [f"{frame['name']}[{frame['index']}]" for frame in frames] + [f"{name}[{index}]"]
                )
                context = json.dumps(
                    {
                        "family": family,
                        "pointer": f"{path}/@{attribute}",
                        "owner_name": owner["attributes"].get("name"),
                        "account": {
                            key: value
                            for key, value in attributes.items()
                            if key.isascii() and key.lower() in {"username", "accountname", "runas", "newname"}
                        },
                        "source_value": source_value,
                        "value_kind": kind,
                        "decoded_password": decoded if kind == "plaintext-password" else None,
                        "decoding_error": error,
                        "evidence": "saved GPP password material; no credential validity check or preference execution",
                        "span": "complete source XML; value is structurally extracted",
                    },
                    ensure_ascii=False,
                )
                finding = (value, 0, len(data), context)
                # A small XML file can repeat a long owner name or ancestry in
                # thousands of findings. Bound retained derived evidence, not
                # source/password lengths; never return a silently truncated
                # subset. FileParser exposes this as a representation error.
                evidence_size += sys.getsizeof(finding) + sys.getsizeof(value) + sys.getsizeof(context)
                if evidence_size > evidence_budget:
                    raise ValueError(
                        f"GPP XML derived evidence exceeds context budget of {evidence_budget} bytes; "
                        "inspection is incomplete, no partial or truncated GPP findings were returned"
                    )
                findings.append(finding)
        frames.append({"name": name, "index": index, "children": 0, "attributes": attributes})

    parser.StartElementHandler = start
    parser.EndElementHandler = lambda _name: frames.pop()
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = reject_declaration
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ValueError(f"invalid XML during GPP inspection: {exc}") from exc
    return tuple(findings)
