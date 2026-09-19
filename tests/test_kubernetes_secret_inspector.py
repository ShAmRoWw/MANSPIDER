"""Structural, false-positive, robustness, and dispatch coverage for Secret JSON."""

import base64
from datetime import datetime, timezone
import json
from pathlib import PurePosixPath
import tracemalloc

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from man_spider.lib.parser import FileParser
from man_spider.lib.parser.credential_json import (
    _public_material,
    _resources,
    inspect_kubernetes_secret_json,
)
from man_spider.rules import load_rule_files
from tests.rule_pack_2_5_structured_cases import STRUCTURED_INSPECTOR_CASES


def encoded(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return base64.b64encode(value).decode("ascii")


def inspect(document):
    return inspect_kubernetes_secret_json(json.dumps(document).encode("utf-8"))


def secret(value, key="password", *, field="data", resource_type="Opaque"):
    return {"kind": "Secret", "type": resource_type, field: {key: encoded(value) if field == "data" else value}}


def values(document):
    return [entry[0] for entry in inspect(document)]


@pytest.fixture(scope="module")
def parser(tmp_path_factory):
    pack_path = tmp_path_factory.mktemp("kubernetes-inspector-pack") / "rules.json"
    pack_path.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "pack": {"id": "manspider.inspector-test", "version": "2.5.0"},
                "rules": [
                    {
                        "id": "kubernetes-secret-json",
                        "severity": "high",
                        "confidence": "medium",
                        "category": "credential.configured-secret",
                        "match": {
                            "predicates": [
                                {"field": "extension", "operator": "regex", "value": r"\.json(?:\.(?:bak|old|orig))?$"}
                            ]
                        },
                        "actions": [{"type": "inspect", "detector": "kubernetes-secret-json"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return FileParser([], quiet=True, rules=load_rule_files([pack_path]))


def route_for(parser, path):
    candidate = PurePosixPath(path.replace("\\", "/"))
    return parser.route_rules(
        {
            "filename": candidate.name,
            "path": path,
            "directory": str(candidate.parent),
            "extension": "".join(candidate.suffixes).lower(),
        }
    )


@pytest.fixture(scope="module")
def material():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MANSPIDER public-only fixture")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    return {
        "certificate_pem": certificate.public_bytes(serialization.Encoding.PEM),
        "certificate_der": certificate.public_bytes(serialization.Encoding.DER),
        "public_pem": key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        "public_der": key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        "rsa_public_pem": key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1),
        "rsa_public_der": key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1),
        "ssh_public": key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        ),
        "private_pem": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        "private_der": key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    }


@pytest.mark.parametrize(("path", "content", "rule_id"), STRUCTURED_INSPECTOR_CASES)
def test_inspector_dispatches_from_native_v3_pack(parser, path, content, rule_id):
    route = route_for(parser, path)
    assert [rule.rule_id for rule in route.inspector_rules] == [f"rule:{rule_id}"]
    result = parser.parse_file(path, rule_route=route, data=content.encode("utf-8"))
    assert result.error is None
    assert result.findings
    for finding in result.findings:
        assert finding.rule_id == f"rule:{rule_id}"
        assert finding.representation == "inspect:kubernetes-secret-json"
        assert finding.rule_pack_id == "manspider.inspector-test"
        assert finding.rule_pack_version == "2.5.0"
        assert finding.rule_schema_version == 3
        assert finding.confidence == "medium"
        assert (finding.start, finding.end) == (0, len(content.encode("utf-8")))
        assert json.loads(finding.context)["source_value"]


def test_inspector_dispatch_uses_shared_source_bytes_once(parser):
    calls = []
    data = json.dumps({"kind": "Secret", "stringData": {"one": "FirstSecret!", "two": "SecondSecret!"}}).encode()
    result = parser.parse_file(
        "fixture.json",
        rule_route=route_for(parser, "fixture.json"),
        data_loader=lambda: calls.append(True) or data,
    )
    assert calls == [True]
    assert [finding.value for finding in result.findings] == ["FirstSecret!", "SecondSecret!"]


@pytest.mark.parametrize("path", ["fixture.txt", "fixture.yaml", "fixture.json.exe", "fixture.bin"])
def test_json_inspection_does_not_route_arbitrary_files(parser, path):
    assert not route_for(parser, path).inspector_rules


@pytest.mark.parametrize(
    "document",
    [
        [{"kind": "ConfigMap", "data": {"password": "Public!"}}, secret("First!"), secret("Second!")],
        {
            "kind": "List",
            "items": [
                {"kind": "ConfigMap", "stringData": {"password": "Public!"}},
                secret("First!"),
                secret("Second!"),
            ],
        },
        {
            "kind": "SecretList",
            "items": [{"data": {"password": encoded("First!")}}, {"stringData": {"password": "Second!"}}],
        },
        {
            "kind": "List",
            "items": [
                {"kind": "SecretList", "items": [{"data": {"password": encoded("First!")}}]},
                {"kind": "List", "items": [secret("Second!")]},
            ],
        },
    ],
)
def test_resource_ownership_and_source_order(document):
    assert values(document) == ["First!", "Second!"]


@pytest.mark.parametrize(
    "document",
    [
        {"kind": "ConfigMap", "data": {"password": encoded("NotASecret!")}},
        {"kind": "ConfigMap", "nested": secret("NotAnOwnedSecret!")},
        {"wrapper": secret("NotARootResource!")},
        {"kind": "List", "items": [{"data": {"password": encoded("NoSecretKind!")}}]},
        {"kind": "SecretList", "items": [{"kind": "ConfigMap", "data": {"password": encoded("WrongExplicitKind!")}}]},
        {"apiVersion": "example.test/v1", "kind": "Secret", "stringData": {"password": "WrongApi!"}},
        [{"kind": "Secret", "data": {}}, {"data": {"password": encoded("CrossObject!")}}],
        {"kind": "Secret", "data": {"nested": {"password": encoded("NotFlat!")}}},
    ],
)
def test_unowned_or_wrong_typed_data_never_joins(document):
    assert inspect(document) == ()


def test_stringdata_precedence_is_per_key_and_overrides_empty_or_invalid_values():
    document = {
        "kind": "Secret",
        "data": {
            "same": encoded("Old!"),
            "remaining": encoded("Remain!"),
            "empty": encoded("NotEffective!"),
            "invalid": encoded("AlsoOverridden!"),
        },
        "stringData": {"same": "New!", "empty": "", "invalid": None, "extra": "Extra!"},
    }
    findings = inspect(document)
    assert [entry[0] for entry in findings] == ["New!", "Remain!", "Extra!"]
    assert [json.loads(entry[3])["pointer"] for entry in findings] == [
        "/stringData/same",
        "/data/remaining",
        "/stringData/extra",
    ]


@pytest.mark.parametrize("bad_kind", [{}, [], 3, None, True])
def test_malformed_kind_does_not_hide_valid_siblings(bad_kind):
    assert values({"kind": "List", "items": [{"kind": bad_kind}, secret("ValidSibling!")]}) == ["ValidSibling!"]


def test_malformed_surrogate_key_and_value_do_not_hide_valid_siblings():
    document = {"kind": "Secret", "stringData": {"bad": "\ud800", "\udfff": "BadKey!", "password": "ValidSibling!"}}
    assert values(document) == ["ValidSibling!"]


@pytest.mark.parametrize(
    "value", [None, 12, [], {}, True, "", " ", "invalid base64!", "U2Vj cmV0IQ==", "U2VjcmV0IQ==="]
)
def test_invalid_base64_and_nonstring_values_are_not_secret_evidence(value):
    assert inspect({"kind": "Secret", "data": {"password": value}}) == ()


def test_crlf_base64_is_accepted_without_changing_original_evidence():
    source = "U2VjcmV0\r\nRml4dHVyZSE="
    findings = inspect({"kind": "Secret", "data": {"password": source}})
    assert findings[0][0] == "SecretFixture!"
    assert json.loads(findings[0][3])["source_value"] == source


@pytest.mark.parametrize(
    "placeholder", ["${PASSWORD}", "$(PASSWORD)", "{{ PASSWORD }}", "<% PASSWORD %>", "$PASSWORD", "  ${PASSWORD}\n"]
)
@pytest.mark.parametrize("field", ["data", "stringData"])
def test_only_complete_template_references_are_filtered(placeholder, field):
    assert inspect(secret(placeholder, field=field)) == ()


@pytest.mark.parametrize(
    "literal",
    [
        "$argon2id$v=19$m=65536,t=2,p=1$c2FsdA$Rml4dHVyZQ",
        "$pbkdf2-sha256$29000$c2FsdA$Rml4dHVyZQ",
        "$uperSecret!",
        "${VARIABLE}LiteralSuffix!",
        "changeme",
        "${unterminated",
        "x" * 10000,
    ],
)
@pytest.mark.parametrize("field", ["data", "stringData"])
def test_real_literal_hash_and_nonplaceholder_values_are_retained(literal, field):
    assert values(secret(literal, field=field)) == [literal]


@pytest.mark.parametrize(
    "encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"]
)
def test_utf_encodings_and_escaped_kind_take_the_real_parser_path(encoding):
    content = '{"ki\\u006ed":"Sec\\u0072et","stringData":{"password":"UnicodeFixture!"}}'
    raw = content.encode(encoding)
    findings = inspect_kubernetes_secret_json(raw)
    assert findings[0][0] == "UnicodeFixture!"
    assert findings[0][1:3] == (0, len(raw))


def test_json_pointer_escaping_and_unmasked_unicode_evidence():
    content = {"kind": "List", "items": [secret("Секрет\\Value!", key="a~/b", field="stringData")]}
    findings = inspect(content)
    assert findings[0][0] == "Секрет\\Value!"
    context = json.loads(findings[0][3])
    assert context["pointer"] == "/items/0/stringData/a~0~1b"
    assert context["source_value"] == context["decoded_utf8"] == "Секрет\\Value!"


def test_binary_evidence_is_original_unmasked_base64():
    binary = b"\xff\xfe\x00BinarySecret!"
    findings = inspect(secret(binary))
    assert findings[0][0] == encoded(binary)
    context = json.loads(findings[0][3])
    assert context["source_value"] == encoded(binary)
    assert context["decoded_utf8"] is None


@pytest.mark.parametrize(
    "name",
    [
        "certificate_pem",
        "certificate_der",
        "public_pem",
        "public_der",
        "rsa_public_pem",
        "rsa_public_der",
        "ssh_public",
    ],
)
def test_valid_wholly_public_material_is_not_reported(material, name):
    assert _public_material(material[name])
    assert inspect(secret(material[name], key="tls.crt")) == ()


def test_multiple_public_pem_blocks_and_whitespace_are_not_reported(material):
    bundle = (
        b" \r\n" + material["certificate_pem"] + b"\n\t" + material["public_pem"] + material["rsa_public_pem"] + b"\n"
    )
    assert _public_material(bundle)
    assert inspect(secret(bundle)) == ()


@pytest.mark.parametrize(
    "name", ["certificate_pem", "certificate_der", "public_pem", "public_der", "rsa_public_der", "ssh_public"]
)
@pytest.mark.parametrize("extra", [b"\npassword=ActualSecret!", b" PasswordInComment!", b"\x00HiddenBinarySecret!"])
def test_mixed_public_and_secret_input_is_never_suppressed(material, name, extra):
    mixed = material[name] + extra
    assert not _public_material(mixed)
    assert inspect(secret(mixed))


@pytest.mark.parametrize("name", ["private_pem", "private_der"])
def test_private_material_is_retained_even_when_named_public(material, name):
    assert not _public_material(material[name])
    assert inspect(secret(material[name], key="ca.crt"))


def test_pem_certificate_plus_private_key_is_retained(material):
    assert inspect(secret(material["certificate_pem"] + material["private_pem"]))


def test_public_pem_with_extra_der_bytes_inside_base64_is_retained(material):
    body = encoded(material["certificate_der"] + b"HiddenSecret!").encode()
    candidate = b"-----BEGIN CERTIFICATE-----\n" + body + b"\n-----END CERTIFICATE-----"
    assert inspect(secret(candidate))


def test_ssh_with_extra_binary_bytes_inside_base64_is_retained(material):
    algorithm, body = material["ssh_public"].split()
    candidate = algorithm + b" " + base64.b64encode(base64.b64decode(body) + b"HiddenSecret!")
    assert inspect(secret(candidate))


def test_malformed_unicode_base64_does_not_hide_valid_siblings():
    document = {"kind": "Secret", "data": {"broken": "\ud800", "password": encoded("ValidSibling!")}}
    assert values(document) == ["ValidSibling!"]


def test_json_recursion_error_produces_a_controlled_error(monkeypatch):
    def depth_error(*args, **kwargs):
        raise RecursionError("JSON decoder nesting limit")

    monkeypatch.setattr(json, "loads", depth_error)
    with pytest.raises(ValueError, match="invalid JSON during Kubernetes Secret inspection"):
        inspect_kubernetes_secret_json(b'{"kind":"Secret","data":{}}')


@pytest.mark.parametrize(
    "raw",
    [
        b"0\x80garbage",
        b"0\xffgarbage",
        b"0\x82\x01",
        b"0\x01\x00secret",
        b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
        b"ssh-rsa malformed",
    ],
)
def test_invalid_public_formats_are_not_silently_suppressed(raw):
    assert not _public_material(raw)


@pytest.mark.parametrize(
    "resource_type,public_keys",
    [
        ("kubernetes.io/service-account-token", ["namespace"]),
        (
            "bootstrap.kubernetes.io/token",
            [
                "description",
                "expiration",
                "auth-extra-groups",
                "usage-bootstrap-authentication",
                "usage-bootstrap-signing",
            ],
        ),
    ],
)
def test_public_metadata_suppression_is_scoped_to_the_standard_secret_type(resource_type, public_keys):
    document = {"kind": "Secret", "type": resource_type, "stringData": {key: "PublicMetadata" for key in public_keys}}
    document["stringData"]["token-secret"] = "ActualTokenSecret!"
    assert values(document) == ["ActualTokenSecret!"]
    document["type"] = "Opaque"
    assert values(document) == ["PublicMetadata"] * len(public_keys) + ["ActualTokenSecret!"]


def test_malformed_resource_type_does_not_raise():
    document = secret("ActualSecret!")
    document["type"] = {}
    assert values(document) == ["ActualSecret!"]


def test_bootstrap_identifier_is_public_but_the_complete_secret_is_retained():
    document = {
        "kind": "Secret",
        "type": "bootstrap.kubernetes.io/token",
        "stringData": {"token-id": "abc123", "token-secret": "a1b2c3d4e5f6g7h8"},
    }
    findings = inspect(document)
    assert [entry[0] for entry in findings] == ["a1b2c3d4e5f6g7h8"]
    assert json.loads(findings[0][3])["pointer"] == "/stringData/token-secret"
    document["type"] = "Opaque"
    assert values(document) == ["abc123", "a1b2c3d4e5f6g7h8"]


@pytest.mark.parametrize("key", ["username", "USER", "Login"])
def test_standalone_user_identity_is_not_classified_as_secret(key):
    assert inspect(secret("admin", key=key)) == ()


@pytest.mark.parametrize(
    "raw",
    [
        b'{"kind":"Secret",',
        b'{"kind":"Secret","data":{"password":NaN}}',
        b'{"kind":"Secret","data":{"password":Infinity}}',
        b'{"kind":"Secret","data":{"password":"\xff"}}',
    ],
)
def test_malformed_candidate_json_produces_a_controlled_error(raw):
    with pytest.raises(ValueError, match="invalid JSON during Kubernetes Secret inspection"):
        inspect_kubernetes_secret_json(raw)


def test_parser_surfaces_inspector_error_instead_of_silent_success(parser):
    result = parser.parse_file("broken.json", rule_route=route_for(parser, "broken.json"), data=b'{"kind":"Secret",')
    assert result.error
    assert "invalid JSON during Kubernetes Secret inspection" in result.error
    assert result.representation_errors[0].representation == "inspect:kubernetes-secret-json"
    assert not result.findings


def test_negative_fast_guard_avoids_json_decode(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("noncandidate must not decode")

    monkeypatch.setattr(json, "loads", forbidden)
    assert inspect_kubernetes_secret_json(b"ordinary text, not JSON") == ()
    assert inspect_kubernetes_secret_json(b'{"kind":"ConfigMap","data":{"password":"Public"}}') == ()


def test_traversal_frontier_does_not_allocate_per_sibling():
    document = [secret("First!")] + [None] * 300000
    tracemalloc.start()
    try:
        resources = _resources(document)
        assert next(resources)[0] is document[0]
        assert list(resources) == []
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 1024 * 1024
