"""GPP ownership, passive crypto, XML safety, persistence and bounded memory."""

import base64
import json
import tracemalloc
from importlib import import_module

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from man_spider.lib.parser import FileParser
from man_spider.lib.parser.group_policy import (
    GPP_AES_KEY,
    _MAX_EVIDENCE_BUDGET,
    _MIN_EVIDENCE_BUDGET,
    _ciphertext,
    _decrypt,
    inspect_group_policy_preference_password,
)
from man_spider.rules import load_rule_files
from tests.rule_pack_2_6_gpp_cases import GPP_CPASSWORD, GPP_PASSWORD, STRUCTURED_INSPECTOR_CASES


def xml(value=GPP_CPASSWORD, *, family="Groups", item="User", attribute="cpassword", extra=""):
    return f'<{family}><{item} name="fixture"><Properties {attribute}="{value}" {extra}/></{item}></{family}>'


def inspect(value):
    return inspect_group_policy_preference_password(value.encode() if isinstance(value, str) else value)


@pytest.mark.parametrize(("path", "content", "rule_id"), STRUCTURED_INSPECTOR_CASES)
def test_synthetic_known_ciphertexts_are_decoded_with_owner_evidence(path, content, rule_id):
    result = inspect(content)
    assert [row[0] for row in result] == [GPP_PASSWORD]
    context = json.loads(result[0][3])
    assert context["source_value"] == GPP_CPASSWORD
    assert context["value_kind"] == "plaintext-password"
    assert context["decoded_password"] == GPP_PASSWORD
    assert context["pointer"].endswith(("/@cpassword", "/@cPassword"))
    assert result[0][1:3] == (0, len(content.encode()))


@pytest.mark.parametrize(
    ("family", "item"),
    [
        ("Groups", "User"),
        ("NTServices", "NTService"),
        ("Drives", "Drive"),
        ("DataSources", "DataSource"),
        ("Printers", "SharedPrinter"),
        ("ScheduledTasks", "Task"),
        ("ScheduledTasks", "TaskV2"),
        ("ScheduledTasks", "ImmediateTask"),
        ("ScheduledTasks", "ImmediateTaskV2"),
    ],
)
@pytest.mark.parametrize("attribute", ["cpassword", "cPassword", "CPASSWORD", "cPassWord"])
def test_real_preference_families_and_mixed_case_property(family, item, attribute):
    assert inspect(xml(family=family, item=item, attribute=attribute))[0][0] == GPP_PASSWORD


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"])
def test_xml_encodings_keep_cpassword_visible_to_guard_and_parser(encoding):
    source = xml(extra='userName="Пользователь"')
    rows = inspect(source.encode(encoding))
    assert rows[0][0] == GPP_PASSWORD
    assert json.loads(rows[0][3])["account"]["userName"] == "Пользователь"


@pytest.mark.parametrize(
    ("encoded", "password"),
    [
        (GPP_CPASSWORD, GPP_PASSWORD),
        ("/IPZ94bmercMsL1+uKpXlgpnxEdxzX+KZgqhRrIe4F4", "ПарольСтенда!"),
        ("K+4awteH2T+08TODETt5iw", "  "),
    ],
)
def test_known_unicode_and_space_passwords_are_not_masked_or_trimmed(encoded, password):
    for source in (encoded, encoded + "=" * (-len(encoded) % 4), encoded[:10] + "\n" + encoded[10:]):
        assert _decrypt(_ciphertext(source)) == password
        assert inspect(xml(source))[0][0] == password


@pytest.mark.parametrize(
    "source", ["", "${PASSWORD}", "{{ secret }}", "****", "AAAAA", "A===", "YWJjZA==", "YQ==garbage", "YWJjZA==\u00a0"]
)
def test_invalid_or_empty_ciphertext_is_not_a_password_candidate(source):
    assert inspect(xml(source)) == ()


@pytest.mark.parametrize(
    "source",
    [
        lambda: f"<!-- {xml()} --><Groups />",
        lambda: "<root><![CDATA[" + xml() + "]]></root>",
        lambda: xml(attribute="data-cpassword"),
        lambda: xml(attribute="x:cpassword", extra='xmlns:x="https://example.invalid/not-gpp"'),
        lambda: xml(family="Other", item="User"),
        lambda: xml(family="Groups", item="Group"),
        lambda: f'<Properties cpassword="{GPP_CPASSWORD}" />',
        lambda: f'<Groups><User><Nested><Properties cpassword="{GPP_CPASSWORD}" /></Nested></User></Groups>',
        lambda: (
            f'<Groups xmlns="https://example.invalid/not-gpp"><User><Properties cpassword="{GPP_CPASSWORD}" /></User></Groups>'
        ),
        lambda: xml(attribute="description", extra='userName="looks like cpassword but is not it"'),
    ],
)
def test_cpassword_is_an_owned_xml_attribute_not_nearby_text(source):
    assert inspect(source()) == ()


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_unicode_casefold_alias_is_not_a_cpassword_attribute(encoding):
    # XML treats this as a different identifier: casefold alone maps sharp S to
    # 'ss'. The comment also exercises the UTF-8 fast-path with a password hint.
    source = "<!-- cpassword -->" + xml(attribute="cpaßword")
    assert inspect(source.encode(encoding)) == ()


def test_different_case_attributes_retain_independent_structural_evidence():
    source = xml(extra=f'cPassword="{GPP_CPASSWORD}"')
    rows = inspect(source)
    assert [row[0] for row in rows] == [GPP_PASSWORD, GPP_PASSWORD]
    assert {json.loads(row[3])["pointer"].rsplit("/", 1)[-1] for row in rows} == {"@cpassword", "@cPassword"}


def test_gpo_report_wrappers_and_disabled_or_delete_items_do_not_hide_stored_values():
    source = (
        "<GPO><Computer><ExtensionData>"
        + xml(extra='action="D" disabled="1" userName="EXAMPLE\\fixture"')
        + "</ExtensionData></Computer></GPO>"
    )
    row = inspect(source)[0]
    assert row[0] == GPP_PASSWORD
    assert json.loads(row[3])["account"] == {"userName": "EXAMPLE\\fixture"}


def test_repeated_equal_values_and_malformed_sibling_have_separate_pointers():
    source = (
        "<Groups><User>"
        + f'<Properties cpassword="{GPP_CPASSWORD}" />' * 2
        + '<Properties cpassword="invalid" /></User></Groups>'
    )
    rows = inspect(source)
    assert [row[0] for row in rows] == [GPP_PASSWORD, GPP_PASSWORD]
    assert len({json.loads(row[3])["pointer"] for row in rows}) == 2


def test_valid_ciphertext_without_valid_padding_is_only_encrypted_material():
    source = base64.b64encode(bytes(16)).decode()
    row = inspect(xml(source))[0]
    assert row[0] == source
    context = json.loads(row[3])
    assert context["value_kind"] == "encrypted-password-candidate"
    assert context["decoded_password"] is None
    assert context["decoding_error"]


@pytest.mark.parametrize(
    "padded",
    [
        b"A" * 16,  # Not a PKCS7 suffix.
        b"A" * 15 + b"\x00",  # Zero-length padding is forbidden.
        b"A" * 14 + b"\x03\x02",  # Padding bytes must agree.
        b"x" + b"\x0f" * 15,  # Valid padding, incomplete UTF-16 code unit.
        b"\x00\xd8" + b"\x0e" * 14,  # Valid padding, unpaired UTF-16 surrogate.
    ],
)
def test_padding_and_utf16_are_strict_without_lossy_decoding(padded):
    encryptor = Cipher(algorithms.AES(GPP_AES_KEY), modes.CBC(bytes(16))).encryptor()
    encoded = base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode()
    row = inspect(xml(encoded))[0]
    context = json.loads(row[3])
    assert row[0] == encoded
    assert context["value_kind"] == "encrypted-password-candidate"
    assert context["decoded_password"] is None
    assert context["decoding_error"]


def test_successfully_decoded_empty_password_is_not_reported_as_nonempty_secret():
    assert inspect(xml("0G8sBHI8gLl7UyMxTc/3gA")) == ()


@pytest.mark.parametrize(
    "declaration",
    [
        '<!DOCTYPE Groups [<!ENTITY local SYSTEM "file:///tmp/manspider-must-not-read">]>',
        '<!DOCTYPE Groups SYSTEM "https://example.invalid/must-not-fetch.dtd">',
        '<!DOCTYPE Groups [<!ENTITY secret "' + GPP_CPASSWORD + '">]>',
    ],
)
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_no_dtd_entity_expansion_or_external_resolution(declaration, encoding, monkeypatch):
    import socket

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: pytest.fail("XML must never open a socket"))
    with pytest.raises(ValueError, match="DTD and entity declarations are disabled"):
        inspect((declaration + xml("&local;")).encode(encoding))


def test_standard_xml_character_references_are_resolved_without_external_io():
    encoded = "K+4awteH2T+08TODETt5iw"
    assert inspect(xml(encoded.replace("+", "&#43;")))[0][0] == "  "


def test_malformed_xml_is_visible_as_error_not_silent_no_match():
    with pytest.raises(ValueError, match="invalid XML"):
        inspect(xml()[:-3])


def test_wide_document_uses_streaming_not_a_tree_or_sibling_frontier():
    data = b"<Groups><!-- cpassword -->" + b'<User name="public" />' * 60000 + b"</Groups>"
    tracemalloc.start()
    try:
        assert inspect(data) == ()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * 1024 * 1024


def test_deep_xml_has_explicit_limit_without_expanding_path_per_ancestor():
    with pytest.raises(ValueError, match="nesting exceeds"):
        inspect(b"<a>" * 513 + b"<!-- cpassword -->" + b"</a>" * 513)


@pytest.mark.parametrize("long_ancestry", [False, True])
def test_repeated_owner_or_ancestry_cannot_amplify_retained_context_without_bound(long_ancestry):
    properties = f'<Properties cpassword="{GPP_CPASSWORD}" />' * 300
    if long_ancestry:
        wrapper = "wrapper" + "x" * 3000
        source = f"<{wrapper}>" * 20 + f"<Groups><User>{properties}</User></Groups>" + f"</{wrapper}>" * 20
    else:
        source = f'<Groups><User name="{"x" * 30000}">{properties}</User></Groups>'
    tracemalloc.start()
    try:
        with pytest.raises(ValueError, match="derived evidence exceeds context budget.*no partial or truncated"):
            inspect(source)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * 1024 * 1024


def test_context_budget_has_minimum_and_absolute_ceiling():
    assert _MIN_EVIDENCE_BUDGET == 1024 * 1024
    assert _MAX_EVIDENCE_BUDGET == 32 * 1024 * 1024


def test_context_budget_failure_does_not_drop_or_mask_an_individual_password(monkeypatch):
    group_policy = import_module("man_spider.lib.parser.group_policy")

    monkeypatch.setattr(group_policy, "_MAX_EVIDENCE_BUDGET", 100)
    with pytest.raises(ValueError, match="context budget of 100 bytes; inspection is incomplete"):
        inspect(xml())


def test_native_dispatch_uses_source_bytes_once_and_preserves_independent_failures(tmp_path, monkeypatch):
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "rules": [
                    {
                        "id": "gpp",
                        "match": {"predicates": [{"field": "extension", "operator": "exact", "value": ".xml"}]},
                        "actions": [
                            {"type": "inspect", "detector": "group-policy-preference-password"},
                            {"type": "scan", "representation": "raw", "pattern": "cpassword"},
                        ],
                    }
                ],
            }
        )
    )
    parser = FileParser([], quiet=True, rules=load_rule_files([path]))
    route = parser.route_rules({"filename": "Groups.xml", "extension": ".xml"})
    calls = []
    result = parser.parse_file(
        "Groups.xml", rule_route=route, data_loader=lambda: calls.append(True) or xml().encode()
    )
    assert result.error is None
    assert calls == [True]
    assert GPP_PASSWORD in {finding.value for finding in result.findings}
    failed = parser.parse_file("Groups.xml", rule_route=route, data=xml()[:-3].encode())
    assert failed.error
    assert any(finding.representation == "raw" for finding in failed.findings)
    monkeypatch.setattr(import_module("man_spider.lib.parser.group_policy"), "_MAX_EVIDENCE_BUDGET", 100)
    exhausted = parser.parse_file("Groups.xml", rule_route=route, data=xml().encode())
    assert exhausted.error
    assert any("context budget of 100 bytes" in str(error) for error in exhausted.representation_errors)
    assert any(finding.representation == "raw" for finding in exhausted.findings)
    assert not any(
        finding.representation == "inspect:group-policy-preference-password" for finding in exhausted.findings
    )
