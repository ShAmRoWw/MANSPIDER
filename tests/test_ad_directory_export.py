"""Ownership, representation and passive-only AD export inspector regressions."""

import base64
import codecs
import json
import tracemalloc
from importlib import import_module

import pytest

from man_spider.lib.parser import FileParser
from man_spider.lib.parser.ad_directory_export import (
    _objects,
    inspect_active_directory_json_secrets,
    inspect_active_directory_ldif_secrets,
)
from man_spider.rules import load_rule_files
from tests.rule_pack_2_6_ad_structured_cases import (
    BITLOCKER_FIXTURE,
    JSON_RULE,
    LAPS_PAYLOAD,
    OPAQUE_FIXTURE,
    STRUCTURED_INSPECTOR_CASES,
)


def encoded(value):
    return base64.b64encode(value).decode("ascii")


def ldif(data):
    return inspect_active_directory_ldif_secrets(data.encode("utf-8") if isinstance(data, str) else data)


def structured(value):
    return inspect_active_directory_json_secrets(json.dumps(value).encode("utf-8"))


def values(findings):
    return [finding[0] for finding in findings]


def contexts(findings):
    return [json.loads(finding[3]) for finding in findings]


@pytest.mark.parametrize("path,source,rule_id", STRUCTURED_INSPECTOR_CASES)
def test_structured_fixtures_have_unmasked_evidence(path, source, rule_id):
    inspector = (
        inspect_active_directory_json_secrets if rule_id == JSON_RULE else inspect_active_directory_ldif_secrets
    )
    data = source.encode("utf-8")
    found = inspector(data)
    assert found, path
    for value, start, end, context in found:
        assert value
        assert (start, end) == (0, len(data))
        assert json.loads(context)["source_value"] is not None


@pytest.mark.parametrize("line_ending", ["\n", "\r\n"])
def test_ldif_physical_folding_and_first_line(line_ending):
    source = line_ending.join(
        [
            "version: 1",
            "dn: CN=LabPC,DC=example,DC=test",
            "ms-Mcs-AdmPwd: Folded",
            " Fixture!",
            "",
        ]
    )
    found = ldif(source)
    assert values(found) == ["FoldedFixture!"]
    context = contexts(found)[0]
    assert context["line"] == 3
    assert context["record_dn"] == "CN=LabPC,DC=example,DC=test"
    assert context["source_attribute_line"] == "ms-Mcs-AdmPwd: FoldedFixture!"


def test_ldif_fold_before_utf8_decode_and_valid_sibling_after_invalid():
    source = b"ms-Mcs-AdmPwd: \xd0\n \xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c!\nms-Mcs-AdmPwd: \xff\nms-Mcs-AdmPwd: LastFixture!"
    assert values(ldif(source)) == ["пароль!", "LastFixture!"]


def test_ldif_does_not_treat_tab_or_orphan_space_as_folding():
    source = " ms-Mcs-AdmPwd: OrphanFixture!\n\tms-Mcs-AdmPwd: TabFixture!\nms-Mcs-AdmPwd: OwnedFixture!\n\tIgnored"
    assert values(ldif(source)) == ["OwnedFixture!"]


def test_ldif_comments_and_owned_attribute_options():
    source = "# ms-Mcs-AdmPwd: CommentFixture!\n ms-Mcs-AdmPwd: FoldedComment!\nms-Mcs-AdmPwd;lang-en;binary: OptionsFixture!\n"
    found = ldif(source)
    assert values(found) == ["OptionsFixture!"]
    assert ";lang-en;binary:" in contexts(found)[0]["source_attribute_line"]


@pytest.mark.parametrize(
    "name",
    [
        "x-ms-Mcs-AdmPwd",
        "ms-Mcs-AdmPwd-extra",
        "ms-Mcs-AdmPwd;",
        "ms-Mcs-AdmPwd;bad_option",
        "ms-Mcs-AdmPwd ",
        "1ms-Mcs-AdmPwd",
        "description",
    ],
)
def test_ldif_rejects_unknown_or_invalid_attribute_names(name):
    assert not ldif(name + ": FixtureSecret!")


def test_ldif_plaintext_safe_bytes_are_not_implicitly_split():
    # RFC line separators are LF / CRLF; VT and FF inside values stay literal.
    assert values(ldif("ms-Mcs-AdmPwd: before\vafter\fFixture!")) == ["before\vafter\fFixture!"]


def test_ldif_record_dn_never_crosses_blank_or_replacement_dn():
    source = "dn: CN=First\nms-Mcs-AdmPwd: SameFixture!\n\nms-Mcs-AdmPwd: SameFixture!\ndn:: !!!\nms-Mcs-AdmPwd: SameFixture!\n"
    found = ldif(source)
    assert values(found) == ["SameFixture!"] * 3
    evidence = contexts(found)
    assert [entry["record_dn"] for entry in evidence] == ["CN=First", None, None]
    assert len({finding[3] for finding in found}) == 3


def test_ldif_base64_dn_and_change_record_still_preserve_owned_password():
    source = f"dn:: {encoded('CN=Компьютер'.encode())}\nchangetype: modify\nreplace: ms-Mcs-AdmPwd\nms-Mcs-AdmPwd: ChangeImportFixture!\n-\n"
    found = ldif(source)
    assert values(found) == ["ChangeImportFixture!"]
    assert contexts(found)[0]["record_dn"] == "CN=Компьютер"


@pytest.mark.parametrize(
    "uri", ["file:///etc/shadow", "https://example.test/secret", "ldap://example.test/", r"\\server\share\secret"]
)
def test_ldif_url_values_are_never_resolved(uri, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("URL/file access is forbidden")

    monkeypatch.setattr("builtins.open", forbidden)
    source = f"dn:< {uri}\nms-Mcs-AdmPwd:< {uri}\nmsDS-ManagedPassword:< {uri}\nms-Mcs-AdmPwd: InlineFixture!"
    found = ldif(source)
    assert values(found) == ["InlineFixture!"]
    assert contexts(found)[0]["record_dn"] is None


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-32"])
def test_ldif_bom_exports(encoding):
    assert values(ldif("MS-MCS-ADMPWD: BomFixture!\n".encode(encoding))) == ["BomFixture!"]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-32"])
@pytest.mark.parametrize("line_ending", ["\n", "\r\n"])
def test_ldif_guard_cannot_skip_a_folded_attribute_name(encoding, line_ending):
    source = f"ms-Mcs-Adm{line_ending} Pwd: NameFoldFixture!{line_ending}".encode(encoding)
    assert values(ldif(source)) == ["NameFoldFixture!"]


def test_ldif_folded_name_and_marker_base64_combination():
    payload = encoded(json.dumps(LAPS_PAYLOAD).encode())
    assert values(ldif("msLAPS-Pass\n word:\n : " + payload)) == [LAPS_PAYLOAD["p"]]


def test_ldif_unrelated_binary_log_is_skipped_without_decode():
    assert ldif(codecs.BOM_UTF16_LE + b"\xff") == ()
    assert ldif(bytes(range(256)) * 64) == ()


@pytest.mark.parametrize("invalid", ["***", "TQ", "TR==", "TQ===", "TQ==\t", "TQ== TQ==", "", "é"])
def test_ldif_malformed_base64_is_not_guessed(invalid):
    assert not ldif("ms-Mcs-AdmPwd:: " + invalid)
    assert not ldif("msDS-ManagedPassword:: " + invalid)


def test_ldif_base64_fold_preserves_source_and_decoded_plaintext():
    original = encoded("Base64LapsFixture!".encode())
    found = ldif("ms-Mcs-AdmPwd:: " + original[:7] + "\n " + original[7:])
    assert values(found) == ["Base64LapsFixture!"]
    assert contexts(found)[0]["source_value"] == original
    assert contexts(found)[0]["decoded_utf8"] == "Base64LapsFixture!"


@pytest.mark.parametrize(
    "attribute",
    [
        "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRMPassword",
        "msLAPS-EncryptedDSRMPasswordHistory",
        "msDS-ManagedPassword",
        "supplementalCredentials",
        "msFVE-KeyPackage",
    ],
)
def test_known_opaque_attributes_are_not_claimed_plaintext(attribute):
    source = encoded(OPAQUE_FIXTURE)
    for found in (
        ldif(f"{attribute}:: {source}"),
        structured({attribute: source}),
        structured({attribute: list(OPAQUE_FIXTURE)}),
    ):
        assert values(found) == [source]
        context = contexts(found)[0]
        assert context["value_kind"] == "opaque-secret-bytes"
        assert context["decoded_utf8"] is None
        assert context["decoded_bytes_length"] == len(OPAQUE_FIXTURE)
    assert not ldif(f"{attribute}: {source}")


@pytest.mark.parametrize(
    "value", [[0, 256], [0, -1], [0, True], [0, 1.0], [], ["not base64"], {"value": "AQID"}, None]
)
def test_json_opaque_invalid_types_and_bytes_are_not_coerced(value):
    assert not structured({"msDS-ManagedPassword": value})


def test_json_opaque_mixed_multivalue_siblings_and_source_array():
    found = structured({"msDS-ManagedPassword": ["!!!!", encoded(OPAQUE_FIXTURE), list(OPAQUE_FIXTURE), None]})
    assert values(found) == [encoded(OPAQUE_FIXTURE)] * 2
    evidence = contexts(found)
    assert [entry["pointer"] for entry in evidence] == ["/msDS-ManagedPassword/1", "/msDS-ManagedPassword/2"]
    assert evidence[1]["source_value"] == list(OPAQUE_FIXTURE)
    assert evidence[1]["encoding"] == "byte-array"


def test_unicodepwd_requires_quoted_utf16_write_value_and_keeps_source():
    raw = '"ImportedПароль!"'.encode("utf-16-le")
    source = encoded(raw)
    for found in (
        ldif("unicodePwd:: " + source),
        structured({"unicodePwd": source}),
        structured({"unicodePwd": list(raw)}),
    ):
        assert values(found) == ["ImportedПароль!"]
        assert contexts(found)[0]["value_kind"] == "unicode-password-write-value"


@pytest.mark.parametrize(
    "raw",
    [
        b"odd",
        b'"PlainUTF8!"',
        "NoQuotes!".encode("utf-16-le"),
        b'"\x00\x00\xd8"\x00',
        '""'.encode("utf-16-le"),
        '"${PASSWORD}"'.encode("utf-16-le"),
        '"a\x00b"'.encode("utf-16-le"),
    ],
)
def test_unicodepwd_malformed_never_labeled_plaintext(raw):
    assert not ldif("unicodePwd:: " + encoded(raw))
    assert not structured({"unicodePwd": encoded(raw)})


def test_unicodepwd_plain_literal_is_not_guessed():
    assert not ldif('unicodePwd: "PlainFixture!"')
    assert not structured({"unicodePwd": '"PlainFixture!"'})


def test_laps_json_owned_password_and_account_time_context():
    source = json.dumps(LAPS_PAYLOAD)
    for found in (
        ldif("msLAPS-Password: " + source),
        ldif("msLAPS-Password:: " + encoded(source.encode())),
        structured({"msLAPS-Password": source}),
        structured({"msLAPS-Password": LAPS_PAYLOAD}),
    ):
        assert values(found) == [LAPS_PAYLOAD["p"]]
        context = contexts(found)[0]
        assert context["laps_account"] == LAPS_PAYLOAD["n"]
        assert context["laps_update_time"] == LAPS_PAYLOAD["t"]


@pytest.mark.parametrize(
    "payload",
    [
        {"p": "${PASSWORD}"},
        {"p": None},
        {"password": "WrongKeyFixture!"},
        {"p": {"p": "NestedFixture!"}},
        {"n": "Administrator", "t": "123"},
        "invalid JSON",
        {"p": "\ud800"},
    ],
)
def test_laps_json_invalid_payload_is_isolated(payload):
    found = structured({"msLAPS-Password": [payload, LAPS_PAYLOAD]})
    assert values(found) == [LAPS_PAYLOAD["p"]]
    assert contexts(found)[0]["pointer"] == "/msLAPS-Password/1"


@pytest.mark.parametrize(
    "public_attribute",
    [
        "msLAPS-PasswordExpirationTime",
        "msLAPS-CurrentPasswordVersion",
        "ms-Mcs-AdmPwdExpirationTime",
        "msDS-ManagedPasswordId",
        "msDS-ManagedPasswordPreviousId",
        "msFVE-RecoveryGuid",
        "msFVE-VolumeGuid",
        "p",
        "description",
        "userPassword",
        "MsLaps-Password-SchemaName",
    ],
)
def test_public_and_unowned_attributes_are_not_secrets(public_attribute):
    source = "PublicInventoryFixture!"
    assert not ldif(f"{public_attribute}: {source}")
    assert not structured({public_attribute: source})


def test_known_attribute_payload_cannot_smuggle_other_attribute_ownership():
    assert not structured({"msLAPS-Password": {"ms-Mcs-AdmPwd": "WrongOwner!"}})
    assert not structured({"msDS-ManagedPassword": {"ms-Mcs-AdmPwd": "WrongOwner!"}})


def test_json_all_objects_same_values_and_local_dn_ownership():
    found = structured(
        {
            "dn": "CN=Parent",
            "a/b~c": [
                {"dn": "CN=First", "ms-Mcs-AdmPwd": ["SameFixture!", "SameFixture!"]},
                {"ms-Mcs-AdmPwd": "SameFixture!"},
            ],
        }
    )
    assert values(found) == ["SameFixture!"] * 3
    evidence = contexts(found)
    assert [entry["record_dn"] for entry in evidence] == ["CN=First", "CN=First", None]
    assert [entry["pointer"] for entry in evidence] == [
        "/a~1b~0c/0/ms-Mcs-AdmPwd/0",
        "/a~1b~0c/0/ms-Mcs-AdmPwd/1",
        "/a~1b~0c/1/ms-Mcs-AdmPwd",
    ]
    assert len({finding[3] for finding in found}) == 3


def test_json_escaped_attribute_key_and_value_bypass_literal_guard():
    source = rb'{"ms\u004caps-Password":"{\"p\":\"EscapedFixture!\"}"}'
    assert values(inspect_active_directory_json_secrets(source)) == ["EscapedFixture!"]


@pytest.mark.parametrize("key", ["msLAPſ-Password", "msDS-ManagedPaſſword", "msFVE-KeyPackage"])
def test_unicode_casefold_aliases_do_not_impersonate_literal_ldap_attribute_names(key):
    assert not structured({key: {"p": "FalseOwnerFixture!"}})
    assert not structured({key: encoded(OPAQUE_FIXTURE)})


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-32"])
def test_json_bom_and_case_insensitive_attribute(encoding):
    source = json.dumps({"MS-MCS-ADMPWD": "BomJsonFixture!"}).encode(encoding)
    assert values(inspect_active_directory_json_secrets(source)) == ["BomJsonFixture!"]


@pytest.mark.parametrize(
    "placeholder",
    [
        "${PASSWORD}",
        "$(Get-Secret)",
        "{{ secret }}",
        "<%=secret%>",
        "[redacted]",
        "<redacted>",
        "MASKED",
        "*****",
        "",
        "  ",
    ],
)
def test_placeholders_are_fullmatch_not_usable_literal_passwords(placeholder):
    assert not ldif("ms-Mcs-AdmPwd: " + placeholder)
    assert not structured({"ms-Mcs-AdmPwd": placeholder})


@pytest.mark.parametrize(
    "literal",
    [
        "$uperSecret!",
        "$PASSWORD",
        "%PASSWORD%",
        "prefix${PASSWORD}suffix",
        "changeme",
        "!",
        " secret with spaces ",
        "пароль🔑!",
    ],
)
def test_nonplaceholder_literals_are_preserved_without_strength_filter(literal):
    assert values(structured({"ms-Mcs-AdmPwd": literal})) == [literal]


@pytest.mark.parametrize("literal", ["$Abc12345", "$PASSWORD", "%PASSWORD%"])
def test_owned_ad_passwords_are_literals_not_bare_script_variable_expressions(literal):
    # The schema-owned export is data, unlike a script's assignment expression.
    assert values(ldif("ms-Mcs-AdmPwd: " + literal)) == [literal]
    assert values(structured({"ms-Mcs-AdmPwd": literal})) == [literal]
    assert values(structured({"msLAPS-Password": {"p": literal}})) == [literal]
    assert values(ldif("msLAPS-Password: " + json.dumps({"p": literal}))) == [literal]
    write_value = encoded(('"' + literal + '"').encode("utf-16-le"))
    assert values(ldif("unicodePwd:: " + write_value)) == [literal]
    assert values(structured({"unicodePwd": write_value})) == [literal]


def test_unicode_casefold_alias_cannot_impersonate_dn_context():
    found = structured({"diſtinguiſhedName": "CN=WrongOwner", "ms-Mcs-AdmPwd": "Fixture!"})
    assert values(found) == ["Fixture!"]
    assert contexts(found)[0]["record_dn"] is None


@pytest.mark.parametrize("separator", ["-", " ", ""])
def test_bitlocker_full_numeric_validation_with_canonical_value(separator):
    source = BITLOCKER_FIXTURE.replace("-", separator)
    for found in (ldif("msFVE-RecoveryPassword: " + source), structured({"msFVE-RecoveryPassword": source})):
        assert values(found) == [BITLOCKER_FIXTURE]
        assert contexts(found)[0]["source_value"] == source
        assert contexts(found)[0]["value_kind"] == "bitlocker-recovery-password"


@pytest.mark.parametrize(
    "invalid",
    [
        BITLOCKER_FIXTURE.replace("000011", "000012"),
        BITLOCKER_FIXTURE.replace("720885", "720896"),
        BITLOCKER_FIXTURE[:-1],
        BITLOCKER_FIXTURE + "0",
        BITLOCKER_FIXTURE.replace("-", "\t"),
        "{" + BITLOCKER_FIXTURE + "}",
        "".join(chr(0xFF10 + int(c)) if c.isdigit() else c for c in BITLOCKER_FIXTURE),
    ],
)
def test_bitlocker_shape_checksum_range_and_ascii_boundaries(invalid):
    assert not ldif("msFVE-RecoveryPassword: " + invalid)
    assert not structured({"msFVE-RecoveryPassword": invalid})


def test_iterative_object_walk_supports_depth_without_python_recursion():
    document = {"ms-Mcs-AdmPwd": "DeepFixture!"}
    for _ in range(1500):
        document = {"child": document}
    assert sum(1 for _ in _objects(document)) == 1501


def test_deep_or_invalid_json_is_explicit_error_when_relevant():
    with pytest.raises(ValueError, match="invalid JSON"):
        inspect_active_directory_json_secrets(b'{"ms-Mcs-AdmPwd":')
    with pytest.raises(ValueError, match="invalid JSON"):
        inspect_active_directory_json_secrets(b'{"ms-Mcs-AdmPwd":NaN}')
    assert inspect_active_directory_json_secrets(b"unrelated binary\xff") == ()


def test_invalid_laps_inner_json_does_not_hide_valid_sibling():
    found = structured({"msLAPS-Password": '{"p":NaN}', "ms-Mcs-AdmPwd": "SiblingFixture!"})
    assert values(found) == ["SiblingFixture!"]


@pytest.mark.parametrize(
    "source",
    [
        '{"ms-Mcs-AdmPwd":"FirstFixture!","ms-Mcs-AdmPwd":null}',
        '{"ms-Mcs-AdmPwd":null,"ms-Mcs-AdmPwd":"LastFixture!"}',
        '{"msLAPS-Password":{"p":"FirstFixture!","p":null}}',
        '{"note":1,"note":2,"ms-Mcs-AdmPwd":"VisibleFixture!"}',
        '{"ms-Mcs-AdmPwd":"FirstFixture!","ms-Mcs-Adm\\u0050wd":null}',
    ],
)
def test_exact_duplicate_json_keys_are_explicit_errors_not_last_wins(source):
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        inspect_active_directory_json_secrets(source.encode())


@pytest.mark.parametrize("format", ["json", "ldif", "ldif-base64"])
def test_embedded_laps_json_duplicate_member_cannot_be_swallowed_as_invalid_sibling(format):
    payload = '{"p":"FirstFixture!","p":null}'
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        if format == "json":
            structured({"msLAPS-Password": payload, "ms-Mcs-AdmPwd": "SiblingFixture!"})
        else:
            marker = ":: " if format == "ldif-base64" else ": "
            source = encoded(payload.encode()) if format == "ldif-base64" else payload
            ldif("msLAPS-Password" + marker + source + "\nms-Mcs-AdmPwd: SiblingFixture!")


def test_ascii_case_alias_attributes_remain_distinct_legal_export_properties():
    found = structured({"ms-Mcs-AdmPwd": "FirstFixture!", "MS-MCS-ADMPWD": "LastFixture!"})
    assert values(found) == ["FirstFixture!", "LastFixture!"]
    assert [entry["pointer"] for entry in contexts(found)] == ["/ms-Mcs-AdmPwd", "/MS-MCS-ADMPWD"]


def test_wide_object_walk_does_not_materialize_a_sibling_frontier():
    document = {"items": [{} for _ in range(60000)]}
    tracemalloc.start()
    try:
        assert sum(1 for _ in _objects(document)) == 60001
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 2 * 1024 * 1024


def test_deep_long_keys_without_findings_do_not_retain_ancestor_pointer_copies():
    key = "w" * 1000
    source = ("{" + json.dumps(key) + ":") * 200 + '{"ms-Mcs-AdmPwd":null}' + "}" * 200
    data = source.encode()
    tracemalloc.start()
    try:
        assert inspect_active_directory_json_secrets(data) == ()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 3 * 1024 * 1024


def test_ldif_wide_comments_remain_a_stream_not_a_document_tree():
    source = b"# ms-Mcs-AdmPwd is documentation only\n" * 30000
    tracemalloc.start()
    try:
        assert ldif(source) == ()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4 * 1024 * 1024


@pytest.mark.parametrize("source_kind", ["json-dn", "ldif-dn", "json-ancestry"])
def test_repeated_dn_or_ancestry_cannot_amplify_retained_evidence_without_bound(source_kind):
    if source_kind == "ldif-dn":
        source = ("dn: CN=" + "x" * 30000 + "\n" + "ms-Mcs-AdmPwd: FixtureSecret!\n" * 300).encode()
        inspector = inspect_active_directory_ldif_secrets
    else:
        document = {"ms-Mcs-AdmPwd": ["FixtureSecret!"] * 300}
        if source_kind == "json-dn":
            document["dn"] = "CN=" + "x" * 30000
        else:
            for _ in range(20):
                document = {"wrapper" + "x" * 3000: document}
        source = json.dumps(document).encode()
        inspector = inspect_active_directory_json_secrets
    tracemalloc.start()
    try:
        with pytest.raises(ValueError, match="derived evidence exceeds context budget.*no partial or truncated"):
            inspector(source)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * 1024 * 1024


def test_native_inspectors_share_a_single_source_read_and_isolate_failures(tmp_path, monkeypatch):
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "rules": [
                    {
                        "id": "ad-export-inspection-test",
                        "match": {"predicates": [{"field": "extension", "operator": "exact", "value": ".json"}]},
                        "actions": [
                            {"type": "inspect", "detector": "active-directory-ldif-secrets"},
                            {"type": "inspect", "detector": "active-directory-json-secrets"},
                            {"type": "scan", "representation": "raw", "pattern": "SharedReadFixture!"},
                        ],
                    }
                ],
            }
        )
    )
    parser = FileParser([], quiet=True, rules=load_rule_files([path]))
    route = parser.route_rules({"filename": "directory.json", "extension": ".json"})
    source = json.dumps({"ms-Mcs-AdmPwd": ["SharedReadFixture!", "SharedReadFixture!"]}).encode()
    reads = []
    result = parser.parse_file("directory.json", rule_route=route, data_loader=lambda: reads.append(True) or source)
    assert reads == [True]
    assert result.error is None
    found = [
        finding for finding in result.findings if finding.representation == "inspect:active-directory-json-secrets"
    ]
    assert [finding.value for finding in found] == ["SharedReadFixture!", "SharedReadFixture!"]
    # A representation-specific parsing error cannot discard another inspector
    # or a raw scan. This mixed-format pack is deliberately broader than default.
    result = parser.parse_file("directory.json", rule_route=route, data=b"ms-Mcs-AdmPwd: SharedReadFixture!")
    assert result.error
    assert {finding.representation for finding in result.findings} >= {"inspect:active-directory-ldif-secrets", "raw"}
    result = parser.parse_file(
        "directory.json",
        rule_route=route,
        data=b'{"ms-Mcs-AdmPwd":"SharedReadFixture!","ms-Mcs-AdmPwd":null}',
    )
    assert result.error
    assert any("duplicate JSON object key" in str(error) for error in result.representation_errors)
    assert any(finding.representation == "raw" for finding in result.findings)
    monkeypatch.setattr(import_module("man_spider.lib.parser.ad_directory_export"), "_MAX_EVIDENCE_BUDGET", 100)
    result = parser.parse_file("directory.json", rule_route=route, data=source)
    assert result.error
    assert any("context budget of 100 bytes; inspection is incomplete" in str(e) for e in result.representation_errors)
    assert any(finding.representation == "raw" for finding in result.findings)
    assert not any(finding.representation.startswith("inspect:") for finding in result.findings)
