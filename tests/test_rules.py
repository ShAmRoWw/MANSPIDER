import json
import sqlite3
import subprocess
import sys

import pytest

from man_spider.evidence_storage import configure_evidence_reader, context_join, context_sql
from man_spider.lib.parser import FileParser
from man_spider.state import SCHEMA_VERSION
from man_spider.rules import (
    RuleConfigurationError,
    RuleEngine,
    compose_rules,
    load_builtin_rules,
    load_rule_files,
)


def write_rules(path, rules, schema_version=None, pack=None):
    payload = {"rules": rules}
    if schema_version is not None:
        payload["schema_version"] = schema_version
    if pack is not None:
        payload["pack"] = pack
    path.write_text(json.dumps(payload), encoding="utf-8")


def database_rows(path, query):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    configure_evidence_reader(connection)
    try:
        return connection.execute(query).fetchall()
    finally:
        connection.close()


def run_rule_scan(scope, rule_file, state_file):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "man_spider.manspider",
            str(scope),
            "--yes",
            "--rules",
            str(rule_file),
            "--state-file",
            str(state_file),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_rule_files_load_named_regexes_with_normalized_flags(tmp_path):
    path = tmp_path / "rules.json"
    write_rules(
        path,
        [
            {
                "id": "case-sensitive-token",
                "pattern": r"TOKEN_[A-Z]+",
                "flags": ["multiline"],
                "description": "fixture",
            },
            {"id": "disabled", "pattern": "NEVER", "enabled": False},
        ],
    )

    assert load_rule_files([path]) == [
        {
            "schema_version": 1,
            "id": "case-sensitive-token",
            "description": "fixture",
            "match": {"condition": "all", "predicates": []},
            "actions": [
                {
                    "type": "scan",
                    "representation": "text",
                    "pattern": r"TOKEN_[A-Z]+",
                    "flags": ["multiline"],
                }
            ],
            "rule_source": str(path.resolve()),
            "rule_pack_id": "legacy-json",
            "rule_pack_version": "1",
        }
    ]


def test_named_rules_produce_all_findings_with_stable_rule_identity(tmp_path):
    file = tmp_path / "tokens.txt"
    file.write_text("TOKEN_ONE token_two TOKEN_THREE", encoding="utf-8")
    rules = [
        {
            "id": "uppercase-token",
            "pattern": r"TOKEN_[A-Z]+",
            "flags": [],
            "description": "case-sensitive fixture",
        }
    ]

    result = FileParser([], quiet=True, blocked_extensions=[], rules=rules).parse_file(file)

    assert [finding.value for finding in result.findings] == ["TOKEN_ONE", "TOKEN_THREE"]
    assert {finding.rule_id for finding in result.findings} == {"rule:uppercase-token"}


@pytest.mark.parametrize(
    ("rules", "message"),
    [
        ([{"id": "bad", "pattern": "["}], "invalid regex"),
        ([{"id": "bad", "pattern": "ok", "flags": ["unknown"]}], "unsupported flags"),
        ([{"pattern": "ok"}], "non-empty string id"),
        ([{"id": "bad", "pattern": "ok", "extra": True}], "unsupported fields"),
    ],
)
def test_invalid_rules_fail_during_configuration(tmp_path, rules, message):
    path = tmp_path / "bad.json"
    write_rules(path, rules)

    with pytest.raises(RuleConfigurationError, match=message):
        load_rule_files([path])


def test_duplicate_active_rule_ids_are_rejected_across_files(tmp_path):
    one = tmp_path / "one.json"
    two = tmp_path / "two.json"
    write_rules(one, [{"id": "duplicate", "pattern": "one"}])
    write_rules(two, [{"id": "duplicate", "pattern": "two"}])

    with pytest.raises(RuleConfigurationError, match="Duplicate active rule id"):
        load_rule_files([one, two])


def test_v2_pack_identity_is_normalized_into_every_rule(tmp_path):
    path = tmp_path / "pack.json"
    write_rules(
        path,
        [{"id": "packed", "match": {}, "actions": [{"type": "report"}]}],
        schema_version=2,
        pack={"id": "example.credentials", "version": "2026.09.0"},
    )

    rule = load_rule_files([path])[0]

    assert rule["rule_source"] == str(path.resolve())
    assert rule["rule_pack_id"] == "example.credentials"
    assert rule["rule_pack_version"] == "2026.09.0"


def test_v3_classification_and_rule_local_exclusion_are_normalized_and_routed(tmp_path):
    path = tmp_path / "rules-v3.json"
    write_rules(
        path,
        [
            {
                "id": "targeted-secret",
                "severity": "critical",
                "confidence": "high",
                "category": "credential.password",
                "tags": ["windows", "configuration", "windows"],
                "match": {"predicates": [{"field": "extension", "operator": "exact", "value": ".conf"}]},
                "exclude": {
                    "condition": "any",
                    "predicates": [
                        {"field": "path", "operator": "contains", "value": "vendor"},
                        {"field": "filename", "operator": "exact", "value": "example.conf"},
                    ],
                },
                "actions": [{"type": "scan", "pattern": "SECRET_[A-Z]+", "flags": []}],
            },
            {
                "id": "independent-rule",
                "severity": "low",
                "category": "sensitive.configuration",
                "match": {"predicates": [{"field": "extension", "operator": "exact", "value": ".conf"}]},
                "actions": [{"type": "report"}],
            },
        ],
        schema_version=3,
        pack={"id": "example.v3", "version": "1"},
    )

    rules = load_rule_files([path])
    classified = next(rule for rule in rules if rule["id"] == "targeted-secret")
    assert classified["tags"] == ["configuration", "windows"]
    engine = RuleEngine(rules)

    normal = engine.route({"path": "deploy/app.conf", "filename": "app.conf", "extension": ".conf"})
    assert set(normal.matched_rule_ids) == {"rule:independent-rule", "rule:targeted-secret"}
    content = next(rule for rule in normal.content_rules if rule.rule_id == "rule:targeted-secret")
    assert (content.severity, content.confidence, content.category, content.tags) == (
        "critical",
        "high",
        "credential.password",
        ("configuration", "windows"),
    )

    excluded = engine.route({"path": "vendor/app.conf", "filename": "app.conf", "extension": ".conf"})
    assert excluded.matched_rule_ids == ("rule:independent-rule",)
    assert excluded.metadata_rules[0].severity == "low"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("severity", "red", "severity must be one of"),
        ("confidence", "certain", "confidence must be one of"),
        ("category", "Invalid Category", "lower-case classification name"),
        ("tags", ["valid", "Not Valid"], "array of lower-case classification names"),
        ("exclude", {"condition": "all", "predicates": []}, "exclude requires at least one predicate"),
    ],
)
def test_v3_invalid_classification_and_empty_exclusion_fail_before_scan(tmp_path, field, value, message):
    path = tmp_path / "bad-v3.json"
    rule = {"id": "bad", "actions": [{"type": "report"}], field: value}
    write_rules(path, [rule], schema_version=3)

    with pytest.raises(RuleConfigurationError, match=message):
        load_rule_files([path])


def test_v3_only_fields_are_rejected_by_v2(tmp_path):
    path = tmp_path / "bad-v2.json"
    write_rules(
        path,
        [{"id": "bad", "severity": "high", "actions": [{"type": "report"}]}],
        schema_version=2,
    )

    with pytest.raises(RuleConfigurationError, match="unsupported fields: severity"):
        load_rule_files([path])


def test_private_key_inspector_parses_encrypted_pkcs12_and_ignores_public_certificate(tmp_path):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MANSPIDER fixture")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    password = "UnmaskedPfxPassword!"
    key_file = tmp_path / "identity.pfx"
    key_file.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"fixture",
            key,
            certificate,
            None,
            serialization.BestAvailableEncryption(password.encode()),
        )
    )
    public_file = tmp_path / "public.pem"
    public_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path = tmp_path / "inspect-v3.json"
    write_rules(
        path,
        [
            {
                "id": "cryptographic-private-key",
                "severity": "critical",
                "confidence": "high",
                "category": "cryptographic.private-key",
                "match": {
                    "predicates": [
                        {
                            "field": "extension",
                            "operator": "regex",
                            "value": r"\.(?:pem|pfx)$",
                        }
                    ]
                },
                "actions": [
                    {
                        "type": "inspect",
                        "detector": "private-key-material",
                        "passwords": [password],
                    }
                ],
            }
        ],
        schema_version=3,
    )
    parser = FileParser([], quiet=True, blocked_extensions=[], rules=load_rule_files([path]))

    key_result = parser.parse_file(
        key_file,
        rule_route=parser.route_rules({"extension": ".pfx"}),
    )
    public_result = parser.parse_file(
        public_file,
        rule_route=parser.route_rules({"extension": ".pem"}),
    )

    assert key_result.error is None
    assert [(finding.value, finding.representation) for finding in key_result.findings] == [
        ("PKCS#12 private key material", "inspect:private-key-material")
    ]
    assert f'password="{password}"' in key_result.findings[0].context
    assert key_result.findings[0].severity == "critical"
    assert public_result.error is None
    assert public_result.findings == ()


def test_inspector_action_requires_v3_and_valid_bounded_passwords(tmp_path):
    path = tmp_path / "bad-inspector.json"
    write_rules(
        path,
        [
            {
                "id": "bad",
                "actions": [{"type": "inspect", "detector": "private-key-material"}],
            }
        ],
        schema_version=2,
    )
    with pytest.raises(RuleConfigurationError, match="requires schema_version 3"):
        load_rule_files([path])

    write_rules(
        path,
        [
            {
                "id": "bad",
                "actions": [
                    {
                        "type": "inspect",
                        "detector": "private-key-material",
                        "passwords": ["x" * 257],
                    }
                ],
            }
        ],
        schema_version=3,
    )
    with pytest.raises(RuleConfigurationError, match="at most 64 strings"):
        load_rule_files([path])


def test_builtin_pack_is_versioned_and_finds_metadata_and_content(tmp_path):
    rules = load_builtin_rules()
    parser = FileParser([], quiet=True, blocked_extensions=[], rules=rules)
    candidate = tmp_path / ".env.production"
    candidate.write_text("password = UnmaskedFixtureSecret!\n", encoding="utf-8")
    route = parser.route_rules(
        {
            "share": "Public",
            "directory": "deploy",
            "path": "deploy/.env.production",
            "filename": ".env.production",
            "extension": ".production",
            "size": candidate.stat().st_size,
            "mtime": candidate.stat().st_mtime,
        }
    )

    assert {rule["rule_pack_id"] for rule in rules} == {"manspider.default"}
    assert {rule["rule_pack_version"] for rule in rules} == {"2.7.0"}
    assert {rule["rule_source"] for rule in rules} == {"builtin:manspider.default"}
    assert "rule:sensitive-configuration-file" in route.metadata_rule_ids
    result = parser.parse_file(candidate, rule_route=route)
    assert ("rule:assigned-secret", "password = UnmaskedFixtureSecret!", "medium") in {
        (finding.rule_id, finding.value, finding.confidence) for finding in result.findings
    }
    assert {finding.rule_id for finding in result.findings} == {
        "rule:assigned-secret",
        "rule:credential-assignment-candidate",
        "rule:credential-keyword-candidate",
    }
    assert result.findings[0].rule_pack_id == "manspider.default"


def test_rule_composition_requires_explicit_known_overrides_and_disables(tmp_path):
    base = load_builtin_rules()
    override_path = tmp_path / "override.json"
    write_rules(
        override_path,
        [{"id": "assigned-secret", "actions": [{"type": "scan", "pattern": "CUSTOM_SECRET"}]}],
        schema_version=2,
        pack={"id": "custom.overrides", "version": "1"},
    )
    overrides = load_rule_files([override_path])

    composed = compose_rules([base], overrides=overrides, disabled_rule_ids=["aws-access-key-id"])

    assert "aws-access-key-id" not in {rule["id"] for rule in composed}
    replaced = next(rule for rule in composed if rule["id"] == "assigned-secret")
    assert replaced["actions"][0]["pattern"] == "CUSTOM_SECRET"
    assert replaced["rule_pack_id"] == "custom.overrides"
    with pytest.raises(RuleConfigurationError, match="Duplicate active rule id"):
        compose_rules([base, base])
    with pytest.raises(RuleConfigurationError, match="does not replace any loaded rule"):
        compose_rules([base], overrides=[dict(overrides[0], id="missing")])
    with pytest.raises(RuleConfigurationError, match="Unknown rule IDs requested for disable"):
        compose_rules([base], disabled_rule_ids=["missing"])


def test_v2_metadata_predicates_route_report_and_content_actions(tmp_path):
    path = tmp_path / "rules-v2.json"
    write_rules(
        path,
        [
            {
                "id": "interesting-config",
                "description": "route only small configuration files",
                "match": {
                    "condition": "all",
                    "predicates": [
                        {"field": "extension", "operator": "exact", "value": ".conf"},
                        {"field": "path", "operator": "contains", "value": "secrets"},
                        {"field": "size", "operator": "between", "value": [1, 4096]},
                        {"field": "filename", "operator": "endswith", "value": ".bak", "negate": True},
                    ],
                },
                "actions": [
                    {"type": "report"},
                    {
                        "type": "scan",
                        "representation": "text",
                        "pattern": r"TOKEN_[A-Z]+",
                        "flags": [],
                    },
                ],
            }
        ],
        schema_version=2,
    )
    rules = load_rule_files([path])
    engine = RuleEngine(rules)

    route = engine.route(
        {
            "share": "Public",
            "directory": "secrets",
            "path": r"secrets\application.conf",
            "filename": "application.conf",
            "extension": ".CONF",
            "size": 512,
            "mtime": 100,
        }
    )
    rejected = engine.route(
        {
            "share": "Public",
            "directory": "ordinary",
            "path": r"ordinary\application.conf.bak",
            "filename": "application.conf.bak",
            "extension": ".conf.bak",
            "size": 512,
            "mtime": 100,
        }
    )

    assert route.matched_rule_ids == ("rule:interesting-config",)
    assert route.metadata_rule_ids == ("rule:interesting-config",)
    assert route.requires_content is True
    assert route.content_rules[0].pattern == r"TOKEN_[A-Z]+"
    assert rejected.matched is False


def test_v2_content_rule_is_applied_only_to_its_metadata_route(tmp_path):
    rules_path = tmp_path / "rules-v2.json"
    write_rules(
        rules_path,
        [
            {
                "id": "config-token",
                "match": {
                    "predicates": [
                        {"field": "filename", "operator": "regex", "value": r"\.conf$"},
                    ]
                },
                "actions": [{"type": "scan", "representation": "text", "pattern": "SECRET_TOKEN"}],
            }
        ],
        schema_version=2,
    )
    parser = FileParser([], quiet=True, blocked_extensions=[], rules=load_rule_files([rules_path]))
    content = tmp_path / "content.txt"
    content.write_text("SECRET_TOKEN", encoding="utf-8")
    matching_route = parser.route_rules(
        {"filename": "application.conf", "path": "application.conf", "extension": ".conf", "size": 12}
    )
    unmatched_route = parser.route_rules(
        {"filename": "notes.txt", "path": "notes.txt", "extension": ".txt", "size": 12}
    )

    assert [finding.value for finding in parser.parse_file(content, rule_route=matching_route).findings] == [
        "SECRET_TOKEN"
    ]
    assert parser.parse_file(content, rule_route=unmatched_route).findings == ()


def test_v2_any_condition_routes_when_one_predicate_matches(tmp_path):
    rules_path = tmp_path / "rules-v2.json"
    write_rules(
        rules_path,
        [
            {
                "id": "finance-or-readme",
                "match": {
                    "condition": "any",
                    "predicates": [
                        {"field": "share", "operator": "exact", "value": "Finance"},
                        {"field": "filename", "operator": "startswith", "value": "README"},
                    ],
                },
                "actions": [{"type": "report"}],
            }
        ],
        schema_version=2,
    )
    engine = RuleEngine(load_rule_files([rules_path]))

    assert engine.route({"share": "Public", "filename": "readme.txt"}).matched is True
    assert engine.route({"share": "Public", "filename": "notes.txt"}).matched is False


def test_content_predicate_group_supports_all_string_operators_and_negation(tmp_path):
    rules_path = tmp_path / "content-predicates.json"
    write_rules(
        rules_path,
        [
            {
                "id": "grouped-content",
                "actions": [
                    {
                        "type": "scan",
                        "representation": "text",
                        "condition": "all",
                        "predicates": [
                            {"operator": "contains", "value": "alphasecret"},
                            {"operator": "startswith", "value": "HEADER", "case_sensitive": True},
                            {"operator": "endswith", "value": "trailer"},
                            {"operator": "regex", "value": "AlphaSecret", "flags": []},
                            {"operator": "contains", "value": "FORBIDDEN", "negate": True},
                        ],
                    }
                ],
            }
        ],
        schema_version=2,
        pack={"id": "example.content", "version": "1"},
    )
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("HEADER AlphaSecret AlphaSecret\nTRAILER", encoding="utf-8")
    parser = FileParser([], quiet=True, blocked_extensions=[], rules=load_rule_files([rules_path]))
    route = parser.route_rules({"filename": candidate.name, "path": str(candidate), "size": candidate.stat().st_size})

    result = parser.parse_file(candidate, rule_route=route)

    assert result.error is None
    assert [finding.value for finding in result.findings] == [
        "AlphaSecret",
        "AlphaSecret",
        "HEADER",
        "TRAILER",
        "AlphaSecret",
        "AlphaSecret",
        "not contains:FORBIDDEN",
    ]
    assert {finding.rule_id for finding in result.findings} == {"rule:grouped-content"}
    assert {finding.rule_pack_id for finding in result.findings} == {"example.content"}
    assert result.findings[-1].start == result.findings[-1].end == 0
    assert "satisfied by absence" in result.findings[-1].context


def test_content_predicate_group_any_emits_only_satisfied_predicate_evidence(tmp_path):
    rules_path = tmp_path / "content-any.json"
    write_rules(
        rules_path,
        [
            {
                "id": "any-content",
                "actions": [
                    {
                        "type": "scan",
                        "condition": "any",
                        "predicates": [
                            {"operator": "exact", "value": "does not match", "case_sensitive": True},
                            {"operator": "contains", "value": "TOKEN"},
                        ],
                    }
                ],
            }
        ],
        schema_version=2,
    )
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("prefix token suffix", encoding="utf-8")
    parser = FileParser([], quiet=True, blocked_extensions=[], rules=load_rule_files([rules_path]))

    result = parser.parse_file(candidate, rule_route=parser.route_rules({}))

    assert [(finding.value, finding.start, finding.end) for finding in result.findings] == [("token", 7, 12)]


@pytest.mark.parametrize(
    ("action", "message"),
    [
        ({"type": "scan", "condition": "all", "predicates": []}, "non-empty predicates array"),
        (
            {
                "type": "scan",
                "pattern": "one",
                "predicates": [{"operator": "contains", "value": "two"}],
            },
            "cannot combine pattern/flags",
        ),
        (
            {
                "type": "scan",
                "condition": "neither",
                "predicates": [{"operator": "contains", "value": "value"}],
            },
            'condition must be "all" or "any"',
        ),
        (
            {
                "type": "scan",
                "predicates": [{"operator": "contains", "value": "value", "flags": ["ascii"]}],
            },
            "only supports flags with the regex operator",
        ),
        (
            {
                "type": "scan",
                "predicates": [{"operator": "regex", "value": "["}],
            },
            "invalid regex",
        ),
    ],
)
def test_invalid_content_predicate_groups_fail_before_scan(tmp_path, action, message):
    path = tmp_path / "bad-content-rule.json"
    write_rules(path, [{"id": "bad-content", "actions": [action]}], schema_version=2)

    with pytest.raises(RuleConfigurationError, match=message):
        load_rule_files([path])


@pytest.mark.parametrize(
    ("rule", "message"),
    [
        (
            {
                "id": "bad",
                "match": {},
                "actions": [{"type": "scan", "representation": "embedding", "pattern": "x"}],
            },
            "unsupported representation",
        ),
        (
            {
                "id": "bad",
                "match": {
                    "condition": "all",
                    "predicates": [{"field": "size", "operator": "between", "value": [10, 1]}],
                },
                "actions": [{"type": "report"}],
            },
            "ordered two-number",
        ),
        (
            {"id": "bad", "match": {"condition": "any", "predicates": []}, "actions": [{"type": "report"}]},
            'condition "any" requires predicates',
        ),
    ],
)
def test_v2_invalid_routing_configuration_fails_before_scan(tmp_path, rule, message):
    path = tmp_path / "bad-v2.json"
    write_rules(path, [rule], schema_version=2)

    with pytest.raises(RuleConfigurationError, match=message):
        load_rule_files([path])


def test_extended_fields_require_an_explicit_v2_schema(tmp_path):
    path = tmp_path / "implicit-v1.json"
    write_rules(path, [{"id": "metadata", "actions": [{"type": "report"}]}])

    with pytest.raises(RuleConfigurationError, match="schema_version is not 2"):
        load_rule_files([path])


@pytest.mark.parametrize(
    ("pack", "message"),
    [
        ({"id": "missing-version"}, "pack requires: version"),
        ({"id": "pack", "version": "1", "extra": True}, "pack has unsupported fields"),
        ({"id": "", "version": "1"}, "pack id must be a non-empty string"),
    ],
)
def test_invalid_v2_pack_metadata_fails_before_scan(tmp_path, pack, message):
    path = tmp_path / "bad-pack.json"
    write_rules(
        path,
        [{"id": "metadata", "actions": [{"type": "report"}]}],
        schema_version=2,
        pack=pack,
    )

    with pytest.raises(RuleConfigurationError, match=message):
        load_rule_files([path])


def test_metadata_only_rule_routes_without_content_analysis_end_to_end(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    selected = scope / "selected.conf"
    selected.write_text("content is irrelevant to this rule", encoding="utf-8")
    ignored = scope / "ordinary.txt"
    ignored.write_text("also irrelevant", encoding="utf-8")
    rules_path = tmp_path / "rules-v2.json"
    state_path = tmp_path / "metadata.sqlite3"
    write_rules(
        rules_path,
        [
            {
                "id": "configuration-file",
                "match": {
                    "predicates": [
                        {"field": "extension", "operator": "exact", "value": ".conf"},
                    ]
                },
                "actions": [{"type": "report"}],
            }
        ],
        schema_version=2,
    )

    completed = run_rule_scan(scope, rules_path, state_path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    objects = database_rows(
        state_path,
        "SELECT path, status, reason FROM objects WHERE kind='file' ORDER BY path",
    )
    assert [(row["path"], row["status"]) for row in objects] == [
        (str(ignored), "skipped"),
        (str(selected), "processed"),
    ]
    assert objects[0]["reason"] == "no active rule matched file metadata"
    findings = database_rows(
        state_path,
        f"SELECT f.rule_id,f.value,{context_sql(SCHEMA_VERSION)} AS context "
        f"FROM findings f {context_join(SCHEMA_VERSION)}",
    )
    assert [(row["rule_id"], row["value"]) for row in findings] == [
        ("rule:configuration-file", str(selected)),
    ]
    assert "representation=metadata" in findings[0]["context"]


def test_content_rule_is_extracted_only_for_matching_metadata_route_end_to_end(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    selected = scope / "application.conf"
    selected.write_text("ROUTED_SECRET=one\nROUTED_SECRET=two\n", encoding="utf-8")
    ignored = scope / "notes.txt"
    ignored.write_text("ROUTED_SECRET=must-not-be-reported\n", encoding="utf-8")
    rules_path = tmp_path / "rules-v2.json"
    state_path = tmp_path / "content.sqlite3"
    write_rules(
        rules_path,
        [
            {
                "id": "configuration-secret",
                "match": {
                    "predicates": [
                        {"field": "extension", "operator": "exact", "value": ".conf"},
                    ]
                },
                "actions": [
                    {
                        "type": "scan",
                        "representation": "text",
                        "pattern": r"ROUTED_SECRET=[a-z-]+",
                        "flags": [],
                    }
                ],
            }
        ],
        schema_version=2,
        pack={"id": "integration.secrets", "version": "1.2.3"},
    )

    completed = run_rule_scan(scope, rules_path, state_path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    objects = database_rows(
        state_path,
        "SELECT path, status, reason FROM objects WHERE kind='file' ORDER BY path",
    )
    assert [(row["path"], row["status"]) for row in objects] == [
        (str(selected), "processed"),
        (str(ignored), "skipped"),
    ]
    assert objects[1]["reason"] == "no active rule matched file metadata"
    findings = database_rows(
        state_path,
        """
        SELECT rule_id, representation, rule_source, rule_schema_version,
               rule_pack_id, rule_pack_version, value, context
        FROM findings ORDER BY match_start
        """,
    )
    assert [(row["rule_id"], row["value"]) for row in findings] == [
        ("rule:configuration-secret", "ROUTED_SECRET=one"),
        ("rule:configuration-secret", "ROUTED_SECRET=two"),
    ]
    assert all("must-not-be-reported" not in row["context"] for row in findings)
    assert {row["representation"] for row in findings} == {"text"}
    assert {row["rule_source"] for row in findings} == {str(rules_path.resolve())}
    assert {row["rule_schema_version"] for row in findings} == {2}
    assert {row["rule_pack_id"] for row in findings} == {"integration.secrets"}
    assert {row["rule_pack_version"] for row in findings} == {"1.2.3"}


def test_builtin_pack_provenance_reaches_human_and_json_output_end_to_end(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    secret_file = scope / ".env"
    secret_file.write_text("password=UnmaskedBuiltInFixture!\n", encoding="utf-8")
    editor_session = scope / "Auto Save Session.sublime_session"
    editor_session.write_text(
        '{"password":"UnmaskedEditorSessionFixture!"}\n',
        encoding="utf-8",
    )
    state_path = tmp_path / "builtin.sqlite3"
    json_path = tmp_path / "builtin.json"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "man_spider.manspider",
            str(scope),
            "--yes",
            "--builtin-rules",
            "--state-file",
            str(state_path),
            "--json-file",
            str(json_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "UnmaskedBuiltInFixture!" in completed.stdout
    assert "UnmaskedEditorSessionFixture!" in completed.stdout
    assert "manspider.default@2.7.0" in completed.stdout
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert {finding["rule"] for finding in report["findings"]} == {
        "rule:assigned-secret",
        "rule:credential-assignment-candidate",
        "rule:credential-keyword-candidate",
        "rule:editor-session-artifact",
        "rule:editor-session-text-secret",
        "rule:sensitive-configuration-file",
    }
    assert {finding["representation"] for finding in report["findings"]} == {"metadata", "text"}
    classifications = {
        finding["rule"]: (
            finding["severity"],
            finding["confidence"],
            finding["category"],
            tuple(finding["tags"]),
        )
        for finding in report["findings"]
    }
    assert classifications["rule:assigned-secret"] == (
        "high",
        "medium",
        "credential.assigned-secret",
        ("configuration", "source-code"),
    )
    assert {finding["rule_provenance"]["source"] for finding in report["findings"]} == {"builtin:manspider.default"}
    assert {finding["rule_provenance"]["schema_version"] for finding in report["findings"]} == {3}
    assert {
        (finding["rule_provenance"]["pack"]["id"], finding["rule_provenance"]["pack"]["version"])
        for finding in report["findings"]
    } == {("manspider.default", "2.7.0")}
