"""Regressions for real configuration syntax and detector confidence boundaries."""

from pathlib import PurePosixPath

import pytest

from man_spider.lib.parser import FileParser
from man_spider.rules import load_builtin_rules


PARSER = FileParser([], quiet=True, blocked_extensions=[], rules=load_builtin_rules())


def matches(rule_id: str, content: str) -> list[str]:
    candidate = PurePosixPath("settings/app.xml" if rule_id == "xml-password-element" else "settings/app.json")
    route = PARSER.route_rules(
        {
            "share": "Fixtures",
            "directory": str(candidate.parent),
            "path": str(candidate),
            "filename": candidate.name,
            "extension": "".join(candidate.suffixes).lower(),
            "size": len(content.encode("utf-8")),
            "mtime": 0,
        }
    )
    assert f"rule:{rule_id}" in route.matched_rule_ids
    return [match.group(0) for rule, match in PARSER.match(content, route) if rule.rule_id == f"rule:{rule_id}"]


@pytest.mark.parametrize(
    ("rule_id", "content"),
    [
        ("assigned-secret", '{"password":"UnmaskedProductionPassword!"}'),
        ("assigned-secret", '{"password":\n  "UnmaskedProductionPassword!"}'),
        ("assigned-secret", '{"db_password": "UnmaskedProductionPassword!"}'),
        ("assigned-secret", "export DATABASE_PASSWORD=UnmaskedProductionPassword!"),
        ("assigned-secret", "- client_secret: 'Unmasked production secret'"),
        ("assigned-secret", "passphrase = 'a memorable phrase with punctuation;#!'"),
        ("assigned-secret", '{"api_key":"nullActuallyARealSecret"}'),
        ("aws-access-key-id", '"AccessKeyId": "ASIAABCDEFGHIJKLMNOP"'),
        ("aws-access-key-id", '"AccessKeyId": "AKIAABCDEFGHIJKLMNOP"'),
        ("aws-secret-access-key", '{"SecretAccessKey":"' + "A" * 40 + '"}'),
        ("aws-secret-access-key", '{"SecretAccessKey":\n  "' + "A" * 40 + '"}'),
        ("aws-secret-access-key", "'aws_secret_access_key': '" + "A" * 40 + "'"),
        ("aws-session-token", '{"SessionToken":"' + "A" * 120 + '=="}'),
        ("aws-session-token", "'AWS_SESSION_TOKEN': '" + "A" * 120 + "'"),
        # Ansible's documented 1.2 header has an optional fourth vault-ID field.
        ("ansible-vault-payload", "$ANSIBLE_VAULT;1.2;AES256;production\n0123456789\n"),
        ("ansible-vault-payload", "secret: !vault |\r\n  $ANSIBLE_VAULT;1.2;AES256;dev\r\n  0123456789"),
        ("ansible-vault-payload", "$ANSIBLE_VAULT;1.1;AES256\r\n0123456789\r\n"),
        ("http-basic-authorization", '{"Authorization": "Basic YWxpY2U6c2VjcmV0"}'),
        ("http-basic-authorization", '{"Authorization":\n  "Basic YWxpY2U6c2VjcmV0"}'),
        ("http-basic-authorization", "'Proxy-Authorization': 'Basic YWxpY2U6c2VjcmV0'"),
        ("http-bearer-authorization", '{"Authorization": "Bearer UnmaskedBearerToken-0123456789"}'),
        ("http-bearer-authorization", '{"Authorization":\n  "Bearer UnmaskedBearerToken-0123456789"}'),
        ("http-bearer-authorization", "'Authorization': 'Bearer UnmaskedBearerToken-0123456789'"),
        ("database-credential-uri", "redis://:UnmaskedRedisPassword!@cache.example.test:6379/0"),
        ("database-credential-uri", "rediss://:UnmaskedRedisPassword!@[2001:db8::1]:6379/0"),
        ("database-credential-uri", "postgresql+psycopg://alice:UnmaskedDbPassword!@db.example.test/app"),
        ("database-credential-uri", "mssql+pyodbc://alice:UnmaskedDbPassword!@db.example.test/app"),
        ("generic-connection-string-password", '{"connection_string":{"password":"UnmaskedDbPassword!"}}'),
        ("xml-password-element", '<clientSecret encoding="plain">UnmaskedXmlSecret!</clientSecret>'),
        ("xml-password-element", "<cfg:password>UnmaskedXmlPassword!</cfg:password>"),
        ("xml-password-element", "<password><![CDATA[UnmaskedXmlPassword!<&>]]></password>"),
        ("xml-password-element", "<password>\r\n  UnmaskedXmlPassword!\r\n</password>"),
    ],
)
def test_existing_detectors_cover_configuration_syntax(rule_id, content):
    found = matches(rule_id, content)

    assert found
    assert all(value in content for value in found)


@pytest.mark.parametrize(
    ("rule_id", "content"),
    [
        ("assigned-secret", '{"password": "changeme"}'),
        ("assigned-secret", '{"password":\n  "changeme"}'),
        ("assigned-secret", '{"password":\n  "${DB_PASSWORD}"}'),
        ("assigned-secret", '{"password": "none", "unrelated": "real text"}'),
        ("assigned-secret", '{"password": null}'),
        ("assigned-secret", '{"client_secret": "${CLIENT_SECRET}"}'),
        ("assigned-secret", 'client_secret = "{{ vault.secret }}"'),
        ("assigned-secret", 'client_secret = "$CLIENT_SECRET"'),
        ("assigned-secret", "password =    changeme # replace before deployment"),
        ("assigned-secret", 'notpassword = "ordinary description"'),
        ("assigned-secret", "password: \n unrelatedSetting: ordinary value"),
        ("aws-access-key-id", "AKIAABCDEFGHIJKL"),
        ("aws-access-key-id", "AKIAABCDEFGHIJKLMNOPQ"),
        ("aws-access-key-id", "beforeAKIAABCDEFGHIJKLMNOPafter"),
        ("aws-access-key-id", '"UserId": "AIDAABCDEFGHIJKLMNOP"'),
        ("aws-access-key-id", '"RoleId": "AROAABCDEFGHIJKLMNOP"'),
        ("aws-access-key-id", '"GroupId": "AGPAABCDEFGHIJKLMNOP"'),
        ("aws-secret-access-key", '{"SecretAccessKey":"' + "A" * 39 + '"}'),
        ("aws-secret-access-key", '{"SecretAccessKey":"' + "A" * 41 + '"}'),
        ("aws-session-token", '{"SessionToken":"${AWS_SESSION_TOKEN}"}'),
        ("ansible-vault-payload", "# See $ANSIBLE_VAULT;1.2;AES256;dev for the format"),
        ("ansible-vault-payload", "$ANSIBLE_VAULT;1.2;AES256;dev;unexpected-field"),
        ("http-basic-authorization", '{"Authorization": "Basic ${BASIC_AUTH}"}'),
        ("http-bearer-authorization", '{"Authorization": "Bearer ${ACCESS_TOKEN}"}'),
        ("database-credential-uri", "redis://cache.example.test:6379/0"),
        ("database-credential-uri", "redis://alice:@cache.example.test:6379/0"),
        ("database-credential-uri", "https://alice:UnmaskedPassword!@web.example.test/"),
        ("generic-connection-string-password", '{"connection_string":{"password":"${DB_PASSWORD}"}}'),
        ("generic-connection-string-password", '{"connection_string":{"password":"null"}}'),
        ("xml-password-element", "<password>ordinary value</clientSecret>"),
        ("xml-password-element", "<a:password>ordinary value</b:password>"),
        ("xml-password-element", "<password>${DB_PASSWORD}</password>"),
        ("xml-password-element", "<password><![CDATA[${DB_PASSWORD}]]></password>"),
        ("xml-password-element", '<password value="not element text" />'),
    ],
)
def test_existing_detectors_reject_placeholders_and_false_credentials(rule_id, content):
    assert matches(rule_id, content) == []
