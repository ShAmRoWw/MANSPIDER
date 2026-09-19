"""Synthetic Kubernetes JSON Secret specimens for native inspector integration."""

import base64
import json

RULE_ID = "kubernetes-secret-json"


def _encoded(value):
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


STRUCTURED_INSPECTOR_CASES = (
    (
        "secrets/application.json",
        json.dumps({"apiVersion": "v1", "kind": "Secret", "data": {"password": _encoded("KubernetesJsonFixture!")}}),
        RULE_ID,
    ),
    (
        "backups/application.json.bak",
        json.dumps({"kind": "Secret", "stringData": {"password": "PlainKubernetesFixture!"}}),
        RULE_ID,
    ),
    (
        "secrets/list.json",
        json.dumps(
            {
                "kind": "List",
                "items": [
                    {"kind": "ConfigMap", "data": {"password": "PublicFixture"}},
                    {"kind": "Secret", "stringData": {"token": "ListKubernetesFixture!"}},
                ],
            }
        ),
        RULE_ID,
    ),
    (
        "secrets/typed-list.json",
        json.dumps({"kind": "SecretList", "items": [{"data": {"password": _encoded("TypedListFixture!")}}]}),
        RULE_ID,
    ),
    ("secrets/array.json", json.dumps([{"kind": "Secret", "stringData": {"password": "ArrayFixture!"}}]), RULE_ID),
    (
        "secrets/wrapped.json.old",
        json.dumps({"kind": "Secret", "data": {"password": "U2VjcmV0\nRml4dHVyZSE="}}),
        RULE_ID,
    ),
    (
        "secrets/hash.json",
        json.dumps(
            {"kind": "Secret", "data": {"password": _encoded("$argon2id$v=19$m=65536,t=2,p=1$c2FsdA$Rml4dHVyZUhBU0g")}}
        ),
        RULE_ID,
    ),
    (
        "secrets/binary.json",
        json.dumps(
            {"kind": "Secret", "data": {"key": base64.b64encode(b"\xff\xfe\x00BinaryFixture").decode("ascii")}}
        ),
        RULE_ID,
    ),
    ("secrets/escaped.json", '{"ki\\u006ed":"Sec\\u0072et","stringData":{"password":"EscapedKindFixture!"}}', RULE_ID),
)

SOURCES = (
    (RULE_ID, "https://kubernetes.io/docs/concepts/configuration/secret/"),
    (RULE_ID, "https://pkg.go.dev/encoding/base64#Encoding.DecodeString"),
)
