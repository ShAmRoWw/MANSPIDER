"""Persistence of unmasked structurally extracted values through the real CLI."""

import base64
import json
import sqlite3
import subprocess
import sys

from man_spider.evidence_storage import configure_evidence_reader, context_join, context_sql
from man_spider.state import SCHEMA_VERSION

def test_builtin_structured_values_survive_cli_and_state(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    source = scope / "secret.json.bak"
    encoded = base64.b64encode(b"EncodedFixtureSecret!").decode()
    source.write_text(
        json.dumps(
            {
                "kind": "Secret",
                "apiVersion": "v1",
                "data": {"password": encoded, "binary": "AP/+/w=="},
                "stringData": {
                    "second": "UnmaskedSecondFixture!",
                    "same": "EncodedFixtureSecret!",
                    "username": "public-user",
                },
            }
        )
    )
    state = tmp_path / "scan.sqlite3"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "man_spider.manspider",
            str(scope),
            "--yes",
            "--builtin-rules",
            "--state-file",
            str(state),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    with sqlite3.connect(state) as database:
        configure_evidence_reader(database)
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert database.execute("SELECT status FROM runs").fetchone() == ("complete",)
        rows = database.execute(
            f"SELECT f.value, {context_sql(SCHEMA_VERSION)} AS context, f.rule_pack_id, f.rule_pack_version "
            f"FROM findings f {context_join(SCHEMA_VERSION)} "
            "WHERE f.representation='inspect:kubernetes-secret-json'"
        ).fetchall()
    assert {row[0] for row in rows} == {"EncodedFixtureSecret!", "AP/+/w==", "UnmaskedSecondFixture!"}
    assert len(rows) == 4
    assert all(row[2:] == ("manspider.default", "2.7.0") for row in rows)
    contexts = [json.loads(row[1]) for row in rows if row[0] == "EncodedFixtureSecret!"]
    assert {context["pointer"] for context in contexts} == {"/data/password", "/stringData/same"}
    context = next(context for context in contexts if context["pointer"] == "/data/password")
    assert context["source_value"] == encoded
    assert context["decoded_utf8"] == "EncodedFixtureSecret!"
    assert context["pointer"] == "/data/password"
