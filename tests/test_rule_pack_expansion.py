"""Positive, near-miss, and routing regressions for the 2.4 default pack."""

from pathlib import PurePosixPath

import pytest

from man_spider.lib.parser import FileParser
from man_spider.rules import load_builtin_rules
from tests.rule_pack_expansion_content_cases import CONTENT_CASES, NEGATIVE_CASES
from tests.rule_pack_expansion_metadata_cases import METADATA_CASES
from tests.rule_pack_expansion_metadata_cases import NEGATIVE_CASES as METADATA_NEGATIVE_CASES
from tests.rule_pack_expansion_pgpass_cases import CONTENT_CASES as PGPASS_CASES
from tests.rule_pack_expansion_pgpass_cases import NEGATIVE_CASES as PGPASS_NEGATIVE_CASES


PARSER = FileParser([], quiet=True, blocked_extensions=[], rules=load_builtin_rules())


def route_for(path, content=""):
    candidate = PurePosixPath(path.replace("\\", "/"))
    return PARSER.route_rules(
        {
            "share": "Fixtures",
            "directory": str(candidate.parent),
            "path": path,
            "filename": candidate.name,
            "extension": "".join(candidate.suffixes).lower(),
            "size": len(content.encode("utf-8")),
            "mtime": 0,
        }
    )


@pytest.mark.parametrize(("path", "content", "rule_id"), list(CONTENT_CASES) + PGPASS_CASES)
def test_new_content_rule_matches_unmasked_evidence(path, content, rule_id):
    route = route_for(path, content)
    assert f"rule:{rule_id}" in route.matched_rule_ids
    matches = [match for rule, match in PARSER.match(content, route) if rule.rule_id == f"rule:{rule_id}"]
    assert matches
    assert all(match.group(0) in content for match in matches)


@pytest.mark.parametrize(("path", "content", "rule_id"), list(NEGATIVE_CASES) + PGPASS_NEGATIVE_CASES)
def test_new_content_rule_rejects_its_near_misses(path, content, rule_id):
    # Other rules may legitimately report a candidate; only this detector is rejected.
    assert f"rule:{rule_id}" not in {rule.rule_id for rule, _ in PARSER.match(content, route_for(path, content))}


@pytest.mark.parametrize(("path", "rule_id"), METADATA_CASES)
def test_new_metadata_artifacts_route_on_both_path_styles(path, rule_id):
    assert f"rule:{rule_id}" in route_for(path).metadata_rule_ids


@pytest.mark.parametrize(("path", "rule_id"), METADATA_NEGATIVE_CASES)
def test_new_metadata_artifacts_reject_similar_names(path, rule_id):
    assert f"rule:{rule_id}" not in route_for(path).metadata_rule_ids


@pytest.mark.parametrize(
    "path",
    [
        "users/.aws/credentials",
        "users/.aws/config",
        "users/.kube/config",
        "users/.cargo/credentials",
        "deploy/credentials",
        "deploy/secrets",
        "deploy/password",
        "deploy/passwords",
        "deploy/logins",
        "deploy/.envrc",
        "users/.bash_history",
        "users/.zsh_history",
        "users/.mysql_history",
        "users/.psql_history",
        "users/.local/share/fish/fish_history",
        "users/.vault-token",
        "users/.pgpass",
        "users/.bash_history~",
        "users/.aws/credentials.20260905",
        "users/.kube/config.old",
        "run/secrets/kubernetes.io/serviceaccount/token",
        "run/secrets/kubernetes.io/serviceaccount/token.bak",
        "requests/production.http",
        "requests/production.rest",
        "requests/login.bru",
        "analysis/experiment.ipynb",
        "editors/Session.sublime_session",
        "editors/project.sublime-project",
        "editors/User.sublime-settings",
        "editors/project.sublime-workspace",
        "editors/project.code-workspace",
        "editors/project.katesession",
        "settings/app.json.20260905",
        "settings/app.conf~",
    ],
)
def test_extended_text_routes_reach_precise_detectors_and_real_parser(tmp_path, path):
    candidate = tmp_path / path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    content = '{"aws_access_key_id":"AKIAABCDEFGHIJKLMNOP"}\n'
    candidate.write_text(content, encoding="utf-8")
    route = route_for(path, content)
    assert "rule:aws-access-key-id" in route.matched_rule_ids
    result = PARSER.parse_file(candidate, rule_route=route)
    assert result.error is None
    assert "rule:aws-access-key-id" in {finding.rule_id for finding in result.findings}


@pytest.mark.parametrize(
    "path", ["ordinary.bin", "images/photo.png", "program/app.exe", "notes/readme", "notes/token"]
)
def test_text_gate_expansion_does_not_force_arbitrary_or_binary_reads(path):
    assert not route_for(path).content_rules


@pytest.mark.parametrize("path", [".pgpass", ".pgpass.old", ".pgpass~", "postgresql/pgpass.conf", "pgpass.conf.bak.2"])
def test_existing_database_artifact_rule_covers_postgresql_password_backups(path):
    assert "rule:database-client-credential-file" in route_for(path).metadata_rule_ids


@pytest.mark.parametrize(
    ("path", "content", "rule_id"),
    [case for case in list(CONTENT_CASES) + PGPASS_CASES if case[-1] != "erlang-cookie-value"],
)
def test_new_content_rules_retain_every_occurrence(path, content, rule_id):
    def evidence(text):
        return [
            match.group(0)
            for rule, match in PARSER.match(text, route_for(path, text))
            if rule.rule_id == f"rule:{rule_id}"
        ]

    original = evidence(content)
    assert original
    assert evidence(content + "\n" + content) == original + original


def test_expanded_shared_route_reads_source_only_once(tmp_path):
    content = b'{"password":"UnmaskedSharedSecret!","key":"AKIAABCDEFGHIJKLMNOP"}'
    reads = []

    def loader():
        reads.append(True)
        return content

    route = route_for("users/.aws/credentials", content.decode())
    result = PARSER.parse_file(tmp_path / "credentials", rule_route=route, data_loader=loader)
    assert result.error is None
    assert reads == [True]
    assert {"rule:assigned-secret", "rule:aws-access-key-id"} <= {finding.rule_id for finding in result.findings}
