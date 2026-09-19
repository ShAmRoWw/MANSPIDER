from datetime import datetime
import json

import pytest

from man_spider.cli import ConfigurationError, build_parser, format_configuration, parse_options


EXPECTED_OPTION_STRINGS = {
    "username": {"-u", "--username"},
    "password": {"-p", "--password"},
    "domain": {"-d", "--domain"},
    "loot_dir": {"-l", "--loot-dir"},
    "maxdepth": {"-m", "--maxdepth"},
    "hash": {"-H", "--hash"},
    "kerberos": {"-k", "--kerberos"},
    "aes_key": {"-aesKey", "--aes-key"},
    "dc_ip": {"-dc-ip", "--dc-ip"},
    "threads": {"-t", "--threads"},
    "max_sessions_per_host": {"--max-sessions-per-host"},
    "allow_external_dfs": {"--allow-external-dfs"},
    "filenames": {"-f", "--filenames"},
    "extensions": {"-e", "--extensions"},
    "exclude_extensions": {"--exclude-extensions"},
    "content": {"-c", "--content"},
    "sharenames": {"--sharenames"},
    "exclude_sharenames": {"--exclude-sharenames"},
    "dirnames": {"--dirnames"},
    "exclude_dirnames": {"--exclude-dirnames"},
    "quiet": {"-q", "--quiet"},
    "no_download": {"--download"},
    "max_failed_logons": {"-mfail", "--max-failed-logons"},
    "or_logic": {"-o", "--or-logic"},
    "max_filesize": {"-s", "--max-filesize"},
    "verbose": {"-v", "--verbose"},
    "wordlist": {"--wordlist"},
    "modified_after": {"--modified-after"},
    "modified_before": {"--modified-before"},
}


def test_current_cli_option_strings():
    actions = {action.dest: set(action.option_strings) for action in build_parser()._actions}
    for destination, option_strings in EXPECTED_OPTION_STRINGS.items():
        assert actions[destination] == option_strings


def test_current_scan_defaults(tmp_path):
    options = parse_options([str(tmp_path), "-f", "secret"])

    assert options.maxdepth == 15
    assert options.threads == 5
    assert options.max_sessions_per_host == 4
    assert options.allow_external_dfs is False
    assert options.no_smb_metrics is False
    assert options.smb_metrics_path == str(options.state_path).replace(".sqlite3", ".smb-metrics.json")
    assert options.no_eta is False
    assert options.no_unclassified_report is False
    assert options.unclassified_report_path == str(options.state_path).replace(".sqlite3", ".unclassified-files.jsonl")
    assert options.max_filesize == 10 * 1024 * 1024
    assert options.max_failed_logons is None
    assert options.exclude_sharenames == ["ipc$", "c$", "admin$", "print$"]
    assert options.or_logic is False
    assert options.no_download is True
    assert options.large_domain_mode == "auto"
    assert options.non_text_policy == "auto"
    assert options.large_domain is None
    assert options.json_path is None
    assert options.preflight_timeout == 10
    assert options.preflight_time_budget == 300
    assert options.no_resume_prompt is False
    assert options.state_path_explicit is False
    assert options.refresh_resume is False
    assert options.resume_strategy == "continue"


def test_matching_file_copies_are_disabled_by_default(tmp_path):
    options = parse_options([str(tmp_path), "-f", "secret"])

    assert options.no_download is True
    rendered = format_configuration(options)
    assert "download_matches: False" in rendered
    assert "metadata_size_policy: no global size limit" in rendered
    assert "max_filesize_scope: content analysis and downloaded copies only" in rendered
    assert "content_reading: enabled when required by filters or rules" in rendered


def test_download_requires_explicit_opt_in_and_loot_directory_does_not_enable_it(tmp_path):
    arguments = [str(tmp_path), "-f", "secret", "--loot-dir", str(tmp_path / "loot")]
    assert parse_options(arguments).no_download is True

    options = parse_options([*arguments, "--download"])
    assert options.no_download is False
    assert "download_matches: True" in format_configuration(options)


@pytest.mark.parametrize("legacy_option", ["-n", "--no-download"])
@pytest.mark.parametrize("download_position", [None, "before", "after"])
def test_removed_no_download_options_are_rejected(tmp_path, capsys, legacy_option, download_position):
    arguments = [legacy_option]
    if download_position == "before":
        arguments.insert(0, "--download")
    elif download_position == "after":
        arguments.append("--download")
    with pytest.raises(SystemExit) as exc:
        parse_options([str(tmp_path), "-f", "secret", *arguments])
    assert exc.value.code == 2
    assert f"unrecognized arguments: {legacy_option}" in capsys.readouterr().err


def test_download_help_explains_default_content_reading_and_metadata_size_policy():
    rendered = " ".join(build_parser().format_help().split())
    assert "--download" in rendered
    assert "--no-download" not in rendered
    assert " -n" not in rendered
    assert "matching files are copied there only with --download" in rendered
    assert "does not enable downloading" in rendered
    assert "content is still read when required by filters or rules" in rendered
    assert "metadata matches have no global size limit" in rendered


def test_dynamic_eta_is_default_and_can_be_disabled_for_diagnostics(tmp_path):
    options = parse_options([str(tmp_path), "-f", "secret", "--no-eta"])

    assert options.no_eta is True
    assert "dynamic_eta: False" in format_configuration(options)


def test_external_dfs_requires_explicit_opt_in(tmp_path):
    options = parse_options([str(tmp_path), "-f", "secret", "--allow-external-dfs"])

    assert options.allow_external_dfs is True
    assert "allow_external_dfs: True" in format_configuration(options)
    assert "--allow-external-dfs" in build_parser().format_help()


def test_unclassified_report_is_default_and_can_be_disabled(tmp_path):
    options = parse_options([str(tmp_path), "-f", "secret", "--no-unclassified-report"])

    assert options.no_unclassified_report is True
    assert options.unclassified_report_path is None
    assert "unclassified_file_report: disabled" in format_configuration(options)


def test_options_are_normalized_and_deduplicated_in_input_order(tmp_path):
    options = parse_options(
        [
            str(tmp_path),
            str(tmp_path),
            "-f",
            "secret",
            "-e",
            "TXT",
            ".Log",
            "txt",
            "--sharenames",
            "Public",
            "PUBLIC",
            "--dirnames",
            "Finance",
            "FINANCE",
            "--modified-after",
            "2026-01-01",
            "--modified-before",
            "2026-02-01",
        ]
    )

    assert options.targets == [tmp_path]
    assert options.extensions == [".txt", ".log"]
    assert options.sharenames == ["public"]
    assert options.dirnames == ["finance"]
    assert options.modified_after == datetime(2026, 1, 1)
    assert options.modified_before == datetime(2026, 2, 1)


def test_documented_empty_extension_disables_extension_include_category(tmp_path):
    options = parse_options([str(tmp_path), "-e", "", "-c", "secret"])
    assert options.extensions == []


def test_empty_exclude_sharenames_still_disables_name_defaults(tmp_path):
    options = parse_options([str(tmp_path), "-f", "secret", "--exclude-sharenames"])
    assert options.exclude_sharenames == []


def test_share_exclusions_can_be_added_and_selectively_overridden(tmp_path):
    options = parse_options(
        [
            str(tmp_path),
            "-f",
            "secret",
            "--add-exclude-sharenames",
            "BACKUP",
            "--allow-sharenames",
            "C$",
        ]
    )

    assert options.exclude_sharenames == ["ipc$", "admin$", "print$", "backup"]
    assert options.allow_sharenames == ["c$"]


def test_all_default_name_exclusions_can_be_disabled(tmp_path):
    options = parse_options(
        [str(tmp_path), "-f", "secret", "--no-default-share-exclusions", "--add-exclude-sharenames", "custom"]
    )
    assert options.exclude_sharenames == ["custom"]


def test_wordlist_is_loaded_before_regex_validation(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("# comment\nPassword\n  API[_-]?KEY  \n", encoding="utf-8")

    options = parse_options([str(tmp_path), "-f", "name", "--wordlist", str(wordlist)])
    assert options.content == ["Password", "API[_-]?KEY"]


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["-m", "0"], "--maxdepth"),
        (["-t", "0"], "--threads"),
        (["--max-sessions-per-host", "0"], "--max-sessions-per-host"),
        (["--object-retries", "-1"], "--object-retries"),
        (["--preflight-timeout", "0"], "--preflight-timeout"),
        (["--preflight-time-budget", "0"], "--preflight-time-budget"),
        (["-s", "0"], "--max-filesize"),
        (["-mfail", "0"], "--max-failed-logons"),
        (["--modified-after", "2026-02-02", "--modified-before", "2026-02-01"], "--modified-after"),
    ],
)
def test_conflicting_or_unsafe_values_fail_before_scan(tmp_path, arguments, message):
    with pytest.raises(ConfigurationError, match=message):
        parse_options([str(tmp_path), "-f", "secret", *arguments])


@pytest.mark.parametrize("option", ["-f", "-c"])
def test_invalid_regex_fails_before_scan(tmp_path, option):
    with pytest.raises(ConfigurationError, match="Invalid regex"):
        parse_options([str(tmp_path), option, "["])


def test_scan_requires_an_existing_filter_category(tmp_path):
    with pytest.raises(ConfigurationError, match="Please specify at least one"):
        parse_options([str(tmp_path)])


def test_kerberos_keeps_existing_ccache_requirement(tmp_path):
    with pytest.raises(ConfigurationError, match="KRB5CCNAME"):
        parse_options([str(tmp_path), "-f", "secret", "-k"], environ={})


def test_kerberos_normalizes_standard_file_cache_name_and_displays_it(tmp_path):
    ccache = tmp_path / "krb5cc"
    ccache.write_bytes(b"test cache")

    options = parse_options(
        ["fileserver.test.local", "-f", "secret", "-k"],
        environ={"KRB5CCNAME": f"FILE:{ccache}"},
    )

    assert options.krb5_ccache == str(ccache)
    assert f"krb5_ccache: {ccache}" in format_configuration(options)


def test_kerberos_rejects_missing_or_unsupported_cache_before_scan(tmp_path):
    with pytest.raises(ConfigurationError, match="not found"):
        parse_options(
            ["fileserver.test.local", "-f", "secret", "-k"],
            environ={"KRB5CCNAME": f"FILE:{tmp_path / 'missing'}"},
        )
    with pytest.raises(ConfigurationError, match="not supported"):
        parse_options(
            ["fileserver.test.local", "-f", "secret", "-k"],
            environ={"KRB5CCNAME": "KEYRING:persistent:1000"},
        )


def test_smb_scan_requires_explicit_credentials():
    with pytest.raises(ConfigurationError, match="--username"):
        parse_options(["fileserver.test.local", "-f", "secret"])

    with pytest.raises(ConfigurationError, match="--password"):
        parse_options(["fileserver.test.local", "-f", "secret", "-u", "runuser"])


def test_explicit_empty_password_remains_a_supported_credential():
    options = parse_options(["fileserver.test.local", "-f", "secret", "-u", "runuser", "-p", ""])
    assert options.username_provided is True
    assert options.password_provided is True
    assert options.password == ""


def test_effective_configuration_contains_full_credentials(tmp_path):
    options = parse_options(
        [
            str(tmp_path),
            "-f",
            "secret",
            "-u",
            "runuser",
            "-p",
            "FixturePassword123!",
            "-d",
            "test.local",
        ]
    )

    rendered = format_configuration(options)
    assert "username: runuser" in rendered
    assert "password: FixturePassword123!" in rendered
    assert "domain: test.local" in rendered
    assert "max_failed_logons: unlimited" in rendered
    assert "***" not in rendered


def test_state_file_and_resume_are_mutually_exclusive(tmp_path):
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args([str(tmp_path), "-f", "secret", "--state-file", "new.sqlite3", "--resume", "old.sqlite3"])
    assert exc.value.code == 2


def test_json_output_is_opt_in_and_uses_a_separate_file(tmp_path):
    state_path = tmp_path / "scan.sqlite3"
    automatic = parse_options([str(tmp_path), "-f", "secret", "--state-file", str(state_path), "--json"])
    explicit_path = tmp_path / "reports" / "scan.json"
    explicit = parse_options(
        [
            str(tmp_path),
            "-f",
            "secret",
            "--state-file",
            str(state_path),
            "--json-file",
            str(explicit_path),
        ]
    )

    assert automatic.json_path == str(tmp_path / "scan.json")
    assert explicit.json_path == str(explicit_path)


def test_json_output_never_overwrites_state_or_an_existing_new_scan_report(tmp_path):
    state_path = tmp_path / "scan.sqlite3"
    with pytest.raises(ConfigurationError, match="same path"):
        parse_options(
            [
                str(tmp_path),
                "-f",
                "secret",
                "--state-file",
                str(state_path),
                "--json-file",
                str(state_path),
            ]
        )

    existing = tmp_path / "existing.json"
    existing.write_text("preserve", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="already exists"):
        parse_options(
            [
                str(tmp_path),
                "-f",
                "secret",
                "--state-file",
                str(state_path),
                "--json-file",
                str(existing),
            ]
        )


def test_json_output_cannot_overwrite_automatic_sidecar_reports(tmp_path):
    state_path = tmp_path / "scan.sqlite3"
    for sidecar in ("scan.smb-metrics.json", "scan.unclassified-files.jsonl"):
        with pytest.raises(ConfigurationError, match="cannot overwrite the generated"):
            parse_options(
                [
                    str(tmp_path),
                    "-f",
                    "secret",
                    "--state-file",
                    str(state_path),
                    "--json-file",
                    str(tmp_path / sidecar),
                ]
            )


def test_explicit_resume_path_is_normalized_without_opening_it(tmp_path):
    resume_path = tmp_path / "scan.sqlite3"
    options = parse_options([str(tmp_path), "-f", "secret", "--resume", str(resume_path)])
    assert options.resume_mode is True
    assert options.state_path == str(resume_path)
    assert not resume_path.exists()


@pytest.mark.parametrize("option", ["--refresh-resume", "--rescan"])
def test_explicit_refresh_resume_strategy_has_documented_aliases(tmp_path, option):
    resume_path = tmp_path / "scan.sqlite3"
    options = parse_options([str(tmp_path), "-f", "secret", "--resume", str(resume_path), option])

    assert options.resume_mode is True
    assert options.refresh_resume is True
    assert options.resume_strategy == "refresh"
    assert "resume_strategy: refresh" in format_configuration(options)


def test_large_domain_and_format_policy_overrides_are_normalized(tmp_path):
    options = parse_options(
        [
            str(tmp_path),
            "-c",
            "secret",
            "--large-domain",
            "--large-domain-target-threshold",
            "50",
            "--large-domain-share-threshold",
            "200",
            "--non-text-policy",
            "skip",
            "--read-formats",
            "ZIP",
            "--skip-formats",
            "bin",
        ]
    )

    assert options.large_domain_mode == "always"
    assert options.large_domain_target_threshold == 50
    assert options.large_domain_share_threshold == 200
    assert options.non_text_policy == "skip"
    assert options.read_formats == [".zip"]
    assert options.skip_formats == [".bin"]


def test_conflicting_format_overrides_fail_before_scan(tmp_path):
    with pytest.raises(ConfigurationError, match="both --read-formats and --skip-formats"):
        parse_options([str(tmp_path), "-c", "secret", "--read-formats", "zip", "--skip-formats", ".ZIP"])


def test_legacy_rule_file_is_normalized_and_rendered(tmp_path):
    rule_file = tmp_path / "rules.json"
    rule_file.write_text(
        json.dumps({"rules": [{"id": "api-token", "pattern": r"TOKEN_[A-Z]+"}]}),
        encoding="utf-8",
    )

    options = parse_options([str(tmp_path), "--rules", str(rule_file)])
    rendered = format_configuration(options)

    assert options.rules == [
        {
            "schema_version": 1,
            "id": "api-token",
            "description": "",
            "match": {"condition": "all", "predicates": []},
            "actions": [
                {
                    "type": "scan",
                    "representation": "text",
                    "pattern": r"TOKEN_[A-Z]+",
                    "flags": ["ignorecase"],
                }
            ],
            "rule_source": str(rule_file.resolve()),
            "rule_pack_id": "legacy-json",
            "rule_pack_version": "1",
        }
    ]
    assert f"rule_files: {rule_file}" in rendered
    assert r"active_rules: api-token=>text:TOKEN_[A-Z]+" in rendered
    assert "rule_representation_plan: text=[api-token]" in rendered


def test_invalid_rule_file_fails_before_scan(tmp_path):
    rule_file = tmp_path / "bad.json"
    rule_file.write_text('{"rules": [{"id": "bad", "pattern": "["}]}', encoding="utf-8")

    with pytest.raises(ConfigurationError, match="invalid regex"):
        parse_options([str(tmp_path), "--rules", str(rule_file)])


def test_builtin_pack_can_be_enabled_and_rules_explicitly_disabled(tmp_path):
    options = parse_options([str(tmp_path), "--builtin-rules", "--disable-rules", "aws-access-key-id"])
    rendered = format_configuration(options)

    assert {rule["rule_pack_id"] for rule in options.rules} == {"manspider.default"}
    assert "aws-access-key-id" not in {rule["id"] for rule in options.rules}
    assert "builtin_rules: True" in rendered
    assert "disabled_rules: aws-access-key-id" in rendered
    assert "active_rule_packs: manspider.default@2.7.0" in rendered
    assert "active_rules: 250 enabled" in rendered
    assert (
        "rule_representation_plan: inspect:active-directory-json-secrets=1, inspect:active-directory-ldif-secrets=1, "
        "inspect:group-policy-preference-password=1, inspect:kubernetes-secret-json=1, inspect:private-key-material=3, "
        "inspect:russian-json-credential-value=1, inspect:russian-legacy-credential-value=1, metadata="
        in rendered
    )
    assert "use --verbose" in rendered


def test_verbose_configuration_expands_large_rule_pack(tmp_path):
    options = parse_options([str(tmp_path), "--builtin-rules", "--verbose"])

    rendered = format_configuration(options)

    assert "active_rules: active-directory-json-secrets[" in rendered
    assert "age-secret-identity[" in rendered
    assert "github-access-token[" in rendered
    assert "rule_representation_plan: inspect:active-directory-json-secrets=[" in rendered
    assert "inspect:kubernetes-secret-json=[" in rendered
    assert "inspect:private-key-material=[" in rendered
    assert "full definitions are persisted" not in rendered


def test_rule_override_file_must_explicitly_replace_a_loaded_id(tmp_path):
    override_file = tmp_path / "overrides.json"
    override_file.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "pack": {"id": "test.overrides", "version": "1"},
                "rules": [
                    {
                        "id": "assigned-secret",
                        "actions": [{"type": "scan", "pattern": "OVERRIDDEN_SECRET"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    options = parse_options([str(tmp_path), "--builtin-rules", "--rule-overrides", str(override_file)])
    replacement = next(rule for rule in options.rules if rule["id"] == "assigned-secret")

    assert replacement["actions"][0]["pattern"] == "OVERRIDDEN_SECRET"
    assert replacement["rule_pack_id"] == "test.overrides"
    with pytest.raises(ConfigurationError, match="does not replace any loaded rule"):
        parse_options([str(tmp_path), "-f", "secret", "--rule-overrides", str(override_file)])


def test_unknown_disabled_rule_and_implicit_pack_collision_fail(tmp_path):
    with pytest.raises(ConfigurationError, match="Unknown rule IDs requested for disable"):
        parse_options([str(tmp_path), "--builtin-rules", "--disable-rules", "missing-rule"])

    collision = tmp_path / "collision.json"
    collision.write_text(
        json.dumps({"rules": [{"id": "assigned-secret", "pattern": "collision"}]}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="use --rule-overrides"):
        parse_options([str(tmp_path), "--builtin-rules", "--rules", str(collision)])
