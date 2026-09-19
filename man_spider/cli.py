import argparse
import os
import re
from datetime import datetime
from pathlib import Path

from man_spider.filters import normalize_directory_filter
from man_spider.lib.util import bytes_to_human, human_to_int, make_targets
from man_spider.path_safety import (
    UnsafeWritePath,
    require_local_path,
    require_local_write_path,
    safe_temporary_directory,
)
from man_spider.policy import DEFAULT_LARGE_DOMAIN_SHARE_THRESHOLD, DEFAULT_LARGE_DOMAIN_TARGET_THRESHOLD
from man_spider.preflight import DEFAULT_AUTH_TIMEOUT_SECONDS, DEFAULT_PREFLIGHT_TIME_BUDGET_SECONDS
from man_spider.rules import (
    RULE_DETAIL_DISPLAY_LIMIT,
    RuleConfigurationError,
    build_rule_representation_plan,
    compose_rules,
    format_rule,
    format_rule_representation_plan,
    load_builtin_rules,
    load_rule_files,
)
from man_spider.session_paths import session_path_conflict
from man_spider.state import default_state_directory, default_state_path, resume_search_directories


DEFAULT_EXCLUDED_SHARES = ["IPC$", "C$", "ADMIN$", "PRINT$"]

EXAMPLES = """
# EXAMPLES

Example 1: Search the network for filenames that may contain creds
$ manspider 192.168.0.0/24 -f passw user admin account network login logon cred -d evilcorp -u bob -p Passw0rd

Example 2: Search for XLSX files containing "password"
$ manspider share.evilcorp.local -c password -e xlsx -d evilcorp -u bob -p Passw0rd

Example 3: Search for interesting file extensions
$ manspider share.evilcorp.local -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config -d evilcorp -u bob -p Passw0rd

Example 4: Search for finance-related files
$ manspider share.evilcorp.local --dirnames bank financ payable payment reconcil remit voucher vendor eft swift -f '[0-9]{5,}' -d evilcorp -u bob -p Passw0rd
"""


class ConfigurationError(ValueError):
    """Raised when CLI values are syntactically valid but cannot form a scan."""


class StoreWithPresence(argparse.Action):
    """Store a value and remember that the corresponding option was explicit."""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        setattr(namespace, f"{self.dest}_provided", True)


def _parse_filesize(value: str) -> int:
    try:
        return human_to_int(value)
    except ValueError as exc:
        # argparse otherwise replaces the useful syntax/overflow explanation
        # with the generic "invalid <type> value" message.
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scan for juicy data on SMB shares. Logs are stored in $HOME/.manspider; "
            "matching files are copied there only with --download. Durable scan states are created automatically under the "
            "platform user-state directory. All filters are case-insensitive."
        ),
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="+",
        type=make_targets,
        help=(
            "IPs, Hostnames, CIDR ranges, or files containing targets to spider "
            '(NOTE: local searching also supported, specify directory name or keyword "loot" '
            "to search downloaded files)"
        ),
    )
    parser.set_defaults(
        username_provided=False,
        password_provided=False,
        hash_provided=False,
        exclude_sharenames_provided=False,
    )
    parser.add_argument("-u", "--username", action=StoreWithPresence, default="", help="username for authentication")
    parser.add_argument("-p", "--password", action=StoreWithPresence, default="", help="password for authentication")
    parser.add_argument("-d", "--domain", default="", help="domain for authentication")
    parser.add_argument(
        "-l",
        "--loot-dir",
        default="",
        help="destination for --download copies; does not enable downloading (default ~/.manspider/loot/)",
    )
    state_group = parser.add_mutually_exclusive_group()
    state_group.add_argument(
        "--state-file",
        default=None,
        metavar="FILE",
        help="override the automatic SQLite scan-state path",
    )
    state_group.add_argument(
        "--resume",
        dest="resume_file",
        default=None,
        metavar="FILE",
        help="resume a specific SQLite scan state (normally selected by the interactive prompt)",
    )
    parser.add_argument(
        "--no-resume-prompt",
        action="store_true",
        help="start a new automatic scan state without offering unfinished scans",
    )
    parser.add_argument(
        "-y", "--yes", action="store_true",
        help="explicitly approve this main scan without an interactive prompt; still display the final scan review",
    )
    parser.add_argument(
        "--refresh-resume",
        "--rescan",
        dest="refresh_resume",
        action="store_true",
        help=(
            "when resuming, re-enumerate the complete directory tree to discover "
            "new or changed objects (default resume follows only unfinished work)"
        ),
    )
    json_group = parser.add_mutually_exclusive_group()
    json_group.add_argument(
        "--json",
        action="store_true",
        help="write an optional JSON report next to the SQLite state file",
    )
    json_group.add_argument(
        "--json-file",
        default=None,
        metavar="FILE",
        help="write an optional JSON report to this file",
    )
    parser.add_argument("-m", "--maxdepth", type=int, default=15, help="maximum depth to spider (default: 15)")
    parser.add_argument("-H", "--hash", action=StoreWithPresence, default="", help="NTLM hash for authentication")
    parser.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters",
    )
    parser.add_argument(
        "-aesKey",
        "--aes-key",
        action="store",
        metavar="HEX",
        help="AES key to use for Kerberos Authentication (128 or 256 bits)",
    )
    parser.add_argument(
        "-dc-ip",
        "--dc-ip",
        action="store",
        metavar="IP",
        help=(
            "IP Address of the domain controller. If omitted it will use the domain part "
            "(FQDN) specified in the target parameter"
        ),
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=5,
        help="global concurrent worker/SMB-session budget (default: 5)",
    )
    parser.add_argument(
        "--max-sessions-per-host",
        type=int,
        default=4,
        metavar="INT",
        help="maximum simultaneous SMB sessions to one host (default: 4)",
    )
    parser.add_argument(
        "--no-smb-metrics",
        action="store_true",
        help="disable passive per-host SMB telemetry and its final report",
    )
    parser.add_argument(
        "--allow-external-dfs",
        action="store_true",
        help=(
            "allow DFS referrals to other SMB servers, including authentication with scan credentials "
            "(default: skip and warn; same-server DFS keeps the existing connection)"
        ),
    )
    parser.add_argument(
        "--no-eta",
        action="store_true",
        help="disable the passive dynamic scan-time estimate (primarily for diagnostics/A-B)",
    )
    parser.add_argument(
        "--no-unclassified-report",
        action="store_true",
        help="disable the passive JSONL report of files not fully covered by active rules",
    )
    parser.add_argument(
        "--object-retries",
        type=int,
        default=1,
        metavar="INT",
        help="retries for an object that ended in error (default: 1)",
    )
    parser.add_argument(
        "--preflight-timeout",
        type=int,
        default=DEFAULT_AUTH_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=f"per-target credential preflight timeout (default: {DEFAULT_AUTH_TIMEOUT_SECONDS})",
    )
    parser.add_argument(
        "--preflight-time-budget",
        type=int,
        default=DEFAULT_PREFLIGHT_TIME_BUDGET_SECONDS,
        metavar="SECONDS",
        help=(
            "overall credential preflight budget across unavailable replacement targets "
            f"(default: {DEFAULT_PREFLIGHT_TIME_BUDGET_SECONDS})"
        ),
    )
    large_domain_group = parser.add_mutually_exclusive_group()
    large_domain_group.add_argument(
        "--large-domain-mode",
        choices=("auto", "always", "never"),
        default="auto",
        help="select large-domain policy automatically, always, or never (default: auto)",
    )
    large_domain_group.add_argument(
        "--large-domain",
        dest="large_domain_mode",
        action="store_const",
        const="always",
        help="force large-domain content policy",
    )
    large_domain_group.add_argument(
        "--no-large-domain",
        dest="large_domain_mode",
        action="store_const",
        const="never",
        help="disable automatic large-domain classification",
    )
    parser.add_argument(
        "--large-domain-target-threshold",
        type=int,
        default=DEFAULT_LARGE_DOMAIN_TARGET_THRESHOLD,
        metavar="INT",
        help=f"SMB target threshold for auto policy (default: {DEFAULT_LARGE_DOMAIN_TARGET_THRESHOLD})",
    )
    parser.add_argument(
        "--large-domain-share-threshold",
        type=int,
        default=DEFAULT_LARGE_DOMAIN_SHARE_THRESHOLD,
        metavar="INT",
        help=f"estimated share threshold for auto policy (default: {DEFAULT_LARGE_DOMAIN_SHARE_THRESHOLD})",
    )
    parser.add_argument(
        "--non-text-policy",
        choices=("auto", "read", "skip"),
        default="auto",
        help="content policy for archives, images, and binary formats (default: auto)",
    )
    parser.add_argument(
        "--read-formats",
        nargs="+",
        default=[],
        metavar="EXT",
        help="explicitly enable content analysis for these extensions",
    )
    parser.add_argument(
        "--skip-formats",
        nargs="+",
        default=[],
        metavar="EXT",
        help="disable content analysis for these extensions while retaining metadata matching",
    )
    parser.add_argument(
        "-f",
        "--filenames",
        nargs="+",
        default=[],
        help="filter filenames using regex (space-separated)",
        metavar="REGEX",
    )
    parser.add_argument(
        "-e",
        "--extensions",
        nargs="+",
        default=[],
        help="only show filenames with these extensions (space-separated, e.g. `docx xlsx` for only word & excel docs)",
        metavar="EXT",
    )
    parser.add_argument(
        "--exclude-extensions", nargs="+", default=[], help="ignore files with these extensions", metavar="EXT"
    )
    parser.add_argument(
        "-c",
        "--content",
        nargs="+",
        default=[],
        help="search for file content using regex (multiple supported)",
        metavar="REGEX",
    )
    parser.add_argument(
        "--sharenames",
        nargs="+",
        default=[],
        help="only search shares with these names (multiple supported)",
        metavar="SHARE",
    )
    parser.add_argument(
        "--exclude-sharenames",
        nargs="*",
        action=StoreWithPresence,
        default=list(DEFAULT_EXCLUDED_SHARES),
        help="don't search shares with these names (multiple supported)",
        metavar="SHARE",
    )
    parser.add_argument(
        "--add-exclude-sharenames",
        nargs="+",
        default=[],
        help="add names to the effective default/legacy share exclusions",
        metavar="SHARE",
    )
    parser.add_argument(
        "--allow-sharenames",
        nargs="+",
        default=[],
        help="remove individual names from the effective name-based share exclusions",
        metavar="SHARE",
    )
    parser.add_argument(
        "--no-default-share-exclusions",
        action="store_true",
        help="disable all default name-based share exclusions (type exclusions still apply)",
    )
    parser.add_argument(
        "--dirnames",
        nargs="+",
        default=[],
        help="only search directories containing these strings (multiple supported)",
        metavar="DIR",
    )
    parser.add_argument(
        "--exclude-dirnames",
        nargs="+",
        default=[],
        help="don't search directories containing these strings (multiple supported)",
        metavar="DIR",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="omit surrounding match context; keep full matched values")
    parser.add_argument(
        "--download",
        dest="no_download",
        action="store_false",
        default=True,
        help=(
            "save local copies of matching files within --max-filesize (disabled by default); "
            "content is still read when required by filters or rules"
        ),
    )
    parser.add_argument("-mfail", "--max-failed-logons", type=int, help="limit failed logons", metavar="INT")
    parser.add_argument(
        "-o",
        "--or-logic",
        action="store_true",
        help="use OR logic instead of AND (files match if filename OR extension OR content match)",
    )
    parser.add_argument(
        "-s",
        "--max-filesize",
        type=_parse_filesize,
        default=human_to_int("10M"),
        help=(
            'maximum size for content analysis and --download copies, e.g. "500K" or ".5M" '
            "(default: 10M); filename/extension and other metadata matches have no global size limit"
        ),
        metavar="SIZE",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="show debugging messages")
    parser.add_argument(
        "--wordlist",
        default=None,
        metavar="FILE",
        help="path to a wordlist file (one word per line) to search for in file contents",
    )
    parser.add_argument(
        "--rules",
        dest="rule_files",
        nargs="+",
        action="extend",
        default=[],
        metavar="JSON",
        help="load legacy regex or versioned metadata/content rules from JSON",
    )
    parser.add_argument(
        "--builtin-rules",
        action="store_true",
        help="enable the versioned MANSPIDER default rule pack",
    )
    parser.add_argument(
        "--rule-overrides",
        dest="rule_override_files",
        nargs="+",
        action="extend",
        default=[],
        metavar="JSON",
        help="explicitly replace loaded rules by ID using these rule files",
    )
    parser.add_argument(
        "--disable-rules",
        nargs="+",
        default=[],
        metavar="ID",
        help="disable loaded rules by exact ID",
    )
    parser.add_argument(
        "--modified-after",
        type=str,
        metavar="DATE",
        help="only show files modified after this date (format: YYYY-MM-DD)",
    )
    parser.add_argument(
        "--modified-before",
        type=str,
        metavar="DATE",
        help="only show files modified before this date (format: YYYY-MM-DD)",
    )
    return parser


def _load_content_wordlist(filepath: str) -> list[str]:
    wordlist_path = Path(filepath)
    if not wordlist_path.is_file():
        raise ConfigurationError(f"Wordlist file not found: {filepath}")

    try:
        with wordlist_path.open(encoding="utf-8") as wordlist:
            words = [line.strip() for line in wordlist if line.strip() and not line.lstrip().startswith("#")]
    except OSError as exc:
        raise ConfigurationError(f"Unable to read wordlist {filepath}: {exc}") from exc
    except UnicodeError as exc:
        raise ConfigurationError(f"Wordlist must be valid UTF-8: {filepath}: {exc}") from exc

    if not words:
        raise ConfigurationError(f"Wordlist file is empty: {filepath}")
    return words


def _parse_date(value: str | None, option: str) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise ConfigurationError(f"Invalid date format for {option}. Use YYYY-MM-DD") from exc


def _normalize_extension(extension: str) -> str:
    if extension and not extension.startswith("."):
        extension = f".{extension}"
    return extension.lower()


def _deduplicate(values):
    return list(dict.fromkeys(values))


def _kerberos_cache_path(environ: dict[str, str]) -> str:
    value = str(environ.get("KRB5CCNAME", ""))
    if not value:
        raise ConfigurationError("KRB5CCNAME is not set in the environment")
    if value.upper().startswith("FILE:"):
        value = value[5:]
    elif ":" in value:
        cache_type = value.split(":", 1)[0]
        raise ConfigurationError(
            f'KRB5CCNAME cache type "{cache_type}" is not supported by Impacket; use a FILE cache'
        )
    path = Path(value).expanduser()
    if not path.is_file():
        raise ConfigurationError(f"Kerberos credential cache not found: {path}")
    return str(path)


def normalize_options(
    options,
    environ: dict[str, str] | None = None,
    *,
    defer_existing_json_check: bool = False,
):
    environ = os.environ if environ is None else environ

    if options.wordlist:
        options.content = list(options.content) + _load_content_wordlist(options.wordlist)
    options.content = _deduplicate(options.content)
    options.rule_files = _deduplicate(str(Path(value).expanduser()) for value in options.rule_files)
    options.rule_override_files = _deduplicate(str(Path(value).expanduser()) for value in options.rule_override_files)
    options.disable_rules = _deduplicate(options.disable_rules)
    try:
        rule_sets = []
        if options.builtin_rules:
            rule_sets.append(load_builtin_rules())
        if options.rule_files:
            rule_sets.append(load_rule_files(options.rule_files))
        override_rules = load_rule_files(options.rule_override_files)
        options.rules = compose_rules(
            rule_sets,
            overrides=override_rules,
            disabled_rule_ids=options.disable_rules,
        )
    except RuleConfigurationError as exc:
        raise ConfigurationError(str(exc)) from exc

    options.modified_after = _parse_date(options.modified_after, "--modified-after")
    options.modified_before = _parse_date(options.modified_before, "--modified-before")
    normalized_extensions = _deduplicate(_normalize_extension(value) for value in options.extensions)
    # The documented `-e '' -c ...` invocation means no extension include
    # category, allowing content analysis across extensions.
    options.extensions = [] if "" in normalized_extensions else normalized_extensions
    options.exclude_extensions = [
        value for value in _deduplicate(_normalize_extension(value) for value in options.exclude_extensions) if value
    ]
    options.read_formats = [
        value for value in _deduplicate(_normalize_extension(value) for value in options.read_formats) if value
    ]
    options.skip_formats = [
        value for value in _deduplicate(_normalize_extension(value) for value in options.skip_formats) if value
    ]
    options.sharenames = _deduplicate(value.lower() for value in options.sharenames)
    if options.no_default_share_exclusions:
        effective_share_exclusions = []
    elif options.exclude_sharenames_provided:
        # Preserve the legacy option's replacement semantics.
        effective_share_exclusions = list(options.exclude_sharenames)
    else:
        effective_share_exclusions = list(DEFAULT_EXCLUDED_SHARES)
    effective_share_exclusions.extend(options.add_exclude_sharenames)
    allowed_shares = {value.lower() for value in options.allow_sharenames}
    options.exclude_sharenames = _deduplicate(
        value.lower() for value in effective_share_exclusions if value.lower() not in allowed_shares
    )
    options.add_exclude_sharenames = _deduplicate(value.lower() for value in options.add_exclude_sharenames)
    options.allow_sharenames = _deduplicate(value.lower() for value in options.allow_sharenames)
    options.dirnames = _deduplicate(normalize_directory_filter(value) for value in options.dirnames)
    options.exclude_dirnames = _deduplicate(normalize_directory_filter(value) for value in options.exclude_dirnames)

    flattened_targets = (target for group in options.targets for target in group)
    options.targets = _deduplicate(flattened_targets)
    options.large_domain = None
    options.scope_estimate = None
    options.blocked_content_extensions = None
    options.krb5_ccache = _kerberos_cache_path(environ) if options.kerberos else None

    options.state_path_explicit = options.resume_file is not None or options.state_file is not None
    options.state_directory = str(default_state_directory(environ))
    options.resume_search_directories = tuple(str(path) for path in resume_search_directories(environ))
    options.resume_mode = options.resume_file is not None
    options.resume_strategy = "refresh" if options.refresh_resume else "continue"
    if options.resume_mode:
        options.state_path = str(Path(options.resume_file).expanduser())
    elif options.state_file:
        options.state_path = str(Path(options.state_file).expanduser())
    else:
        options.state_path = str(default_state_path(options.state_directory))

    if options.json_file:
        options.json_path = str(Path(options.json_file).expanduser())
    elif options.json:
        options.json_path = str(Path(options.state_path).with_suffix(".json"))
    else:
        options.json_path = None
    options.smb_metrics_path = (
        None if options.no_smb_metrics else str(Path(options.state_path).with_suffix(".smb-metrics.json"))
    )
    options.unclassified_report_path = (
        None
        if options.no_unclassified_report
        else str(Path(options.state_path).with_suffix(".unclassified-files.jsonl"))
    )

    validate_options(
        options,
        environ=environ,
        defer_existing_json_check=defer_existing_json_check,
    )
    return options


def validate_options(
    options,
    environ: dict[str, str] | None = None,
    *,
    defer_existing_json_check: bool = False,
) -> None:
    environ = os.environ if environ is None else environ

    if not (options.filenames or options.extensions or options.exclude_extensions or options.content or options.rules):
        raise ConfigurationError(
            "Please specify at least one of --filenames, --content, --rules, --extensions, or --exclude-extensions"
        )
    if options.maxdepth <= 0:
        raise ConfigurationError("--maxdepth must be greater than zero")
    if options.threads <= 0:
        raise ConfigurationError("--threads must be greater than zero")
    if options.max_sessions_per_host <= 0:
        raise ConfigurationError("--max-sessions-per-host must be greater than zero")
    if options.object_retries < 0:
        raise ConfigurationError("--object-retries cannot be negative")
    if options.preflight_timeout <= 0:
        raise ConfigurationError("--preflight-timeout must be greater than zero")
    if options.preflight_time_budget <= 0:
        raise ConfigurationError("--preflight-time-budget must be greater than zero")
    if options.large_domain_target_threshold <= 0:
        raise ConfigurationError("--large-domain-target-threshold must be greater than zero")
    if options.large_domain_share_threshold <= 0:
        raise ConfigurationError("--large-domain-share-threshold must be greater than zero")
    if options.max_filesize <= 0:
        raise ConfigurationError("--max-filesize must be greater than zero")
    if options.max_failed_logons is not None and options.max_failed_logons <= 0:
        raise ConfigurationError("--max-failed-logons must be greater than zero")

    # A normal filesystem path may actually be a UNC path or a CIFS/NFS mount.
    # Refuse every location MANSPIDER can modify unless its backing filesystem
    # is explicitly known to be local. This check happens before preflight or
    # scan-state creation, so a bad path cannot cause a partial network run.
    try:
        writable_paths = {
            "SQLite state": options.state_path,
            "text log directory": Path(options.state_path).parent,
            "temporary storage": safe_temporary_directory(environ),
            "JSON report": getattr(options, "json_path", None),
            "SMB metrics report": getattr(options, "smb_metrics_path", None),
            "unclassified-file report": getattr(options, "unclassified_report_path", None),
        }
        if not options.no_download:
            writable_paths["loot"] = options.loot_dir or Path.home() / ".manspider" / "loot"
        for purpose, path in writable_paths.items():
            if path is not None:
                require_local_write_path(path, purpose=purpose)
        # A mounted network tree sent through the local-scanning branch would
        # expose the live source path to native/path-only extractors. Users can
        # scan that storage through the guarded SMB path instead.
        for target in options.targets:
            if isinstance(target, Path):
                require_local_path(target, purpose="local scan target")
    except UnsafeWritePath as exc:
        raise ConfigurationError(str(exc)) from exc

    if options.json_path:
        json_path = Path(options.json_path).resolve(strict=False)
        conflict = session_path_conflict(options.state_path, json_path)
        if conflict == "SQLite state file":
            raise ConfigurationError("--json-file cannot be the same path as the SQLite state file")
        if conflict is not None:
            raise ConfigurationError(f"--json-file cannot overwrite the reserved {conflict}: {json_path}")
        generated_outputs = {
            "passive SMB metrics report": getattr(options, "smb_metrics_path", None),
            "unclassified-file report": getattr(options, "unclassified_report_path", None),
        }
        for description, generated_path in generated_outputs.items():
            if generated_path and json_path == Path(generated_path).resolve(strict=False):
                raise ConfigurationError(f"--json-file cannot overwrite the generated {description}")
        if not options.resume_mode and not defer_existing_json_check and json_path.exists():
            raise ConfigurationError(f"JSON output already exists: {json_path}; choose another path")
    if options.modified_after and options.modified_before and options.modified_after > options.modified_before:
        raise ConfigurationError("--modified-after cannot be later than --modified-before")
    if options.aes_key and not re.fullmatch(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64})", options.aes_key):
        raise ConfigurationError("--aes-key must contain a 128-bit or 256-bit hexadecimal key")
    conflicting_formats = sorted(set(options.read_formats) & set(options.skip_formats))
    if conflicting_formats:
        raise ConfigurationError(
            "Extensions cannot be present in both --read-formats and --skip-formats: " + ", ".join(conflicting_formats)
        )

    smb_targets = [target for target in options.targets if not isinstance(target, Path)]
    if smb_targets and not options.kerberos:
        if not options.username_provided or not options.username:
            raise ConfigurationError("SMB scans require an explicit --username")
        if not options.password_provided and not (options.hash_provided and options.hash):
            raise ConfigurationError("SMB scans require an explicit --password, --hash, or --kerberos")

    for option, expressions in (("--filenames", options.filenames), ("--content", options.content)):
        for expression in expressions:
            try:
                re.compile(expression, re.IGNORECASE)
            except (re.error, OverflowError, RecursionError) as exc:
                raise ConfigurationError(f'Invalid regex for {option}: "{expression}": {exc}') from exc


def parse_options(
    argv: list[str] | None = None,
    *,
    parser: argparse.ArgumentParser | None = None,
    environ: dict[str, str] | None = None,
    defer_existing_json_check: bool = False,
):
    parser = build_parser() if parser is None else parser
    return normalize_options(
        parser.parse_args(argv),
        environ=environ,
        defer_existing_json_check=defer_existing_json_check,
    )


def format_configuration(options) -> str:
    from man_spider.lib.finding_log import display_text

    targets = ", ".join(display_text(target) for target in options.targets)
    local_count = sum(isinstance(target, Path) for target in options.targets)
    smb_count = len(options.targets) - local_count

    if not smb_count:
        authentication = "not required (local-only)"
    elif options.kerberos:
        authentication = "kerberos"
    elif options.hash:
        authentication = "ntlm-hash"
    else:
        authentication = "password"

    def values(items) -> str:
        return ", ".join(display_text(item) for item in items) if items else "none"

    rule_values = [format_rule(rule) for rule in options.rules]
    rule_packs = sorted(
        {
            f"{rule['rule_pack_id']}@{rule['rule_pack_version']}"
            for rule in options.rules
            if rule.get("rule_pack_id") is not None
        }
    )
    compact_rule_output = len(rule_values) > RULE_DETAIL_DISPLAY_LIMIT and not options.verbose
    if compact_rule_output:
        severity_order = ("critical", "high", "medium", "low", "info")
        severity_counts = {
            severity: sum(rule.get("severity") == severity for rule in options.rules) for severity in severity_order
        }
        severity_summary = ", ".join(f"{severity}={count}" for severity, count in severity_counts.items() if count)
        active_rules = (
            f"{len(rule_values)} enabled ({severity_summary}; "
            "full definitions are persisted; use --verbose to display them)"
        )
        representation_plan = build_rule_representation_plan(options.rules)
        representation_summary = ", ".join(
            f"{representation}={len(rule_ids)}" for representation, rule_ids in sorted(representation_plan.items())
        )
        rule_representation_plan = f"{representation_summary} (rule IDs are persisted; use --verbose to display them)"
    else:
        active_rules = values(rule_values)
        rule_representation_plan = display_text(format_rule_representation_plan(options.rules))

    return "\n".join(
        (
            "Effective configuration:",
            f"  targets ({len(options.targets)}; SMB={smb_count}, local={local_count}): {targets}",
            f"  authentication: {authentication}",
            f"  username: {display_text(options.username)}",
            f"  password: {display_text(options.password)}",
            f"  domain: {display_text(options.domain)}",
            f"  hash: {display_text(options.hash)}",
            f"  kerberos: {options.kerberos}",
            f"  krb5_ccache: {display_text(getattr(options, 'krb5_ccache', None) or '')}",
            f"  aes_key: {display_text(options.aes_key or '')}",
            f"  dc_ip: {display_text(options.dc_ip or '')}",
            f"  threads: {options.threads}",
            f"  max_sessions_per_host: {options.max_sessions_per_host}",
            f"  allow_external_dfs: {options.allow_external_dfs}",
            f"  passive_smb_metrics: {display_text(options.smb_metrics_path or 'disabled')}",
            f"  dynamic_eta: {not options.no_eta}",
            f"  unclassified_file_report: {display_text(options.unclassified_report_path or 'disabled')}",
            f"  object_retries: {options.object_retries}",
            f"  preflight_timeout: {options.preflight_timeout} seconds per target",
            f"  preflight_time_budget: {options.preflight_time_budget} seconds total",
            f"  large_domain_mode: {options.large_domain_mode}",
            f"  large_domain_thresholds: targets={options.large_domain_target_threshold}; shares={options.large_domain_share_threshold}",
            f"  effective_large_domain: {options.large_domain if options.large_domain is not None else 'pending preliminary estimate'}",
            f"  non_text_policy: {options.non_text_policy}",
            f"  read_format_overrides: {values(options.read_formats)}",
            f"  skip_format_overrides: {values(options.skip_formats)}",
            f"  maxdepth: {options.maxdepth}",
            f"  max_filesize: {bytes_to_human(options.max_filesize)} ({options.max_filesize} bytes)",
            "  max_filesize_scope: content analysis and downloaded copies only",
            "  metadata_size_policy: no global size limit (explicit rule size conditions still apply)",
            f"  max_failed_logons: {options.max_failed_logons if options.max_failed_logons is not None else 'unlimited'}",
            f"  logic_between_include_categories: {'OR' if options.or_logic else 'AND'}",
            f"  filename_includes: {values(options.filenames)}",
            f"  extension_includes: {values(options.extensions)}",
            f"  extension_excludes: {values(options.exclude_extensions)}",
            f"  content_includes: {values(options.content)}",
            f"  builtin_rules: {options.builtin_rules}",
            f"  rule_files: {values(options.rule_files)}",
            f"  rule_override_files: {values(options.rule_override_files)}",
            f"  disabled_rules: {values(options.disable_rules)}",
            f"  active_rule_packs: {values(rule_packs)}",
            f"  active_rules: {active_rules}",
            f"  rule_representation_plan: {rule_representation_plan}",
            f"  share_includes: {values(options.sharenames)}",
            f"  share_excludes: {values(options.exclude_sharenames)}",
            f"  share_exclusion_overrides: allowed={values(options.allow_sharenames)}; defaults_disabled={options.no_default_share_exclusions}",
            f"  directory_includes: {values(options.dirnames)}",
            f"  directory_excludes: {values(options.exclude_dirnames)}",
            f"  modified_after: {options.modified_after.date().isoformat() if options.modified_after else 'none'}",
            f"  modified_before: {options.modified_before.date().isoformat() if options.modified_before else 'none'}",
            f"  loot_dir: {display_text(options.loot_dir or str(Path.home() / '.manspider' / 'loot'))}",
            f"  state_file: {display_text(options.state_path)}",
            f"  resume: {options.resume_mode}",
            f"  resume_strategy: {options.resume_strategy if options.resume_mode else 'new scan'}",
            f"  json_output: {display_text(options.json_path or 'disabled')}",
            f"  download_matches: {not options.no_download}",
            "  content_reading: enabled when required by filters or rules, independently of --download",
            f"  show_match_context: {not options.quiet}",
            f"  main_scan_approval: {'explicit --yes for this invocation' if getattr(options, 'yes', False) else 'interactive approval required'}",
            f"  credential_preflight: {'required (up to 3 definitive SMB targets)' if smb_count else 'not required'}",
            (
                "  authentication_fallback: supplied credentials -> Guest -> null session"
                if smb_count
                else "  authentication_fallback: not applicable to local-only scan"
            ),
        )
    )
