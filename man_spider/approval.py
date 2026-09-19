"""Explicit operator approval of the final, effective scan configuration."""

import logging
import sys
from pathlib import Path

from man_spider.cli import format_configuration
from man_spider.lib import logger as logger_module
from man_spider.lib.finding_log import display_text
from man_spider.lib.logger import log_scan_summary
from man_spider.policy import format_scope_policy
from man_spider.progress import format_progress


log = logging.getLogger("manspider")
APPROVAL_PROMPT = "Start the main scan? [y/N]: "


def format_scan_summary(options, state=None) -> str:
    """Describe actual post-preflight policy, not the initial pending defaults."""

    result = getattr(options, "preflight_result", None)
    status = getattr(getattr(result, "status", None), "value", "completed successfully")
    lines = [
        "MAIN SCAN REVIEW — awaiting operator approval",
        format_configuration(options),
        format_scope_policy(options),
        "Preflight result: " + display_text(status),
    ]
    for attempt in getattr(result, "attempts", ()):
        lines.append(
            f"  {display_text(attempt.target)}: {display_text(attempt.outcome.value)}; {display_text(attempt.reason)}"
        )
    rule_ids = [display_text(rule["id"]) for rule in options.rules]
    lines.append("Enabled rule IDs: " + (", ".join(rule_ids) if rule_ids else "none; explicit CLI filters apply"))
    if state is not None:
        run = state.run_row()
        lines.extend(
            (
                f"Scan identity: {display_text(run['run_id'])}; scanner version: {display_text(run['scanner_version'])}",
                "Current saved progress: " + format_progress(state.progress_snapshot(), targets_total=len(options.targets)),
                f"Full rule definitions and effective configuration: {display_text(state.path)} (SQLite config_json)",
            )
        )
        if options.resume_mode:
            lines.append(
                f"Legacy size-skipped files to revisit after approval: {state.legacy_size_skip_count()} "
                "(metadata reporting; content/download limits remain in force)"
            )
    # The review is built in a spawned child; only the supervisor owns the
    # actual file handler, so carry its selected path in invocation options.
    lines.append("Text log: " + display_text(
        getattr(options, "text_log_path", None) or logger_module.logpath or "not initialized"
    ))
    lines.extend(
        (
            "Operational notes:",
            "  Remote access is read-only; no remote file creation, modification or deletion is requested.",
            "  Rules and inspectors run locally; found credentials are not used to connect or validate anywhere.",
            "  Preflight has already checked supplied credentials; main enumeration and file reads have not started.",
            "  Loot downloads are disabled by default; --download is required to save matching remote files.",
            "  Metadata-only matches have no global size limit and need no content read unless --download is requested.",
            "  The size limit applies to content reads and optional downloads, not metadata findings.",
            "  No loot copies will be saved; active content rules may still read files within the size limit."
            if options.no_download
            else "  --download is enabled: matching remote files within the size limit are copied to local loot storage.",
            "  OFFLINE/HSM reads, when needed, remain allowed with full-path warnings and may trigger server-side recall.",
            "  Read-only scanning still consumes server/network resources; configured concurrency is an upper bound.",
            "  Network failures allow one full-file retry; reconnect pauses grow from 1 to 30 seconds per worker endpoint.",
            "  Resume grants recorded network failures a fresh visit; a total outage does not cause an indefinite global wait.",
            "  Temporary analysis files, when needed, stay in a private local per-run directory created after approval.",
            "  External DFS targets are explicitly allowed for this invocation."
            if options.allow_external_dfs
            else "  External DFS targets are not allowed; existing scope restrictions remain in force.",
            "  Scan duration is not known before enumeration; the ETA, if enabled, updates during scanning.",
            "  Approval applies only to this invocation, including when resuming a saved session.",
        )
    )
    if options.resume_mode:
        lines.append(
            "  Resume refresh re-enumerates directories; unchanged terminal files remain reusable."
            if options.refresh_resume
            else "  Resume continues unfinished work and its ancestors; completed unrelated subtrees are not revisited."
        )
    if options.or_logic and options.content and any(not isinstance(target, Path) for target in options.targets):
        lines.append(
            "  WARNING: --or-logic searches content even when filename/extension include filters do not match."
        )
    return "\n".join(lines)


def confirm_scan(options, summary, *, stdin=None) -> bool:
    """Display first, then require affirmative input or explicit CLI approval."""

    log_scan_summary(summary)
    if getattr(options, "yes", False):
        log_scan_summary("Main scan explicitly approved by --yes for this invocation.")
        return True
    stdin = sys.stdin if stdin is None else stdin
    try:
        interactive = stdin.isatty()
    except (AttributeError, OSError, ValueError):
        interactive = False
    if not interactive:
        log_scan_summary(
            "Main scan not approved: interactive input is unavailable. "
            "Run in a terminal, or pass --yes to explicitly approve an automated run."
        )
        return False

    while True:
        sys.stdout.write(APPROVAL_PROMPT)
        sys.stdout.flush()
        try:
            answer = stdin.readline()
        except (EOFError, OSError, ValueError):
            return False
        answer = answer.strip().casefold()
        if answer in {"y", "yes", "д", "да"}:
            log_scan_summary("Main scan approved by the operator.")
            return True
        if answer in {"", "n", "no", "н", "нет"}:
            return False
        sys.stdout.write("Enter yes to approve, or no to cancel.\n")
        sys.stdout.flush()
