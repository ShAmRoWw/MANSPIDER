#!/usr/bin/env python3

import logging
import multiprocessing
import os
import signal
import sqlite3
import sys
import threading
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from man_spider.cli import ConfigurationError, build_parser, parse_options, validate_options
from man_spider.approval import confirm_scan, format_scan_summary
from man_spider.lib.logger import prepare_logging, start_listener, stop_listener
from man_spider.lib.finding_log import display_text, display_traceback
from man_spider.lib.spider import MANSPIDER
from man_spider.lib.spiderling import (
    _ignore_worker_interrupts,
    _install_worker_interrupt_handler,
    _run_worker_cleanup,
    _start_worker_process,
)
from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib.cancellation import check_worker_cancellation
from man_spider.lib.process_lifecycle import (
    OwnedScanFamily,
    ProcessCleanupError,
    enter_scan_process_group,
    stop_scan_descendants,
)
from man_spider.lib.util import bytes_to_human
from man_spider.output import JsonOutputError, write_json_report
from man_spider.metrics import default_smb_metrics_path, write_smb_metrics_report
from man_spider.policy import apply_scope_policy, estimate_scope, restore_scope_policy
from man_spider.path_safety import UnsafeWritePath, require_safe_standard_streams
from man_spider.preflight import AttemptOutcome, PreflightStatus, verify_credentials
from man_spider.progress import format_progress
from man_spider.unclassified import default_unclassified_report_path, write_unclassified_report
from man_spider.state import (
    ResumableScan,
    ScanLease,
    ScanState,
    StateError,
    discover_resumable_scans,
    normalized_scan_configuration,
)


log = logging.getLogger("manspider")
log.setLevel(logging.INFO)

EXIT_CREDENTIALS_INVALID = 3
EXIT_PREFLIGHT_UNAVAILABLE = 4
EXIT_STATE_ERROR = 5
EXIT_COMPLETE_WITH_ERRORS = 2
EXIT_SCAN_NOT_APPROVED = 7
EXIT_SMB_SAFETY_ERROR = 8

try:
    SCANNER_VERSION = version("man-spider")
except PackageNotFoundError:
    SCANNER_VERSION = "2.0.0+source"


def credential_preflight(options) -> int:
    result = verify_credentials(options)
    options.preflight_result = result
    options.preflight_share_cache = {
        (attempt.target.host.casefold(), attempt.target.port): attempt.shares
        for attempt in result.attempts
        if attempt.outcome == AttemptOutcome.SUCCESS and attempt.share_count is not None
    }
    if result.status == PreflightStatus.NOT_REQUIRED:
        log.info("Credential preflight: not required for a local-only scan")
        return 0

    log.info(
        "Credential preflight: checking random SMB targets until the first success "
        f"or {result.required_definitive_results} definitive rejections; "
        f"timeout={options.preflight_timeout}s per target, total budget={options.preflight_time_budget}s"
    )
    for attempt_number, attempt in enumerate(result.attempts, start=1):
        message = (
            f"Credential preflight attempt {attempt_number} on {display_text(attempt.target)}: "
            f"{display_text(attempt.outcome.value)}: {display_text(attempt.reason)}"
        )
        if attempt.outcome == AttemptOutcome.SUCCESS:
            log.info(message)
        else:
            log.warning(message)

    if result.status == PreflightStatus.SUCCESS:
        log.info(
            "Credential preflight succeeded: at least one SMB target authenticated the supplied credentials; "
            "main-scan Guest/null fallback remains enabled"
        )
        return 0
    if result.status == PreflightStatus.CREDENTIALS_INVALID:
        log.critical(
            "Credential preflight failed: every required definitive target rejected the supplied credentials; "
            "the main scan was not started"
        )
        return EXIT_CREDENTIALS_INVALID

    if result.budget_exhausted:
        log.critical(
            "Credential preflight unavailable: the total time budget expired before enough definitive "
            "authentication results were collected; the main scan was not started"
        )
    else:
        log.critical(
            "Credential preflight unavailable: transport/protocol errors prevented the required number of definitive "
            "authentication results; the main scan was not started"
        )
    return EXIT_PREFLIGHT_UNAVAILABLE


def _mark_run(
    state: ScanState | None,
    state_path: Path | None,
    run_id: str | None,
    status: str,
    reason: str | None = None,
) -> None:
    """Persist a terminal status even after the pre-scan connection was closed."""

    _ignore_worker_interrupts()
    stop_scan_descendants()
    attached = None
    try:
        if state is None:
            if state_path is None or run_id is None:
                return
            attached = ScanState.attach(state_path, run_id)
            state = attached
        state.set_run_status(status, reason=reason)
    finally:
        if attached is not None:
            attached.close()


def _emit_terminal_output(
    state: ScanState | None,
    state_path: Path | None,
    run_id: str | None,
    options,
    *,
    include_json: bool = True,
    eta_estimator=None,
    targets_completed: int | None = None,
) -> None:
    """Emit one final state/progress view and refresh explicitly requested JSON."""

    attached = None
    try:
        if state is None:
            if state_path is None or run_id is None:
                return
            attached = ScanState.attach(state_path, run_id)
            state = attached

        destination = None
        if include_json and getattr(options, "json_path", None):
            destination = write_json_report(
                state,
                options.json_path,
                overwrite=options.resume_mode,
            )

        status = state.run_row()["status"]
        snapshot = state.progress_snapshot()
        eta = None
        if eta_estimator is not None:
            try:
                eta = eta_estimator.update(
                    snapshot,
                    targets_completed=targets_completed,
                )
            except Exception as exc:
                log.warning(f"Unable to calculate final dynamic ETA: {display_text(exc)}")
        log.info(f"Scan state: {display_text(status)}; database: {display_text(state.path)}")
        log.info(
            format_progress(
                snapshot,
                targets_completed=targets_completed,
                targets_total=len(options.targets),
                eta=eta,
            )
        )
        if destination is not None:
            log.info(f"JSON report: {display_text(destination)}")
    finally:
        if attached is not None:
            attached.close()


def _emit_terminal_output_best_effort(
    state: ScanState | None,
    state_path: Path | None,
    run_id: str | None,
    options,
    *,
    include_json: bool = True,
) -> None:
    """Do not let a secondary reporting failure replace the scan's real error."""

    if run_id is None:
        return
    try:
        _emit_terminal_output(
            state,
            state_path,
            run_id,
            options,
            include_json=include_json,
        )
    except Exception as exc:
        log.critical(f"Unable to produce final scan output: {display_text(exc)}")


def _write_smb_metrics_best_effort(manspider, state, state_path, run_id, options) -> None:
    """Persist passive telemetry without allowing it to change scan outcome."""

    collector = getattr(manspider, "smb_metrics", None) if manspider is not None else None
    destination = getattr(options, "smb_metrics_path", None)
    if collector is None or not destination or state_path is None:
        return

    attached = None
    run_status = "unknown"
    try:
        current_state = state
        if current_state is None:
            attached = ScanState.attach(state_path, run_id)
            current_state = attached
        run_status = current_state.run_row()["status"]
    except Exception as exc:
        log.warning(f"Unable to read final state status for SMB metrics: {display_text(exc)}")
    finally:
        if attached is not None:
            attached.close()

    try:
        report = collector.report(
            run_id=run_id,
            run_status=run_status,
            state_path=state_path,
        )
        written = write_smb_metrics_report(report, destination)
        log.info(f"Passive SMB metrics report: {display_text(written)}")
    except Exception as exc:
        log.warning(f"Unable to write passive SMB metrics report {display_text(destination)}: {display_text(exc)}")


def _write_unclassified_report_best_effort(state, state_path, run_id, options) -> None:
    """Export durable coverage observations without changing the scan outcome."""

    destination = getattr(options, "unclassified_report_path", None)
    if not destination or state_path is None or run_id is None:
        return
    attached = None
    try:
        current_state = state
        if current_state is None:
            attached = ScanState.attach(state_path, run_id)
            current_state = attached
        written, count = write_unclassified_report(current_state, destination)
        log.info(f"Unclassified-file report: {display_text(written)} ({count:,} files)")
    except Exception as exc:
        log.warning(f"Unable to write unclassified-file report {display_text(destination)}: {display_text(exc)}")
    finally:
        if attached is not None:
            attached.close()


def go(options, command: list[str] | None = None, *, approval_request=None) -> int:
    """Run an already normalized and validated scan configuration."""

    require_safe_standard_streams()
    command = list(sys.argv) if command is None else command
    if options.kerberos:
        os.environ["KRB5CCNAME"] = options.krb5_ccache
    local_listener = False
    if not getattr(options, "_external_log_listener", False):
        options.text_log_path = str(prepare_logging(options.state_path))
        try:
            local_listener = start_listener()
        except BaseException:
            stop_listener(True)
            raise
    log.info("MANSPIDER command executed: " + " ".join(display_text(argument) for argument in command))

    state = None
    state_path = None
    run_id = None
    lease = None
    manspider = None
    try:
        lease = ScanLease.acquire(options.state_path)
        restored_policy = False
        if options.resume_mode:
            persisted_configuration = ScanState.read_configuration(options.state_path)
            restored_policy = restore_scope_policy(options, persisted_configuration)
        log.info("Preparing credential preflight; the main scan will wait for operator approval.")

        configuration = normalized_scan_configuration(options)
        if options.resume_mode:
            state = ScanState.resume(options.state_path, configuration, SCANNER_VERSION)
            state_action = "Resumed"
        else:
            state = ScanState.create(options.state_path, configuration, SCANNER_VERSION)
            state_action = "Created"
        state_path = state.path
        run_id = state.run_id
        options.state_run_id = run_id
        log.info(f"{state_action} scan state: {display_text(state_path)}")
        if options.resume_mode:
            if options.refresh_resume:
                log.info(
                    "Resume strategy: refresh; the full directory tree will be re-enumerated, "
                    "while unchanged terminal files remain reusable"
                )
            else:
                log.info(
                    "Resume strategy: continue; only unfinished work and the ancestor directories "
                    "needed to reach it will be revisited"
                )

        preflight_exit = credential_preflight(options)
        check_worker_cancellation()
        if preflight_exit:
            state.set_run_status("preflight_failed", reason=f"Credential preflight exit code {preflight_exit}")
            _emit_terminal_output(state, state_path, run_id, options)
            return preflight_exit

        if not restored_policy:
            estimate = estimate_scope(options, getattr(options, "preflight_result", None))
            apply_scope_policy(options, estimate)
            state.update_configuration(normalized_scan_configuration(options))
        summary = format_scan_summary(options, state)
        approved = approval_request(summary) if approval_request is not None else confirm_scan(options, summary)
        if approved is not True:
            reason = "Main scan was not approved by the operator"
            state.set_run_status("interrupted", reason=reason)
            log.warning(reason + "; no main-scan workers were started")
            _emit_terminal_output(state, state_path, run_id, options)
            return EXIT_SCAN_NOT_APPROVED

        if options.resume_mode:
            metadata_requeued = state.requeue_legacy_size_skips()
            if metadata_requeued:
                log.info(
                    f"Resume: requeued {metadata_requeued:,} legacy size-skipped files for metadata reporting; "
                    "content and downloads remain size-limited"
                )
            reopened = state.prepare_resume(retry_limit=options.object_retries + 1)
            if reopened:
                log.info(
                    f"Resume: enabled {reopened:,} network-failed objects or required ancestor containers "
                    "for another visit; unrelated retry limits remain unchanged"
                )

        # Do not let worker processes inherit a live SQLite connection. Workers
        # attach independently when recording manifest objects and findings.
        state.close()
        state = None

        log.info(
            f"Content/download size limit: {bytes_to_human(options.max_filesize)}; "
            "metadata-only findings have no global size limit"
        )
        log.info(
            f"Using up to {options.threads:,} concurrent workers and "
            f"{options.max_sessions_per_host:,} SMB sessions per host"
        )

        manspider = MANSPIDER(options)
        manspider.start()
        if stop_scan_descendants():
            raise StateError("Scan returned with live workers; remaining processes were stopped")
        state = ScanState.attach(state_path, run_id)
        blocked = state.settle_blocked_objects()
        if blocked:
            log.warning(
                f"Manifest: {blocked:,} unfinished objects could not be reached because "
                "an ancestor failed or was blocked by scope policy; "
                "recorded with the ancestor's error/skip outcome and reason"
            )
        final_status = state.finish()
        _emit_terminal_output(
            state,
            state_path,
            run_id,
            options,
            eta_estimator=getattr(manspider, "eta_estimator", None),
            targets_completed=getattr(manspider, "targets_completed", None),
        )
        return EXIT_COMPLETE_WITH_ERRORS if final_status == "complete_with_errors" else 0
    except KeyboardInterrupt:
        try:
            _mark_run(state, state_path, run_id, "interrupted", reason="Interrupted by user")
        except StateError as state_exc:
            log.critical(f"Unable to record interrupted scan state: {display_text(state_exc)}")
        log.critical("Interrupted")
        _emit_terminal_output_best_effort(state, state_path, run_id, options)
        return 130
    except ReadOnlySMBViolation as exc:
        reason = f"Read-only SMB safety violation: {exc}; scan stopped"
        try:
            _mark_run(state, state_path, run_id, "interrupted", reason=reason)
        except StateError as state_exc:
            log.critical(f"Unable to record interrupted scan state: {display_text(state_exc)}")
        log.critical(display_text(reason))
        _emit_terminal_output_best_effort(state, state_path, run_id, options)
        return EXIT_SMB_SAFETY_ERROR
    except StateError as exc:
        try:
            _mark_run(state, state_path, run_id, "interrupted", reason=str(exc))
        except StateError:
            pass
        log.critical(f"Scan state error: {display_text(exc)}")
        _emit_terminal_output_best_effort(
            state,
            state_path,
            run_id,
            options,
            include_json=not isinstance(exc, JsonOutputError),
        )
        return EXIT_STATE_ERROR
    except sqlite3.Error as exc:
        reason = f"Persistent state database failure: {type(exc).__name__}: {exc}"
        try:
            _mark_run(state, state_path, run_id, "interrupted", reason=reason)
        except StateError:
            pass
        log.critical(display_text(reason))
        _emit_terminal_output_best_effort(state, state_path, run_id, options, include_json=False)
        return EXIT_STATE_ERROR
    except Exception as exc:
        try:
            _mark_run(state, state_path, run_id, "interrupted", reason=str(exc))
        except StateError as state_exc:
            log.critical(f"Unable to record interrupted scan state: {display_text(state_exc)}")
        if log.level <= logging.DEBUG:
            log.critical(display_traceback(exc))
        else:
            log.critical(f"Critical error (-v to debug): {display_text(exc)}")
        _emit_terminal_output_best_effort(state, state_path, run_id, options)
        return 1
    finally:
        writers_stopped = False
        try:
            # No report may race surviving worker writes, even when a real
            # exception escaped one of the terminal-state handlers above.
            _ignore_worker_interrupts()
            stop_scan_descendants()
            writers_stopped = True
            _write_unclassified_report_best_effort(state, state_path, run_id, options)
        finally:
            try:
                if writers_stopped:
                    _write_smb_metrics_best_effort(manspider, state, state_path, run_id, options)
            finally:
                try:
                    if state is not None:
                        state.close()
                finally:
                    try:
                        if lease is not None:
                            lease.release()
                    finally:
                        stop_listener(local_listener)


def _run_scan(options, command: list[str], approval_connection=None, supervisor_connection=None) -> None:
    # multiprocessing replaces a child's stdin with /dev/null. The supervisor
    # owns the real terminal and must display the review and collect the answer.
    def request_approval(summary):
        try:
            approval_connection.send(summary)
            return approval_connection.recv() is True
        except (EOFError, OSError):
            return False

    try:
        if supervisor_connection is not None:
            supervisor_connection.close()
        if approval_connection is not None:
            ready = enter_scan_process_group()
            if ready is not None:
                approval_connection.send(ready)
        _install_worker_interrupt_handler()
        raise SystemExit(
            go(options, command=command, approval_request=request_approval if approval_connection is not None else None)
        )
    except KeyboardInterrupt:
        _ignore_worker_interrupts()
        raise SystemExit(130) from None
    finally:
        _ignore_worker_interrupts()
        _run_worker_cleanup(
            stop_scan_descendants,
            lambda: approval_connection.close() if approval_connection is not None else None,
        )


def _external_interrupt(_signum, _frame) -> None:
    raise KeyboardInterrupt


def _resume_candidate_line(index: int, candidate: ResumableScan) -> str:
    targets = ", ".join(display_text(target) for target in candidate.targets) if candidate.targets else "<unknown>"
    started = candidate.created_at.replace("T", " ").replace("+00:00", " UTC")
    status = "running after an unclean stop" if candidate.status == "running" else candidate.status
    return f"  [{index}] {display_text(started)} | {display_text(status)} | targets: {targets}\n      {display_text(candidate.path)}"


def offer_automatic_resume(options, *, stdin=None, stdout=None) -> ResumableScan | None:
    """Offer unlocked unfinished default states without blocking automation."""

    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    if options.state_path_explicit or options.no_resume_prompt:
        return None
    try:
        interactive = stdin.isatty()
    except (AttributeError, OSError):
        interactive = False
    if not interactive:
        return None

    candidates = discover_resumable_scans(options.resume_search_directories)
    if not candidates:
        return None

    stdout.write("Unfinished MANSPIDER scans (newest first):\n")
    for index, candidate in enumerate(candidates, start=1):
        stdout.write(_resume_candidate_line(index, candidate) + "\n")
    stdout.write("  [0] Start a new scan\n")

    while True:
        stdout.write(f"Select a scan to resume [0-{len(candidates)}], or press Enter for a new scan: ")
        stdout.flush()
        answer = stdin.readline()
        if answer == "" or not answer.strip() or answer.strip() == "0":
            stdout.write("Starting a new scan.\n")
            stdout.flush()
            return None
        try:
            selected = int(answer.strip())
        except ValueError:
            selected = -1
        if 1 <= selected <= len(candidates):
            candidate = candidates[selected - 1]
            options.resume_file = str(candidate.path)
            options.resume_mode = True
            options.state_path = str(candidate.path)
            options.smb_metrics_path = (
                None if options.no_smb_metrics else str(default_smb_metrics_path(candidate.path))
            )
            options.unclassified_report_path = (
                None
                if options.no_unclassified_report
                else str(default_unclassified_report_path(candidate.path))
            )
            if options.json and not options.json_file:
                options.json_path = str(candidate.path.with_suffix(".json"))
            validate_options(options)
            stdout.write(f"Resuming scan state: {candidate.path}\n")
            stdout.flush()
            return candidate
        stdout.write(f"Enter a number from 0 through {len(candidates)}.\n")


class _SupervisorInterrupts:
    """Keep repeated terminal signals out of the supervisor's finalization.

    Unlike worker-only handlers, this also protects the original CLI process.
    A single Python state change takes effect before raising the first interrupt;
    subsequent signals return normally even during join/state/log cleanup.
    Direct library callers regain their original handlers when main returns.
    """

    def __init__(self):
        self.previous = {}
        self.stopping = False
        self.requested = False

    def __enter__(self):
        if threading.current_thread() is not threading.main_thread():
            return self
        signals = [signal.SIGINT]
        if os.name == "posix":
            signals.extend((signal.SIGTERM, signal.SIGHUP))
        try:
            for signum in signals:
                previous = signal.getsignal(signum)
                # Respect an explicitly ignored terminal interrupt inherited
                # from the caller; restore all other policies on leaving main.
                if signum == signal.SIGINT and previous == signal.SIG_IGN:
                    continue
                self.previous[signum] = previous
                signal.signal(signum, self.handle)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def handle(self, signum, frame):
        if self.stopping or self.requested:
            return
        previous = self.previous.get(signum)
        if signum == signal.SIGINT and callable(previous) and previous is not signal.default_int_handler:
            # A custom non-cancelling handler must retain its own semantics.
            try:
                previous(signum, frame)
            except KeyboardInterrupt:
                self.requested = True
                raise
            return
        self.requested = True
        raise KeyboardInterrupt

    def checkpoint(self):
        # A dependency destructor can suppress the first exception. Keep the
        # request until the supervisor actually enters its protected cleanup.
        if self.requested and not self.stopping:
            raise KeyboardInterrupt

    def begin_cleanup(self):
        self.stopping = True

    def __exit__(self, *_exc):
        self.begin_cleanup()
        for signum, previous in self.previous.items():
            signal.signal(signum, previous)
        self.previous.clear()


def main(argv: list[str] | None = None) -> int:
    """Library entrypoint: restore the caller's signal policy on return."""

    with _SupervisorInterrupts() as interrupts:
        try:
            return _main(argv, interrupts)
        except KeyboardInterrupt:
            # Before scan setup there may be no state/report/listener to close.
            # The scan-specific path below still owns its full finalization.
            interrupts.begin_cleanup()
            return 130


def cli() -> int:
    """Executable entrypoint: protect the interpreter's atexit phase too.

    The console script immediately passes this result to SystemExit. Restoring
    SIGINT here would allow the remaining keypresses to interrupt multiprocessing
    or logging finalizers after main had already finished correctly. Library
    callers use main(argv), which restores their original signal handlers.
    """

    interrupts = _SupervisorInterrupts()
    interrupts.__enter__()
    try:
        return _main(None, interrupts)
    except KeyboardInterrupt:
        return 130
    finally:
        # Python resets callable signal handlers during Py_Finalize. An OS-level
        # ignore disposition survives that last phase as well; otherwise a late
        # keypress can still change the already selected exit status to SIGINT.
        # This is deliberately confined to the executable, not main(argv).
        interrupts.begin_cleanup()
        for signum in interrupts.previous:
            signal.signal(signum, signal.SIG_IGN)


def _stop_supervised_scan(process, family):
    """Stop only the registered child and its verified private session."""

    if process is None:
        return
    if family.discover(process):
        family.stop()
        process.join(timeout=0)
        return
    # Cancellation can precede setsid/readiness. Signal only our registered
    # child, then look again for a private session established during startup.
    for method in ('interrupt', 'terminate', 'kill'):
        if family.discover(process):
            family.stop()
            process.join(timeout=0)
            return
        if not process.is_alive():
            return
        if method == 'interrupt' and os.name == 'posix' and process.pid is not None:
            try:
                os.kill(process.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
        elif method == 'kill':
            process.kill()
        else:
            process.terminate()
        process.join(timeout=5)
    if family.discover(process):
        family.stop()
        process.join(timeout=0)
    if process.is_alive():
        raise ProcessCleanupError('Scan coordinator did not stop; terminal output was not published')


def _supervisor_interruption_output(options, reason):
    """Publish only after all supervised writers have stopped."""

    marked = False
    attached = None
    try:
        marked = ScanState.interrupt_latest(options.state_path, reason=reason)
        if marked:
            log.info(f"Scan state marked interrupted: {display_text(options.state_path)}")
    except StateError as exc:
        log.critical(f"Unable to record interrupted scan state: {display_text(exc)}")
    try:
        attached = ScanState.attach_latest(options.state_path)
        if marked:
            _emit_terminal_output(attached, attached.path, attached.run_id, options)
        elif getattr(options, 'json_path', None):
            # The child may have persisted interrupted before producing JSON.
            destination = write_json_report(attached, options.json_path, overwrite=True)
            log.info(f"JSON report: {display_text(destination)}")
    except (StateError, sqlite3.Error, OSError) as exc:
        log.critical(f"Unable to produce supervisor interruption output: {display_text(exc)}")
    finally:
        if attached is not None:
            attached.close()


def _main(argv, interrupts) -> int:
    try:
        require_safe_standard_streams()
    except UnsafeWritePath:
        # Writing an explanation to the rejected stream would itself violate
        # the safety invariant. The shell may already have opened/truncated a
        # redirection before Python started; MANSPIDER performs no further I/O.
        return 6
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)

    if not arguments:
        parser.print_help()
        return 1

    try:
        options = parse_options(
            arguments,
            parser=parser,
            defer_existing_json_check=True,
        )
    except ConfigurationError as exc:
        parser.error(str(exc))

    try:
        offer_automatic_resume(options)
        validate_options(options)
    except ConfigurationError as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("\nResume selection cancelled.", file=sys.stderr)
        return 130

    if options.verbose:
        log.setLevel(logging.DEBUG)

    try:
        options.text_log_path = str(prepare_logging(options.state_path))
    except (OSError, ValueError) as exc:
        parser.error(f"Unable to prepare local logging: {exc}")

    approval_parent = approval_child = process = None
    family = OwnedScanFamily()
    try:
        executable = sys.argv[0] if argv is None else "manspider"
        command = [executable, *arguments]
        options._external_log_listener = True
        approval_parent, approval_child = multiprocessing.Pipe(duplex=True)
        process = multiprocessing.Process(
            target=_run_scan, args=(options, command, approval_child, approval_parent), daemon=False
        )
        # Fork before starting the listener thread. The child inherits the logging
        # queue, while queued configuration messages remain ordered before scan output.
        _start_worker_process(process)
        approval_child.close()
        start_listener()
        while True:
            interrupts.checkpoint()
            if approval_parent.poll(0.1):
                try:
                    summary = approval_parent.recv()
                except EOFError:
                    break
                if family.accept(summary, process):
                    continue
                try:
                    approved = confirm_scan(options, summary)
                except (OSError, ValueError) as exc:
                    log.error(f"Unable to display or collect scan approval: {display_text(exc)}; main scan will not start")
                    approved = False
                try:
                    approval_parent.send(approved)
                except (BrokenPipeError, EOFError, OSError):
                    pass
                break
            if not process.is_alive():
                break
        # A cheap local checkpoint also recovers a signal suppressed inside a
        # supervisor destructor. This does not generate network requests.
        while process.is_alive():
            interrupts.checkpoint()
            process.join(timeout=0.5)
        interrupts.checkpoint()
        family.discover(process)
        remaining = family.stop(grace=1.0)
        # Known exit codes already passed through go's state/report handling.
        # In particular, a rejected resume configuration must not cause the
        # supervisor to rewrite the previously saved session.
        if remaining or process.exitcode not in (*range(9), 130):
            interrupts.begin_cleanup()
            _supervisor_interruption_output(options, f"Scan coordinator exited with code {process.exitcode}")
            if remaining and not process.exitcode:
                return EXIT_STATE_ERROR
        return process.exitcode if process.exitcode is not None else 1
    except KeyboardInterrupt:
        interrupts.begin_cleanup()
        log.critical("Interrupted")
        if process is None:
            return 130
        try:
            _stop_supervised_scan(process, family)
        except ProcessCleanupError as exc:
            log.critical(display_text(exc))
            return EXIT_STATE_ERROR
        # A simultaneous interrupt must not hide a genuine safety/state error.
        # These handled exits also decide whether any state/report mutation
        # was permitted (a rejected legacy resume may not own a run at all).
        if process.exitcode in (EXIT_STATE_ERROR, EXIT_SMB_SAFETY_ERROR):
            return process.exitcode
        _supervisor_interruption_output(options, "Interrupted by user")
        return 130
    finally:
        # Protect even a first Ctrl+C arriving after scanning has finished.
        # A real close/listener error still propagates after all releases.
        interrupts.begin_cleanup()
        _run_worker_cleanup(
            lambda: _stop_supervised_scan(process, family),
            lambda: approval_parent.close() if approval_parent is not None else None,
            lambda: approval_child.close() if approval_child is not None else None,
            # prepare_logging created this invocation's listener even if the
            # child was interrupted before start_listener could run.
            lambda: stop_listener(True),
        )


if __name__ == "__main__":
    raise SystemExit(cli())
