import re
import logging
import math
import os
import queue
import multiprocessing
import signal
import tempfile
from pathlib import Path
from types import SimpleNamespace
from time import monotonic, sleep

from man_spider.lib.spiderling import *
from man_spider.lib.spiderling import (
    _ignore_worker_interrupts,
    _install_worker_interrupt_handler,
    _run_target_worker_process,
    _start_worker_process,
)
from man_spider.lib.logger import log_queue, start_listener, stop_listener
from man_spider.lib.cancellation import check_worker_cancellation
from man_spider.lib.finding_log import display_text
from man_spider.lib.parser import FileParser
from man_spider.lib.localfs import normalize_loot_root, prepare_loot_root
from man_spider.path_safety import (
    UnsafeWritePath,
    create_private_local_directory,
    remove_owned_local_tree,
    require_local_path,
    safe_temporary_directory,
)
from man_spider.filters import ScopeMatcher
from man_spider.policy import ScopeEstimate, apply_scope_policy
from man_spider.progress import DynamicETAEstimator, ETAEstimate, format_progress
from man_spider.metrics import SMBMetricsCollector
from man_spider.state import ScanState, StateError, utc_now

# set up logging
log = logging.getLogger("manspider")

DEFAULT_PROGRESS_INTERVAL_SECONDS = 5.0


def estimated_eta_share_scope(options) -> int | None:
    """Prefer an explicit share scope over domain-wide extrapolation."""

    targets = list(getattr(options, "targets", ()))
    if not targets or any(isinstance(target, Path) for target in targets):
        return None
    explicit_shares = list(getattr(options, "sharenames", ()))
    if explicit_shares:
        excluded = {str(share).casefold() for share in getattr(options, "exclude_sharenames", ())}
        included_count = sum(str(share).casefold() not in excluded for share in explicit_shares)
        return len(targets) * included_count
    scope_estimate = getattr(options, "scope_estimate", None) or {}
    return scope_estimate.get("estimated_shares")


class MANSPIDER:
    def __init__(self, options):

        self.targets = options.targets
        for target in self.targets:
            if isinstance(target, Path):
                require_local_path(target, purpose="local scan target")
        self.threads = options.threads
        self.max_sessions_per_host = getattr(options, "max_sessions_per_host", 4)
        self.allow_external_dfs = bool(getattr(options, "allow_external_dfs", False))
        self.maxdepth = options.maxdepth
        self.quiet = options.quiet

        self.username = options.username
        self.password = options.password
        self.domain = options.domain
        self.nthash = options.hash
        self.use_kerberos = options.kerberos
        self.aes_key = options.aes_key
        self.dc_ip = options.dc_ip
        self.max_failed_logons = options.max_failed_logons
        self.max_filesize = options.max_filesize
        self.object_retry_limit = getattr(options, "object_retries", 1) + 1
        self.state_path = getattr(options, "state_path", None)
        self.state_run_id = getattr(options, "state_run_id", None)
        self.resume_mode = bool(getattr(options, "resume_mode", False))
        self.refresh_resume = bool(getattr(options, "refresh_resume", False))
        self.preflight_share_cache = getattr(options, "preflight_share_cache", {})
        self.external_log_listener = bool(getattr(options, "_external_log_listener", False))
        self.smb_metrics_enabled = not bool(getattr(options, "no_smb_metrics", False))
        self.smb_metrics = SMBMetricsCollector() if self.smb_metrics_enabled else None
        self.eta_enabled = not bool(getattr(options, "no_eta", False))
        self.unclassified_report_enabled = not bool(getattr(options, "no_unclassified_report", False))

        if getattr(options, "blocked_content_extensions", None) is None:
            estimate = ScopeEstimate(
                smb_targets=sum(not isinstance(target, Path) for target in options.targets),
                local_targets=sum(isinstance(target, Path) for target in options.targets),
                sampled_targets=0,
                observed_shares=0,
                estimated_shares=None,
                target_threshold=getattr(options, "large_domain_target_threshold", 256),
                share_threshold=getattr(options, "large_domain_share_threshold", 1024),
                mode=getattr(options, "large_domain_mode", "auto"),
                large_domain=bool(getattr(options, "large_domain", False)),
                reason="direct library invocation without preliminary estimate",
            )
            apply_scope_policy(options, estimate)
        self.blocked_content_extensions = options.blocked_content_extensions

        self.share_whitelist = options.sharenames
        self.share_blacklist = options.exclude_sharenames

        self.dir_whitelist = options.dirnames
        self.dir_blacklist = options.exclude_dirnames

        self.no_download = options.no_download

        # applies "or" logic instead of "and"
        # e.g. file is downloaded if filename OR extension OR content match
        self.or_logic = options.or_logic

        self.extension_blacklist = options.exclude_extensions
        self.file_extensions = options.extensions

        if self.file_extensions:
            extensions_str = '"' + '", "'.join(list(self.file_extensions)) + '"'
            log.info(f"Searching by file extension: {display_text(extensions_str)}")

        self.init_filename_filters(options.filenames)
        self.parser = FileParser(
            options.content,
            quiet=self.quiet,
            blocked_extensions=self.blocked_content_extensions,
            rules=getattr(options, "rules", ()),
        )
        self.scope_matcher = ScopeMatcher(
            filename_filters=self.filename_filters,
            extensions=self.file_extensions,
            excluded_extensions=self.extension_blacklist,
            content_active=self.parser.has_cli_content_filters,
            included_shares=self.share_whitelist,
            excluded_shares=self.share_blacklist,
            included_directories=self.dir_whitelist,
            excluded_directories=self.dir_blacklist,
            date_active=bool(options.modified_after or options.modified_before),
            or_logic=self.or_logic,
        )

        self.eta_estimator = (
            DynamicETAEstimator(
                total_targets=len(self.targets),
                estimated_total_shares=estimated_eta_share_scope(options),
            )
            if self.eta_enabled
            else None
        )
        self.progress_interval_seconds = DEFAULT_PROGRESS_INTERVAL_SECONDS
        self.next_progress_at = None

        self.failed_logons = 0
        self.targets_completed = 0

        self.process_context = multiprocessing.get_context("spawn")
        self.spiderling_pool = [None] * self.threads
        self.spiderling_queue = self.process_context.Queue()
        # One global budget covers target coordinators and their additional
        # share workers.  The parent reserves coordinator capacity before any
        # child starts, preventing a busy host from starving unlaunched
        # targets of their first SMB session.
        self.share_worker_slots = self.process_context.BoundedSemaphore(self.threads)
        self._base_slot_reserved = [False] * self.threads

        # prevents needing to continually instantiate new SMBClients
        # {target: SMBClient() ...}
        self.smb_client_cache = dict()

        # Created lazily by start() so construction failures cannot leak a
        # temporary directory. Every scan gets an isolated directory.
        self.tmp_dir = None
        self._owned_tmp_dir = None
        self._owned_tmp_identity = None
        self._previous_temp_environment = None
        self._previous_tempfile_directory = None

        # directory to store matching documents
        configured_loot = options.loot_dir or Path.home() / ".manspider" / "loot"
        self.loot_dir = (
            normalize_loot_root(configured_loot) if options.no_download else prepare_loot_root(configured_loot)
        )

        if not options.no_download:
            log.info(f"Matching files will be downloaded to {display_text(self.loot_dir)}")

        self.modified_after = options.modified_after
        self.modified_before = options.modified_before

        if self.modified_after:
            log.info(f"Filtering files modified after: {display_text(self.modified_after.strftime('%Y-%m-%d'))}")
        if self.modified_before:
            log.info(f"Filtering files modified before: {display_text(self.modified_before.strftime('%Y-%m-%d'))}")

    def start(self):
        local_listener = False
        if not self.external_log_listener:
            local_listener = start_listener()
        try:
            _install_worker_interrupt_handler()
            self.prepare_temp_dir()
            self.initialize_progress_tracking()
            self._start()
        except KeyboardInterrupt:
            _ignore_worker_interrupts()
            forced_stop = self.stop_workers()
            # Children may fail while flushing state during cancellation.
            # Their joined queue and non-cancellation exits still take priority
            # over the parent's earlier KeyboardInterrupt.
            if forced_stop:
                log.warning("Some workers required forced interruption; skipping potentially damaged message queue")
            else:
                self.check_spiderling_queue(wait_for_feeders=True)
            for worker in self.spiderling_pool:
                if worker is not None and worker.exitcode not in (
                    None, 0, 130, -signal.SIGINT, -signal.SIGTERM, -signal.SIGKILL,
                ):
                    raise StateError(f"Spiderling process {worker.pid} exited with code {worker.exitcode}")
            raise
        except BaseException:
            _ignore_worker_interrupts()
            self.stop_workers()
            raise
        finally:
            self.persist_scan_timing()
            try:
                self.spiderling_queue.close()
                self.spiderling_queue.join_thread()
            finally:
                self.cleanup_temp_dir()
                stop_listener(local_listener)

    def prepare_temp_dir(self):
        if getattr(self, "_owned_tmp_dir", None) is not None:
            self.tmp_dir = self._owned_tmp_dir
            return
        temporary_base = safe_temporary_directory()
        temporary_root, identity = create_private_local_directory(
            temporary_base,
            prefix="manspider-",
            purpose="scan temporary directory",
        )
        self._owned_tmp_dir = temporary_root
        self._owned_tmp_identity = identity
        self.tmp_dir = temporary_root
        self._previous_temp_environment = {name: os.environ.get(name) for name in ("TMPDIR", "TEMP", "TMP")}
        self._previous_tempfile_directory = tempfile.tempdir
        for name in ("TMPDIR", "TEMP", "TMP"):
            os.environ[name] = str(temporary_root)
        # Python's tempfile module caches its selection independently of the
        # environment. Third-party extractors (notably Kreuzberg/PDFium) must
        # inherit the private run directory even if tempfile was used earlier.
        tempfile.tempdir = str(temporary_root)

    def stop_workers(self):
        """Stop every active target process before the scanner parent exits."""

        workers = [process for process in self.spiderling_pool if process is not None]
        forced_stop = False
        if os.name == "posix":
            for process in workers:
                if process.is_alive() and process.pid is not None:
                    try:
                        os.kill(process.pid, signal.SIGINT)
                    except ProcessLookupError:
                        pass
        else:
            for process in workers:
                if process.is_alive():
                    forced_stop = True
                    process.terminate()
        self.join_workers(workers, timeout=5)
        remaining = [process for process in workers if process.is_alive()]
        for process in remaining:
            forced_stop = True
            process.terminate()
        self.join_workers(remaining, timeout=5)
        remaining = [process for process in remaining if process.is_alive()]
        for process in remaining:
            forced_stop = True
            process.kill()
        self.join_workers(remaining, timeout=5)
        self.release_base_worker_slots()
        return forced_stop

    @staticmethod
    def join_workers(workers, timeout):
        """Wait for a group within one shared timeout budget."""

        deadline = monotonic() + timeout
        for process in workers:
            process.join(timeout=max(0, deadline - monotonic()))

    def cleanup_temp_dir(self):
        # Never trust the public/worker-facing tmp_dir attribute for deletion:
        # an exception handler, plugin, or accidental assignment must not turn
        # cleanup into arbitrary rmtree on a local or mounted network path.
        temporary_root = getattr(self, "_owned_tmp_dir", None)
        if temporary_root is None:
            return
        expected_identity = getattr(self, "_owned_tmp_identity", None)
        try:
            remove_owned_local_tree(
                temporary_root,
                expected_identity=expected_identity,
                purpose="scan temporary cleanup",
            )
        except FileNotFoundError:
            pass
        except UnsafeWritePath as exc:
            log.warning(f"Refusing to remove unsafe scan temporary directory {display_text(temporary_root)}: {display_text(exc)}")
            return
        except OSError as exc:
            log.warning(f"Unable to remove scan temporary directory {display_text(temporary_root)}: {display_text(exc)}")
            return
        finally:
            if getattr(self, "_owned_tmp_dir", None) == temporary_root:
                self._owned_tmp_dir = None
                self._owned_tmp_identity = None
                self.tmp_dir = None
            previous_environment = getattr(self, "_previous_temp_environment", None)
            if previous_environment is not None:
                for name, previous in previous_environment.items():
                    if os.environ.get(name) != str(temporary_root):
                        continue
                    if previous is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = previous
                self._previous_temp_environment = None
                tempfile.tempdir = getattr(self, "_previous_tempfile_directory", None)
                self._previous_tempfile_directory = None

    def _start(self):

        self.reserve_base_worker_slots()

        for target in self.targets:
            while True:
                check_worker_cancellation()
                self.check_spiderling_queue()
                launched = False
                for i, process in enumerate(self.spiderling_pool):
                    if process is None or not process.is_alive():
                        self.ensure_worker_succeeded(process)
                        self.spiderling_pool[i] = self.process_context.Process(
                            target=_run_target_worker_process,
                            args=(target, self.worker_context()),
                            daemon=False,
                        )
                        _start_worker_process(self.spiderling_pool[i])
                        launched = True
                        break
                    self.check_spiderling_queue()
                    self.maybe_report_progress()
                if launched:
                    break
                # Polling at 100 Hz keeps scheduling responsive without burning
                # an entire CPU core while every worker slot is occupied.
                sleep(0.01)

        while True:
            check_worker_cancellation()
            self.check_spiderling_queue()
            self.maybe_report_progress()
            for index, spiderling in enumerate(self.spiderling_pool):
                if spiderling is not None and not spiderling.is_alive():
                    self.ensure_worker_succeeded(spiderling)
                    self.spiderling_pool[index] = None
                    self.release_base_worker_slot(index)
            dead_spiderlings = [s is None or not s.is_alive() for s in self.spiderling_pool]
            if all(dead_spiderlings):
                break
            sleep(0.01)

        # make sure the queue is empty
        self.check_spiderling_queue(wait_for_feeders=True)

    def initialize_progress_tracking(self):
        """Start invocation-local main-scan timing without any remote work."""

        interval = getattr(self, "progress_interval_seconds", DEFAULT_PROGRESS_INTERVAL_SECONDS)
        self._scan_timing_started_monotonic = monotonic()
        self._scan_timing_started_at = utc_now()
        self._scan_timing_elapsed = 0.0
        self._scan_timing_eta = None
        self.next_progress_at = self._scan_timing_started_monotonic + interval
        estimator = getattr(self, "eta_estimator", None)
        if not getattr(self, "state_path", None) or not getattr(self, "state_run_id", None):
            return
        state = None
        try:
            state = ScanState.attach(self.state_path, self.state_run_id)
            if estimator is not None:
                try:
                    estimator.initialize(state.progress_snapshot())
                    self._scan_timing_eta = ETAEstimate(status="calculating", elapsed_seconds=0.0)
                except Exception as exc:
                    self.eta_estimator = None
                    log.warning(f"Dynamic ETA disabled after local initialization failure: {display_text(exc)}")
            self.persist_scan_timing(state)
        except Exception as exc:
            # Timing is informational and must never determine scan success.
            self.eta_estimator = None
            log.warning(f"Dynamic ETA disabled after local initialization failure: {display_text(exc)}")
        finally:
            if state is not None:
                state.close()

    def persist_scan_timing(self, state=None):
        """Save a passive heartbeat; telemetry failures cannot replace scan errors."""

        started = getattr(self, "_scan_timing_started_monotonic", None)
        if started is None or not getattr(self, "state_path", None) or not getattr(self, "state_run_id", None):
            return
        attached = None
        try:
            elapsed = max(self._scan_timing_elapsed, monotonic() - started, 0.0)
            if not math.isfinite(elapsed):
                return
            self._scan_timing_elapsed = elapsed
            if state is None:
                attached = ScanState.attach(self.state_path, self.state_run_id)
                state = attached
            eta = self._scan_timing_eta
            state.set_checkpoint("scan_timing", {
                "version": 1,
                "started_at": self._scan_timing_started_at,
                "updated_at": utc_now(),
                "elapsed_seconds": elapsed,
                "eta": eta.as_dict() if eta is not None else None,
            })
        except Exception as exc:
            log.warning(f"Unable to persist local scan timing: {display_text(exc)}")
        finally:
            if attached is not None:
                try:
                    attached.close()
                except Exception as exc:
                    log.warning(f"Unable to close local scan timing state: {display_text(exc)}")

    def maybe_report_progress(self, *, force=False):
        """Report on a wall-clock cadence even when no files finish."""

        now = monotonic()
        deadline = getattr(self, "next_progress_at", None)
        if not force and deadline is not None and now < deadline:
            return
        self.next_progress_at = now + getattr(
            self,
            "progress_interval_seconds",
            DEFAULT_PROGRESS_INTERVAL_SECONDS,
        )
        self.report_progress()

    def reserve_base_worker_slots(self):
        """Reserve one global worker slot for every active target-process slot."""

        reservations = min(self.threads, len(self.targets))
        for index in range(reservations):
            if not self._base_slot_reserved[index]:
                self.share_worker_slots.acquire()
                self._base_slot_reserved[index] = True

    def release_base_worker_slot(self, index):
        """Expose idle target capacity to remaining share workers."""

        reservations = getattr(self, "_base_slot_reserved", ())
        if index >= len(reservations) or not reservations[index]:
            return
        self.share_worker_slots.release()
        reservations[index] = False

    def release_base_worker_slots(self):
        """Release every coordinator reservation, idempotently."""

        for index in range(len(getattr(self, "_base_slot_reserved", ()))):
            self.release_base_worker_slot(index)

    def worker_context(self):
        """Return only the picklable configuration needed by a spawned worker."""

        return SimpleNamespace(
            username=self.username,
            password=self.password,
            domain=self.domain,
            nthash=self.nthash,
            use_kerberos=self.use_kerberos,
            aes_key=self.aes_key,
            dc_ip=self.dc_ip,
            preflight_share_cache=self.preflight_share_cache,
            parser=self.parser,
            scope_matcher=self.scope_matcher,
            quiet=self.quiet,
            maxdepth=self.maxdepth,
            max_filesize=self.max_filesize,
            no_download=self.no_download,
            share_whitelist=self.share_whitelist,
            share_blacklist=self.share_blacklist,
            dir_whitelist=self.dir_whitelist,
            dir_blacklist=self.dir_blacklist,
            or_logic=self.or_logic,
            filename_filters=self.filename_filters,
            file_extensions=self.file_extensions,
            extension_blacklist=self.extension_blacklist,
            blocked_content_extensions=self.blocked_content_extensions,
            loot_dir=self.loot_dir,
            tmp_dir=self.tmp_dir,
            modified_after=self.modified_after,
            modified_before=self.modified_before,
            state_path=self.state_path,
            state_run_id=self.state_run_id,
            resume_mode=self.resume_mode,
            refresh_resume=self.refresh_resume,
            object_retry_limit=self.object_retry_limit,
            threads=self.threads,
            max_sessions_per_host=self.max_sessions_per_host,
            allow_external_dfs=self.allow_external_dfs,
            smb_metrics_enabled=self.smb_metrics_enabled,
            unclassified_report_enabled=self.unclassified_report_enabled,
            session_slot_directory=(str(self.tmp_dir / "smb-session-slots") if self.tmp_dir is not None else None),
            share_worker_slots=self.share_worker_slots,
            spiderling_queue=self.spiderling_queue,
            log_queue=log_queue,
        )

    def ensure_worker_succeeded(self, process):
        """Treat an abnormal worker exit as a systemic, resumable scan failure."""

        if process is None:
            return
        process.join()
        if process.exitcode not in (None, 0):
            # A joined worker has flushed its multiprocessing queue feeder.
            # Preserve its specific safety failure before generic exit handling.
            if getattr(self, "spiderling_queue", None) is not None:
                self.check_spiderling_queue(wait_for_feeders=True)
            if process.exitcode in (130, -signal.SIGINT):
                raise KeyboardInterrupt
            for running in self.spiderling_pool:
                if running is not None and running.is_alive():
                    running.terminate()
                    running.join(timeout=5)
            raise StateError(f"Spiderling process {process.pid} exited with code {process.exitcode}")

    def init_file_extensions(self, file_extensions):
        """
        Get ready to search by file extension
        """

        self.file_extensions = FileExtensions()
        if file_extensions:
            self.file_extensions.update(file_extensions)

    def init_filename_filters(self, filename_filters):
        """
        Get ready to search by filename
        """

        # strings to look for in filenames
        # if empty, all filenames are matched
        self.filename_filters = []
        for f in filename_filters:
            regex_str = str(f)
            try:
                if not any([f.startswith(x) for x in ["^", ".*"]]):
                    regex_str = rf".*{regex_str}"
                if not any([f.endswith(x) for x in ["$", ".*"]]):
                    regex_str = rf"{regex_str}.*"
                self.filename_filters.append(re.compile(regex_str, re.I))
            except re.error as e:
                log.error(f'Unsupported filename regex "{display_text(f)}": {display_text(e)}')
                sleep(1)
        if self.filename_filters:
            filename_filter_str = '"' + '", "'.join([f.pattern for f in self.filename_filters]) + '"'
            log.info(f"Searching by filename: {display_text(filename_filter_str)}")

    def check_spiderling_queue(self, *, wait_for_feeders=False):
        """
        Empty the spiderling queue
        """

        while 1:
            try:
                if wait_for_feeders:
                    message = self.spiderling_queue.get(timeout=0.02)
                else:
                    message = self.spiderling_queue.get_nowait()
                self.process_message(message)

            except queue.Empty:
                break

    def process_message(self, message):
        """
        Process messages from spiderlings
        Log messages, errors, files, etc.
        """
        if message.type == "s":
            raise ReadOnlySMBViolation(f"{message.target}: {message.content}")
        if message.type == "a":
            if message.content == False:
                self.failed_logons += 1
            if self.lockout_threshold():
                log.error(f"REACHED MAXIMUM FAILED LOGONS OF {self.max_failed_logons:,}")
                log.error("CONTINUING UNLAUNCHED TARGETS WITH GUEST/NULL SESSIONS")
                self.username = ""
                self.password = ""
                self.nthash = ""
                self.domain = ""
        elif message.type == "p":
            if isinstance(message.content, dict) and message.content.get("target_complete"):
                self.targets_completed += 1
            self.maybe_report_progress()
        elif message.type == "m" and self.smb_metrics is not None:
            for warning in self.smb_metrics.ingest(message.content):
                log.warning(f"SMB performance warning: {display_text(warning)}")

    def report_progress(self):
        if not self.state_path or not self.state_run_id:
            log.info(f"Progress: targets={display_text(self.targets_completed)}/{display_text(len(self.targets))}")
            return
        state = ScanState.attach(self.state_path, self.state_run_id)
        try:
            snapshot = state.progress_snapshot()
            eta = None
            estimator = getattr(self, "eta_estimator", None)
            if estimator is not None:
                try:
                    eta = estimator.update(
                        snapshot,
                        targets_completed=self.targets_completed,
                    )
                except Exception as exc:
                    # A forecast must never alter traversal or final findings.
                    self.eta_estimator = None
                    log.warning(f"Dynamic ETA disabled after local calculation failure: {display_text(exc)}")
            self._scan_timing_eta = eta
            self.persist_scan_timing(state)
        finally:
            state.close()
        log.info(
            format_progress(
                snapshot,
                targets_completed=self.targets_completed,
                targets_total=len(self.targets),
                eta=eta,
            )
        )

    def lockout_threshold(self):
        """
        Return True if we've reached max failed logons
        """

        if self.max_failed_logons is not None:
            if self.failed_logons >= self.max_failed_logons and self.domain:
                return True
        return False

    def get_smb_client(self, target):
        """
        Check if we already have an smb_client cached
        If not, then create it
        """

        smb_client = self.smb_client_cache.get(target, None)

        if smb_client is None:
            smb_client = SMBClient(
                target.host,
                self.username,
                self.password,
                self.domain,
                self.nthash,
                self.use_kerberos,
                self.aes_key,
                self.dc_ip,
                port=target.port,
                session_slot_directory=(str(self.tmp_dir / "smb-session-slots") if self.tmp_dir is not None else None),
                max_sessions_per_host=self.max_sessions_per_host,
                allow_external_dfs=self.allow_external_dfs,
            )
            logon_result = smb_client.login()
            if logon_result == False:
                self.failed_logons += 1
            self.smb_client_cache[target] = smb_client

        return smb_client
