import logging
import multiprocessing
import os
import pathlib
import queue
import signal
import threading
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from itertools import chain
from datetime import datetime

from impacket.smb import SharedFile

from man_spider.lib.smb import *
from man_spider.error_policy import DFS_SCOPE_BLOCKED_MARKER
from man_spider.lib.file import *
from man_spider.lib.util import *
from man_spider.lib.errors import *
from man_spider.lib.logger import configure_worker_logging
from man_spider.lib.cancellation import (
    begin_worker_cleanup,
    check_worker_cancellation,
    request_worker_cancellation,
    reset_worker_cancellation,
)
from man_spider.lib.finding_log import display_text, display_traceback, finding_log_message, grouped_console_overrides
from man_spider.lib.localfs import loot_storage_file, normalize_loot_root
from man_spider.formats import blocked_content_extension
from man_spider.path_safety import (
    UnsafeWritePath,
    anonymous_local_file,
    local_file_descriptor,
    require_local_path,
    safe_temporary_directory,
)
from man_spider.state import (
    FindingRecord,
    ScanState,
    StateError,
    directory_object_key,
    local_object_key,
    share_object_key,
    smb_object_key,
    target_object_key,
)


log = logging.getLogger("manspider.spiderling")


class SpiderlingMessage:
    """
    Message which gets sent back to the parent through parent_queue
    """

    def __init__(self, message_type, target, content):
        """
        "message_type" is a string, and can be:
            "e" - error
            "a" - authentication failure
        """
        self.type = message_type
        self.target = target
        self.content = content


class SMBMetricsPublisher:
    """Publish bounded process-local aggregates through the existing queue."""

    def __init__(self, message_queue, target):
        self.message_queue = message_queue
        self.target = target

    def __call__(self, snapshot):
        self.message_queue.put(SpiderlingMessage("m", self.target, snapshot))


def _report_read_only_failure(parent, target, failure):
    """Wake the scan supervisor without downgrading a blocked SMB operation."""

    # Even if the queue itself has failed, re-raising the original exception
    # below still produces an abnormal worker exit and interrupts the scan.
    with suppress(Exception):
        parent.spiderling_queue.put(SpiderlingMessage("s", target, str(failure)))


@dataclass(frozen=True)
class ShareSubtreeWork:
    """A disjoint directory subtree already claimed by its coordinator."""

    share: str
    path: str
    depth: int
    decision: object | None = None


def _ignore_worker_interrupts():
    """Do not let a repeated Ctrl+C interrupt a child already unwinding."""

    if threading.current_thread() is threading.main_thread() and multiprocessing.parent_process() is not None:
        begin_worker_cleanup()
        signal.signal(signal.SIGINT, signal.SIG_IGN)


def _interrupt_worker(_signum, _frame):
    if request_worker_cancellation():
        raise KeyboardInterrupt


def _start_worker_process(process):
    """Defer cancellation until the parent registers its fully started child.

    A pthread mask alone is not sufficient: another unmasked thread (such as
    a Queue feeder) can receive SIGINT and cause CPython to run its handler in
    this main thread during Process.start(). Keep that Python handler harmless
    until _popen/pid are registered, while retaining the inherited child mask
    which protects spawn/unpickle before the worker entrypoint is reached.
    """

    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("MANSPIDER worker processes must be started from the main thread")
    check_worker_cancellation()
    if os.name != "posix" or not hasattr(signal, "pthread_sigmask"):
        process.start()
        return
    attribute = "_manspider_startup_sigmask"
    missing = object()
    previous_attribute = getattr(process, attribute, missing)
    startup_signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous_handlers = {signum: signal.getsignal(signum) for signum in startup_signals}
    deferred = []

    def defer_interrupt(signum, frame):
        # Standard signals can coalesce; never accumulate one frame per keypress.
        if not deferred:
            deferred.append((signum, frame))

    # Preserve callers which explicitly ignore SIGINT or request its default
    # OS disposition. Only Python handlers can interrupt Process.start().
    for signum, previous_handler in previous_handlers.items():
        if callable(previous_handler):
            signal.signal(signum, defer_interrupt)
    previous_mask = None
    attribute_set = False
    failure = None
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set(startup_signals))
        # Process attributes survive spawn's pickle; module globals do not.
        # The child must not unmask a SIGINT already blocked by its caller.
        setattr(process, attribute, previous_mask)
        attribute_set = True
        process.start()
    except BaseException as exc:
        failure = exc
        raise
    finally:
        try:
            try:
                if attribute_set:
                    if previous_attribute is missing:
                        delattr(process, attribute)
                    else:
                        setattr(process, attribute, previous_attribute)
            finally:
                try:
                    if previous_mask is not None:
                        # Still defer Python delivery while restoring the exact
                        # caller mask, including a SIGINT it had already blocked.
                        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                finally:
                    for signum, previous_handler in previous_handlers.items():
                        if callable(previous_handler):
                            signal.signal(signum, previous_handler)
            if deferred:
                previous_handlers[deferred[0][0]](*deferred[0])
        except BaseException:
            if failure is not None and not isinstance(failure, KeyboardInterrupt):
                raise failure
            raise


def _install_worker_interrupt_handler():
    """Configure actual process children, never a direct/threaded library call."""

    if threading.current_thread() is threading.main_thread() and multiprocessing.parent_process() is not None:
        reset_worker_cancellation()
        signal.signal(signal.SIGINT, _interrupt_worker)
        if os.name == "posix":
            # Escalation must terminate this process, not re-enter cleanup via
            # the CLI supervisor's inherited Python exception handler.
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGHUP, signal.SIG_DFL)
        process = multiprocessing.current_process()
        attribute = "_manspider_startup_sigmask"
        previous_mask = getattr(process, attribute, None)
        if previous_mask is not None:
            # Consume only our marker. Unmasking can immediately deliver the
            # deferred SIGINT, now inside the entrypoint's protected try.
            delattr(process, attribute)
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        check_worker_cancellation()


def _run_worker_cleanup(*actions):
    """Attempt all releases without a later cancellation hiding a real error."""

    failure = None
    for action in actions:
        try:
            action()
        except BaseException as exc:
            _ignore_worker_interrupts()
            if (
                failure is None
                or isinstance(failure, KeyboardInterrupt) and not isinstance(exc, KeyboardInterrupt)
                or isinstance(exc, ReadOnlySMBViolation) and not isinstance(failure, ReadOnlySMBViolation)
            ):
                failure = exc
    if failure is not None:
        raise failure


def _run_target_worker_process(target, parent):
    """Translate normal cancellation to an explicit, traceback-free child exit."""

    try:
        _install_worker_interrupt_handler()
        Spiderling(target, parent)
    except KeyboardInterrupt:
        _ignore_worker_interrupts()
        raise SystemExit(130) from None


def _run_share_worker_process(
    target,
    parent,
    target_object_id,
    session_configuration,
    work_queue,
    stop_event,
    error_queue,
    admission_closed=None,
):
    """Run a persistent, independently authenticated share worker process."""

    slots = None
    acquired = False
    worker = None
    failure = None

    def record_failure(exc):
        nonlocal failure
        _ignore_worker_interrupts()
        # A real cleanup failure must remain visible even after cancellation.
        if failure is None or (isinstance(failure, KeyboardInterrupt) and not isinstance(exc, KeyboardInterrupt)):
            failure = exc
        stop_event.set()
        if isinstance(exc, ReadOnlySMBViolation):
            _report_read_only_failure(parent, target, exc)

    try:
        _install_worker_interrupt_handler()
        configure_worker_logging(parent.log_queue)
        slots = getattr(parent, "share_worker_slots", None)
        if slots is not None:
            while not stop_event.is_set() and not (
                admission_closed is not None and admission_closed.is_set()
            ):
                check_worker_cancellation()
                if slots.acquire(timeout=0.1):
                    acquired = True
                    break
            # Exhaustion can race with acquisition. Keep ownership until the
            # existing finally releases the token, without opening a session.
            if acquired and not stop_event.is_set() and not (
                admission_closed is not None and admission_closed.is_set()
            ):
                worker = Spiderling._create_share_worker(
                    target,
                    parent,
                    target_object_id,
                    session_configuration,
                )
                if worker is not None:
                    worker._consume_share_queue(work_queue, stop_event)
    except BaseException as exc:
        record_failure(exc)
    finally:
        try:
            if worker is not None:
                worker._close_share_worker()
        except BaseException as exc:
            record_failure(exc)
        finally:
            if acquired:
                try:
                    slots.release()
                except BaseException as exc:
                    record_failure(exc)
    if failure is not None:
        try:
            error_queue.put((type(failure).__name__, str(failure)))
        except BaseException as exc:
            if isinstance(failure, KeyboardInterrupt) and not isinstance(exc, KeyboardInterrupt):
                raise
        if isinstance(failure, KeyboardInterrupt):
            raise SystemExit(130) from None
        raise failure


class Spiderling:
    """
    Enumerates SMB shares and spiders all possible directories/filenames up to maxdepth
    Designed to be threadable
    """

    # these extensions don't get parsed for content, unless explicitly specified
    dont_parse = [
        ".png",
        ".gif",
        ".tiff",
        ".msi",
        ".bmp",
        ".jpg",
        ".jpeg",
        ".zip",
        ".gz",
        ".bz2",
        ".7z",
        ".xz",
    ]
    state_completion_batch_size = 64
    state_claim_batch_size = 64
    remote_pipeline_queue_size = 8
    remote_extraction_batch_size = 8
    remote_extraction_batch_bytes = 16 * 1024 * 1024
    remote_pipeline_poll_interval = 0.05

    def __init__(self, target, parent):

        configure_worker_logging(parent.log_queue)
        self.parent = parent
        self.target = target
        self.local_object_ids = {}
        self.local_initial_metadata = {}
        self.local_rule_routes = {}
        self.local_unclassified_records = {}
        self.file_analysis_observations = {}
        self.local_directory_ids = {}
        self.target_object_id = None
        self.completed_files_since_progress = 0
        self.pending_state_completions = []
        self.pending_unclassified_records = []
        self.pending_unclassified_deletions = []
        self._state_completion_lock = threading.RLock()
        self.scan_state = None
        self._owns_scan_state = False
        self.fast_resume = bool(getattr(parent, "resume_mode", False) and not getattr(parent, "refresh_resume", False))
        self.resume_frontier = frozenset()
        target_finished = False
        target_failure = None
        target_interrupted = False
        try:
            if self.state_enabled:
                self.scan_state = ScanState.attach(
                    self.parent.state_path,
                    self.parent.state_run_id,
                    thread_safe=True,
                )
                self._owns_scan_state = True
                if self.fast_resume:
                    self.resume_frontier = self.build_resume_frontier()
            decision = self.prepare_container(
                object_key=target_object_key(target),
                kind="target",
                target=str(target),
                path=str(target),
            )
            if decision is not None:
                self.target_object_id = decision.object_id
                if not decision.should_process:
                    self.log_container_skip("target", str(target), decision)
                    return

            # unless we're only searching local files, connect to target
            if isinstance(self.target, pathlib.Path):
                self.local = True
                self.go()
                self.complete_container(self.target_object_id, "processed")
                target_finished = True

            else:
                self.local = False

                self.smb_client = SMBClient(
                    target.host,
                    parent.username,
                    parent.password,
                    parent.domain,
                    parent.nthash,
                    parent.use_kerberos,
                    parent.aes_key,
                    parent.dc_ip,
                    port=target.port,
                    dfs_auth_failure_callback=self.report_dfs_auth_failure,
                    session_slot_directory=getattr(parent, "session_slot_directory", None),
                    max_sessions_per_host=getattr(parent, "max_sessions_per_host", None),
                    allow_external_dfs=getattr(parent, "allow_external_dfs", False),
                )
                self.enable_client_metrics(self.smb_client)

                logon_result = self.smb_client.login()
                if logon_result not in [True, None]:
                    self.message_parent("a", logon_result)
                    self.record_counter("authentication_failures")

                if logon_result is None:
                    reason = "SMB transport or protocol connection could not be established"
                    connection_error = getattr(self.smb_client, "last_connection_error", None)
                    if is_network_unavailable(connection_error):
                        reason = network_error_reason(connection_error)
                    self.complete_container(self.target_object_id, "error", reason=reason)
                    target_finished = True
                    log.warning(f"Error scanning target {display_text(target)}: {display_text(reason)}; continuing")
                    return

                cache_key = (target.host.casefold(), target.port)
                cached_shares = parent.preflight_share_cache.get(cache_key)
                if cached_shares is not None:
                    self.smb_client.seed_shares(cached_shares)
                self.go()
                reason = None
                if logon_result is False:
                    reason = "supplied credentials were rejected; Guest/null fallback was attempted"
                self.complete_container(self.target_object_id, "processed", reason=reason)
                target_finished = True

        except ReadOnlySMBViolation as exc:
            target_failure = exc
            _ignore_worker_interrupts()
            _report_read_only_failure(parent, target, exc)
            log.critical(f"Read-only SMB safety violation while spidering {display_text(self.target)}: {display_text(exc)}; stopping scan")
            raise

        except StateError as exc:
            target_failure = exc
            _ignore_worker_interrupts()
            log.critical(f"Persistent state failure while spidering {display_text(self.target)}: {display_text(exc)}")
            raise

        except KeyboardInterrupt as exc:
            target_failure = exc
            target_interrupted = True
            _ignore_worker_interrupts()
            log.info("Spiderling interrupted")
            raise

        # log all exceptions
        except Exception as e:
            if self.target_object_id is not None and not target_finished:
                self.complete_container(self.target_object_id, "error", reason=network_error_reason(e))
            if log.level <= logging.DEBUG:
                log.error(display_traceback())
            else:
                log.error(f"Error in spiderling for {display_text(self.target)}: {display_text(e)}; continuing")
        finally:
            try:
                self._close_share_worker()
            except ReadOnlySMBViolation as exc:
                _report_read_only_failure(parent, target, exc)
                log.critical(f"Read-only SMB safety violation during cleanup for {display_text(self.target)}: {display_text(exc)}")
                raise
            except KeyboardInterrupt:
                target_interrupted = True
                _ignore_worker_interrupts()
                if target_failure is not None and not isinstance(target_failure, KeyboardInterrupt):
                    raise target_failure
                raise
            finally:
                try:
                    if not target_interrupted:
                        self.message_parent("p", {"target_complete": True})
                except Exception:
                    pass

    def go(self):
        """
        go spider go spider go
        """

        if self.local:
            for file in self.files:
                self.process_file(file)
        else:
            self.scan_remote_shares()

        log.info(f"Finished spidering {display_text(self.target)}")

    def process_file(self, file):
        """Apply parsing, selection, persistence, and loot handling to one file."""
        check_worker_cancellation()

        rule_route = self.rule_route(file)
        if self.requires_content(file):
            if getattr(file, "skip_content", False):
                self.remember_file_analysis(file, "not_analyzed", "format_policy", self.observed_content_read(file))
                findings = self.metadata_rule_findings(file, rule_route)
                if not findings and not self.parser_has_rules:
                    findings = (self.metadata_finding(file),)
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"{display_text(file)}: content disabled by current format policy")
                if isinstance(file, RemoteFile) and not self.parent.no_download and not self.save_file(file):
                    self.complete_file(
                        file,
                        "error",
                        reason="unable to save retrieved loot",
                        changed=file.changed,
                    )
                    return
                self.complete_file(
                    file,
                    "skipped",
                    reason="content disabled by current format policy",
                    findings=findings,
                    changed=getattr(file, "changed", None),
                )
                return
            self.parse_file(file)
            return

        self.remember_file_analysis(file, "not_analyzed", "metadata_only", self.observed_content_read(file))
        findings = self.metadata_rule_findings(file, rule_route)
        if not findings and not self.parser_has_rules:
            findings = (self.metadata_finding(file),)
        if isinstance(file, RemoteFile):
            if not self.parent.no_download and not self.save_file(file):
                self.complete_file(
                    file,
                    "error",
                    reason="unable to save retrieved loot",
                    changed=file.changed,
                )
                return
        self.complete_file(
            file,
            "processed",
            findings=findings,
            changed=getattr(file, "changed", None),
        )

    def scan_remote_shares(self):
        """Schedule disjoint shares or sparse-share subtrees over SMB sessions."""

        shares = tuple(self.shares)
        if not shares:
            return
        session_capacity = min(
            max(1, getattr(self.parent, "threads", 1)),
            max(1, getattr(self.parent, "max_sessions_per_host", 1)),
        )
        if len(shares) < session_capacity:
            self._scan_sparse_share_set(shares, session_capacity)
            return
        self._run_parallel_share_work(shares, min(len(shares), session_capacity))

    def _scan_sparse_share_set(self, shares, session_capacity):
        """Split upper directory levels when shares alone cannot fill capacity."""

        work_items = []
        share_object_ids = []
        for share in shares:
            decision = self.prepare_container(
                object_key=share_object_key(self.target, share),
                kind="share",
                target=str(self.target),
                share=share,
                path=share,
            )
            share_object_id = decision.object_id if decision is not None else None
            if decision is not None and not decision.should_process:
                self.log_container_skip("share", f"{self.target}\\{share}", decision)
                continue
            try:
                with self.smb_client.pin_share(share):
                    self.process_remote_files(
                        self.files_for_share(
                            share,
                            subtree_sink=work_items.append,
                        )
                    )
            except (StateError, ReadOnlySMBViolation):
                raise
            except Exception as exc:
                reason = network_error_reason(exc)
                self.complete_container(share_object_id, "error", reason=reason)
                log.warning(f"Error planning share {display_text(self.target)}\\{display_text(share)}: {display_text(reason)}; continuing")
                continue
            share_object_ids.append(share_object_id)

        # A narrow root may expose only one directory. Expand upper levels in
        # the coordinator until there is enough disjoint work or the tree ends.
        while work_items and len(work_items) < session_capacity:
            work_item = work_items.pop(0)
            self.scan_subtree(work_item, subtree_sink=work_items.append)

        if work_items:
            self._run_parallel_share_work(
                work_items,
                min(len(work_items), session_capacity),
            )
        for share_object_id in share_object_ids:
            self.complete_container(share_object_id, "processed")

    def _run_parallel_share_work(self, work_items, worker_count):
        """Run fixed disjoint work through persistent process-owned sessions."""

        if worker_count == 1:
            for work_item in work_items:
                check_worker_cancellation()
                self._dispatch_share_work(work_item)
            return

        process_context = getattr(self.parent, "share_process_context", None)
        if process_context is None:
            process_context = multiprocessing.get_context("spawn")
        work_queue = process_context.JoinableQueue()
        for work_item in work_items:
            work_queue.put(work_item)
        # Queue.empty() is explicitly unreliable across multiprocessing feeder
        # threads. One FIFO marker per possible consumer makes exhaustion exact
        # without polling or dropping work which has not reached the pipe yet.
        for _consumer in range(worker_count):
            work_queue.put(None)
        stop_event = process_context.Event()
        admission_closed = process_context.Event()
        error_queue = process_context.Queue()
        session_configuration = self._session_configuration()
        workers = [
            process_context.Process(
                target=_run_share_worker_process,
                args=(
                    self.target,
                    self.parent,
                    self.target_object_id,
                    session_configuration,
                    work_queue,
                    stop_event,
                    error_queue,
                    admission_closed,
                ),
                name=f"manspider-share-{index + 2}-{self.target}",
                daemon=False,
            )
            for index in range(worker_count - 1)
        ]
        work_completed = False
        try:
            for worker in workers:
                _start_worker_process(worker)

            self._consume_share_queue(work_queue, stop_event)
            # All work precedes the FIFO markers, so a normal return means
            # every task has been dequeued, not necessarily completed. Stop
            # only idle admission: setting stop_event here would discard a
            # task another consumer already dequeued but has not dispatched.
            # Waiters must not need a slot held by this joining coordinator.
            admission_closed.set()
            for worker in workers:
                worker.join()
            self._raise_share_worker_failures(workers, error_queue)
            work_completed = True
        except KeyboardInterrupt:
            _ignore_worker_interrupts()
            stop_event.set()
            forced_stop = self._stop_share_workers(workers)
            # A worker can discover a genuine state/safety failure while
            # unwinding cancellation. Join before draining its feeder and do
            # not replace that failure with the coordinator's earlier SIGINT.
            if forced_stop:
                log.warning("Some share workers required forced interruption; skipping potentially damaged error queue")
            self._raise_share_worker_failures(workers, error_queue, interrupted=True, read_queue=not forced_stop)
            raise
        except BaseException:
            _ignore_worker_interrupts()
            stop_event.set()
            self._stop_share_workers(workers)
            raise
        finally:
            self._close_process_queue(work_queue, abandon=not work_completed)
            self._close_process_queue(error_queue)

    @staticmethod
    def _raise_share_worker_failures(workers, error_queue, *, interrupted=False, read_queue=True):
        failures = []
        # A killed Queue feeder can leave a readable header with a truncated
        # body: neither get_nowait nor get(timeout=...) bounds that body read.
        while read_queue:
            try:
                failures.append(error_queue.get_nowait())
            except queue.Empty:
                break
        failed_processes = [worker for worker in workers if worker.exitcode not in (None, 0)]
        for failure_type, reason in failures:
            if failure_type == ReadOnlySMBViolation.__name__:
                raise ReadOnlySMBViolation(f"Share worker blocked an unsafe SMB operation: {reason}")
        real_failures = [failure for failure in failures if failure[0] != KeyboardInterrupt.__name__]
        if real_failures:
            failure_type, reason = real_failures[0]
            raise StateError(f"Share worker failed ({failure_type}): {reason}")
        cancellation_exits = (130, -signal.SIGINT)
        if interrupted:
            # These exits can result from our bounded stop fallback, not an
            # unexpected failure during the actual scan.
            cancellation_exits += (-signal.SIGTERM, -signal.SIGKILL)
        unexpected_processes = [worker for worker in failed_processes if worker.exitcode not in cancellation_exits]
        if unexpected_processes:
            details = ", ".join(f"{worker.name}={worker.exitcode}" for worker in unexpected_processes)
            raise StateError(f"Share worker process exited abnormally: {details}")
        if failures or failed_processes:
            raise KeyboardInterrupt

    @staticmethod
    def _stop_share_workers(workers):
        """Stop nested share processes within a bounded failure timeout."""

        forced_stop = False
        if os.name == "posix":
            for worker in workers:
                if worker.is_alive() and getattr(worker, "pid", None) is not None:
                    with suppress(ProcessLookupError):
                        os.kill(worker.pid, signal.SIGINT)
        for worker in workers:
            if worker.is_alive():
                worker.join(timeout=0.5)
        for worker in workers:
            if worker.is_alive():
                forced_stop = True
                worker.terminate()
        for worker in workers:
            if worker.is_alive():
                worker.join(timeout=5)
        for worker in workers:
            if worker.is_alive():
                kill = getattr(worker, "kill", None)
                if kill is not None:
                    forced_stop = True
                    kill()
        for worker in workers:
            if worker.is_alive():
                worker.join(timeout=5)
        return forced_stop

    @staticmethod
    def _close_process_queue(process_queue, *, abandon=False):
        if abandon:
            # The coordinator owns this feeder. Cancelled consumers will not
            # drain the pending tasks; joining its full pipe would hang exit.
            # Manifest state, not this ephemeral queue, drives the next resume.
            cancel_join = getattr(process_queue, "cancel_join_thread", None)
            if cancel_join is not None:
                cancel_join()
        close = getattr(process_queue, "close", None)
        if close is not None:
            close()
        join_thread = getattr(process_queue, "join_thread", None)
        if join_thread is not None and not abandon:
            join_thread()

    def _consume_share_queue(self, work_queue, stop_event):
        """Drain locally owned share tasks until complete or systemically failed."""

        while not stop_event.is_set():
            check_worker_cancellation()
            work_item = work_queue.get()
            try:
                if work_item is None or stop_event.is_set():
                    return
                self._dispatch_share_work(work_item)
            finally:
                work_queue.task_done()

    def _dispatch_share_work(self, work_item):
        if isinstance(work_item, ShareSubtreeWork):
            self.scan_subtree(work_item)
        else:
            self.scan_share(work_item)

    def _new_share_worker(self):
        """Create and authenticate a share worker without retrying rejected credentials."""

        return self._create_share_worker(
            self.target,
            self.parent,
            self.target_object_id,
            self._session_configuration(),
        )

    def _session_configuration(self):
        source = self.smb_client
        return {
            "server": source.server,
            "username": source.username,
            "password": source.password,
            "domain": source.domain,
            "nthash": source.nthash,
            "use_kerberos": source.use_kerberos and source.username not in (None, "", "Guest"),
            "aes_key": source.aes_key,
            "dc_ip": source.dc_ip,
            "port": source.port,
            "hostname": source.hostname,
            "dns_domain": source.dns_domain,
            "session_slot_directory": source.session_slot_directory,
            "max_sessions_per_host": source.max_sessions_per_host,
            "allow_external_dfs": source.allow_external_dfs,
        }

    @classmethod
    def _create_share_worker(cls, target, parent, target_object_id, session_configuration):
        """Build process-owned SMB and state resources from resolved auth."""

        client = SMBClient(
            session_configuration["server"],
            session_configuration["username"],
            session_configuration["password"],
            session_configuration["domain"],
            session_configuration["nthash"],
            session_configuration["use_kerberos"],
            session_configuration["aes_key"],
            session_configuration["dc_ip"],
            port=session_configuration["port"],
            session_slot_directory=session_configuration["session_slot_directory"],
            max_sessions_per_host=session_configuration["max_sessions_per_host"],
            allow_external_dfs=session_configuration.get("allow_external_dfs", False),
        )
        enable_metrics = getattr(client, "enable_metrics", None)
        message_queue = getattr(parent, "spiderling_queue", None)
        if enable_metrics is not None and message_queue is not None and getattr(parent, "smb_metrics_enabled", True):
            enable_metrics(SMBMetricsPublisher(message_queue, target))
        client.hostname = session_configuration["hostname"]
        client.dns_domain = session_configuration["dns_domain"]
        logon_result = client.login(first_try=False)
        if logon_result is not True:
            client.close()
            log.warning(f"{display_text(target)}: Additional SMB session unavailable; remaining workers continue")
            return None

        worker = cls.__new__(cls)
        worker.parent = parent
        worker.target = target
        worker.local = False
        worker.local_object_ids = {}
        worker.local_initial_metadata = {}
        worker.local_rule_routes = {}
        worker.local_unclassified_records = {}
        worker.file_analysis_observations = {}
        worker.local_directory_ids = {}
        worker.target_object_id = target_object_id
        worker.completed_files_since_progress = 0
        worker.pending_state_completions = []
        worker.pending_unclassified_records = []
        worker.pending_unclassified_deletions = []
        worker._state_completion_lock = threading.RLock()
        worker.fast_resume = bool(
            getattr(parent, "resume_mode", False) and not getattr(parent, "refresh_resume", False)
        )
        worker.resume_frontier = frozenset()
        worker.smb_client = client
        client.dfs_auth_failure_callback = worker.report_dfs_auth_failure
        worker.scan_state = None
        worker._owns_scan_state = False
        try:
            if worker.state_enabled:
                worker.scan_state = ScanState.attach(
                    worker.parent.state_path,
                    worker.parent.state_run_id,
                    thread_safe=True,
                )
                worker._owns_scan_state = True
                if worker.fast_resume:
                    worker.resume_frontier = worker.build_resume_frontier()
        except BaseException:
            client.close()
            raise
        return worker

    def report_dfs_auth_failure(self, server):
        """Account for rejected credentials on a referred SMB endpoint."""

        log.warning(f"{display_text(self.target)}: Credentials were rejected by DFS target {display_text(server)}")
        self.message_parent("a", False)
        self.record_counter("authentication_failures")

    def _close_share_worker(self):
        """Close resources in the same process that created them."""

        def close_smb_client():
            smb_client = getattr(self, "smb_client", None)
            close = getattr(smb_client, "close", None)
            if close is not None:
                close()

        def close_scan_state():
            if self.scan_state is not None and self._owns_scan_state:
                self.scan_state.close()

        _run_worker_cleanup(
            self.flush_unclassified_observations,
            self.flush_state_completions,
            close_smb_client,
            close_scan_state,
        )

    def scan_share(self, share):
        """Own one share from lifecycle claim through terminal persistence."""

        decision = self.prepare_container(
            object_key=share_object_key(self.target, share),
            kind="share",
            target=str(self.target),
            share=share,
            path=share,
        )
        share_object_id = decision.object_id if decision is not None else None
        if decision is not None and not decision.should_process:
            self.log_container_skip("share", f"{self.target}\\{share}", decision)
            return
        try:
            with self.smb_client.pin_share(share):
                self.process_remote_files(self.files_for_share(share))
        except (StateError, ReadOnlySMBViolation):
            raise
        except Exception as exc:
            reason = network_error_reason(exc)
            self.complete_container(share_object_id, "error", reason=reason)
            log.warning(f"Error scanning share {display_text(self.target)}\\{display_text(share)}: {display_text(reason)}; continuing")
        else:
            self.complete_container(share_object_id, "processed")
        finally:
            self.flush_state_completions()

    def scan_subtree(self, work_item, subtree_sink=None):
        """Own one preclaimed directory subtree without duplicating share state."""

        try:
            with self.smb_client.pin_share(work_item.share):
                self.process_remote_files(
                    self.files_for_share(
                        work_item.share,
                        work_item.path,
                        work_item.depth,
                        prepared_decision=work_item.decision,
                        subtree_sink=subtree_sink,
                    )
                )
        except (StateError, ReadOnlySMBViolation):
            raise
        except Exception as exc:
            reason = network_error_reason(exc)
            object_id = work_item.decision.object_id if work_item.decision is not None else None
            self.complete_container(object_id, "error", reason=reason)
            log.warning(
                f"Error scanning subtree {display_text(self.target)}\\{display_text(work_item.share)}\\{display_text(work_item.path)}: {display_text(reason)}; continuing"
            )

    def process_remote_files(self, files):
        """Overlap SMB production with extraction through a bounded handoff."""

        iterator = iter(files)
        try:
            first_file = next(iterator)
        except StopIteration:
            return
        work_queue = queue.Queue(maxsize=self.remote_pipeline_queue_size)
        stop = object()
        cancelled = threading.Event()
        consumer_failed = threading.Event()
        failures = []

        def consume():
            while True:
                remote_file = work_queue.get()
                batch = []
                stop_after_batch = remote_file is stop
                if not stop_after_batch:
                    batch.append(remote_file)
                    while len(batch) < self.remote_extraction_batch_size:
                        try:
                            next_file = work_queue.get_nowait()
                        except queue.Empty:
                            break
                        if next_file is stop:
                            work_queue.task_done()
                            stop_after_batch = True
                            break
                        batch.append(next_file)
                try:
                    if not batch:
                        return
                    if cancelled.is_set():
                        for abandoned in batch:
                            abandoned.cleanup()
                        return
                    self.process_remote_batch(batch)
                except BaseException as exc:
                    if isinstance(exc, ReadOnlySMBViolation):
                        _report_read_only_failure(self.parent, self.target, exc)
                    for abandoned in batch:
                        try:
                            abandoned.cleanup()
                        except OSError:
                            pass
                    failures.append(exc)
                    consumer_failed.set()
                    return
                finally:
                    for _remote_file in batch:
                        work_queue.task_done()
                    if not batch:
                        work_queue.task_done()
                if stop_after_batch:
                    return

        consumer = threading.Thread(
            target=consume,
            name=f"manspider-extract-{self.target}",
            daemon=False,
        )
        consumer.start()
        producer_failure = None
        held_file = None
        try:
            for held_file in chain((first_file,), iterator):
                check_worker_cancellation()
                while not consumer_failed.is_set():
                    check_worker_cancellation()
                    try:
                        work_queue.put(held_file, timeout=self.remote_pipeline_poll_interval)
                        held_file = None
                        break
                    except queue.Full:
                        continue
                if held_file is not None:
                    held_file.cleanup()
                    held_file = None
                    break
        except BaseException as exc:
            producer_failure = exc
            cancelled.set()
            if isinstance(exc, ReadOnlySMBViolation):
                _report_read_only_failure(self.parent, self.target, exc)
            if held_file is not None:
                held_file.cleanup()
                held_file = None
        finally:
            if producer_failure is not None or consumer_failed.is_set():
                cancelled.set()
                close = getattr(iterator, "close", None)
                if close is not None:
                    try:
                        close()
                    except BaseException as exc:
                        if producer_failure is None:
                            producer_failure = exc

            if not consumer_failed.is_set():
                while consumer.is_alive():
                    try:
                        work_queue.put(stop, timeout=self.remote_pipeline_poll_interval)
                        break
                    except queue.Full:
                        continue
            consumer.join()

            while True:
                try:
                    abandoned = work_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    if abandoned is not stop:
                        abandoned.cleanup()
                finally:
                    work_queue.task_done()

        # A concurrent parser/cleanup error must not hide an SMB safety stop.
        for failure in (*failures, producer_failure):
            if isinstance(failure, ReadOnlySMBViolation):
                raise failure
        if failures:
            raise failures[0]
        if producer_failure is not None:
            raise producer_failure

    def process_remote_batch(self, files):
        """Pre-extract safe structured groups, then finish files in FIFO order."""

        parser = getattr(self.parent, "parser", None)
        if parser is None:
            for remote_file in files:
                self.process_file(remote_file)
            return
        groups = []
        group = []
        group_bytes = 0
        for remote_file in files:
            mime_type = parser.structured_bytes_mime_type(
                remote_file.name,
                self.rule_route(remote_file),
            )
            size = remote_file.retrieved_size
            batchable = remote_file.retrieved and mime_type is not None and size is not None
            if not batchable or size > self.remote_extraction_batch_bytes:
                continue
            if group and (
                len(group) >= self.remote_extraction_batch_size
                or group_bytes + size > self.remote_extraction_batch_bytes
            ):
                if len(group) >= 2:
                    groups.append(group)
                group = []
                group_bytes = 0
            group.append(remote_file)
            group_bytes += size
        if len(group) >= 2:
            groups.append(group)

        for candidates in groups:
            outcomes = parser.preextract_structured_batch(
                (
                    id(remote_file),
                    remote_file.name,
                    self.rule_route(remote_file),
                    remote_file.content_bytes,
                )
                for remote_file in candidates
            )
            for remote_file in candidates:
                outcome = outcomes.get(id(remote_file))
                if outcome is not None:
                    remote_file.precomputed_representations["structured"] = outcome

        for remote_file in files:
            self.process_file(remote_file)

    @property
    def files(self):
        """
        Yields all files on the target to be parsed/downloaded
        Premptively download matching files into temp directory
        """

        if self.local:
            for file in list_files(
                self.target,
                onerror=self.record_local_walk_error,
                prune_directory=self.local_directory_excluded,
                enter_directory=self.enter_local_directory,
                leave_directory=self.leave_local_directory,
            ):
                check_worker_cancellation()
                try:
                    require_local_path(file, purpose="local scan file")
                except UnsafeWritePath as exc:
                    reason = f"unsafe local scan file skipped: {exc}"
                    log.warning(f"{display_text(file)}: {display_text(reason)}")
                    self.record_exclusion(
                        object_key=local_object_key(file),
                        kind="file",
                        target=str(pathlib.Path(self.target).resolve()),
                        path=str(pathlib.Path(file).absolute()),
                        reason=reason,
                    )
                    continue
                try:
                    stat_result = file.stat()
                except OSError as exc:
                    reason = f"unable to read local metadata: {type(exc).__name__}: {exc}"
                    object_key = local_object_key(file)
                    resolved_target = str(pathlib.Path(self.target).resolve())
                    resolved_path = str(pathlib.Path(file).resolve())
                    unclassified_record = None
                    if self.unclassified_report_enabled:
                        rule_route = self.evaluate_rule_route(
                            {
                                "share": None,
                                "directory": str(pathlib.Path(file).parent),
                                "path": resolved_path,
                                "filename": file.name,
                                "extension": "".join(pathlib.Path(file).suffixes).lower(),
                                "size": None,
                                "mtime": None,
                            }
                        )
                        unclassified_record = self.classify_file_coverage(
                            object_key=object_key,
                            target=resolved_target,
                            share=None,
                            path=resolved_path,
                            full_path=resolved_path,
                            filename=file.name,
                            size=None,
                            mtime=None,
                            rule_route=rule_route,
                            selected=False,
                        )
                        if unclassified_record is not None:
                            unclassified_record["content_status"] = "metadata_unavailable"
                            unclassified_record["content_read"] = False
                    self.record_error_object(
                        object_key=object_key,
                        kind="file",
                        target=resolved_target,
                        path=resolved_path,
                        reason=reason,
                        unclassified_record=unclassified_record,
                    )
                    log.warning(f"Error reading metadata for {display_text(file)}: {display_text(reason)}; continuing")
                    continue
                self.local_initial_metadata[local_object_key(file)] = (
                    stat_result.st_size,
                    stat_result.st_mtime_ns,
                    stat_result.st_dev,
                    stat_result.st_ino,
                )
                scope_values = self.local_scope_values(file, stat_result=stat_result)
                directory_reason = self.parent.scope_matcher.directory_exclusion(scope_values["directory"])
                if directory_reason:
                    log.info(f"Excluded {display_text(file)}: {display_text(directory_reason)}")
                    directory_path = pathlib.Path(file).parent
                    self.record_exclusion(
                        object_key=directory_object_key(self.target, None, directory_path),
                        kind="directory",
                        target=str(pathlib.Path(self.target).resolve()),
                        path=str(directory_path.resolve()),
                        reason=directory_reason,
                    )
                    continue
                file_reason = self.parent.scope_matcher.file_exclusion(file.name)
                if file_reason:
                    log.info(f"Excluded {display_text(file)}: {display_text(file_reason)}")
                    self.record_exclusion(
                        object_key=local_object_key(file),
                        kind="file",
                        target=str(pathlib.Path(self.target).resolve()),
                        path=str(pathlib.Path(file).resolve()),
                        reason=file_reason,
                    )
                    continue
                selected = self.parent.scope_matcher.pre_content_candidate(**scope_values)
                rule_metadata = self.local_rule_metadata(file, stat_result, scope_values)
                rule_route = self.evaluate_rule_route(rule_metadata) if self.unclassified_report_enabled else None
                object_key = local_object_key(file)
                unclassified_record = self.classify_file_coverage(
                    object_key=object_key,
                    target=str(pathlib.Path(self.target).resolve()),
                    share=None,
                    path=str(pathlib.Path(file).resolve()),
                    full_path=str(pathlib.Path(file).resolve()),
                    filename=file.name,
                    size=stat_result.st_size,
                    mtime=stat_result.st_mtime,
                    rule_route=rule_route,
                    selected=selected,
                )
                if unclassified_record is not None:
                    if selected:
                        self.local_unclassified_records[object_key] = unclassified_record
                    else:
                        self.queue_unclassified_observation(unclassified_record)
                elif self.unclassified_report_enabled:
                    self.queue_unclassified_observation(covered_object_key=object_key)

                if not selected:
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug(f"Excluded {display_text(file)}: active include categories do not match")
                    continue
                decision = self.prepare_local_file(file, stat_result)
                if decision is not None and not decision.should_process:
                    if unclassified_record is not None:
                        unclassified_record["processing_status"] = decision.prior_status or "reused"
                        unclassified_record["processing_reason"] = "unchanged terminal object reused by resume"
                        unclassified_record["content_status"] = "reused_without_content_read"
                        unclassified_record["content_read"] = False
                        unclassified_record["_manifest_object_id"] = decision.object_id
                        self.local_unclassified_records.pop(object_key, None)
                        self.queue_unclassified_observation(unclassified_record)
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug(f"Resume: unchanged {display_text(file)} already has terminal status {display_text(decision.prior_status)}")
                    continue
                if rule_route is None:
                    rule_route = self.evaluate_rule_route(rule_metadata)
                self.local_rule_routes[local_object_key(file)] = rule_route
                if self.parser_has_rules and not rule_route.matched and not self.parser_has_cli_content_filters:
                    self.complete_file(file, "skipped", reason="no active rule matched file metadata")
                    continue
                if self.complete_oversized_file(file, stat_result.st_size, scope_values, rule_route):
                    continue
                if self.requires_content(file) and self.is_binary_file(file):
                    metadata_selected = self.parent.scope_matcher.final_include(
                        **scope_values,
                        content_match=False,
                    )
                    if metadata_selected:
                        if log.isEnabledFor(logging.DEBUG):
                            log.debug(f"{display_text(file)}: matched metadata filters; content disabled by current format policy")
                    else:
                        if log.isEnabledFor(logging.DEBUG):
                            log.debug(f"Skipped {display_text(file)}: content disabled by current format policy")
                    self.complete_file(
                        file,
                        "skipped",
                        reason="content disabled by current format policy",
                        findings=(
                            self.metadata_rule_findings(file, rule_route)
                            or (
                                (self.metadata_finding(file),)
                                if metadata_selected and not self.parser_has_rules
                                else ()
                            )
                        ),
                    )
                    continue
                yield file

        else:
            for share in self.shares:
                yield from self.iter_share_files(share)

    def iter_share_files(self, share):
        """Yield one share's files and persist exactly one share lifecycle."""

        decision = self.prepare_container(
            object_key=share_object_key(self.target, share),
            kind="share",
            target=str(self.target),
            share=share,
            path=share,
        )
        share_object_id = decision.object_id if decision is not None else None
        if decision is not None and not decision.should_process:
            self.log_container_skip("share", f"{self.target}\\{share}", decision)
            return
        try:
            with self.smb_client.pin_share(share):
                yield from self.files_for_share(share)
        except (StateError, ReadOnlySMBViolation):
            raise
        except Exception as exc:
            reason = network_error_reason(exc)
            self.complete_container(share_object_id, "error", reason=reason)
            log.warning(f"Error scanning share {display_text(self.target)}\\{display_text(share)}: {display_text(reason)}; continuing")
        else:
            self.complete_container(share_object_id, "processed")

    def files_for_share(
        self,
        share,
        path="",
        depth=0,
        prepared_decision=None,
        subtree_sink=None,
    ):
        """Yield retrieval-ready files from one already-owned share."""

        for remote_file in self.list_files(
            share,
            path,
            depth,
            prepared_decision=prepared_decision,
            subtree_sink=subtree_sink,
        ):
            needs_retrieval = not self.parent.no_download or (
                self.requires_content(remote_file) and not getattr(remote_file, "skip_content", False)
            )
            if needs_retrieval:
                try:
                    retrieved = self.get_file(remote_file)
                except DFSReferralBlocked as exc:
                    remote_file.cleanup()
                    reason = f"{DFS_SCOPE_BLOCKED_MARKER} {exc}"
                    metadata_findings = ()
                    if self.parent.scope_matcher.final_include(**remote_file.scope_values, content_match=False):
                        metadata_findings = self.metadata_rule_findings(remote_file, self.rule_route(remote_file))
                        if not metadata_findings and not self.parser_has_rules:
                            metadata_findings = (self.metadata_finding(remote_file),)
                    self.complete_file(
                        remote_file, "skipped", reason=reason,
                        findings=metadata_findings,
                        content_status="blocked_by_dfs_policy",
                    )
                    log.warning(f"Skipped {display_text(remote_file)}: {display_text(reason)}")
                    continue
                if not retrieved:
                    log.warning(f"Error retrieving required file {display_text(remote_file)}; continuing")
                    self.complete_file(
                        remote_file,
                        "error",
                        reason=remote_file.retrieval_error or "unable to retrieve required file",
                        content_read=False,
                        content_status="retrieval_failed",
                    )
                    continue
            yield remote_file

    def parse_file(self, file):
        """
        Simple wrapper around self.parent.parser.parse_file()
        For sole purpose of threading
        """
        check_worker_cancellation()

        self.remember_file_analysis(
            file, "not_analyzed", "read_failed", self.observed_content_read(file),
        )
        try:
            if isinstance(file, RemoteFile):
                rule_route = self.rule_route(file)
                self.remember_file_analysis(
                    file, "unknown", "unobserved", self.observed_content_read(file),
                )
                result = self.parent.parser.parse_file(
                    file.name,
                    pretty_filename=str(file),
                    rule_route=rule_route,
                    data_loader=file.content_bytes,
                    path_factory=file.materialize,
                    precomputed_representations=file.precomputed_representations,
                )
                self.remember_parser_analysis(file, result)
                metadata_findings = self.metadata_rule_findings(file, rule_route)
                if result.error:
                    file.cleanup()
                    self.complete_file(
                        file,
                        "error",
                        reason=result.error,
                        findings=self.partial_findings(file, rule_route, result),
                        changed=file.changed,
                    )
                    return
                if result.skipped_reason:
                    file.cleanup()
                    self.complete_file(
                        file,
                        "skipped",
                        reason=result.skipped_reason,
                        findings=metadata_findings,
                        changed=file.changed,
                    )
                    return
                scope_values = file.scope_values
                selected = self.parent.scope_matcher.final_include(
                    **scope_values,
                    content_match=self.cli_content_matched(result),
                )
                findings = self.selected_findings(file, rule_route, result, selected)
                if selected:
                    if not self.parent.no_download and (findings or not self.parser_has_rules):
                        if not self.save_file(file):
                            self.complete_file(
                                file,
                                "error",
                                reason="unable to save retrieved loot",
                                findings=findings,
                                changed=file.changed,
                            )
                            return
                    else:
                        file.cleanup()
                else:
                    file.cleanup()
                if file.changed:
                    log.warning(f"{display_text(file)}: changed while it was being read; completed content is retained")
                self.complete_file(
                    file,
                    "processed",
                    reason=None if selected else "active include categories did not match after content analysis",
                    findings=findings,
                    changed=file.changed,
                )

            else:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"Found file: {display_text(file)}")
                rule_route = self.rule_route(file)
                with ExitStack() as local_resources:
                    source_descriptor, _resolved_source = local_resources.enter_context(
                        local_file_descriptor(file, purpose="local scan input")
                    )
                    source_bytes = None
                    materialized_path = None

                    def load_source_bytes():
                        nonlocal source_bytes
                        if source_bytes is None:
                            self.remember_file_read(file, None)
                            with os.fdopen(os.dup(source_descriptor), "rb") as source:
                                source.seek(0)
                                source_bytes = source.read()
                            self.remember_file_read(file, True)
                        return source_bytes

                    def materialize_source():
                        nonlocal materialized_path
                        if materialized_path is None:
                            temporary_root = getattr(self.parent, "tmp_dir", None) or safe_temporary_directory()
                            descriptor, materialized_path = local_resources.enter_context(
                                anonymous_local_file(temporary_root, purpose="local parser materialization")
                            )
                            payload = load_source_bytes()
                            view = memoryview(payload)
                            while view:
                                written = os.write(descriptor, view)
                                if written <= 0:
                                    raise OSError("short write while materializing local parser input")
                                view = view[written:]
                            os.lseek(descriptor, 0, os.SEEK_SET)
                        return materialized_path

                    self.remember_file_analysis(file, "unknown", "unobserved", False)
                    result = self.parent.parser.parse_file(
                        file,
                        file,
                        rule_route=rule_route,
                        data_loader=load_source_bytes,
                        path_factory=materialize_source,
                    )
                    self.remember_parser_analysis(file, result)
                changed, post_read_identity = self.local_post_read_identity(file)
                metadata_findings = self.metadata_rule_findings(file, rule_route)
                if result.error:
                    self.complete_file(
                        file,
                        "error",
                        reason=result.error,
                        findings=self.partial_findings(file, rule_route, result),
                        changed=changed,
                    )
                    return
                if result.skipped_reason:
                    self.complete_file(
                        file,
                        "skipped",
                        reason=result.skipped_reason,
                        findings=metadata_findings,
                        changed=changed,
                    )
                    return
                scope_values = self.local_scope_values(file)
                selected = self.parent.scope_matcher.final_include(
                    **scope_values,
                    content_match=self.cli_content_matched(result),
                )
                findings = self.selected_findings(file, rule_route, result, selected)
                if changed:
                    log.warning(f"{display_text(file)}: changed while it was being read; completed content is retained")
                self.complete_file(
                    file,
                    "processed",
                    reason=None if selected else "active include categories did not match after content analysis",
                    findings=findings,
                    changed=changed,
                    post_read_identity=post_read_identity if changed else None,
                )

        except (StateError, ReadOnlySMBViolation):
            raise

        # log all exceptions
        except Exception as e:
            self.complete_file(file, "error", reason=str(e))
            if log.level <= logging.DEBUG:
                log.error(display_traceback())
            else:
                log.error(f"Error parsing file {display_text(file)}: {display_text(e)}")

        except KeyboardInterrupt:
            log.critical("File parsing interrupted")
            raise

        finally:
            if isinstance(file, RemoteFile):
                try:
                    file.cleanup()
                except OSError as exc:
                    log.warning(f"Unable to remove temporary content for {display_text(file)}: {display_text(exc)}")

    def local_scope_values(self, file, stat_result=None):
        try:
            relative = pathlib.Path(file).relative_to(self.target)
            directory = relative.parent
        except (ValueError, OSError):
            directory = pathlib.Path(file).parent
        if stat_result is not None:
            modified = stat_result.st_mtime
        else:
            try:
                modified = pathlib.Path(file).stat().st_mtime
            except OSError:
                modified = None
        return {
            "share": None,
            "directory": directory,
            "filename": pathlib.Path(file).name,
            "date_match": self.date_match(modified),
        }

    def local_rule_metadata(self, file, stat_result, scope_values):
        return {
            "share": None,
            "directory": str(scope_values["directory"]),
            "path": str(pathlib.Path(file).resolve()),
            "filename": pathlib.Path(file).name,
            "extension": "".join(pathlib.Path(file).suffixes).lower(),
            "size": stat_result.st_size,
            "mtime": stat_result.st_mtime,
        }

    @property
    def shares(self):
        """
        Lists all shares on single target
        Includes both enumerated shares and user-specified shares (which may be hidden from enumeration)
        """

        # Keep track of shares we've already yielded to avoid duplicates
        yielded_shares = set()

        # First, yield enumerated shares that match filters
        enumerated_shares = self.smb_client.shares
        if self.smb_client.share_listing_error:
            reason = f"unable to enumerate shares: {self.smb_client.share_listing_error}"
            if self.smb_client.share_listing_error.startswith(NETWORK_UNAVAILABLE_MARKER):
                reason = self.smb_client.share_listing_error
            self.record_error_object(
                object_key=f"share-enumeration|{target_object_key(self.target)}",
                kind="share_enumeration",
                target=str(self.target),
                path=str(self.target),
                reason=reason,
            )
            log.warning(f"{display_text(self.target)}: {display_text(reason)}; explicit shares will still be attempted")
        elif self.state_enabled and getattr(self.parent, "resume_mode", False):
            self.open_state().resolve_share_enumeration(f"share-enumeration|{target_object_key(self.target)}")

        for share in enumerated_shares:
            share_type = self.smb_client.share_type(share)
            exclusion = self.parent.scope_matcher.share_exclusion(share, share_type)
            if exclusion:
                log.info(f"Excluded {display_text(self.target)}\\{display_text(share)}: {display_text(exclusion)}")
                self.record_exclusion(
                    object_key=share_object_key(self.target, share),
                    kind="share",
                    target=str(self.target),
                    share=share,
                    path=share,
                    reason=exclusion,
                )
                continue
            if not self.parent.scope_matcher.should_traverse_share(share):
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"Excluded {display_text(self.target)}\\{display_text(share)}: share include category does not match")
                continue
            yielded_shares.add(share.lower())
            yield share

        # If user specified a share whitelist, also try those shares even if not enumerated
        # (some shares are hidden from enumeration but still accessible)
        if self.parent.share_whitelist:
            for share in self.parent.share_whitelist:
                if share.lower() not in yielded_shares:
                    exclusion = self.parent.scope_matcher.share_exclusion(share)
                    if exclusion:
                        log.info(f"Excluded explicit share {display_text(self.target)}\\{display_text(share)}: {display_text(exclusion)}")
                        self.record_exclusion(
                            object_key=share_object_key(self.target, share),
                            kind="share",
                            target=str(self.target),
                            share=share,
                            path=share,
                            reason=exclusion,
                        )
                        continue
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug(f"{display_text(self.target)}: Adding non-enumerated share from whitelist: {display_text(share)}")
                    yielded_shares.add(share.lower())
                    yield share

    def list_files(
        self,
        share,
        path="",
        depth=0,
        tries=2,
        prepared_decision=None,
        subtree_sink=None,
    ):
        """
        List files inside a specific directory
        Only yield files which conform to all filters (except content)
        """
        check_worker_cancellation()
        directory_key = directory_object_key(self.target, share, path)
        if depth >= self.parent.maxdepth:
            reason = "maximum depth reached"
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"Skipped {display_text(self.target)}\\{display_text(share)}\\{display_text(path)}: {display_text(reason)}")
            self.record_terminal_object(
                object_key=directory_key,
                kind="directory",
                target=str(self.target),
                share=share,
                path=path,
                status="skipped",
                reason=reason,
            )
            return

        directory_exclusion = self.parent.scope_matcher.directory_exclusion(path)
        if directory_exclusion:
            log.info(f"Excluded {display_text(self.target)}\\{display_text(share)}\\{display_text(path)}: {display_text(directory_exclusion)}; subtree pruned")
            self.record_exclusion(
                object_key=directory_key,
                kind="directory",
                target=str(self.target),
                share=share,
                path=path,
                reason=directory_exclusion,
            )
            return

        decision = prepared_decision
        if decision is None:
            decision = self.prepare_container(
                object_key=directory_key,
                kind="directory",
                target=str(self.target),
                share=share,
                path=path,
            )
        directory_object_id = decision.object_id if decision is not None else None
        if decision is not None and not decision.should_process:
            self.log_container_skip(
                "directory",
                f"{self.target}\\{share}\\{path}",
                decision,
            )
            return

        files = []
        last_error = None
        listed = False
        while tries > 0:
            try:
                files = list(self.smb_client.ls(share, path))
                listed = True
                last_error = None
                break
            except DFSReferralBlocked as exc:
                reason = f"{DFS_SCOPE_BLOCKED_MARKER} {exc}"
                self.complete_container(directory_object_id, "skipped", reason=reason)
                log.warning(f"Skipped {display_text(self.target)}\\{display_text(share)}\\{display_text(path)}: {display_text(reason)}; subtree not traversed")
                return
            except FileListError as exc:
                last_error = exc
                if "ACCESS_DENIED" in str(exc):
                    break
                tries -= 1

        if not listed:
            reason = str(last_error or "directory listing failed")
            self.complete_container(directory_object_id, "error", reason=reason)
            log.warning(f"Error listing {display_text(self.target)}\\{display_text(share)}\\{display_text(path)}: {display_text(reason)}; continuing")
            return
        if files:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.target)}: {display_text(share)}{display_text(path)}: contains {len(files):,} items")

        verification_candidates = []
        work_items = []
        claim_candidates = []
        unclassified_records = []
        covered_object_keys = []
        reused_unclassified_records = []
        try:
            for entry in files:
                name = entry.get_longname()
                full_path = f"{path}\\{name}"
                if entry.is_directory():
                    work_items.append(("directory", full_path, self.remote_file_attributes(entry)))
                    continue

                file_exclusion = self.parent.scope_matcher.file_exclusion(name)
                if file_exclusion:
                    log.info(f"Excluded {display_text(self.target)}\\{display_text(share)}{display_text(full_path)}: {display_text(file_exclusion)}")
                    self.record_exclusion(
                        object_key=smb_object_key(self.target, share, full_path.lstrip("\\")),
                        kind="file",
                        target=str(self.target),
                        share=share,
                        path=full_path.lstrip("\\"),
                        reason=file_exclusion,
                    )
                    continue

                full_path_fixed = full_path.lstrip("\\")
                object_key = smb_object_key(self.target, share, full_path_fixed)
                remote_unc_path = f"\\\\{self.target.host}\\{share}\\{full_path_fixed}"
                try:
                    filesize = entry.get_filesize()
                except ReadOnlySMBViolation:
                    raise
                except Exception as exc:
                    reason = f"unable to read file size: {type(exc).__name__}: {exc}"
                    self.smb_client.handle_impacket_error(exc)
                    unclassified_record = None
                    if self.unclassified_report_enabled:
                        rule_route = self.evaluate_rule_route(
                            {
                                "share": share,
                                "directory": path,
                                "path": full_path_fixed,
                                "filename": name,
                                "extension": "".join(pathlib.Path(name).suffixes).lower(),
                                "size": None,
                                "mtime": None,
                            }
                        )
                        unclassified_record = self.classify_file_coverage(
                            object_key=object_key,
                            target=str(self.target),
                            share=share,
                            path=full_path_fixed,
                            full_path=remote_unc_path,
                            filename=name,
                            size=None,
                            mtime=None,
                            rule_route=rule_route,
                            selected=False,
                        )
                        if unclassified_record is not None:
                            unclassified_record["content_status"] = "metadata_unavailable"
                            unclassified_record["content_read"] = False
                    self.record_error_object(
                        object_key=object_key,
                        kind="file",
                        target=str(self.target),
                        share=share,
                        path=full_path_fixed,
                        reason=reason,
                        unclassified_record=unclassified_record,
                    )
                    log.warning(f"Error reading size for {display_text(self.target)}\\{display_text(share)}{display_text(full_path)}: {display_text(reason)}; continuing")
                    continue

                try:
                    change_time = entry.get_mtime_epoch()
                    last_write_time = self.remote_last_write_time(entry, change_time)
                    date_selected = self.date_match(last_write_time)
                except ReadOnlySMBViolation:
                    raise
                except Exception as exc:
                    reason = f"unable to read file modification time: {type(exc).__name__}: {exc}"
                    self.smb_client.handle_impacket_error(exc)
                    self.record_counter("metadata_errors")
                    remote_file = RemoteFile(
                        full_path_fixed,
                        share,
                        self.target,
                        size=filesize,
                        mtime=None,
                        file_id=self.remote_file_id(entry),
                        tmp_dir=getattr(self.parent, "tmp_dir", None),
                        smb_attributes=self.remote_file_attributes(entry),
                    )
                    if self.unclassified_report_enabled:
                        rule_metadata = {
                            "share": share,
                            "directory": path,
                            "path": remote_file.name,
                            "filename": name,
                            "extension": "".join(pathlib.Path(name).suffixes).lower(),
                            "size": filesize,
                            "mtime": None,
                        }
                        remote_file.rule_route = self.evaluate_rule_route(rule_metadata)
                        remote_file.unclassified_record = self.classify_file_coverage(
                            object_key=object_key,
                            target=str(self.target),
                            share=share,
                            path=full_path_fixed,
                            full_path=remote_file.unc_path,
                            filename=name,
                            size=filesize,
                            mtime=None,
                            rule_route=remote_file.rule_route,
                            selected=True,
                        )
                        if remote_file.unclassified_record is not None:
                            remote_file.unclassified_record["content_status"] = "metadata_unavailable"
                            remote_file.unclassified_record["content_read"] = False
                    decision = self.prepare_remote_file(remote_file)
                    if decision is None or decision.should_process:
                        completion_values = {
                            "content_read": False,
                            "content_status": "metadata_unavailable",
                        }
                        self.complete_file(remote_file, "error", reason=reason, **completion_values)
                    elif remote_file.unclassified_record is not None:
                        remote_file.unclassified_record["processing_status"] = decision.prior_status or "error"
                        remote_file.unclassified_record["processing_reason"] = reason
                        remote_file.unclassified_record["_manifest_object_id"] = decision.object_id
                        reused_unclassified_records.append(remote_file.unclassified_record)
                    log.warning(
                        f"Error reading modification time for {display_text(self.target)}\\{display_text(share)}{display_text(full_path)}: {display_text(reason)}; continuing"
                    )
                    continue

                scope_values = {
                    "share": share,
                    "directory": path,
                    "filename": name,
                    "date_match": date_selected,
                }
                selected = self.parent.scope_matcher.pre_content_candidate(**scope_values)
                rule_metadata = {
                    "share": share,
                    "directory": path,
                    "path": full_path_fixed,
                    "filename": name,
                    "extension": "".join(pathlib.Path(name).suffixes).lower(),
                    "size": filesize,
                    "mtime": last_write_time,
                }
                rule_route = self.evaluate_rule_route(rule_metadata) if self.unclassified_report_enabled else None
                unclassified_record = self.classify_file_coverage(
                    object_key=object_key,
                    target=str(self.target),
                    share=share,
                    path=full_path_fixed,
                    full_path=remote_unc_path,
                    filename=name,
                    size=filesize,
                    mtime=last_write_time,
                    rule_route=rule_route,
                    selected=selected,
                )
                if unclassified_record is not None:
                    if not selected:
                        unclassified_records.append(unclassified_record)
                elif self.unclassified_report_enabled:
                    covered_object_keys.append(object_key)

                if not selected:
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug(f"Excluded {display_text(self.target)}\\{display_text(share)}{display_text(full_path)}: active include categories do not match")
                    continue

                file_id = self.remote_file_id(entry)
                remote_file = RemoteFile(
                    full_path_fixed,
                    share,
                    self.target,
                    size=filesize,
                    mtime=change_time,
                    file_id=file_id,
                    tmp_dir=getattr(self.parent, "tmp_dir", None),
                    smb_attributes=self.remote_file_attributes(entry),
                    last_write_time=last_write_time,
                )
                remote_file.scope_values = scope_values
                remote_file.rule_route = rule_route
                remote_file.unclassified_record = unclassified_record
                claim_candidates.append(remote_file)
                work_items.append(("file", remote_file, name))

            directory_candidates = [
                item
                for item_kind, item, _name in work_items
                if item_kind == "directory"
                and depth + 1 < self.parent.maxdepth
                and self.parent.scope_matcher.directory_exclusion(item) is None
            ]
            directory_decisions, decisions = self.prepare_remote_entries(
                share,
                directory_candidates,
                claim_candidates,
            )
            decisions_by_file = {
                id(remote_file): decision for remote_file, decision in zip(claim_candidates, decisions, strict=True)
            }
            for item_kind, item, name in work_items:
                if item_kind == "directory":
                    child_decision = directory_decisions.get(item)
                    will_enumerate = item in directory_decisions and (
                        child_decision is None or child_decision.should_process
                    )
                    if subtree_sink is not None and item in directory_decisions:
                        if child_decision is None or child_decision.should_process:
                            self.warn_recall_access(
                                "directory",
                                share,
                                item,
                                name,
                                "enumerated",
                            )
                            subtree_sink(
                                ShareSubtreeWork(
                                    share=share,
                                    path=item,
                                    depth=depth + 1,
                                    decision=child_decision,
                                )
                            )
                        continue
                    if will_enumerate:
                        self.warn_recall_access(
                            "directory",
                            share,
                            item,
                            name,
                            "enumerated",
                        )
                    yield from self.list_files(
                        share,
                        item,
                        depth + 1,
                        prepared_decision=directory_decisions.get(item),
                        subtree_sink=subtree_sink,
                    )
                    continue

                remote_file = item
                filesize = remote_file.size
                scope_values = remote_file.scope_values
                decision = decisions_by_file[id(remote_file)]
                if decision is not None and not decision.should_process:
                    if getattr(remote_file, "unclassified_record", None) is not None:
                        remote_file.unclassified_record["processing_status"] = decision.prior_status or "reused"
                        remote_file.unclassified_record["processing_reason"] = (
                            "unchanged terminal object reused by resume"
                        )
                        remote_file.unclassified_record["content_status"] = "reused_without_content_read"
                        remote_file.unclassified_record["content_read"] = False
                        remote_file.unclassified_record["_manifest_object_id"] = decision.object_id
                        reused_unclassified_records.append(remote_file.unclassified_record)
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug(f"Resume: unchanged {display_text(remote_file)} already has terminal status {display_text(decision.prior_status)}")
                    continue

                if remote_file.rule_route is None:
                    remote_file.rule_route = self.evaluate_rule_route(
                        {
                            "share": share,
                            "directory": path,
                            "path": remote_file.name,
                            "filename": name,
                            "extension": "".join(pathlib.Path(name).suffixes).lower(),
                            "size": filesize,
                            "mtime": remote_file.last_write_time,
                        }
                    )
                if (
                    self.parser_has_rules
                    and not remote_file.rule_route.matched
                    and not self.parser_has_cli_content_filters
                ):
                    self.complete_file(remote_file, "skipped", reason="no active rule matched file metadata")
                    continue

                if self.complete_oversized_file(remote_file, filesize, scope_values, remote_file.rule_route):
                    continue

                if self.requires_content(remote_file) and self.is_binary_file(name):
                    if self.parent.scope_matcher.final_include(**scope_values, content_match=False):
                        remote_file.skip_content = True
                        yield remote_file
                        if remote_file.retrieved:
                            verification_candidates.append(remote_file)
                    else:
                        log.info(
                            f"Skipped {display_text(remote_file)}: content disabled by current format policy and metadata filters do not select it"
                        )
                        self.complete_file(remote_file, "skipped", reason="content disabled by current format policy")
                    continue

                yield remote_file
                if remote_file.retrieved:
                    verification_candidates.append(remote_file)
        except (StateError, ReadOnlySMBViolation):
            raise
        except Exception as exc:
            reason = network_error_reason(exc)
            coverage_values = {}
            observations = (*unclassified_records, *reused_unclassified_records)
            if observations:
                coverage_values["unclassified_records"] = observations
            if covered_object_keys and getattr(self.parent, "resume_mode", False):
                coverage_values["unclassified_deletions"] = covered_object_keys
            self.complete_container(directory_object_id, "error", reason=reason, **coverage_values)
            log.warning(f"Error processing directory {display_text(self.target)}\\{display_text(share)}\\{display_text(path)}: {display_text(reason)}; continuing")
            return
        self.verify_remote_files(share, path, verification_candidates)
        coverage_values = {}
        observations = (*unclassified_records, *reused_unclassified_records)
        if observations:
            coverage_values["unclassified_records"] = observations
        if covered_object_keys and getattr(self.parent, "resume_mode", False):
            coverage_values["unclassified_deletions"] = covered_object_keys
        self.complete_container(directory_object_id, "processed", **coverage_values)

    def path_match(self, file):
        """
        Based on whether "or" logic is enabled, return True or False
        if the filename + extension meets the requirements
        """
        filename_match = self.filename_match(file)
        extension_match = self.extension_whitelisted(file)
        if self.parent.or_logic:
            return (filename_match and self.parent.filename_filters) or (
                extension_match and self.parent.file_extensions
            )
        else:
            return filename_match and extension_match

    def share_match(self, share):
        """
        Return true if "share" matches any of the share filters
        """

        # if the share has been whitelisted
        if (not self.parent.share_whitelist) or (share.lower() in self.parent.share_whitelist):
            # and hasn't been blacklisted
            if (not self.parent.share_blacklist) or (share.lower() not in self.parent.share_blacklist):
                return True
            else:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"{display_text(self.target)}: Skipping blacklisted share: {display_text(share)}")
        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.target)}: Skipping share {display_text(share)}: not in whitelist")

        return False

    def dir_match(self, path):
        """
        Return true if "path" matches any of the directory filters
        """

        # convert forward slashes to backwards
        dirname = str(path).lower().replace("/", "\\")

        # root path always passes
        if not path:
            return True

        # if whitelist check passes
        if (not self.parent.dir_whitelist) or any([k.lower() in dirname for k in self.parent.dir_whitelist]):
            # and blacklist check passes
            if (not self.parent.dir_blacklist) or not any([k.lower() in dirname for k in self.parent.dir_blacklist]):
                return True
            else:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"{display_text(self.target)}: Skipping blacklisted dir: {display_text(path)}")
        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.target)}: Skipping dir {display_text(path)}: not in whitelist")

        return False

    def filename_match(self, filename):
        """
        Return true if "filename" matches any of the filename filters
        """

        if (not self.parent.filename_filters) or any(
            [f_regex.match(str(pathlib.Path(filename).stem)) for f_regex in self.parent.filename_filters]
        ):
            return True
        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.target)}: {display_text(filename)} does not match filename filters")

        return False

    def is_binary_file(self, filename):
        """
        Returns true if file is a bad extension type, e.g. encrypted or compressed
        """

        if blocked_content_extension(filename, self.parent.blocked_content_extensions) is not None:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.target)}: Not parsing {display_text(filename)} due to active format policy")
            return True
        return False

    def extension_blacklisted(self, filename):
        """
        Return True if folder, file name, or extension has been blacklisted
        """
        extension = "".join(pathlib.Path(filename).suffixes).lower()
        excluded_extensions = list(self.parent.extension_blacklist)

        if not excluded_extensions:
            return False

        if not any([extension.endswith(e) for e in excluded_extensions]):
            return False
        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.target)}: Skipping file with blacklisted extension: {display_text(filename)}")
            return True

    def extension_whitelisted(self, filename):
        """
        Return True if file extension has been whitelisted
        """
        # a .tar.gz file will match both filters ".gz" and ".tar.gz"
        extension = "".join(pathlib.Path(filename).suffixes).lower()
        extensions = list(self.parent.file_extensions)

        if not extensions:
            return True

        # if whitelist check passes
        if any([(extension.endswith(e) if e else extension == e) for e in extensions]):
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.target)}: {display_text(filename)} matches extension filters")
            return True
        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.target)}: Skipping file {display_text(filename)}, does not match extension filters")
            return False

    def message_parent(self, message_type, content=""):
        """
        Send a message to the parent spider
        """

        self.parent.spiderling_queue.put(SpiderlingMessage(message_type, self.target, content))

    def enable_client_metrics(self, client):
        """Attach passive metrics when supported by the concrete SMB client."""

        enable = getattr(client, "enable_metrics", None)
        message_queue = getattr(self.parent, "spiderling_queue", None)
        if enable is not None and message_queue is not None and getattr(self.parent, "smb_metrics_enabled", True):
            enable(SMBMetricsPublisher(message_queue, self.target))

    @property
    def state_enabled(self):
        return bool(getattr(self.parent, "state_path", None) and getattr(self.parent, "state_run_id", None))

    @property
    def unclassified_report_enabled(self):
        return self.state_enabled and bool(getattr(self.parent, "unclassified_report_enabled", False))

    def open_state(self):
        if not self.state_enabled:
            return None
        if getattr(self, "scan_state", None) is None:
            self.scan_state = ScanState.attach(
                self.parent.state_path,
                self.parent.state_run_id,
                thread_safe=True,
            )
        return self.scan_state

    def extension_is_recognized(self, extension):
        """Check active rule and CLI extension vocabularies without touching file content."""

        if not extension:
            return False
        resolver = getattr(self.parent.parser, "recognizes_extension", None)
        if resolver is not None and resolver(extension):
            return True
        return any(extension.endswith(value) for value in getattr(self.parent, "file_extensions", ()) if value)

    def classify_file_coverage(
        self,
        *,
        object_key,
        target,
        share,
        path,
        full_path,
        filename,
        size,
        mtime,
        rule_route,
        selected,
    ):
        """Describe a rule/analysis gap using metadata already returned by listing."""

        if not self.unclassified_report_enabled:
            return None
        extension = "".join(pathlib.Path(filename).suffixes).lower()
        extension_recognized = self.extension_is_recognized(extension)
        route_matched = bool(rule_route and getattr(rule_route, "matched", False))
        matched_rule_ids = tuple(getattr(rule_route, "matched_rule_ids", ()))
        reasons = []

        if not extension:
            reasons.append("extensionless")
        elif not extension_recognized:
            reasons.append("unrecognized_extension")

        if self.parser_has_rules and not route_matched:
            reasons.append("no_active_rule_match")
        elif not self.parser_has_rules and not selected:
            reasons.append("not_selected_by_active_filters")

        requires_content = False
        resolver = getattr(self.parent.parser, "requires_content", None)
        if resolver is not None:
            requires_content = bool(resolver(rule_route))
        else:
            requires_content = bool(getattr(self.parent.parser, "content_filters", ()))

        content_status = "not_selected" if not selected else "not_requested"
        content_read = False
        if selected and requires_content:
            if size is not None and (size < 0 or size > self.parent.max_filesize):
                content_status = "blocked_by_size_policy"
                reasons.append("content_not_analyzed_size_policy")
            elif (
                blocked_content_extension(
                    filename,
                    getattr(self.parent, "blocked_content_extensions", ()),
                    original_extension=extension,
                )
                is not None
            ):
                content_status = "blocked_by_format_policy"
                reasons.append("content_not_analyzed_format_policy")
            elif route_matched or self.parser_has_cli_content_filters:
                content_status = "pending"
                content_read = None

        reasons = tuple(dict.fromkeys(reasons))
        if not reasons:
            return None
        return {
            "object_key": object_key,
            "target": target,
            "share": share,
            "path": path,
            "full_path": full_path,
            "filename": filename,
            "extension": extension,
            "extension_recognized": extension_recognized,
            "size": size,
            "mtime": mtime,
            "reasons": reasons,
            "matched_rule_ids": matched_rule_ids,
            "content_status": content_status,
            "content_read": content_read,
            "processing_status": "pending" if selected else "not_selected",
            "processing_reason": None if selected else "active include categories did not match",
        }

    def queue_unclassified_observation(self, record=None, *, covered_object_key=None):
        """Buffer local-listing observations within the existing 64-object durability bound."""

        if not self.unclassified_report_enabled:
            return
        if not hasattr(self, "pending_unclassified_records"):
            self.pending_unclassified_records = []
        if not hasattr(self, "pending_unclassified_deletions"):
            self.pending_unclassified_deletions = []
        if record is not None:
            self.pending_unclassified_records.append(record)
        if covered_object_key is not None and getattr(self.parent, "resume_mode", False):
            self.pending_unclassified_deletions.append(covered_object_key)
        if (
            len(self.pending_unclassified_records) + len(self.pending_unclassified_deletions)
            >= self.state_claim_batch_size
        ):
            self.flush_unclassified_observations()

    def flush_unclassified_observations(self):
        records, deletions = self.take_unclassified_observations()
        if not records and not deletions:
            return
        state = self.open_state()
        if records:
            state.upsert_unclassified_files(records)
        if deletions:
            state.delete_unclassified_files(deletions)

    def take_unclassified_observations(self):
        """Detach buffered local observations for an atomic container completion."""

        records = getattr(self, "pending_unclassified_records", None)
        deletions = getattr(self, "pending_unclassified_deletions", None)
        detached_records = tuple(records or ())
        detached_deletions = tuple(deletions or ())
        if records is not None:
            records.clear()
        if deletions is not None:
            deletions.clear()
        return detached_records, detached_deletions

    def build_resume_frontier(self):
        """Return containers which must be reopened to reach unfinished work."""

        state = self.open_state()
        target_values = [str(self.target)]
        if isinstance(self.target, pathlib.Path):
            target_values.append(str(self.target.resolve()))
        rows = state.resumable_objects(
            targets=target_values,
            retry_limit=getattr(self.parent, "object_retry_limit", 2),
        )
        frontier = set()
        target_key = target_object_key(self.target)
        remote_prefixes = {}
        if not isinstance(self.target, pathlib.Path):
            endpoint = f"{self.target.host.casefold()}|{self.target.port}|"
            remote_prefixes = {
                "file": f"smb|{endpoint}",
                "directory": f"directory|smb|{endpoint}",
                "share": f"share|smb|{endpoint}",
            }
        for row in rows:
            if not isinstance(self.target, pathlib.Path):
                # Display targets are ambiguous for IPv6 plus a custom port.
                # Existing canonical keys keep host and port separate, including
                # in old manifests: never reopen this endpoint for another's work.
                if row["kind"] in {"target", "share_enumeration"}:
                    expected_key = (
                        target_key if row["kind"] == "target" else f"share-enumeration|{target_key}"
                    )
                    if row["object_key"] != expected_key:
                        continue
                else:
                    prefix = remote_prefixes.get(row["kind"])
                    if prefix is None or not row["object_key"].startswith(prefix):
                        continue
            frontier.add(row["object_key"])
            frontier.add(target_key)
            share = row["share"]
            if isinstance(self.target, pathlib.Path):
                if row["kind"] not in {"file", "directory"} or not row["path"]:
                    continue
                current = pathlib.Path(row["path"])
                if row["kind"] == "file":
                    current = current.parent
                root = self.target.resolve()
                try:
                    current = current.resolve()
                    current.relative_to(root)
                except (OSError, ValueError):
                    continue
                while True:
                    frontier.add(directory_object_key(self.target, None, current))
                    if current == root:
                        break
                    current = current.parent
                continue

            if not share:
                continue
            frontier.add(share_object_key(self.target, share))
            if row["kind"] == "share":
                frontier.add(directory_object_key(self.target, share, ""))
                continue
            if row["kind"] not in {"file", "directory"}:
                continue
            parts = [part for part in str(row["path"] or "").replace("/", "\\").split("\\") if part]
            if row["kind"] == "file" and parts:
                parts.pop()
            frontier.add(directory_object_key(self.target, share, ""))
            for index in range(1, len(parts) + 1):
                frontier.add(directory_object_key(self.target, share, "\\".join(parts[:index])))
        if log.isEnabledFor(logging.DEBUG):
            log.debug(f"Resume frontier for {display_text(self.target)}: {len(frontier):,} containers for {len(rows):,} objects")
        return frozenset(frontier)

    def log_container_skip(self, kind, display, decision):
        """Distinguish intentional fast-resume pruning from exhausted errors."""

        if self.fast_resume and decision.prior_status in {"processed", "skipped"}:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"Resume: {display_text(kind)} {display_text(display)} is complete and has no unfinished descendants")
            return
        log.warning(f"Retry policy exhausted for {display_text(kind)} {display_text(display)}; retaining its error status")

    def prepare_container(
        self,
        *,
        object_key,
        kind,
        target=None,
        share=None,
        path=None,
        always_process=True,
    ):
        if not self.state_enabled:
            return None
        state = self.open_state()
        counter_name = {
            "target": "targets_discovered",
            "share": "shares_discovered",
            "directory": "directories_discovered",
            "file": "files_discovered",
        }.get(kind)
        if always_process and self.fast_resume:
            always_process = object_key in self.resume_frontier
        return state.claim_object(
            object_key=object_key,
            kind=kind,
            target=target,
            share=share,
            path=path,
            retry_limit=getattr(self.parent, "object_retry_limit", 2),
            always_process=always_process,
            discovery_counter=counter_name,
        )

    def complete_container(
        self,
        object_id,
        status,
        reason=None,
        *,
        unclassified_records=(),
        unclassified_deletions=(),
    ):
        if not self.state_enabled or object_id is None:
            return
        self.queue_state_completion(
            {
                "object_id": object_id,
                "status": status,
                "reason": reason,
                "unclassified_records": unclassified_records,
                "unclassified_deletions": unclassified_deletions,
            }
        )

    def record_terminal_object(self, *, status, reason=None, unclassified_record=None, **object_values):
        decision = self.prepare_container(always_process=False, **object_values)
        if decision is not None and decision.should_process:
            analysis_values = {}
            if object_values.get("kind") == "file":
                analysis_values = {
                    "analysis_status": "not_analyzed",
                    "analysis_reason": "metadata_unavailable",
                    "analysis_read": False,
                }
            self.queue_state_completion(
                {
                    "object_id": decision.object_id,
                    "status": status,
                    "reason": reason,
                    "unclassified_record": unclassified_record,
                    **analysis_values,
                }
            )

    def record_error_object(self, *, reason, **object_values):
        self.record_terminal_object(status="error", reason=reason, **object_values)

    def record_counter(self, name, amount=1):
        if not self.state_enabled:
            return
        self.open_state().increment_counter(name, amount)

    def record_local_walk_error(self, exc):
        path = pathlib.Path(getattr(exc, "filename", None) or self.target)
        reason = f"unable to traverse local directory: {type(exc).__name__}: {exc}"
        key = directory_object_key(self.target, None, path)
        object_id = self.local_directory_ids.get(key)
        if object_id is None:
            self.record_error_object(
                object_key=key,
                kind="directory",
                target=str(pathlib.Path(self.target).resolve()),
                path=str(path.resolve()),
                reason=reason,
            )
        else:
            self.complete_container(object_id, "error", reason=reason)
        log.warning(f"Error traversing {display_text(path)}: {display_text(reason)}; continuing")

    def enter_local_directory(self, path):
        """Persist a local directory before yielding any of its files."""

        try:
            require_local_path(path, purpose="local scan directory")
        except UnsafeWritePath as exc:
            reason = f"unsafe local scan directory skipped: {exc}"
            log.warning(f"{display_text(path)}: {display_text(reason)}; subtree pruned")
            self.record_exclusion(
                object_key=directory_object_key(self.target, None, path),
                kind="directory",
                target=str(pathlib.Path(self.target).resolve()),
                path=str(pathlib.Path(path).absolute()),
                reason=reason,
            )
            return False
        key = directory_object_key(self.target, None, path)
        decision = self.prepare_container(
            object_key=key,
            kind="directory",
            target=str(pathlib.Path(self.target).resolve()),
            path=str(pathlib.Path(path).resolve()),
        )
        if decision is None:
            return True
        self.local_directory_ids[key] = decision.object_id
        if not decision.should_process:
            self.log_container_skip("local directory", str(path), decision)
            return False
        return True

    def leave_local_directory(self, path):
        key = directory_object_key(self.target, None, path)
        object_id = self.local_directory_ids.pop(key, None)
        records, deletions = self.take_unclassified_observations()
        coverage_values = {}
        if records:
            coverage_values["unclassified_records"] = records
        if deletions:
            coverage_values["unclassified_deletions"] = deletions
        self.complete_container(object_id, "processed", **coverage_values)

    def prepare_local_file(self, file, stat_result):
        """Register local work and atomically move it to in-progress."""

        if not self.state_enabled:
            return None
        key = local_object_key(file)
        state = self.open_state()
        decision = state.claim_object(
            object_key=key,
            kind="file",
            target=str(pathlib.Path(self.target).resolve()),
            path=str(pathlib.Path(file).resolve()),
            size=stat_result.st_size,
            mtime=stat_result.st_mtime_ns,
            file_id=f"{stat_result.st_dev}:{stat_result.st_ino}",
            retry_limit=getattr(self.parent, "object_retry_limit", 2),
            discovery_counter="files_discovered",
        )
        self.local_object_ids[key] = decision.object_id
        return decision

    def prepare_remote_file(self, remote_file):
        """Register SMB work and atomically move it to in-progress."""

        return self.prepare_remote_files((remote_file,))[0]

    def prepare_remote_files(self, remote_files):
        """Register one bounded directory batch of SMB files atomically."""

        remote_files = tuple(remote_files)
        _directories, decisions = self.prepare_remote_entries(None, (), remote_files)
        return decisions

    def prepare_remote_entries(self, share, directory_paths, remote_files):
        """Claim child directories and files from one listing in bounded transactions."""

        directory_paths = tuple(directory_paths)
        remote_files = tuple(remote_files)
        if not self.state_enabled:
            return ({path: None for path in directory_paths}, (None,) * len(remote_files))
        state = self.open_state()
        entries = [
            (
                "directory",
                path,
                {
                    "object_key": directory_object_key(self.target, share, path),
                    "kind": "directory",
                    "target": str(self.target),
                    "share": share,
                    "path": path,
                    "retry_limit": getattr(self.parent, "object_retry_limit", 2),
                    "always_process": (
                        not self.fast_resume or directory_object_key(self.target, share, path) in self.resume_frontier
                    ),
                    "discovery_counter": "directories_discovered",
                },
            )
            for path in directory_paths
        ]
        entries.extend(
            (
                "file",
                remote_file,
                {
                    "object_key": smb_object_key(remote_file.target, remote_file.share, remote_file.name),
                    "kind": "file",
                    "target": str(remote_file.target),
                    "share": remote_file.share,
                    "path": remote_file.name,
                    "size": remote_file.size,
                    "mtime": remote_file.mtime,
                    "file_id": remote_file.file_id,
                    "retry_limit": getattr(self.parent, "object_retry_limit", 2),
                    "discovery_counter": "files_discovered",
                },
            )
            for remote_file in remote_files
        )
        entry_decisions = []
        for offset in range(0, len(entries), self.state_claim_batch_size):
            batch = entries[offset : offset + self.state_claim_batch_size]
            entry_decisions.extend(state.claim_objects(values for _kind, _entry, values in batch))

        directory_decisions = {}
        decisions = []
        for (kind, entry, _values), decision in zip(entries, entry_decisions, strict=True):
            if kind == "directory":
                directory_decisions[entry] = decision
            else:
                entry.object_id = decision.object_id
                decisions.append(decision)
        return directory_decisions, tuple(decisions)

    def object_id(self, file):
        if isinstance(file, RemoteFile):
            return file.object_id
        return self.local_object_ids.get(local_object_key(file))

    @staticmethod
    def observed_content_read(file):
        """Observe existing read state; never open a file to answer this."""

        if isinstance(file, RemoteFile):
            return bool(getattr(file, "content_read", False) or file.retrieved)
        return False

    def remember_file_analysis(self, file, status, reason, read):
        observations = getattr(self, "file_analysis_observations", None)
        if observations is None:
            observations = self.file_analysis_observations = {}
        observations[id(file)] = {
            "analysis_status": status,
            "analysis_reason": reason,
            "analysis_read": read,
        }

    def remember_file_read(self, file, read):
        observation = getattr(self, "file_analysis_observations", {}).get(id(file))
        if observation is not None and observation["analysis_read"] is not True:
            observation["analysis_read"] = read

    def remember_parser_analysis(self, file, result):
        selected = getattr(result, "analysis_selected", None)
        completed = getattr(result, "analysis_completed", None)
        read = getattr(result, "analysis_read", None)
        previous = getattr(self, "file_analysis_observations", {}).get(id(file), {})
        if self.observed_content_read(file) or previous.get("analysis_read") is True:
            read = True
        error = getattr(result, "error", None)
        skipped = getattr(result, "skipped_reason", None)
        if isinstance(selected, int) and isinstance(completed, int) and 0 <= completed <= selected:
            if selected and completed == selected and not error and not skipped:
                status, reason = "analyzed", None
            elif completed:
                status, reason = "partial", "partial_analysis"
            else:
                status = "not_analyzed"
                reason = "analysis_failed" if error else (
                    "format_policy" if skipped else "no_active_rules" if not selected else "not_started"
                )
        elif skipped:
            status, reason = "not_analyzed", "format_policy"
        else:
            status, reason = "unknown", "unobserved"
        self.remember_file_analysis(file, status, reason, read)

    def complete_file(
        self,
        file,
        status,
        reason=None,
        findings=(),
        changed=None,
        post_read_identity=None,
        content_read=None,
        content_status=None,
    ):
        analysis_values = getattr(self, "file_analysis_observations", {}).pop(id(file), None)
        if analysis_values is None:
            analysis_reason = {
                "metadata_unavailable": "metadata_unavailable",
                "blocked_by_size_policy": "size_policy",
                "blocked_by_format_policy": "format_policy",
                "blocked_by_dfs_policy": "scope_policy",
                "retrieval_failed": "read_failed",
                "not_requested": "metadata_only",
            }.get(content_status)
            if analysis_reason is None:
                if reason == "no active rule matched file metadata":
                    analysis_reason = "no_active_rules"
                elif reason == "content disabled by current format policy":
                    analysis_reason = "format_policy"
                else:
                    analysis_reason = "metadata_only" if status == "processed" else "not_started"
            analysis_values = {
                "analysis_status": "not_analyzed",
                "analysis_reason": analysis_reason,
                "analysis_read": self.observed_content_read(file) or content_read is True,
            }
        elif self.observed_content_read(file):
            analysis_values["analysis_read"] = True
        if (
            isinstance(file, RemoteFile)
            and changed
            and post_read_identity is None
            and file.post_read_identity is not None
        ):
            post_read_identity = file.post_read_identity
        finding_records = tuple(
            finding
            if isinstance(finding, FindingRecord)
            else FindingRecord(
                rule_id=finding.rule_id,
                value=finding.value,
                start=finding.start,
                end=finding.end,
                context=finding.context,
                representation=getattr(finding, "representation", "unknown"),
                rule_source=getattr(finding, "rule_source", "unknown"),
                rule_schema_version=getattr(finding, "rule_schema_version", None),
                rule_pack_id=getattr(finding, "rule_pack_id", None),
                rule_pack_version=getattr(finding, "rule_pack_version", None),
                severity=getattr(finding, "severity", "medium"),
                confidence=getattr(finding, "confidence", "medium"),
                category=getattr(finding, "category", "uncategorized"),
                tags=tuple(getattr(finding, "tags", ())),
                context_offset=getattr(finding, "context_offset", None),
            )
            for finding in findings
        )
        if isinstance(file, RemoteFile):
            unclassified_record = getattr(file, "unclassified_record", None)
        else:
            unclassified_record = getattr(self, "local_unclassified_records", {}).pop(local_object_key(file), None)
        if unclassified_record is not None:
            if content_read is not None:
                unclassified_record["content_read"] = bool(content_read)
            elif isinstance(file, RemoteFile) and file.retrieved:
                unclassified_record["content_read"] = True
            if content_status is not None:
                unclassified_record["content_status"] = content_status
            elif unclassified_record["content_status"] == "pending":
                if status == "processed":
                    unclassified_record["content_status"] = "analyzed"
                    unclassified_record["content_read"] = True
                elif status == "error":
                    unclassified_record["content_status"] = "read_or_analysis_failed"
                    if isinstance(file, RemoteFile) and not file.retrieved:
                        unclassified_record["content_read"] = False
                else:
                    unclassified_record["content_status"] = "not_analyzed"
            unclassified_record["processing_status"] = status
            unclassified_record["processing_reason"] = reason
        if not self.state_enabled:
            self.emit_findings(file, finding_records)
            return
        object_id = self.object_id(file)
        if object_id is None:
            raise StateError(f"No manifest identity is available for {file}")
        self.queue_state_completion(
            {
                "object_id": object_id,
                "status": status,
                "reason": reason,
                "findings": finding_records,
                "changed": changed,
                "post_read_identity": post_read_identity,
                "checkpoint_name": f"target:{self.target}",
                "checkpoint_value": {
                    "object_id": object_id,
                    "path": str(file),
                    "status": status,
                },
                "unclassified_record": unclassified_record,
                **analysis_values,
            },
            file=file,
            findings=finding_records,
        )

    def queue_state_completion(self, completion, *, file=None, findings=()):
        """Buffer one terminal update within the fixed crash-replay bound."""

        with self.state_completion_lock():
            pending = getattr(self, "pending_state_completions", None)
            if pending is None:
                pending = self.pending_state_completions = []
            pending.append((completion, file, findings))
            if len(pending) >= self.state_completion_batch_size:
                self.flush_state_completions()

    def state_completion_lock(self):
        """Return the per-worker lock protecting its completion/output stage."""

        lock = getattr(self, "_state_completion_lock", None)
        if lock is None:
            lock = self._state_completion_lock = threading.RLock()
        return lock

    def flush_state_completions(self):
        """Durably commit a bounded object batch before emitting findings."""

        with self.state_completion_lock():
            pending = getattr(self, "pending_state_completions", None)
            if not pending:
                return
            self.open_state().complete_objects(completion for completion, _file, _findings in pending)
            completed = tuple(pending)
            pending.clear()
            for _completion, file, findings in completed:
                if file is None:
                    continue
                self.emit_findings(file, findings)
                self.completed_files_since_progress += 1
                if self.completed_files_since_progress >= 100:
                    self.completed_files_since_progress = 0
                    self.message_parent("p", {"target_complete": False})

    def emit_findings(self, file, findings):
        """Keep all committed log records, grouping proven same-line console hits."""

        if not findings:
            return
        findings = tuple(findings)
        if isinstance(file, RemoteFile):
            relative = str(file.name).replace("/", "\\").lstrip("\\")
            location = f"\\\\{file.target}\\{file.share}\\{relative}"
        else:
            location = str(file)
        show_context = not getattr(self.parent, "quiet", False)
        try:
            console_views = grouped_console_overrides(location, findings, show_context=show_context)
        except Exception as exc:
            # This is only presentation. A grouping failure must not turn a
            # committed file into an error or prevent its findings being logged.
            console_views = {}
            log.warning(
                f"Console grouping failed for {display_text(location)} ({display_text(type(exc).__name__)}); "
                "displaying all findings separately"
            )
        for index, finding in enumerate(findings):
            message, highlights = finding_log_message(location, finding, show_context=show_context)
            extra = {"finding_highlights": highlights, "finding_severity": finding.severity}
            if index in console_views:
                view = console_views[index]
                if view is None:
                    extra["console_suppressed"] = True
                else:
                    extra["console_message"], extra["console_highlights"], extra["console_severity"] = view
            log.info(
                message,
                extra=extra,
            )

    @staticmethod
    def metadata_finding(file):
        """Represent a selected file even when no content occurrence exists."""

        location = str(file)
        return FindingRecord(
            rule_id="metadata:active-include",
            value=location,
            context="matched active metadata include filters",
            representation="metadata",
            rule_source="cli",
        )

    @property
    def parser_has_rules(self):
        return bool(getattr(self.parent.parser, "has_rules", False))

    @property
    def parser_has_cli_content_filters(self):
        value = getattr(self.parent.parser, "has_cli_content_filters", None)
        if value is None:
            return bool(getattr(self.parent.parser, "content_filters", ()))
        return bool(value)

    def rule_route(self, file):
        if isinstance(file, RemoteFile):
            return getattr(file, "rule_route", None)
        return getattr(self, "local_rule_routes", {}).get(local_object_key(file))

    def evaluate_rule_route(self, metadata):
        resolver = getattr(self.parent.parser, "route_rules", None)
        return resolver(metadata) if resolver is not None else None

    def requires_content(self, file):
        route = self.rule_route(file)
        resolver = getattr(self.parent.parser, "requires_content", None)
        if resolver is None:
            return bool(getattr(self.parent.parser, "content_filters", ()))
        return resolver(route)

    def complete_oversized_file(self, file, size, scope_values, rule_route):
        """Record metadata independently of the content/download size budget.

        Called by both listing paths, before yielding a file to retrieval or
        extraction. Completing it here prevents an explicit --download from
        turning a size-unlimited metadata report into an unlimited file read.
        """

        if 0 <= size <= self.parent.max_filesize:
            return False
        if size < 0:
            reason = f"invalid file size {size}; content and download skipped"
            log.warning(f"Skipped {display_text(file)}: {display_text(reason)}")
            self.complete_file(file, "skipped", reason=reason, content_read=False, content_status="metadata_unavailable")
            return True

        metadata_selected = self.parent.scope_matcher.final_include(**scope_values, content_match=False)
        findings = ()
        if metadata_selected:
            findings = self.metadata_rule_findings(file, rule_route)
            if not findings and not self.parser_has_rules:
                findings = (self.metadata_finding(file),)
        needs_content = self.requires_content(file)
        download_requested = isinstance(file, RemoteFile) and not self.parent.no_download
        if needs_content or download_requested:
            blocked = "content analysis and download" if needs_content and download_requested else (
                "content analysis" if needs_content else "download"
            )
            reason = (
                f"size {size} exceeds content/download limit {self.parent.max_filesize}; "
                f"{blocked} skipped; {len(findings)} metadata findings retained"
            )
            log.warning(f"{display_text(file)}: {display_text(reason)}")
            status = "skipped"
        else:
            reason = "metadata-only processing; content not requested"
            status = "processed"
        self.complete_file(
            file,
            status,
            reason=reason,
            findings=findings,
            content_read=False,
            content_status="blocked_by_size_policy" if needs_content else "not_requested",
        )
        return True

    @staticmethod
    def metadata_rule_findings(file, rule_route):
        if rule_route is None:
            return ()
        location = str(file)
        return tuple(
            FindingRecord(
                rule_id=rule.rule_id,
                value=location,
                context="matched rule metadata predicates; representation=metadata",
                representation=rule.representation,
                rule_source=rule.rule_source,
                rule_schema_version=rule.rule_schema_version,
                rule_pack_id=rule.rule_pack_id,
                rule_pack_version=rule.rule_pack_version,
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                tags=rule.tags,
            )
            for rule in rule_route.metadata_rules
        )

    def cli_content_matched(self, result):
        if not self.parser_has_cli_content_filters:
            return False
        return any(finding.rule_id.startswith("content:") for finding in result.findings)

    def selected_findings(self, file, rule_route, result, selected):
        if not selected:
            return ()
        findings = [*self.metadata_rule_findings(file, rule_route), *result.findings]
        if not findings and not self.parser_has_rules:
            findings.append(self.metadata_finding(file))
        return self.unique_findings(findings)

    def partial_findings(self, file, rule_route, result):
        """Retain successes when another required representation fails."""

        return self.unique_findings([*self.metadata_rule_findings(file, rule_route), *result.findings])

    @staticmethod
    def unique_findings(findings):
        unique = {}
        for finding in findings:
            key = (
                finding.rule_id,
                getattr(finding, "representation", "unknown"),
                getattr(finding, "rule_source", "unknown"),
                getattr(finding, "rule_schema_version", None),
                getattr(finding, "rule_pack_id", None),
                getattr(finding, "rule_pack_version", None),
                getattr(finding, "severity", "medium"),
                getattr(finding, "confidence", "medium"),
                getattr(finding, "category", "uncategorized"),
                tuple(getattr(finding, "tags", ())),
                getattr(finding, "start", None),
                getattr(finding, "end", None),
                finding.value,
                finding.context,
            )
            unique.setdefault(key, finding)
        return tuple(unique.values())

    def local_post_read_identity(self, file):
        """Return whether a local file changed and the identity accepted after a complete read."""

        initial = self.local_initial_metadata.get(local_object_key(file))
        if initial is None:
            return False, None
        try:
            with local_file_descriptor(file, purpose="local post-read identity") as (descriptor, _resolved):
                current = os.fstat(descriptor)
        except (OSError, UnsafeWritePath):
            return True, None
        current_values = (current.st_size, current.st_mtime_ns, current.st_dev, current.st_ino)
        post_read_identity = (
            current.st_size,
            current.st_mtime_ns,
            f"{current.st_dev}:{current.st_ino}",
        )
        return initial != current_values, post_read_identity

    def local_file_changed(self, file):
        """Compatibility helper returning only the post-read change flag."""

        changed, _identity = self.local_post_read_identity(file)
        return changed

    def record_exclusion(self, *, object_key, kind, reason, target=None, share=None, path=None):
        if not self.state_enabled:
            return
        self.open_state().record_exclusion(
            object_key=object_key,
            kind=kind,
            target=target,
            share=share,
            path=path,
            reason=reason,
        )

    def local_directory_excluded(self, path):
        try:
            require_local_path(path, purpose="local scan directory")
        except UnsafeWritePath as exc:
            reason = f"unsafe local scan directory skipped: {exc}"
            log.warning(f"{display_text(path)}: {display_text(reason)}; subtree pruned before enumeration")
            self.record_exclusion(
                object_key=directory_object_key(self.target, None, path),
                kind="directory",
                target=str(pathlib.Path(self.target).resolve()),
                path=str(pathlib.Path(path).absolute()),
                reason=reason,
            )
            return True
        try:
            relative = pathlib.Path(path).relative_to(self.target)
        except (ValueError, OSError):
            relative = pathlib.Path(path)
        reason = self.parent.scope_matcher.directory_exclusion(relative)
        if reason is None:
            return False
        log.info(f"Excluded {display_text(path)}: {display_text(reason)}; subtree pruned")
        self.record_exclusion(
            object_key=directory_object_key(self.target, None, path),
            kind="directory",
            target=str(pathlib.Path(self.target).resolve()),
            path=str(pathlib.Path(path).resolve()),
            reason=reason,
        )
        return True

    @staticmethod
    def remote_last_write_time(entry, change_time):
        """Read precise LastWriteTime for selection, never for file identity.

        Impacket's epoch getter truncates low FILETIME bits. The raw value is
        already in the directory response, so exact epoch subtraction needs no
        additional SMB request. Keep ChangeTime and non-Impacket adapters on
        their historical conversion paths for read verification and resume.
        """

        if isinstance(entry, SharedFile):
            ticks = entry.get_wtime()
            if type(ticks) is not int or not 0 <= ticks <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError("invalid raw LastWriteTime")
            return (ticks - 116_444_736_000_000_000) / 10_000_000
        last_write_reader = getattr(entry, "get_wtime_epoch", None)
        return last_write_reader() if callable(last_write_reader) else change_time

    @staticmethod
    def remote_file_id(entry):
        """Use an SMB file ID when the Impacket directory record exposes one."""

        for attribute in ("get_file_id", "get_fileid"):
            getter = getattr(entry, attribute, None)
            if getter is not None:
                try:
                    return str(getter())
                except Exception:
                    return None
        return None

    @staticmethod
    def remote_file_attributes(entry):
        """Read attributes already present in the SMB directory record."""

        getter = getattr(entry, "get_attributes", None)
        if getter is None:
            return None
        try:
            return int(getter())
        except (TypeError, ValueError):
            return None

    def warn_recall_access(self, object_kind, share, path, smb_attributes, action):
        """Warn before an operation which may recall tiered remote content."""

        indicators = recall_attribute_names(smb_attributes)
        if not indicators:
            return
        remote_path = str(path).replace("/", "\\").lstrip("\\")
        unc_path = f"\\\\{self.target.host}\\{share}"
        if remote_path:
            unc_path += f"\\{remote_path}"
        port_suffix = "" if self.target.port == 445 else f" (SMB port {self.target.port})"
        log.warning(
            f"OFFLINE/HSM {display_text(object_kind)} will be {display_text(action)} and may recall data from remote storage: "
            f"{display_text(unc_path)}{display_text(port_suffix)}; attributes: {display_text(', '.join(indicators))}"
        )

    def parse_local_files(self, files):

        # A target already runs in its own spiderling process. Keeping local
        # parsing here avoids inheriting live per-object state across another
        # process-pool boundary and preserves crash-consistent completion.
        for file in files:
            self.parse_file(file)

    def save_file(self, remote_file):
        """
        Copies retrieved bytes into safely opened local loot storage.
        """
        loot_dest = None
        try:
            loot_root = Path(self.parent.loot_dir).expanduser()
            # MANSPIDER already pins its canonical root during construction.
            # Do not resolve it again: a later symlink substitution must fail,
            # not silently select a different storage root. Normalize only
            # historical direct-library contexts which still pass raw paths.
            if not loot_root.is_absolute() or ".." in loot_root.parts:
                loot_root = normalize_loot_root(loot_root)
            loot_dest = remote_loot_destination(loot_root, remote_file, atomic_replace=True)
            with loot_storage_file(loot_root, loot_dest) as output:
                remote_file.copy_to(output)
            return True
        except ReadOnlySMBViolation:
            raise
        except Exception as exc:
            log.warning(f"Error saving {display_text(remote_file)} to {display_text(loot_dest)}: {display_text(exc)}")
            return False
        finally:
            remote_file.cleanup()

    def get_file(self, remote_file):
        """
        Attempts to retrieve "remote_file" from share and returns True if successful
        """

        try:
            self.warn_recall_access(
                "file",
                remote_file.share,
                remote_file.name,
                remote_file.smb_attributes,
                "read",
            )
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.target)}: Downloading {display_text(remote_file.share)}\\{display_text(remote_file.name)}")
            remote_file.get(self.smb_client)
            remote_file.retrieved = True
            retrieved_size = remote_file.retrieved_size
            remote_file.changed = remote_file.changed or retrieved_size is None or retrieved_size != remote_file.size
            if remote_file.post_read_identity is not None:
                current_size, current_mtime, current_file_id = remote_file.post_read_identity
                remote_file.changed = remote_file.changed or any(
                    (
                        current_size != remote_file.size,
                        remote_file.mtime is not None and current_mtime != remote_file.mtime,
                        bool(remote_file.file_id and current_file_id and current_file_id != remote_file.file_id),
                    )
                )
            return True
        except DFSReferralBlocked:
            raise
        except FileRetrievalError as e:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"{display_text(self.target)}: {display_text(e)}")
            remote_file.retrieval_error = str(e)
            remote_file.cleanup()

        return False

    def verify_remote_files(self, share, path, remote_files):
        """Batch-check post-read identity once per directory without rereading content."""

        if not remote_files:
            return
        fallback_files = []
        for remote_file in remote_files:
            if getattr(remote_file, "post_read_verification_finalized", False):
                # Current retrieval finalizes all verification before parsing,
                # using the single 1+3 budget. Never discover a new identity
                # here after findings already refer to the accepted snapshot.
                if remote_file.changed:
                    log.warning(
                        f"{display_text(remote_file)}: changed or unverified while it was read; completed content is retained"
                    )
                continue
            post_read_identity = remote_file.post_read_identity
            if post_read_identity is None:
                fallback_files.append(remote_file)
                continue
            if remote_file.changed:
                log.warning(f"{display_text(remote_file)}: changed while it was read; completed content is retained")

        if not fallback_files:
            return
        try:
            current_entries = {
                entry.get_longname().casefold(): entry
                for entry in self.smb_client.ls(share, path)
                if not entry.is_directory()
            }
        except ReadOnlySMBViolation:
            raise
        except Exception as exc:
            self.record_counter("post_read_metadata_errors", len(fallback_files))
            log.warning(
                f"Unable to verify post-read metadata for {display_text(self.target)}\\{display_text(share)}\\{display_text(path)}: "
                f"{display_text(type(exc).__name__)}: {display_text(exc)}; completed files are retained and marked changed"
            )
            for remote_file in fallback_files:
                self.mark_remote_file_changed(remote_file)
            return

        for remote_file in fallback_files:
            name = str(remote_file.name).replace("/", "\\").rsplit("\\", 1)[-1]
            current = current_entries.get(name.casefold())
            changed = current is None
            post_read_identity = None
            if current is not None:
                try:
                    current_size = current.get_filesize()
                    current_mtime = current.get_mtime_epoch()
                    current_file_id = self.remote_file_id(current)
                    post_read_identity = (
                        current_size,
                        current_mtime,
                        current_file_id if current_file_id is not None else remote_file.file_id,
                    )
                    changed = any(
                        (
                            current_size != remote_file.size,
                            remote_file.mtime is not None and current_mtime != remote_file.mtime,
                            bool(remote_file.file_id and current_file_id and current_file_id != remote_file.file_id),
                        )
                    )
                except Exception:
                    changed = True
                    self.record_counter("post_read_metadata_errors")
            if changed or remote_file.changed:
                if changed and not remote_file.changed:
                    log.warning(f"{display_text(remote_file)}: changed while or after it was read; completed content is retained")
                self.mark_remote_file_changed(remote_file, post_read_identity=post_read_identity)

    def mark_remote_file_changed(self, remote_file, post_read_identity=None):
        remote_file.changed = True
        if post_read_identity is not None:
            remote_file.size, remote_file.mtime, remote_file.file_id = post_read_identity
        if not self.state_enabled or remote_file.object_id is None:
            return
        with self.state_completion_lock():
            for completion, _file, _findings in reversed(getattr(self, "pending_state_completions", ())):
                if completion["object_id"] != remote_file.object_id:
                    continue
                completion["changed"] = True
                if post_read_identity is not None:
                    completion["post_read_identity"] = post_read_identity
                return
            self.open_state().mark_object_changed(
                remote_file.object_id,
                post_read_identity=post_read_identity,
            )

    def date_match(self, file_time):
        """
        Return True if file modification time matches date filters
        file_time is a unix timestamp
        """

        if file_time is None or not (self.parent.modified_after or self.parent.modified_before):
            return True

        # Keep local calendar comparisons (including repeated/skipped midnight).
        # With no date filters, even a FILETIME outside datetime's range is valid
        # metadata and must not require conversion to a calendar date.
        file_date = datetime.fromtimestamp(file_time)

        # Check modified_after
        if self.parent.modified_after:
            if file_date < self.parent.modified_after:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"{display_text(self.target)}: File too old: {display_text(file_date.strftime('%Y-%m-%d'))}")
                return False

        # Check modified_before
        if self.parent.modified_before:
            if file_date > self.parent.modified_before:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(f"{display_text(self.target)}: File too new: {display_text(file_date.strftime('%Y-%m-%d'))}")
                return False

        return True
