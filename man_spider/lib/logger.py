import logging
import os
import stat
from copy import copy
from sys import stdout
from pathlib import Path
from datetime import datetime
from uuid import uuid4
from multiprocessing import get_context
from logging.handlers import QueueHandler, QueueListener

from man_spider.path_safety import (
    local_directory_descriptor,
    require_local_file_descriptor,
    require_local_write_path,
)
from man_spider.state import default_state_directory


### PRETTY COLORS ###


class ColoredFormatter(logging.Formatter):
    severity_colors = {
        "critical": "\033[1;97;41m",  # bold white on red
        "high": "\033[1;91m",  # bright red
        "medium": "\033[1;93m",  # bright yellow
        "low": "\033[1;94m",  # bright blue
        "info": "\033[1;96m",  # bright cyan
    }
    match_color = "\033[1;96m"  # bold bright cyan; context stays uncolored

    color_mapping = {
        "DEBUG": 69,  # blue
        "INFO": 118,  # green
        "WARNING": 208,  # orange
        "ERROR": 196,  # red
        "CRITICAL": 196,  # red
    }

    char_mapping = {
        "DEBUG": "*",
        "INFO": "+",
        "WARNING": "-",
        "ERROR": "!",
        "CRITICAL": "!!!",
    }

    prefix = "\033[1;38;5;"
    suffix = "\033[0m"

    def __init__(self, pattern, *, use_color=None):

        super().__init__(pattern)
        self.use_color = use_color

    def format(self, record):

        colored_record = copy(record)
        enabled = self.use_color
        if enabled is None:
            enabled = stdout.isatty() and os.environ.get("TERM") != "dumb"
        if os.environ.get("NO_COLOR"):
            enabled = False
        if not enabled:
            return logging.Formatter.format(self, colored_record)

        # Spans belong to the already escaped plain message sent by a worker.
        # Only this private record gets ANSI: QueueListener's file handler sees
        # the unchanged original, regardless of handler order.
        highlights = getattr(record, "finding_highlights", ())
        if highlights:
            message = record.getMessage()
            pieces = []
            cursor = 0
            for start, end, role in highlights:
                color = (
                    self.severity_colors.get(getattr(record, "finding_severity", ""), self.match_color)
                    if role == "severity"
                    else self.match_color
                )
                pieces.extend((message[cursor:start], color, message[start:end], self.suffix))
                cursor = end
            pieces.append(message[cursor:])
            colored_record.msg = "".join(pieces)
            colored_record.args = ()

        levelname = colored_record.levelname
        levelchar = self.char_mapping.get(levelname, "+")
        seq = self.color_mapping.get(levelname, 15)  # default white
        colored_levelname = f"{self.prefix}{seq}m[{levelchar}]{self.suffix}"
        colored_record.levelname = colored_levelname

        return logging.Formatter.format(self, colored_record)

    @classmethod
    def green(cls, s):

        return cls.color(s)

    @classmethod
    def red(cls, s):

        return cls.color(s, level="ERROR")

    @classmethod
    def color(cls, s, level="INFO"):

        color = cls.color_mapping.get(level)
        return f"{cls.prefix}{color}m{s}{cls.suffix}"


class CustomQueueListener(QueueListener):
    """
    Ignore errors in the monitor thread that result from a race condition when the program exits
    """

    def _monitor(self):
        try:
            super()._monitor()
        except Exception:
            pass


### LOG TO STDERR ###


class ConsoleHandler(logging.StreamHandler):
    """Select a per-line view without altering the full file-log record.

    Grouping is independent of TTY/color support, including redirected stdout.
    Never attach this suppression to the logger itself: the file handler must
    still receive every original finding.
    """

    def handle(self, record):
        if getattr(record, "console_suppressed", False):
            return False
        if hasattr(record, "console_message"):
            record = copy(record)
            record.msg = record.console_message
            record.args = ()
            record.finding_highlights = record.console_highlights
            record.finding_severity = record.console_severity
        return super().handle(record)


console = ConsoleHandler(stdout)
# tell the handler to use this format
console.setFormatter(ColoredFormatter("%(levelname)s %(message)s"))

log_queue = get_context("spawn").Queue()
sender = QueueHandler(log_queue)
logging.getLogger("manspider").handlers = [sender]
logging.getLogger("manspider").propagate = False

# File creation is intentionally lazy. Merely importing MANSPIDER must not
# touch HOME, which may be redirected to a mounted customer share.
listener = None
handler = None
logpath = None


class _OwnedStreamHandler(logging.StreamHandler):
    """A StreamHandler which owns and closes its descriptor-backed stream."""

    def close(self):
        try:
            if self.stream is not None:
                self.stream.close()
        finally:
            super().close()


def _prepare_listener(state_path=None):
    global listener, handler, logpath
    if listener is not None:
        if state_path is None:
            return listener
        thread = getattr(listener, "_thread", None)
        if thread is not None and thread.is_alive():
            raise ValueError("Cannot replace the text log while its listener is running")
        stop_listener(True)
    # The supervisor selects the state after automatic resume selection. A
    # resume shares that database, but must never append to a previous log.
    state_path = Path(state_path).expanduser() if state_path is not None else None
    logdir = require_local_write_path(
        state_path.parent if state_path is not None else default_state_directory(),
        purpose="text log",
    )
    prefix = state_path.stem if state_path is not None else "manspider"
    logfile = f"{prefix}.run_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{uuid4().hex[:8]}.log"
    if not (hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd):
        raise OSError("Safe logging requires no-follow directory descriptors on this platform")
    with local_directory_descriptor(
        logdir,
        purpose="text log directory",
        create=True,
        # Logging is initialized before ScanLease. Do not make its new state
        # directory less private than the directory SQLite would have created.
        created_mode=0o700,
    ) as (directory_descriptor, logdir):
        destination = require_local_write_path(logdir / logfile, purpose="text log file")
        descriptor = os.open(
            logfile,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW,
            0o664,
            dir_fd=directory_descriptor,
        )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("Text log destination must be a private regular file")
        require_local_file_descriptor(descriptor, purpose="text log file")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o664)
        stream = open(descriptor, "a", encoding="utf-8", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise
    handler = _OwnedStreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    listener = CustomQueueListener(log_queue, console, handler)
    logpath = destination
    return listener


def prepare_logging(state_path=None) -> Path:
    """Open a new invocation log beside its state before launching workers."""

    _prepare_listener(state_path)
    return logpath


def log_scan_summary(message: str) -> None:
    """Synchronously display/persist a review before asking for approval.

    A queued log alone is not a display barrier. This is called only by the
    supervisor (or a direct library caller), never by a scan worker. Handler
    locks keep each full summary record intact alongside ordinary queued logs.
    """

    record = logging.LogRecord("manspider", logging.INFO, __file__, 0, message, (), None)
    _prepare_listener().handle(record)
    console.flush()
    handler.flush()


def start_listener() -> bool:
    """Start the shared listener once and report whether this caller owns it."""

    current_listener = _prepare_listener()
    thread = getattr(current_listener, "_thread", None)
    if thread is not None and thread.is_alive():
        return False
    current_listener.start()
    return True


def stop_listener(owned: bool) -> None:
    global listener, handler, logpath
    if owned and listener is not None:
        try:
            thread = getattr(listener, "_thread", None)
            if thread is not None and thread.ident is not None:
                listener.stop()
            else:
                # Early startup cancellation can leave records in the shared
                # queue before its listener thread ever starts. Flush through
                # the same FIFO barrier as stop(), without creating a thread;
                # a later library invocation must not inherit these records.
                listener.enqueue_sentinel()
                task_done = getattr(listener.queue, "task_done", None)
                while True:
                    record = listener.dequeue(True)
                    try:
                        if record is listener._sentinel:
                            break
                        listener.handle(record)
                    finally:
                        if task_done is not None:
                            task_done()
        finally:
            current_handler = handler
            listener = handler = logpath = None
            if current_handler is not None:
                current_handler.close()


def configure_worker_logging(queue):
    """Route spawned worker records to the listener owned by the CLI process."""

    logging.getLogger("manspider").handlers = [QueueHandler(queue)]
    logging.getLogger("manspider").propagate = False
