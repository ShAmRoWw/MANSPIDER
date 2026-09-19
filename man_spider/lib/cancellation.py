"""Process-local cancellation which survives an unraisable signal exception.

Signal handlers must not acquire multiprocessing/thread locks. A plain latch
records the request before KeyboardInterrupt can be swallowed by a destructor;
normal work checkpoints deliver it again. Only actual cleanup suppresses it.
"""

import os


_owner = None
_requested = False
_cleaning_up = False


def reset_worker_cancellation():
    """Initialize once per process, not at each nested worker entrypoint."""

    global _owner, _requested, _cleaning_up
    owner = os.getpid()
    if _owner != owner:
        _owner = owner
        _requested = False
        _cleaning_up = False


def request_worker_cancellation():
    """Latch before raising; coalesce subsequent signals while unwinding."""

    global _requested
    first = not _requested and not _cleaning_up
    _requested = True
    return first


def check_worker_cancellation():
    """Cheap, I/O-free checkpoint at work boundaries, never during cleanup."""

    if _requested and not _cleaning_up and _owner == os.getpid():
        raise KeyboardInterrupt


def begin_worker_cleanup():
    global _cleaning_up
    _cleaning_up = True
