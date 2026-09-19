"""Bounded cleanup of the CLI's own Linux scan session, never the shell group.

The coordinator creates a private session before starting any workers. Both
coordinator and supervisor can stop its remaining writers, including orphaned
grandchildren. /proc enumeration is used only at shutdown, not during scanning.
Each signal uses a pidfd and a checked start time when supported by Linux/Python.
"""

from dataclasses import dataclass
import errno
import os
from pathlib import Path
import signal
import sys
from time import monotonic, sleep


SESSION_MESSAGE = "manspider-private-scan-session-v1"
_own_session = None
_PROC = Path("/proc")
_SUPPORTED = sys.platform.startswith("linux")


class ProcessCleanupError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    parent: int
    group: int
    session: int
    started: int
    state: str


def _identity(pid):
    try:
        fields = (_PROC / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    except (FileNotFoundError, ProcessLookupError):
        return None
    return ProcessIdentity(pid, int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19]), fields[0])


def _same_process(first, second):
    return second is not None and (first.pid, first.started, first.session) == (
        second.pid,
        second.started,
        second.session,
    )


def _send(identity, signum):
    """Never signal an identifier which has been recycled since enumeration."""

    descriptor = None
    try:
        if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
            try:
                descriptor = os.pidfd_open(identity.pid)
            except OSError as exc:
                if exc.errno != errno.ENOSYS:
                    raise
        if not _same_process(identity, _identity(identity.pid)):
            return
        if descriptor is not None:
            signal.pidfd_send_signal(descriptor, signum)
        else:  # Older Linux kernels/Python supported by the package.
            os.kill(identity.pid, signum)
    except ProcessLookupError:
        return
    finally:
        if descriptor is not None:
            os.close(descriptor)


class OwnedScanFamily:
    """A verified private session, identified by its original leader's birth."""

    def __init__(self):
        self.leader = None

    def discover(self, process):
        if not _SUPPORTED or self.leader is not None:
            return self.leader is not None
        pid = getattr(process, "pid", None)
        if not isinstance(pid, int) or pid <= 0:
            return False
        identity = _identity(pid)
        if identity is not None and identity.group == pid and identity.session == pid:
            self.leader = identity
        return self.leader is not None

    def accept(self, message, process):
        if not isinstance(message, tuple) or len(message) != 3 or message[0] != SESSION_MESSAGE:
            return False
        pid, started = message[1:]
        if type(pid) is not int or type(started) is not int or pid != process.pid or started < 0:
            raise ProcessCleanupError("Scan process did not establish the expected private session")
        # This ready message comes from our private child pipe. The leader may
        # already have died and been reaped; its orphan writers still own SID.
        current = _identity(pid)
        if current is not None and (current.group, current.session, current.started) != (pid, pid, started):
            raise ProcessCleanupError("Scan process private-session identity changed")
        if self.leader is not None and (self.leader.pid, self.leader.started) != (pid, started):
            raise ProcessCleanupError("Conflicting scan process private-session identity")
        self.leader = current or ProcessIdentity(pid, 0, pid, pid, started, "X")
        return True

    def members(self, *, exclude_leader=False):
        if self.leader is None:
            return []
        current = _identity(self.leader.pid)
        if current is not None and not _same_process(self.leader, current):
            # The original session is gone; this PID belongs to a later process.
            return []
        members = []
        for entry in _PROC.iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                identity = _identity(int(entry.name))
            except PermissionError:
                continue  # Other users' protected /proc entries cannot be ours.
            if (
                identity is not None
                and identity.session == self.leader.pid
                and identity.started >= self.leader.started
                and identity.state not in ("Z", "X")
                and not (exclude_leader and identity.pid == self.leader.pid)
            ):
                members.append(identity)
        return members

    def stop(self, *, exclude_leader=False, grace=25.0, terminate_grace=3.0, kill_grace=3.0):
        """Stop all live members; repeat enumeration to include a late fork."""

        initial = self.members(exclude_leader=exclude_leader)
        if not initial:
            return False
        for signum, duration in (
            (signal.SIGINT, grace),
            (signal.SIGTERM, terminate_grace),
            (signal.SIGKILL, kill_grace),
        ):
            deadline = monotonic() + duration
            signalled = set()
            while True:
                members = self.members(exclude_leader=exclude_leader)
                if not members:
                    return True
                for identity in members:
                    key = (identity.pid, identity.started)
                    if key not in signalled:
                        _send(identity, signum)
                        signalled.add(key)
                if monotonic() >= deadline:
                    break
                sleep(min(0.05, max(0, deadline - monotonic())))
        remaining = self.members(exclude_leader=exclude_leader)
        if remaining:
            raise ProcessCleanupError("Scan writers did not stop: " + ", ".join(str(item.pid) for item in remaining))
        return True


def enter_scan_process_group():
    """Called only by the CLI coordinator, with startup signals still blocked."""

    global _own_session
    if not _SUPPORTED:
        return None
    os.setsid()
    family = OwnedScanFamily()
    identity = _identity(os.getpid())
    if identity is None or identity.session != identity.pid or identity.group != identity.pid:
        raise ProcessCleanupError("Unable to isolate scan workers from the caller process group")
    family.leader = identity
    _own_session = family
    return SESSION_MESSAGE, identity.pid, identity.started


def stop_scan_descendants():
    """Coordinator barrier before terminal state/report publication."""

    family = _own_session
    if family is None or family.leader.pid != os.getpid():
        return False
    return family.stop(exclude_leader=True, grace=1.0)
