"""Passive, endpoint-local recovery pacing. Never sends health-check traffic."""

import logging
from time import monotonic, sleep

from man_spider.lib.finding_log import display_text


log = logging.getLogger("manspider.smb")


class NetworkRecovery:
    """Bound reconnect pressure after failures, with no healthy-path waiting.

    A successful data/metadata operation resets the backoff; authentication
    alone does not, since a server may accept sessions but keep failing reads.
    No retry is scheduled here: existing bounded callers own their attempts.
    """

    def __init__(self, endpoint, *, clock=None, sleeper=None):
        self.endpoint = endpoint
        self._clock = clock or monotonic
        self._sleep = sleeper or sleep
        self.failures = 0
        self.not_before = 0.0

    def failed(self):
        self.failures = min(self.failures + 1, 6)
        delay = min(30.0, float(2 ** (self.failures - 1)))
        self.not_before = self._clock() + delay

    def succeeded(self):
        self.failures = 0
        self.not_before = 0.0

    def wait(self, check_safety):
        if not self.failures:
            return
        remaining = self.not_before - self._clock()
        if remaining <= 0:
            return
        log.warning(
            "%s: network recovery pause %.1f s before reconnecting; Ctrl+C preserves the session",
            display_text(self.endpoint), remaining,
        )
        while remaining > 0:
            check_safety()
            # Short interruptible waits also observe a safety stop raised by
            # another operation in the worker's exclusive DFS transport group.
            self._sleep(min(remaining, 0.2))
            remaining = self.not_before - self._clock()
        check_safety()
