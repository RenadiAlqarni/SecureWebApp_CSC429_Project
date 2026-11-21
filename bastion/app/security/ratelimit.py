"""
Login throttling (extra hardening, secure mode).

After 5 failed logins for the same username from the same IP address within
5 minutes, further attempts are refused with HTTP 429 until the window passes.
This turns online password guessing from thousands of tries per minute into a
handful. Kept in memory for simplicity; a multi-server deployment would keep
these counters in Redis or the database instead.
"""
import threading
import time
from collections import defaultdict, deque


class LoginThrottle:
    def __init__(self, max_attempts=5, window_seconds=300):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._failures = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key, now):
        q = self._failures[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def retry_after(self, key):
        """Seconds the caller must wait, or 0 if a new attempt is allowed."""
        now = time.monotonic()
        with self._lock:
            q = self._prune(key, now)
            if len(q) < self.max_attempts:
                return 0
            return int(self.window - (now - q[0])) + 1

    def record_failure(self, key):
        with self._lock:
            self._failures[key].append(time.monotonic())

    def reset(self, key):
        with self._lock:
            self._failures.pop(key, None)
