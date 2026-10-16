"""Agent-owned reachability watch for the configured network target.

The client is not the authority on machine connectivity. The agent probes the
configured target itself, debounces the result, and records a durable event when
connectivity is lost or regained, so a client that reconnects later can still
show that the machine was isolated and for how long.

The probe is a dependency-free TCP connect. It is injectable so the state
machine can be tested without touching real sockets.
"""
from __future__ import annotations

import socket

DEFAULT_TARGET = "1.1.1.1"
DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 3.0
DEFAULT_DOWN_STREAK = 2
DEFAULT_UP_STREAK = 1

STATE_UNKNOWN = "unknown"
STATE_UP = "up"
STATE_DOWN = "down"


def split_target(value: object, default_port: int = DEFAULT_PORT) -> tuple[str, int]:
    """Split ``host``, ``host:port`` or ``[v6]:port`` into a ``(host, port)`` pair."""
    text = str(value or "").strip()
    if not text:
        text = DEFAULT_TARGET
    if text.startswith("["):
        host, separator, rest = text[1:].partition("]")
        if separator and rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
            if 1 <= port <= 65535:
                return host or DEFAULT_TARGET, port
        return host or DEFAULT_TARGET, default_port
    if text.count(":") == 1:
        host, _, port_text = text.partition(":")
        if host and port_text.isdigit():
            port = int(port_text)
            if 1 <= port <= 65535:
                return host, port
    return text, default_port


def tcp_reachable(target: object, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Return ``True`` only when a TCP connection to the target completes."""
    host, port = split_target(target)
    try:
        with socket.create_connection((host, port), max(0.1, float(timeout))):
            return True
    except OSError:
        return False


class NetworkWatch:
    """Debounced up/down state machine for one reachability target.

    A single failed probe does not raise a false alarm: the watch reports
    ``down`` only after ``down_streak`` consecutive failures and returns to
    ``up`` after ``up_streak`` consecutive successes. The very first resolved
    outcome establishes the state without being reported as a transition.
    """

    def __init__(self, down_streak: int = DEFAULT_DOWN_STREAK, up_streak: int = DEFAULT_UP_STREAK):
        self.down_streak = max(1, int(down_streak))
        self.up_streak = max(1, int(up_streak))
        self._state = STATE_UNKNOWN
        self._failures = 0
        self._successes = 0
        self._since: float | None = None
        self._down_since: float | None = None
        self._first_failure_at: float | None = None
        self._checked_at: float | None = None
        self._seconds_down = 0
        self._target: str | None = None
        self._changed = False

    def evaluate(self, reachable: bool, now: float, target: object = None) -> dict:
        """Feed one probe outcome and return the resulting state snapshot."""
        reachable = bool(reachable)
        self._checked_at = float(now)
        if target is not None:
            self._target = str(target)
        self._changed = False
        if reachable:
            self._successes += 1
            self._failures = 0
            self._first_failure_at = None
            threshold = 1 if self._state == STATE_UNKNOWN else self.up_streak
            if self._state != STATE_UP and self._successes >= threshold:
                previous = self._state
                self._state = STATE_UP
                self._since = float(now)
                if previous == STATE_DOWN:
                    self._seconds_down = max(0, int(now - (self._down_since or now)))
                    self._changed = True
                self._down_since = None
        else:
            self._failures += 1
            self._successes = 0
            if self._first_failure_at is None:
                self._first_failure_at = float(now)
            if self._state != STATE_DOWN and self._failures >= self.down_streak:
                self._state = STATE_DOWN
                self._down_since = self._first_failure_at
                self._seconds_down = 0
                self._changed = True
                self._since = float(now)
        return self.status()

    def status(self) -> dict:
        """Current state without probing the network."""
        return {"state": self._state, "changed": self._changed, "target": self._target,
                "checked_at": self._checked_at, "since": self._since,
                "down_since": self._down_since, "seconds_down": self._seconds_down,
                "failures": self._failures, "down_streak": self.down_streak,
                "up_streak": self.up_streak}
