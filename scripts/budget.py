"""Global counters + limits for the deep (enumerated) audit.

Tracks org-nodes visited and stackql queries issued, plus a wall-clock timeout.
Any limit set to -1 means unlimited (the default). When a limit is reached,
workers should stop starting new work and analysis proceeds on the partial
result set already collected.

Caps are soft within the concurrency window: `should_stop()` is checked before a
worker starts new work, so a few in-flight queries may finish past the limit.
Used only by discover.py (the deep audit); the shallow audit is unaffected.
"""

from __future__ import annotations

import threading
import time


class Budget:
    def __init__(self, *, max_nodes: int = -1, max_queries: int = -1, timeout_seconds: float = -1):
        self.max_nodes = max_nodes
        self.max_queries = max_queries
        self.timeout_seconds = timeout_seconds
        self._nodes = 0
        self._queries = 0
        self._lock = threading.Lock()
        self._start = time.monotonic()

    @classmethod
    def from_env(cls, env) -> "Budget":
        def _num(name: str) -> int:
            try:
                return int(env.get(name, -1))
            except (TypeError, ValueError):
                return -1
        return cls(
            max_nodes=_num("STACKQL_DEEP_MAX_NODES"),
            max_queries=_num("STACKQL_DEEP_MAX_QUERIES"),
            timeout_seconds=_num("STACKQL_DEEP_TIMEOUT"),
        )

    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def add_node(self) -> None:
        with self._lock:
            self._nodes += 1

    def add_query(self) -> None:
        with self._lock:
            self._queries += 1

    def should_stop(self) -> str | None:
        """Return a human-readable reason if any limit is reached, else None."""
        with self._lock:
            nodes, queries = self._nodes, self._queries
        if self.max_nodes >= 0 and nodes >= self.max_nodes:
            return f"node limit reached ({self.max_nodes})"
        if self.max_queries >= 0 and queries >= self.max_queries:
            return f"query limit reached ({self.max_queries})"
        if self.timeout_seconds >= 0 and self.elapsed() >= self.timeout_seconds:
            return f"timeout reached ({self.timeout_seconds:g}s)"
        return None

    def snapshot(self) -> dict:
        with self._lock:
            return {"nodes": self._nodes, "queries": self._queries, "elapsed_s": round(self.elapsed(), 1)}

    def describe_limits(self) -> str:
        def fmt(v, suffix=""):
            return "∞" if v < 0 else f"{v}{suffix}"
        return (f"nodes={fmt(self.max_nodes)}, queries={fmt(self.max_queries)}, "
                f"timeout={fmt(self.timeout_seconds, 's')}")
