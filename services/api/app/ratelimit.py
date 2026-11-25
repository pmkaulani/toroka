from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """Sliding-window limiter, in memory (one process). Use Redis or the gateway when running several workers."""

    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._distinct: dict[str, dict[str, float]] = defaultdict(dict)
        self._lock = threading.Lock()
        self._windows: dict[str, float] = {}
        self._ops = 0

    def hit(self, key: str, limit: int, window: float) -> float:
        """Returns 0 if allowed, else seconds to wait."""
        now = time.monotonic()
        with self._lock:
            self._maybe_sweep(now)
            self._windows[key] = window
            q = self._hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return max(1.0, q[0] + window - now)
            q.append(now)
            return 0.0

    def _maybe_sweep(self, now: float) -> None:
        """Every 1024 calls drop keys whose whole window has expired (otherwise the dicts grow forever)."""
        self._ops += 1
        if self._ops % 1024:
            return
        for k in [k for k, q in self._hits.items() if not q or q[-1] <= now - self._windows.get(k, 0.0)]:
            self._hits.pop(k, None)
            self._windows.pop(k, None)
        for k in [k for k, d in self._distinct.items() if not d]:
            self._distinct.pop(k, None)

    def distinct(self, key: str, item: str, limit: int, window: float) -> float:
        """Caps how many different identifiers one client may look up (anti-enumeration)."""
        now = time.monotonic()
        with self._lock:
            self._maybe_sweep(now)
            d = self._distinct[key]
            for k in [k for k, t in d.items() if t <= now - window]:
                del d[k]
            if item not in d and len(d) >= limit:
                return max(1.0, min(d.values()) + window - now)
            d.setdefault(item, now)
            return 0.0
