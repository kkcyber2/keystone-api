"""Token-bucket rate limiting, keyed by caller identity."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """A token bucket per key.

    `capacity` tokens refill over `window` seconds. A caller may burst up to
    `capacity` requests, then must wait for the bucket to refill.
    """

    def __init__(self, capacity: int, window: float, *, clock=time.monotonic) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if window <= 0:
            raise ValueError("window must be positive")
        self.capacity = float(capacity)
        self.window = float(window)
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _refill_rate(self) -> float:
        return self.capacity / self.window

    def check(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        """Consume `cost` tokens. Returns (allowed, seconds_until_next_token)."""
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity, updated=now)
                self._buckets[key] = bucket
            elapsed = max(0.0, now - bucket.updated)
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self._refill_rate())
            bucket.updated = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, 0.0
            deficit = cost - bucket.tokens
            return False, deficit / self._refill_rate()

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)
