from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after: float | None


class RateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: int,
        time_fn: Callable[[], float] | None = None,
    ) -> None:
        self._limit = limit
        self._window_seconds = window_seconds
        self._time_fn = time_fn or time.monotonic
        self._events: dict[str, deque[float]] = {}

    def allow(self, key: str) -> RateLimitDecision:
        now = self._time_fn()
        window_start = now - self._window_seconds
        bucket = self._events.setdefault(key, deque())
        while bucket and bucket[0] < window_start:
            bucket.popleft()
        if len(bucket) >= self._limit:
            retry_after = self._window_seconds - (now - bucket[0]) if bucket else None
            return RateLimitDecision(allowed=False, retry_after=retry_after)
        bucket.append(now)
        return RateLimitDecision(allowed=True, retry_after=None)
