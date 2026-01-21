from __future__ import annotations

from regulon.rate_limit import RateLimiter


def test_rate_limiter_enforces_window() -> None:
    now = 0.0

    def time_fn() -> float:
        return now

    limiter = RateLimiter(limit=2, window_seconds=10, time_fn=time_fn)
    decision = limiter.allow("client")
    assert decision.allowed
    decision = limiter.allow("client")
    assert decision.allowed

    decision = limiter.allow("client")
    assert not decision.allowed

    now = 11.0
    decision = limiter.allow("client")
    assert decision.allowed
