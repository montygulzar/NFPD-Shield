"""Rate limiting for automated actions and Discord API calls.

Two distinct concerns:

1. **Shield's own budget** - a token bucket per guild per purpose, so a
   detection loop (or an attacker deliberately tripping detectors) cannot make
   Shield hammer the Discord API or spam a log channel.
2. **Discord's rate limits** - :func:`call_with_retry` performs bounded
   exponential backoff and honours ``Retry-After`` from 429 responses. It never
   retries a 403/404, which are permanent failures.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass

from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS

log = get_logger("ratelimit")


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class TokenBucket:
    """Per-key token bucket on the monotonic clock."""

    __slots__ = ("burst", "refill_seconds", "_buckets", "_clock")

    def __init__(self, burst: int, refill_seconds: float, clock=None) -> None:  # noqa: ANN001
        self.burst = max(1, burst)
        self.refill_seconds = max(0.001, refill_seconds)
        self._buckets: dict[object, _Bucket] = {}
        self._clock = clock or time.monotonic

    def consume(self, key: object, amount: float = 1.0) -> bool:
        now = self._clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=float(self.burst), updated=now)
            self._buckets[key] = bucket
        elapsed = max(0.0, now - bucket.updated)
        bucket.tokens = min(
            float(self.burst), bucket.tokens + elapsed * (self.burst / self.refill_seconds)
        )
        bucket.updated = now
        if bucket.tokens >= amount:
            bucket.tokens -= amount
            return True
        return False

    def remaining(self, key: object) -> float:
        bucket = self._buckets.get(key)
        if bucket is None:
            return float(self.burst)
        now = self._clock()
        elapsed = max(0.0, now - bucket.updated)
        return min(
            float(self.burst), bucket.tokens + elapsed * (self.burst / self.refill_seconds)
        )

    def drop(self, key: object) -> None:
        self._buckets.pop(key, None)

    def drop_guild(self, guild_id: int) -> None:
        for key in [k for k in self._buckets if isinstance(k, tuple) and k and k[0] == guild_id]:
            del self._buckets[key]


class RateLimiter:
    """Named token buckets (``enforce``, ``notify``, ``snapshot``, ``restore``)."""

    def __init__(
        self,
        *,
        enforce_burst: int = 5,
        enforce_refill: float = 20.0,
        notify_burst: int = 5,
        notify_refill: float = 30.0,
        clock=None,  # noqa: ANN001
    ) -> None:
        self._buckets = {
            "enforce": TokenBucket(enforce_burst, enforce_refill, clock),
            "notify": TokenBucket(notify_burst, notify_refill, clock),
            "snapshot": TokenBucket(3, 60.0, clock),
            "restore": TokenBucket(2, 300.0, clock),
        }

    def allow(self, purpose: str, guild_id: int, *extra: object) -> bool:
        bucket = self._buckets.get(purpose)
        if bucket is None:
            return True
        ok = bucket.consume((guild_id, *extra))
        if not ok:
            METRICS.incr("ratelimit_denied_total", purpose=purpose)
            log.warning(
                "shield rate limit reached",
                extra={"guild_id": guild_id, "purpose": purpose},
            )
        return ok

    def remaining(self, purpose: str, guild_id: int, *extra: object) -> float:
        bucket = self._buckets.get(purpose)
        return bucket.remaining((guild_id, *extra)) if bucket else 0.0

    def drop_guild(self, guild_id: int) -> None:
        for bucket in self._buckets.values():
            bucket.drop_guild(guild_id)


#: HTTP statuses that must never be retried - retrying cannot help and only
#: burns rate-limit budget.
PERMANENT_STATUSES = frozenset({400, 401, 403, 404, 405})


async def call_with_retry(
    coro_factory,  # noqa: ANN001 - zero-arg callable returning a coroutine
    *,
    attempts: int = 4,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    description: str = "discord call",
    sleeper=None,  # noqa: ANN001
):
    """Await ``coro_factory()`` with bounded exponential backoff and jitter.

    Raises the last exception when every attempt fails. ``coro_factory`` must be
    a *factory* because a coroutine object cannot be awaited twice.
    """
    sleep = sleeper or asyncio.sleep
    delay = base_delay
    last_exc: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            return await coro_factory()
        except Exception as exc:  # noqa: BLE001 - re-raised below
            last_exc = exc
            status = getattr(exc, "status", None) or getattr(
                getattr(exc, "response", None), "status", None
            )
            retry_after = getattr(exc, "retry_after", None)
            if status in PERMANENT_STATUSES and status != 429:
                log.warning(
                    "permanent failure, not retrying",
                    extra={"call": description, "status": status, "error": str(exc)},
                )
                raise
            if attempt >= attempts:
                break
            wait = float(retry_after) if retry_after else min(delay, max_delay)
            wait += random.uniform(0, 0.25)  # noqa: S311 - jitter, not crypto
            METRICS.incr("discord_retries_total")
            log.warning(
                "retrying discord call",
                extra={
                    "call": description,
                    "attempt": attempt,
                    "status": status,
                    "sleep": round(wait, 2),
                },
            )
            await sleep(wait)
            delay = min(delay * 2, max_delay)
    assert last_exc is not None
    raise last_exc
