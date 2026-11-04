"""Monotonic sliding-window counters.

Design notes
------------
* **Monotonic clock for windows.** ``time.monotonic()`` cannot jump backwards
  on NTP correction, so a rate window can never be silently widened or
  collapsed. UTC wall-clock timestamps are used only for persistence and
  reporting.
* **Bounded memory.** Every bucket is trimmed on access and the registry is
  swept periodically, so an idle guild costs nothing and a hostile actor cannot
  grow the process heap without bound.
* **Restart recovery.** :meth:`SlidingWindowRegistry.rehydrate` replays
  persisted events (which carry UTC timestamps) back into monotonic space so a
  process restart mid-raid does not reset every counter to zero.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Hashable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone

WindowKey = tuple[Hashable, ...]

#: Hard cap on retained samples per bucket. A window of 15s cannot legitimately
#: need thousands of samples; the cap bounds memory under flood conditions
#: while still letting the threshold trigger.
MAX_SAMPLES_PER_BUCKET = 512

#: Hard cap on distinct buckets per guild, protecting against key explosion
#: (e.g. an attacker cycling thousands of target IDs).
MAX_BUCKETS_PER_GUILD = 20_000


@dataclass(slots=True)
class WindowHit:
    """Result of feeding one event into a window."""

    key: WindowKey
    count: int
    threshold: int
    window_seconds: float
    first_seen_monotonic: float
    last_seen_monotonic: float
    triggered: bool
    #: Extra per-sample values (e.g. unique mention IDs) accumulated in-window.
    distinct: int = 0

    @property
    def span_seconds(self) -> float:
        return max(0.0, self.last_seen_monotonic - self.first_seen_monotonic)


@dataclass(slots=True)
class _Bucket:
    samples: deque[float] = field(default_factory=deque)
    #: Optional distinct-value tracking, parallel to ``samples``.
    values: deque[Hashable] = field(default_factory=deque)
    last_touch: float = 0.0


class SlidingWindowRegistry:
    """Per-guild collection of sliding windows.

    The registry is intentionally *not* shared across guilds at the key level:
    the guild ID is the first element of every key, and :meth:`drop_guild`
    removes a guild's state wholesale when the bot is removed from it.
    """

    __slots__ = ("_buckets", "_clock", "_last_sweep")

    def __init__(self, clock: callable[[], float] | None = None) -> None:
        self._buckets: dict[WindowKey, _Bucket] = {}
        self._clock = clock or time.monotonic
        self._last_sweep = self._clock()

    # -- core ----------------------------------------------------------
    def add(
        self,
        key: WindowKey,
        *,
        threshold: int,
        window_seconds: float,
        value: Hashable | None = None,
        distinct_threshold: int | None = None,
        now: float | None = None,
    ) -> WindowHit:
        """Record one occurrence and report whether the threshold is crossed.

        ``value``/``distinct_threshold`` support detectors that count *unique*
        things inside the window (unique mention targets), rather than raw
        events.
        """
        current = self._clock() if now is None else now
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket()
            self._buckets[key] = bucket
        bucket.last_touch = current
        bucket.samples.append(current)
        if value is not None:
            bucket.values.append(value)
        self._trim(bucket, current, window_seconds)
        if len(bucket.samples) > MAX_SAMPLES_PER_BUCKET:
            overflow = len(bucket.samples) - MAX_SAMPLES_PER_BUCKET
            for _ in range(overflow):
                bucket.samples.popleft()
                if bucket.values:
                    bucket.values.popleft()

        count = len(bucket.samples)
        distinct = len(set(bucket.values)) if bucket.values else 0
        if distinct_threshold is not None:
            triggered = distinct >= distinct_threshold
            effective_threshold = distinct_threshold
        else:
            triggered = count >= threshold
            effective_threshold = threshold

        return WindowHit(
            key=key,
            count=count,
            threshold=effective_threshold,
            window_seconds=window_seconds,
            first_seen_monotonic=bucket.samples[0] if bucket.samples else current,
            last_seen_monotonic=bucket.samples[-1] if bucket.samples else current,
            triggered=triggered,
            distinct=distinct,
        )

    def peek(self, key: WindowKey, window_seconds: float) -> int:
        bucket = self._buckets.get(key)
        if bucket is None:
            return 0
        self._trim(bucket, self._clock(), window_seconds)
        return len(bucket.samples)

    def reset(self, key: WindowKey) -> None:
        """Clear a bucket, e.g. after an incident fired for that scope."""
        self._buckets.pop(key, None)

    def drop_guild(self, guild_id: int) -> int:
        removed = [k for k in self._buckets if k and k[0] == guild_id]
        for key in removed:
            del self._buckets[key]
        return len(removed)

    def guild_bucket_count(self, guild_id: int) -> int:
        return sum(1 for k in self._buckets if k and k[0] == guild_id)

    def size(self) -> int:
        return len(self._buckets)

    def guild_ids(self) -> set[int]:
        """Guild IDs with live buckets (used by the maintenance sweep)."""
        return {int(key[0]) for key in self._buckets if key and isinstance(key[0], int)}

    # -- maintenance ---------------------------------------------------
    def sweep(self, max_age_seconds: float = 300.0, now: float | None = None) -> int:
        """Drop buckets untouched for longer than any plausible window."""
        current = self._clock() if now is None else now
        self._last_sweep = current
        stale = [
            key
            for key, bucket in self._buckets.items()
            if current - bucket.last_touch > max_age_seconds
        ]
        for key in stale:
            del self._buckets[key]
        return len(stale)

    def enforce_guild_cap(self, guild_id: int) -> int:
        """Evict the oldest buckets for a guild that exceeded the key cap."""
        keys = [(k, b.last_touch) for k, b in self._buckets.items() if k and k[0] == guild_id]
        if len(keys) <= MAX_BUCKETS_PER_GUILD:
            return 0
        keys.sort(key=lambda item: item[1])
        evict = len(keys) - MAX_BUCKETS_PER_GUILD
        for key, _ in keys[:evict]:
            del self._buckets[key]
        return evict

    def rehydrate(
        self,
        key: WindowKey,
        timestamps: Iterable[datetime],
        *,
        window_seconds: float,
        values: Sequence[Hashable] | None = None,
        now_wall: datetime | None = None,
        now_monotonic: float | None = None,
    ) -> int:
        """Replay persisted UTC timestamps into this registry's monotonic space.

        Called at startup from the event log so a restart during an attack does
        not hand the attacker a fresh counter.
        """
        wall_now = now_wall or datetime.now(tz=timezone.utc)
        mono_now = self._clock() if now_monotonic is None else now_monotonic
        bucket = self._buckets.setdefault(key, _Bucket())
        added = 0
        value_list = list(values or [])
        for index, stamp in enumerate(timestamps):
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            age = (wall_now - stamp).total_seconds()
            if age < 0:
                age = 0.0
            if age > window_seconds:
                continue
            bucket.samples.append(mono_now - age)
            if index < len(value_list):
                bucket.values.append(value_list[index])
            added += 1
        bucket.samples = deque(sorted(bucket.samples))
        bucket.last_touch = mono_now
        return added

    # -- internals -----------------------------------------------------
    @staticmethod
    def _trim(bucket: _Bucket, now: float, window_seconds: float) -> None:
        cutoff = now - window_seconds
        samples = bucket.samples
        values = bucket.values
        while samples and samples[0] < cutoff:
            samples.popleft()
            if values:
                values.popleft()


def window_key(guild_id: int, action: str, *parts: Hashable) -> WindowKey:
    """Build a window key. ``guild_id`` is always first so per-guild teardown
    and per-guild caps are cheap, and so two guilds can never share a bucket."""
    return (guild_id, action, *parts)
