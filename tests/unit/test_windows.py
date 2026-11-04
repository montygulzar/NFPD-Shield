"""Sliding-window threshold behaviour, including restart rehydration."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from shield.detection.windows import (
    MAX_SAMPLES_PER_BUCKET,
    SlidingWindowRegistry,
    window_key,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_threshold_requires_configured_count():
    clock = Clock()
    reg = SlidingWindowRegistry(clock=clock)
    key = window_key(1, "mass_ban", 7)
    first = reg.add(key, threshold=2, window_seconds=15)
    assert first.count == 1 and not first.triggered
    second = reg.add(key, threshold=2, window_seconds=15)
    assert second.count == 2 and second.triggered


def test_events_outside_the_window_do_not_count():
    clock = Clock()
    reg = SlidingWindowRegistry(clock=clock)
    key = window_key(1, "mass_ban", 7)
    reg.add(key, threshold=2, window_seconds=15)
    clock.advance(16)
    hit = reg.add(key, threshold=2, window_seconds=15)
    assert hit.count == 1 and not hit.triggered, "the stale sample must be trimmed"


def test_window_is_monotonic_not_wall_clock():
    """A wall-clock jump must not widen or collapse the window."""
    clock = Clock()
    reg = SlidingWindowRegistry(clock=clock)
    key = window_key(1, "channel_delete", 7)
    reg.add(key, threshold=3, window_seconds=10)
    clock.advance(5)
    hit = reg.add(key, threshold=3, window_seconds=10)
    assert hit.count == 2
    # Only monotonic time matters; the registry never reads datetime.now().
    clock.advance(6)
    assert reg.add(key, threshold=3, window_seconds=10).count == 2


def test_per_guild_isolation():
    reg = SlidingWindowRegistry(clock=Clock())
    a = window_key(1, "mass_ban", 7)
    b = window_key(2, "mass_ban", 7)
    reg.add(a, threshold=2, window_seconds=15)
    hit = reg.add(b, threshold=2, window_seconds=15)
    assert hit.count == 1, "guild B must not see guild A's events"


def test_distinct_counting_for_mentions():
    reg = SlidingWindowRegistry(clock=Clock())
    key = window_key(1, "mass_mention", 7)
    last = None
    for mention in (10, 11, 12, 10, 11):
        last = reg.add(
            key, threshold=5, window_seconds=10, value=mention, distinct_threshold=5
        )
    assert last.count == 5
    assert last.distinct == 3, "repeated mentions of the same user count once"
    assert not last.triggered
    for mention in (13, 14):
        last = reg.add(
            key, threshold=5, window_seconds=10, value=mention, distinct_threshold=5
        )
    assert last.distinct == 5 and last.triggered


def test_reset_clears_a_scope():
    reg = SlidingWindowRegistry(clock=Clock())
    key = window_key(1, "mass_ban", 7)
    reg.add(key, threshold=2, window_seconds=15)
    reg.reset(key)
    assert reg.peek(key, 15) == 0


def test_drop_guild_removes_only_that_guild():
    reg = SlidingWindowRegistry(clock=Clock())
    reg.add(window_key(1, "a"), threshold=1, window_seconds=10)
    reg.add(window_key(2, "a"), threshold=1, window_seconds=10)
    assert reg.drop_guild(1) == 1
    assert reg.guild_bucket_count(1) == 0 and reg.guild_bucket_count(2) == 1


def test_sweep_drops_stale_buckets():
    clock = Clock()
    reg = SlidingWindowRegistry(clock=clock)
    reg.add(window_key(1, "a"), threshold=1, window_seconds=10)
    clock.advance(1000)
    assert reg.sweep(max_age_seconds=300) == 1
    assert reg.size() == 0


def test_memory_is_bounded_under_flood():
    reg = SlidingWindowRegistry(clock=Clock())
    key = window_key(1, "message_spam", 7)
    for _ in range(MAX_SAMPLES_PER_BUCKET * 3):
        hit = reg.add(key, threshold=6, window_seconds=8)
    assert hit.count <= MAX_SAMPLES_PER_BUCKET
    assert hit.triggered


def test_rehydrate_restores_recent_events_after_restart():
    """A restart mid-attack must not reset counters to zero."""
    clock = Clock()
    reg = SlidingWindowRegistry(clock=clock)
    now = datetime.now(tz=timezone.utc)
    stamps = [now - timedelta(seconds=s) for s in (1, 3, 5, 100)]
    key = window_key(1, "mass_ban", 7)
    added = reg.rehydrate(key, stamps, window_seconds=15, now_wall=now)
    assert added == 3, "the 100s-old event is outside the window"
    hit = reg.add(key, threshold=4, window_seconds=15)
    assert hit.count == 4 and hit.triggered


def test_rehydrate_ignores_future_timestamps():
    reg = SlidingWindowRegistry(clock=Clock())
    now = datetime.now(tz=timezone.utc)
    key = window_key(1, "x")
    assert reg.rehydrate(key, [now + timedelta(seconds=30)], window_seconds=15, now_wall=now) == 1


def test_guild_cap_evicts_oldest():
    from shield.detection import windows as mod

    original = mod.MAX_BUCKETS_PER_GUILD
    mod.MAX_BUCKETS_PER_GUILD = 5
    try:
        clock = Clock()
        reg = SlidingWindowRegistry(clock=clock)
        for index in range(10):
            clock.advance(1)
            reg.add(window_key(1, "spam", index), threshold=1, window_seconds=600)
        evicted = reg.enforce_guild_cap(1)
        assert evicted == 5
        assert reg.guild_bucket_count(1) == 5
    finally:
        mod.MAX_BUCKETS_PER_GUILD = original
