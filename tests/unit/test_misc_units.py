"""Rate limiting, self-action suppression, redaction, dedupe keys, snapshots."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import discord
import pytest

from shield.backup import serializer
from shield.constants import ActionKey, EventSource
from shield.enforcement.ratelimit import RateLimiter, TokenBucket, call_with_retry
from shield.enforcement.selfguard import SelfActionGuard
from shield.events.normalize import NormalizedEvent, hash_content
from shield.observability.logging import (
    JsonFormatter,
    RedactionFilter,
    configure_logging,
    scrub,
)
from tests.conftest import FAKE_DISCORD_TOKEN, make_http_error


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# -- rate limiting -----------------------------------------------------
def test_token_bucket_limits_burst_then_refills():
    clock = Clock()
    bucket = TokenBucket(3, 30.0, clock=clock)
    assert [bucket.consume("k") for _ in range(4)] == [True, True, True, False]
    clock.advance(10)  # one token per 10s
    assert bucket.consume("k")
    assert not bucket.consume("k")


def test_rate_limiter_is_per_guild():
    clock = Clock()
    limiter = RateLimiter(enforce_burst=1, enforce_refill=60.0, clock=clock)
    assert limiter.allow("enforce", 1)
    assert not limiter.allow("enforce", 1)
    assert limiter.allow("enforce", 2), "guild 2 must have its own budget"


def test_rate_limiter_drop_guild_resets_budget():
    limiter = RateLimiter(enforce_burst=1, enforce_refill=600.0, clock=Clock())
    limiter.allow("enforce", 1)
    assert not limiter.allow("enforce", 1)
    limiter.drop_guild(1)
    assert limiter.allow("enforce", 1)


async def test_call_with_retry_retries_transient_errors():
    attempts = {"n": 0}

    async def flaky():  # noqa: ANN202
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise make_http_error(500)
        return "done"

    result = await call_with_retry(flaky, attempts=5, sleeper=_instant)
    assert result == "done" and attempts["n"] == 3


async def test_call_with_retry_honours_retry_after():
    slept: list[float] = []

    async def sleeper(seconds: float) -> None:
        slept.append(seconds)

    calls = {"n": 0}

    async def flaky():  # noqa: ANN202
        calls["n"] += 1
        if calls["n"] == 1:
            raise make_http_error(429, retry_after=2.5)
        return "ok"

    assert await call_with_retry(flaky, attempts=3, sleeper=sleeper) == "ok"
    assert slept and 2.5 <= slept[0] <= 2.8


async def test_call_with_retry_does_not_retry_forbidden():
    calls = {"n": 0}

    async def denied():  # noqa: ANN202
        calls["n"] += 1
        raise make_http_error(403)

    with pytest.raises(discord.Forbidden):
        await call_with_retry(denied, attempts=5, sleeper=_instant)
    assert calls["n"] == 1


async def test_call_with_retry_gives_up_and_raises():
    async def always_fails():  # noqa: ANN202
        raise make_http_error(503)

    with pytest.raises(discord.HTTPException):
        await call_with_retry(always_fails, attempts=2, sleeper=_instant)


async def _instant(_seconds: float) -> None:
    await asyncio.sleep(0)


# -- self-action suppression -------------------------------------------
def test_selfguard_consumes_one_credit_per_event():
    clock = Clock()
    guard = SelfActionGuard(ttl=30.0, clock=clock)
    guard.register(1, "channel_create", count=3)
    assert [guard.is_self(1, "channel_create", 500 + n) for n in range(4)] == [
        True,
        True,
        True,
        False,
    ]


def test_selfguard_matches_specific_object_id():
    guard = SelfActionGuard(ttl=30.0, clock=Clock())
    guard.register(1, "role_delete", 77)
    assert guard.is_self(1, "role_delete", 77)
    assert not guard.is_self(1, "role_delete", 78)


def test_selfguard_expires():
    clock = Clock()
    guard = SelfActionGuard(ttl=5.0, clock=clock)
    guard.register(1, "channel_create")
    clock.advance(10)
    assert not guard.is_self(1, "channel_create")


def test_selfguard_is_per_guild():
    guard = SelfActionGuard(ttl=30.0, clock=Clock())
    guard.register(1, "channel_create")
    assert not guard.is_self(2, "channel_create")
    guard.clear_guild(1)
    assert not guard.is_self(1, "channel_create")


def test_selfguard_always_recognises_the_bot_user():
    guard = SelfActionGuard(ttl=30.0, clock=Clock())
    guard.bind_bot(42)
    assert guard.is_self(1, "anything", 42)


# -- dedupe keys -------------------------------------------------------
def make_event(**kwargs) -> NormalizedEvent:  # noqa: ANN003
    base = dict(
        guild_id=1,
        action_key=ActionKey.CHANNEL_DELETE,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    base.update(kwargs)
    return NormalizedEvent(**base)


def test_audit_entry_id_dominates_the_dedupe_key():
    event = make_event(target_id=5, actor_id=6, audit_entry_id=123)
    assert event.dedupe_key.endswith("audit:123")


def test_same_target_and_actor_dedupe_together():
    a = make_event(target_id=5, actor_id=6)
    b = make_event(target_id=5, actor_id=6)
    assert a.dedupe_key == b.dedupe_key


def test_different_guilds_never_share_a_dedupe_key():
    a = make_event(guild_id=1, target_id=5)
    b = make_event(guild_id=2, target_id=5)
    assert a.dedupe_key != b.dedupe_key


def test_content_hash_distinguishes_messages():
    moment = datetime.now(tz=timezone.utc)
    a = make_event(
        action_key=ActionKey.JOIN_FLOOD, occurred_at=moment, content_hash="aaa", actor_id=1
    )
    b = make_event(
        action_key=ActionKey.JOIN_FLOOD, occurred_at=moment, content_hash="bbb", actor_id=1
    )
    assert a.dedupe_key != b.dedupe_key


def test_scope_key_groups_actor_and_action():
    assert make_event(actor_id=9).scope_key() == "channel_delete:9"
    assert make_event(actor_id=None).scope_key() == "channel_delete:unattributed"


def test_occurred_at_is_normalised_to_utc():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    assert make_event(occurred_at=naive).occurred_at.tzinfo is timezone.utc


def test_hash_content_is_normalising_and_non_reversible():
    assert hash_content("Hello   WORLD") == hash_content("hello world")
    assert hash_content("a") != hash_content("b")
    assert "hello" not in hash_content("hello")


# -- redaction ---------------------------------------------------------
def test_scrub_removes_tokens_webhooks_and_dsns():
    token = FAKE_DISCORD_TOKEN
    text = (
        f"token={token} "
        "hook=https://discord.com/api/webhooks/123456789/abcdefghijklmnop "
        "dsn=postgresql+asyncpg://user:supersecret@host/db"
    )
    cleaned = scrub(text)
    assert token not in cleaned
    assert "abcdefghijklmnop" not in cleaned
    assert "supersecret" not in cleaned


def test_scrub_redacts_sensitive_keys_recursively():
    payload = {"password": "p", "nested": {"api_key": "k", "safe": 1}, "list": [{"secret": "s"}]}
    cleaned = scrub(payload)
    assert cleaned["password"] == "***redacted***"
    assert cleaned["nested"]["api_key"] == "***redacted***"
    assert cleaned["nested"]["safe"] == 1
    assert cleaned["list"][0]["secret"] == "***redacted***"


def test_redaction_filter_scrubs_log_records(monkeypatch):
    token = FAKE_DISCORD_TOKEN
    monkeypatch.setenv("DISCORD_TOKEN", token)
    filt = RedactionFilter()
    filt.refresh()
    record = logging.LogRecord(
        "shield.test", logging.INFO, "f.py", 1, f"leak {token}", None, None
    )
    record.password = "hunter2"
    record.guild_id = 5
    filt.filter(record)
    rendered = JsonFormatter().format(record)
    assert token not in rendered
    assert "hunter2" not in rendered
    assert '"guild_id": 5' in rendered


def test_configure_logging_is_idempotent(shield_config):
    first = configure_logging(shield_config.logging)
    handlers = len(logging.getLogger().handlers)
    configure_logging(shield_config.logging)
    assert len(logging.getLogger().handlers) == handlers
    assert first.name == "shield"


# -- snapshots ---------------------------------------------------------
def test_snapshot_round_trip_with_encryption():
    from cryptography.fernet import Fernet

    payload = {"schema_version": 1, "guild": {"id": 1, "name": "g"}, "roles": [], "channels": []}
    key = Fernet.generate_key().decode()
    ciphertext = serializer.encrypt_payload(payload, key)
    assert b"guild" not in ciphertext
    assert serializer.decrypt_payload(ciphertext, key) == payload


def test_wrong_key_fails_loudly():
    from cryptography.fernet import Fernet

    payload = {"a": 1}
    ciphertext = serializer.encrypt_payload(payload, Fernet.generate_key().decode())
    with pytest.raises(serializer.SnapshotEncryptionError):
        serializer.decrypt_payload(ciphertext, Fernet.generate_key().decode())


def test_checksum_is_stable_across_key_order():
    a = {"x": 1, "y": [1, 2]}
    b = {"y": [1, 2], "x": 1}
    assert serializer.checksum(a) == serializer.checksum(b)
    assert serializer.checksum(a) != serializer.checksum({"x": 2, "y": [1, 2]})


def test_validate_rejects_truncated_snapshot():
    errors = serializer.validate({"schema_version": 1, "guild": {"id": 1}, "roles": [], "categories": [], "channels": []})
    assert any("@everyone" in e for e in errors)


def test_validate_accepts_a_good_snapshot():
    payload = {
        "schema_version": 1,
        "guild": {"id": 1, "name": "g"},
        "roles": [{"name": "@everyone", "permissions": 0, "is_default": True}],
        "categories": [],
        "channels": [{"name": "general", "type": "text"}],
    }
    assert serializer.validate(payload) == []
