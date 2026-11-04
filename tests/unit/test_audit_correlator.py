"""Audit-log attribution: stale entries, missing permissions, reuse, retries."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import discord

from shield.audit.correlator import AuditCorrelator
from shield.constants import ActionKey, Confidence
from tests.conftest import audit_entry, build_guild, make_http_error, perms

ATTACKER = 400000000000000001
TARGET = 500000000000000001


async def no_sleep(_seconds: float) -> None:
    return None


def correlator(**kwargs) -> AuditCorrelator:  # noqa: ANN003
    kwargs.setdefault("delay", 0.0)
    kwargs.setdefault("window", 20.0)
    kwargs.setdefault("max_attempts", 2)
    kwargs.setdefault("sleeper", no_sleep)
    return AuditCorrelator(**kwargs)


async def test_confirmed_attribution_when_target_matches():
    guild = build_guild()
    guild.audit_entries = [
        audit_entry(
            entry_id=1,
            actor_id=ATTACKER,
            target_id=TARGET,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=0.5,
        )
    ]
    result = await correlator().attribute(
        guild,
        action_key=ActionKey.CHANNEL_DELETE,
        target_id=TARGET,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert result.confirmed
    assert result.actor_id == ATTACKER
    assert result.confidence is Confidence.CONFIRMED
    assert result.audit_entry_id == 1


async def test_stale_entry_is_refused():
    guild = build_guild()
    guild.audit_entries = [
        audit_entry(
            entry_id=2,
            actor_id=ATTACKER,
            target_id=TARGET,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=600,
        )
    ]
    result = await correlator(window=20.0).attribute(
        guild,
        action_key=ActionKey.CHANNEL_DELETE,
        target_id=TARGET,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert result.actor_id is None
    assert result.confidence is Confidence.UNKNOWN
    assert "no matching audit-log entry" in result.reason


async def test_mismatched_target_is_only_likely():
    guild = build_guild()
    guild.audit_entries = [
        audit_entry(
            entry_id=3,
            actor_id=ATTACKER,
            target_id=999,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=1,
        )
    ]
    result = await correlator().attribute(
        guild,
        action_key=ActionKey.CHANNEL_DELETE,
        target_id=TARGET,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert result.confidence is Confidence.LIKELY
    assert not result.confirmed, "LIKELY must never authorise a sanction"


async def test_missing_view_audit_log_is_reported_as_degraded():
    guild = build_guild(bot_permissions=perms(manage_roles=True, send_messages=True))
    result = await correlator().attribute(
        guild,
        action_key=ActionKey.CHANNEL_DELETE,
        target_id=TARGET,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert result.degraded
    assert result.actor_id is None
    assert "View Audit Log" in result.reason
    corr = correlator()
    await corr.attribute(
        guild,
        action_key=ActionKey.CHANNEL_DELETE,
        target_id=TARGET,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert guild.id in corr.degraded_guilds


async def test_forbidden_response_is_not_retried_forever():
    guild = build_guild()
    guild.audit_error = make_http_error(403)
    corr = correlator(max_attempts=5)
    result = await corr.attribute(
        guild,
        action_key=ActionKey.CHANNEL_DELETE,
        target_id=TARGET,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert result.degraded and "Forbidden" in result.reason
    assert guild.id in corr.degraded_guilds


async def test_rate_limit_error_is_retried_then_reported():
    guild = build_guild()
    guild.audit_error = make_http_error(429, retry_after=0.01)
    result = await correlator(max_attempts=3).attribute(
        guild,
        action_key=ActionKey.CHANNEL_DELETE,
        target_id=TARGET,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert result.degraded and "failed after" in result.reason


async def test_audit_entry_is_consumed_only_once():
    """Two gateway events must not both be blamed on one audit entry."""
    guild = build_guild()
    guild.audit_entries = [
        audit_entry(
            entry_id=10,
            actor_id=ATTACKER,
            target_id=TARGET,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=0.2,
        )
    ]
    corr = correlator()
    first = await corr.attribute(
        guild,
        action_key=ActionKey.CHANNEL_DELETE,
        target_id=TARGET,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    second = await corr.attribute(
        guild,
        action_key=ActionKey.CHANNEL_DELETE,
        target_id=TARGET,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert first.confirmed
    assert not second.confirmed


async def test_gateway_only_actions_are_not_correlated():
    guild = build_guild()
    for action in (ActionKey.MESSAGE_SPAM, ActionKey.JOIN_FLOOD, ActionKey.MASS_MENTION):
        result = await correlator().attribute(
            guild, action_key=action, target_id=1, occurred_at=datetime.now(tz=timezone.utc)
        )
        assert result.actor_id is None
        assert "gateway-only" in result.reason


async def test_guild_level_event_needs_no_target_match():
    guild = build_guild()
    guild.audit_entries = [
        audit_entry(
            entry_id=20,
            actor_id=ATTACKER,
            target_id=None,
            action=discord.AuditLogAction.guild_update,
            age_seconds=0.3,
        )
    ]
    result = await correlator().attribute(
        guild,
        action_key=ActionKey.GUILD_SETTINGS_CHANGE,
        target_id=None,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert result.confirmed and result.actor_id == ATTACKER


async def test_clock_skewed_future_entry_is_ignored():
    guild = build_guild()
    entry = audit_entry(
        entry_id=30,
        actor_id=ATTACKER,
        target_id=TARGET,
        action=discord.AuditLogAction.channel_delete,
    )
    entry.created_at = datetime.now(tz=timezone.utc) + timedelta(seconds=60)
    guild.audit_entries = [entry]
    result = await correlator().attribute(
        guild,
        action_key=ActionKey.CHANNEL_DELETE,
        target_id=TARGET,
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert result.actor_id is None


async def test_forget_guild_clears_state():
    guild = build_guild()
    guild.audit_entries = [
        audit_entry(
            entry_id=40,
            actor_id=ATTACKER,
            target_id=TARGET,
            action=discord.AuditLogAction.channel_delete,
        )
    ]
    corr = correlator()
    assert (
        await corr.attribute(
            guild,
            action_key=ActionKey.CHANNEL_DELETE,
            target_id=TARGET,
            occurred_at=datetime.now(tz=timezone.utc),
        )
    ).confirmed
    corr.forget_guild(guild.id)
    # After forgetting, the same entry may be consumed again.
    assert (
        await corr.attribute(
            guild,
            action_key=ActionKey.CHANNEL_DELETE,
            target_id=TARGET,
            occurred_at=datetime.now(tz=timezone.utc),
        )
    ).confirmed
