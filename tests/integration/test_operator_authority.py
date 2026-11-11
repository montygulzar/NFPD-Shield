"""OPERATOR_FULL_AUTHORITY: let the bot operator run owner-only commands.

Off by default (the operator keeps diagnostics scope only). On, the operator
acts with owner authority in every guild - the switch a single-owner
self-hosted deployment uses so the operator can act when a guild owner is away.
"""

from __future__ import annotations

import dataclasses

from shield.commands.authz import Authority, authorize, resolve_authority
from shield.commands.core import ShieldCommands
from shield.db.repositories import UnitOfWork
from tests.conftest import (
    MOD,
    OWNER_A,
    CommandBot,
    FakeInteraction,
    FakeMember,
    build_guild,
    enable_guild,
)

OPERATOR = 1195765102725582968


def operator_bot(shield_config, db, harness, *, full: bool):  # noqa: ANN001, ANN201
    config = dataclasses.replace(
        shield_config,
        operator_ids=frozenset({OPERATOR}),
        operator_full_authority=full,
    )
    return CommandBot(config, db, harness)


def with_operator(guild):  # noqa: ANN001
    member = FakeMember(id=OPERATOR, name="BotOwner", guild=guild)
    guild.members[OPERATOR] = member
    return member


async def test_default_operator_cannot_change_protection(harness, shield_config):  # noqa: ANN001
    bot = operator_bot(shield_config, harness.db, harness, full=False)
    guild = harness.register_guild(build_guild())
    inter = FakeInteraction(bot, guild, with_operator(guild))
    assert await resolve_authority(inter) is Authority.OPERATOR
    result = await authorize(inter, Authority.OWNER, command="shield enable")
    assert not result.allowed and "diagnostics scope only" in result.reason


async def test_full_authority_operator_resolves_as_owner(harness, shield_config):  # noqa: ANN001
    bot = operator_bot(shield_config, harness.db, harness, full=True)
    guild = harness.register_guild(build_guild())
    inter = FakeInteraction(bot, guild, with_operator(guild))
    assert await resolve_authority(inter) is Authority.OWNER
    result = await authorize(inter, Authority.OWNER, command="shield enable")
    assert result.allowed
    assert "bot operator" in result.reason, "the audit trail names why it was allowed"


async def test_full_authority_operator_can_enable_protection(harness, shield_config):  # noqa: ANN001
    """End to end: the operator runs an owner-only command and it takes effect."""
    bot = operator_bot(shield_config, harness.db, harness, full=True)
    cog = ShieldCommands(bot)
    guild = harness.register_guild(build_guild())
    inter = FakeInteraction(bot, guild, with_operator(guild))

    await ShieldCommands.enable.callback(cog, inter, None, True)
    assert "Protection enabled" in inter.text()
    async with harness.db.begin() as session:
        settings = await UnitOfWork(session).guilds.get(guild.id)
    assert settings.enabled is True and settings.enabled_by == OPERATOR


async def test_full_authority_operator_can_pause(harness, shield_config):  # noqa: ANN001
    bot = operator_bot(shield_config, harness.db, harness, full=True)
    cog = ShieldCommands(bot)
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    inter = FakeInteraction(bot, guild, with_operator(guild))
    await ShieldCommands.pause.callback(cog, inter, "owner away")
    assert "PAUSED" in inter.text()
    async with harness.db.begin() as session:
        settings = await UnitOfWork(session).guilds.get(guild.id)
    assert settings.paused is True and settings.paused_by == OPERATOR


async def test_default_operator_cannot_pause(harness, shield_config):  # noqa: ANN001
    bot = operator_bot(shield_config, harness.db, harness, full=False)
    cog = ShieldCommands(bot)
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    inter = FakeInteraction(bot, guild, with_operator(guild))
    await ShieldCommands.pause.callback(cog, inter, "x")
    assert "Not authorized" in inter.text()
    async with harness.db.begin() as session:
        settings = await UnitOfWork(session).guilds.get(guild.id)
    assert settings.paused is False


async def test_a_non_operator_is_unaffected_by_the_switch(harness, shield_config):  # noqa: ANN001
    bot = operator_bot(shield_config, harness.db, harness, full=True)
    guild = harness.register_guild(build_guild())
    inter = FakeInteraction(bot, guild, guild.members[MOD])
    assert await resolve_authority(inter) is Authority.NONE
    result = await authorize(inter, Authority.OWNER, command="shield enable")
    assert not result.allowed


async def test_guild_owner_is_still_owner_with_the_switch_on(harness, shield_config):  # noqa: ANN001
    bot = operator_bot(shield_config, harness.db, harness, full=True)
    guild = harness.register_guild(build_guild())
    inter = FakeInteraction(bot, guild, guild.members[OWNER_A])
    result = await authorize(inter, Authority.OWNER, command="shield enable")
    assert result.allowed
    assert "owner" in result.reason and "operator" not in result.reason


async def test_full_authority_operator_is_still_policed_by_detectors(harness, shield_config):  # noqa: ANN001
    """Authority over commands is not detection exemption.

    OPERATOR_FULL_AUTHORITY lets them run commands; it does not make a nuke
    launched from the operator account invisible. Only an allowlist entry does
    that, and the operator holds none here.
    """
    from datetime import datetime, timezone

    import discord

    from shield.constants import ActionKey, EventSource
    from shield.events.normalize import NormalizedEvent
    from tests.conftest import audit_entry

    harness.config = dataclasses.replace(
        harness.config, operator_ids=frozenset({OPERATOR}), operator_full_authority=True
    )
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    operator = with_operator(guild)
    operator.roles.append(next(r for r in guild.roles if r.name == "Admin"))
    guild.audit_entries.append(
        audit_entry(
            entry_id=1,
            actor_id=OPERATOR,
            target_id=900,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=0.1,
        )
    )
    result = await harness.pipeline.handle(
        NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.CHANNEL_DELETE,
            source=EventSource.GATEWAY,
            occurred_at=datetime.now(tz=timezone.utc),
            target_type="channel",
            target_id=900,
        ),
        guild,
    )
    assert result.code == "enforce"
    assert operator.removed_roles, "the operator is policed like anyone else"
