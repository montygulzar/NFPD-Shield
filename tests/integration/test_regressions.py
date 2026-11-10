"""Regression tests for defects found in the post-merge audit.

Each test names the failure it pins. Most of these were silent: the code ran,
and did the wrong thing.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

import discord
from discord import app_commands

from shield.commands.authz import Authority, authorize
from shield.constants import ActionKey, Confidence, EventSource, TrustScope
from shield.db.repositories import UnitOfWork, merge_previous_state
from shield.events.member_events import MemberEventsCog
from shield.events.normalize import NormalizedEvent
from tests.conftest import (
    ATTACKER,
    MOD,
    OWNER_A,
    VICTIM,
    CommandBot,
    FakeInteraction,
    FakeMember,
    audit_entry,
    build_guild,
    enable_guild,
)


def channel_delete(guild, channel_id: int) -> NormalizedEvent:  # noqa: ANN001
    return NormalizedEvent(
        guild_id=guild.id,
        action_key=ActionKey.CHANNEL_DELETE,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        target_type="channel",
        target_id=channel_id,
    )


def ban(guild, user_id: int) -> NormalizedEvent:  # noqa: ANN001
    return NormalizedEvent(
        guild_id=guild.id,
        action_key=ActionKey.MASS_BAN,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        target_type="user",
        target_id=user_id,
    )


def message(guild, author: int, message_id: int, channel_id: int) -> NormalizedEvent:  # noqa: ANN001
    return NormalizedEvent(
        guild_id=guild.id,
        action_key=ActionKey.MESSAGE_SPAM,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        actor_id=author,
        actor_confidence=Confidence.CONFIRMED,
        target_type="message",
        target_id=message_id,
        channel_id=channel_id,
    )


async def event_count(db, guild_id: int) -> int:  # noqa: ANN001
    async with db.begin() as session:
        rows = await UnitOfWork(session).events.recent(
            guild_id, since=datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        )
    return len(rows)


# -- trust evaluation with an uncached member ---------------------------
async def test_role_allowlist_applies_to_a_member_missing_from_the_cache(harness):  # noqa: ANN001
    """Shield does not chunk guilds, so get_member() misses for unseen members.

    Trust evaluation used to treat a miss as "no roles": a role-scoped allowlist
    entry silently stopped applying and the allowlisted member was sanctioned.
    """
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    admin_role = next(r for r in guild.roles if r.name == "Admin")
    async with harness.db.begin() as session:
        await UnitOfWork(session).trust.add(
            guild.id,
            entity_type="role",
            entity_id=admin_role.id,
            scopes=[TrustScope.DESTRUCTIVE],
            added_by=OWNER_A,
        )
    harness.pipeline.state_cache.invalidate(guild.id)

    real_get = guild.get_member
    guild.get_member = lambda user_id: None if int(user_id) == ATTACKER else real_get(user_id)
    guild.audit_entries.append(
        audit_entry(
            entry_id=1,
            actor_id=ATTACKER,
            target_id=500,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=0.1,
        )
    )
    result = await harness.pipeline.handle(channel_delete(guild, 500), guild)

    assert result.code == "trusted"
    assert guild.members[ATTACKER].removed_roles == []


async def test_actor_who_really_left_is_still_untrusted(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    gone = 999999999999999998
    guild.audit_entries.append(
        audit_entry(
            entry_id=2,
            actor_id=gone,
            target_id=501,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=0.1,
        )
    )
    result = await harness.pipeline.handle(channel_delete(guild, 501), guild)
    assert result.code == "enforce"
    assert "no longer a member" in result.enforcement["summary"]


# -- attribution confidence and rate windows -----------------------------
async def test_a_likely_attribution_never_counts_against_the_actor(harness):  # noqa: ANN001
    """A LIKELY guess used to land in the named actor's window.

    One unrelated event attributed on a hunch plus one real action then crossed
    the threshold and sanctioned a moderator for a single ban.
    """
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    mod = guild.members[MOD]
    mod.roles.append(next(r for r in guild.roles if r.name == "Admin"))

    # Ban 1: a fresh ban entry by MOD exists, but for a different target.
    guild.audit_entries.append(
        audit_entry(
            entry_id=10,
            actor_id=MOD,
            target_id=VICTIM + 50,
            action=discord.AuditLogAction.ban,
            age_seconds=0.1,
        )
    )
    first = await harness.pipeline.handle(ban(guild, VICTIM), guild)
    assert first.decision is None or first.code != "enforce"

    # Ban 2: genuinely MOD's, confirmed.
    guild.audit_entries.append(
        audit_entry(
            entry_id=11,
            actor_id=MOD,
            target_id=VICTIM + 1,
            action=discord.AuditLogAction.ban,
            age_seconds=0.1,
        )
    )
    second = await harness.pipeline.handle(ban(guild, VICTIM + 1), guild)

    assert second.code == "below_threshold", "one confirmed ban is not a mass ban"
    assert mod.removed_roles == []


async def test_a_voluntary_leave_near_someone_elses_kick_is_not_a_kick(harness):  # noqa: ANN001
    """A fresh kick entry for another member is not evidence about this departure."""
    harness.bot.pipeline = harness.pipeline
    cog = MemberEventsCog(harness.bot)
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    guild.audit_entries.append(
        audit_entry(
            entry_id=20,
            actor_id=MOD,
            target_id=VICTIM + 99,  # somebody else was kicked
            action=discord.AuditLogAction.kick,
            age_seconds=0.1,
        )
    )
    await cog.on_member_remove(FakeMember(id=VICTIM, name="leaver", guild=guild))
    assert await event_count(harness.db, guild.id) == 0


# -- protective-mode state ----------------------------------------------
def test_merge_previous_state_keeps_the_original_values():
    original = {"verification_level": "low", "channels": {"1": 0}}
    recapture = {"verification_level": "high", "channels": {"1": 30, "2": 5}}
    merged = merge_previous_state(original, recapture)
    assert merged["verification_level"] == "low"
    assert merged["channels"] == {"1": 0, "2": 5}, "new channels are added, known ones kept"
    assert merge_previous_state(None, recapture) == recapture


async def test_re_entering_raid_mode_does_not_overwrite_the_original_state(harness):  # noqa: ANN001
    """A second join flood used to save the already-raised level as "previous",

    so raid mode expiring "restored" the raised level and slowmode forever.
    """
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)

    for _ in range(2):
        result, until = await harness.lockdown.enable_raid_mode(
            guild, reason="flood", minutes=5, slowmode_seconds=30
        )
        async with harness.db.begin() as session:
            await UnitOfWork(session).guilds.enter_protective_mode(
                guild.id, "raid_mode", result.previous_state, raid_mode_until=until
            )

    async with harness.db.begin() as session:
        settings = await UnitOfWork(session).guilds.get(guild.id)
        state = dict(settings.raid_mode_state)
    assert state["verification_level"] == "low"
    assert state["channels"][str(channel.id)] == 0

    await harness.lockdown.disable_raid_mode(guild, state)
    assert guild.verification_level is discord.VerificationLevel.low
    assert channel.slowmode_delay == 0


# -- message traffic and the database ------------------------------------
async def test_ordinary_messages_write_nothing_to_the_database(harness):  # noqa: ANN001
    """Every chat message used to insert event rows; a busy guild hammered PostgreSQL."""
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)
    for index in range(3):
        result = await harness.pipeline.handle(message(guild, MOD, 100 + index, channel.id), guild)
        assert result.code == "below_threshold"
    assert await event_count(harness.db, guild.id) == 0


async def test_a_triggering_message_is_recorded(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)
    codes = [
        (await harness.pipeline.handle(message(guild, MOD, 200 + i, channel.id), guild)).code
        for i in range(6)
    ]
    assert codes[-1] == "enforce"
    assert await event_count(harness.db, guild.id) == 1, "the one that led somewhere"


async def test_redelivered_message_is_still_deduplicated(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)
    first = await harness.pipeline.handle(message(guild, MOD, 300, channel.id), guild)
    replay = await harness.pipeline.handle(message(guild, MOD, 300, channel.id), guild)
    assert first.code == "below_threshold" and replay.duplicate


async def test_exempt_channels_are_actually_exempt(harness):  # noqa: ANN001
    """`exempt_channel_ids` was documented and stored but never consulted."""
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)
    async with harness.db.begin() as session:
        await UnitOfWork(session).policies.set_values(
            guild.id,
            ActionKey.MESSAGE_SPAM,
            updated_by=OWNER_A,
            options={"exempt_channel_ids": [channel.id]},
        )
    harness.pipeline.state_cache.invalidate(guild.id)
    codes = {
        (await harness.pipeline.handle(message(guild, MOD, 400 + i, channel.id), guild)).code
        for i in range(10)
    }
    assert codes == {"exempt_channel"}
    assert guild.members[MOD].timeouts == []


async def test_exemption_is_settable_by_command(harness, shield_config):  # noqa: ANN001
    from shield.commands.core import ShieldCommands

    bot = CommandBot(shield_config, harness.db, harness)
    cog = ShieldCommands(bot)
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)
    group = cog.thresholds
    spam = app_commands.Choice(name="message spam", value="message_spam")

    inter = FakeInteraction(bot, guild, guild.members[OWNER_A])
    await type(group).set_values.callback(group, inter, spam, exempt_channel=channel)
    assert f"<#{channel.id}>" in inter.text()
    async with harness.db.begin() as session:
        policy = await UnitOfWork(session).policies.get(guild.id, ActionKey.MESSAGE_SPAM)
    assert policy.options["exempt_channel_ids"] == [channel.id]
    assert policy.options["timeout_seconds"] == 300, "other options survive the merge"

    inter = FakeInteraction(bot, guild, guild.members[OWNER_A])
    await type(group).set_values.callback(group, inter, spam, unexempt_channel=channel)
    assert "exempt channels: none" in inter.text()

    wrong = FakeInteraction(bot, guild, guild.members[OWNER_A])
    await type(group).set_values.callback(
        group, wrong, app_commands.Choice(name="mass ban", value="mass_ban"), exempt_channel=channel
    )
    assert "only apply to the message detectors" in wrong.text()


# -- approved guilds ------------------------------------------------------
async def test_unapproved_guilds_are_ignored_by_the_pipeline(harness, shield_config):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    harness.pipeline.config = dataclasses.replace(
        shield_config, approved_guild_ids=(guild.id + 12345,)
    )
    guild.audit_entries.append(
        audit_entry(
            entry_id=30,
            actor_id=ATTACKER,
            target_id=600,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=0.1,
        )
    )
    result = await harness.pipeline.handle(channel_delete(guild, 600), guild)
    assert result.code == "guild_not_approved"
    assert guild.members[ATTACKER].removed_roles == []
    assert await event_count(harness.db, guild.id) == 0


async def test_commands_are_refused_in_an_unapproved_guild(harness, shield_config):  # noqa: ANN001
    bot = CommandBot(
        dataclasses.replace(shield_config, approved_guild_ids=(1,)), harness.db, harness
    )
    guild = harness.register_guild(build_guild())
    inter = FakeInteraction(bot, guild, guild.members[OWNER_A])
    result = await authorize(inter, Authority.DELEGATE, command="shield status")
    assert not result.allowed and "not approved" in result.reason


async def test_unapproved_guild_is_left_when_configured(harness, shield_config):  # noqa: ANN001
    from shield.bot import ShieldBot

    bot = ShieldBot.__new__(ShieldBot)
    bot.shield_config = dataclasses.replace(
        shield_config, approved_guild_ids=(1,), leave_unapproved_guilds=True
    )
    guild = build_guild()
    left: list[int] = []

    async def leave() -> None:
        left.append(guild.id)

    guild.leave = leave
    assert await bot._reject_unapproved(guild) is True
    assert left == [guild.id]

    bot.shield_config = dataclasses.replace(shield_config, approved_guild_ids=(guild.id,))
    assert await bot._reject_unapproved(guild) is False


def test_client_forbids_everyone_and_role_pings(shield_config):
    """Names and reasons in Shield's output are user-influenced."""
    from shield.bot import ShieldBot

    mentions = ShieldBot(shield_config).allowed_mentions
    assert mentions.everyone is False and mentions.roles is False


# -- export ---------------------------------------------------------------
async def test_export_is_not_silently_capped_at_100(harness):  # noqa: ANN001
    from shield.constants import ResponseAction, Severity, ShieldMode

    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    now = datetime.now(tz=timezone.utc)
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        for index in range(130):
            await uow.incidents.create(
                guild_id=guild.id,
                correlation_id=f"c{index}",
                action_key=ActionKey.MASS_BAN,
                actor_id=ATTACKER,
                actor_confidence=Confidence.CONFIRMED,
                severity=Severity.HIGH,
                mode_at_detection=ShieldMode.ENFORCE,
                dry_run=False,
                detected_at=now,
                window_start=now,
                event_count=2,
                threshold_count=2,
                window_seconds=15,
                policy_version=1,
                response=ResponseAction.ALERT_ONLY,
                reason="x",
            )
        rows = await uow.incidents.export(guild.id, now - timedelta(days=1))
    assert len(rows) == 130


# -- guild join -----------------------------------------------------------
async def test_joining_a_guild_initialises_it(harness, shield_config):  # noqa: ANN001
    """on_guild_join logged ``extra={"name": ...}``, a reserved LogRecord field.

    That raised KeyError on every join, before the guild row, the startup
    snapshot or the owner's onboarding DM - so a newly added guild was never
    set up at all.
    """
    from shield.backup.snapshot import SnapshotService
    from shield.bot import ShieldBot

    guild = build_guild()

    class JoinBot(ShieldBot):
        @property
        def guilds(self):  # noqa: ANN201
            return [guild]

    bot = JoinBot.__new__(JoinBot)
    bot.shield_config = shield_config
    bot.db = harness.db
    bot.snapshots = SnapshotService(db=harness.db, limiter=harness.limiter)

    await bot.on_guild_join(guild)

    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        settings = await uow.guilds.get(guild.id)
        snapshot = await uow.snapshots.latest(guild.id)
    assert settings is not None and settings.enabled is False
    assert snapshot is not None, "a startup snapshot is taken on join"
    assert guild.members[OWNER_A].dms, "the owner is told how to proceed"
