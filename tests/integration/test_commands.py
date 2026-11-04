"""Slash-command authorization and behaviour.

Authority is re-checked on the server for every invocation, so these tests call
the real command callbacks with a fake interaction and assert both the reply and
the persisted ``command_audit`` row.
"""

from __future__ import annotations

from datetime import datetime, timezone

import discord
import pytest
from discord import app_commands

from shield.commands.authz import Authority, authorize, resolve_authority
from shield.commands.core import ShieldCommands
from shield.constants import ActionKey, ResponseAction, ShieldMode, TrustScope
from shield.db.repositories import UnitOfWork
from tests.conftest import (
    ATTACKER,
    GUILD_A,
    GUILD_B,
    MOD,
    OWNER_A,
    OWNER_B,
    CommandBot,
    FakeInteraction,
    FakeMember,
    FakeRole,
    build_guild,
    enable_guild,
    perms,
)


@pytest.fixture
def cog(harness, shield_config):  # noqa: ANN001, ANN201
    bot = CommandBot(shield_config, harness.db, harness)
    harness.bot = bot
    harness.pipeline.bot = bot
    return ShieldCommands(bot), bot


def interaction(bot, guild, user) -> FakeInteraction:  # noqa: ANN001
    return FakeInteraction(bot, guild, user)


async def audit_rows(db, guild_id: int):  # noqa: ANN001, ANN201
    async with db.begin() as session:
        uow = UnitOfWork(session)
        return await uow.command_audit.recent(guild_id)


# -- authority ladder --------------------------------------------------
async def test_guild_owner_is_owner_authority(cog, harness):  # noqa: ANN001
    _, bot = cog
    guild = harness.register_guild(build_guild())
    inter = interaction(bot, guild, guild.members[OWNER_A])
    assert await resolve_authority(inter) is Authority.OWNER


async def test_administrator_has_no_shield_authority(cog, harness):  # noqa: ANN001
    """Administrator is explicitly NOT trusted - the compromised-admin case."""
    _, bot = cog
    guild = harness.register_guild(build_guild())
    attacker = guild.members[ATTACKER]
    assert attacker.guild_permissions.administrator
    inter = interaction(bot, guild, attacker)
    assert await resolve_authority(inter) is Authority.NONE


async def test_manage_shield_scope_creates_a_delegate(cog, harness):  # noqa: ANN001
    _, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        await uow.trust.add(
            guild.id,
            entity_type="user",
            entity_id=MOD,
            scopes=[TrustScope.MANAGE_SHIELD],
            added_by=OWNER_A,
        )
    inter = interaction(bot, guild, guild.members[MOD])
    assert await resolve_authority(inter) is Authority.DELEGATE


async def test_delegate_by_role(cog, harness):  # noqa: ANN001
    _, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    colour_role = next(r for r in guild.roles if r.name == "Blue")
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        await uow.trust.add(
            guild.id,
            entity_type="role",
            entity_id=colour_role.id,
            scopes=[TrustScope.MANAGE_SHIELD],
            added_by=OWNER_A,
        )
    inter = interaction(bot, guild, guild.members[MOD])
    assert await resolve_authority(inter) is Authority.DELEGATE


async def test_global_operator_is_only_operator_authority(cog, harness, shield_config):  # noqa: ANN001
    _, bot = cog
    guild = harness.register_guild(build_guild())
    operator = FakeMember(id=shield_config.owner_id, name="Operator", guild=guild)
    guild.members[operator.id] = operator
    inter = interaction(bot, guild, operator)
    assert await resolve_authority(inter) is Authority.OPERATOR


async def test_operator_cannot_change_protection_state(cog, harness, shield_config):  # noqa: ANN001
    _, bot = cog
    guild = harness.register_guild(build_guild())
    operator = FakeMember(id=shield_config.owner_id, name="Operator", guild=guild)
    guild.members[operator.id] = operator
    inter = interaction(bot, guild, operator)
    result = await authorize(inter, Authority.OWNER, command="shield enable")
    assert not result.allowed
    assert "diagnostics scope only" in result.reason


async def test_operator_may_run_diagnostics(cog, harness, shield_config):  # noqa: ANN001
    _, bot = cog
    guild = harness.register_guild(build_guild())
    operator = FakeMember(id=shield_config.owner_id, name="Operator", guild=guild)
    guild.members[operator.id] = operator
    inter = interaction(bot, guild, operator)
    assert (await authorize(inter, Authority.OPERATOR, command="shield health")).allowed


async def test_denials_are_audited(cog, harness):  # noqa: ANN001
    _, bot = cog
    guild = harness.register_guild(build_guild())
    inter = interaction(bot, guild, guild.members[ATTACKER])
    await authorize(inter, Authority.OWNER, command="shield disable", parameters={"x": 1})
    rows = await audit_rows(harness.db, guild.id)
    assert len(rows) == 1
    assert rows[0].allowed is False and rows[0].command == "shield disable"
    assert rows[0].user_id == ATTACKER


async def test_command_audit_is_guild_scoped(cog, harness):  # noqa: ANN001
    _, bot = cog
    guild_a = harness.register_guild(build_guild(GUILD_A, OWNER_A))
    guild_b = harness.register_guild(build_guild(GUILD_B, OWNER_B))
    await authorize(
        interaction(bot, guild_a, guild_a.members[ATTACKER]),
        Authority.OWNER,
        command="shield enable",
    )
    assert len(await audit_rows(harness.db, guild_a.id)) == 1
    assert await audit_rows(harness.db, guild_b.id) == []


# -- command behaviour -------------------------------------------------
async def test_enable_is_owner_only_and_warns(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())

    denied = interaction(bot, guild, guild.members[ATTACKER])
    await ShieldCommands.enable.callback(shield_cog, denied, None, True)
    assert "Not authorized" in denied.text()
    assert "guild owner" in denied.text()

    allowed = interaction(bot, guild, guild.members[OWNER_A])
    await ShieldCommands.enable.callback(shield_cog, allowed, None, True)
    text = allowed.text()
    assert "Protection enabled" in text
    assert "alert_only" in text
    assert "No log channel is set" in text

    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        settings = await uow.guilds.get(guild.id)
    assert settings.enabled is True
    assert settings.mode is ShieldMode.ALERT_ONLY
    assert settings.dry_run is True
    assert settings.enabled_by == OWNER_A


async def test_enable_warns_about_missing_permissions(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(
        build_guild(bot_permissions=perms(send_messages=True))
    )
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await ShieldCommands.enable.callback(shield_cog, inter, None, True)
    assert "Missing permissions" in inter.text()
    assert "view_audit_log" in inter.text()


async def test_pause_and_resume_are_owner_only(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)

    inter = interaction(bot, guild, guild.members[OWNER_A])
    await ShieldCommands.pause.callback(shield_cog, inter, "incident drill")
    assert "PAUSED" in inter.text()
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        settings = await uow.guilds.get(guild.id)
    assert settings.paused is True and settings.pause_reason == "incident drill"

    resume = interaction(bot, guild, guild.members[OWNER_A])
    await ShieldCommands.resume.callback(shield_cog, resume)
    assert "Resumed" in resume.text()
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        settings = await uow.guilds.get(guild.id)
    assert settings.paused is False


async def test_mode_requires_enabled_protection(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    inter = interaction(bot, guild, guild.members[OWNER_A])
    choice = app_commands.Choice(name="enforce", value="enforce")
    await ShieldCommands.set_mode.callback(shield_cog, inter, choice)
    assert "not enabled" in inter.text()


async def test_status_reports_posture(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await ShieldCommands.status.callback(shield_cog, inter)
    text = inter.text()
    assert "enabled" in text
    assert "enforce" in text
    assert "Detectors" in text


async def test_thresholds_set_rejects_empty_change(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    group = shield_cog.thresholds
    inter = interaction(bot, guild, guild.members[OWNER_A])
    action = app_commands.Choice(name="mass ban", value="mass_ban")
    await type(group).set_values.callback(group, inter, action)
    assert "Nothing to change" in inter.text()


async def test_thresholds_set_updates_and_warns(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    group = shield_cog.thresholds
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).set_values.callback(
        group,
        inter,
        app_commands.Choice(name="mass ban", value="mass_ban"),
        threshold=1,
        window=30,
        response=app_commands.Choice(name="alert only", value="alert_only"),
    )
    text = inter.text()
    assert "Policy updated" in text
    assert "threshold 1" in text.replace("**", "")
    assert "false-positive risk" in text

    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        policy = await uow.policies.get(guild.id, ActionKey.MASS_BAN)
        settings = await uow.guilds.get(guild.id)
    assert policy.threshold_count == 1 and policy.window_seconds == 30
    assert policy.response is ResponseAction.ALERT_ONLY
    assert policy.updated_by == OWNER_A
    assert settings.policy_version == 2, "policy version must advance"


async def test_thresholds_are_delegate_level_not_public(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    group = shield_cog.thresholds
    inter = interaction(bot, guild, guild.members[MOD])
    await type(group).view.callback(group, inter, None)
    assert "Not authorized" in inter.text()
    assert "manage_shield" in inter.text()


async def test_whitelist_refuses_everyone_role(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    group = shield_cog.whitelist
    everyone = next(r for r in guild.roles if r.is_default())
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).add.callback(group, inter, None, everyone, None, None, None, None)
    assert "Refusing to allowlist" in inter.text()


async def test_whitelist_requires_exactly_one_target(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    group = shield_cog.whitelist
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).add.callback(group, inter, None, None, None, None, None, None)
    assert "exactly one" in inter.text()


async def test_whitelist_add_is_owner_only_and_explains_risk(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    group = shield_cog.whitelist
    member = guild.members[MOD]

    denied = interaction(bot, guild, guild.members[ATTACKER])
    await type(group).add.callback(group, denied, member, None, None, None, None, None)
    assert "Not authorized" in denied.text()

    inter = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).add.callback(
        group,
        inter,
        member,
        None,
        app_commands.Choice(name="webhooks", value="webhooks"),
        None,
        "logging bot",
        24,
    )
    text = inter.text()
    assert "Allowlisted" in text
    assert "can bypass Shield entirely" in text
    assert "Expires" in text
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        rows = await uow.trust.list_for_guild(guild.id)
    assert rows[0].scopes == ["webhooks"] and rows[0].expires_at is not None


async def test_whitelist_list_mentions_the_implicit_owner_exemption(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    group = shield_cog.whitelist
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).list_entries.callback(group, inter)
    assert "empty" in inter.text()
    assert "guild owner" in inter.text()


async def test_incident_show_cannot_read_another_guild(cog, harness):  # noqa: ANN001
    """Cross-guild IDOR: an incident ID from guild A must not resolve in B."""
    shield_cog, bot = cog
    guild_a = harness.register_guild(build_guild(GUILD_A, OWNER_A))
    guild_b = harness.register_guild(build_guild(GUILD_B, OWNER_B))
    await enable_guild(harness.db, guild_a)
    await enable_guild(harness.db, guild_b)

    from shield.constants import Confidence, Severity

    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        incident = await uow.incidents.create(
            guild_id=guild_a.id,
            correlation_id="c",
            action_key=ActionKey.CHANNEL_DELETE,
            actor_id=ATTACKER,
            actor_confidence=Confidence.CONFIRMED,
            severity=Severity.CRITICAL,
            mode_at_detection=ShieldMode.ENFORCE,
            dry_run=False,
            detected_at=datetime.now(tz=timezone.utc),
            window_start=datetime.now(tz=timezone.utc),
            event_count=1,
            threshold_count=1,
            window_seconds=15,
            policy_version=1,
            response=ResponseAction.STRIP_DANGEROUS_ROLES,
            reason="guild A secret",
        )
        incident_id = incident.id

    group = shield_cog.incidents
    owner_view = interaction(bot, guild_a, guild_a.members[OWNER_A])
    await type(group).show.callback(group, owner_view, incident_id)
    assert "guild A secret" in owner_view.text()

    foreign = interaction(bot, guild_b, guild_b.members[OWNER_B])
    await type(group).show.callback(group, foreign, incident_id)
    text = foreign.text()
    assert "No incident" in text
    assert "guild A secret" not in text


async def test_acknowledge_false_positive_reports_rate(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    from shield.constants import Confidence, Severity

    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        incident = await uow.incidents.create(
            guild_id=guild.id,
            correlation_id="c",
            action_key=ActionKey.CHANNEL_DELETE,
            actor_id=MOD,
            actor_confidence=Confidence.CONFIRMED,
            severity=Severity.HIGH,
            mode_at_detection=ShieldMode.ENFORCE,
            dry_run=False,
            detected_at=datetime.now(tz=timezone.utc),
            window_start=datetime.now(tz=timezone.utc),
            event_count=1,
            threshold_count=1,
            window_seconds=15,
            policy_version=1,
            response=ResponseAction.ALERT_ONLY,
            reason="restructure",
        )
        incident_id = incident.id
        await uow.cooldowns.check_and_set(guild.id, f"channel_delete:{MOD}", 600)

    group = shield_cog.incidents
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).acknowledge.callback(group, inter, incident_id, True, "planned work")
    text = inter.text()
    assert "false_positive" in text
    assert "false-positive rate" in text
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        assert await uow.cooldowns.peek(guild.id, f"channel_delete:{MOD}") is None


async def test_logs_set_refuses_an_unusable_channel(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    group = shield_cog.logs
    channel = guild.get_channel(guild.id + 101)
    channel.bot_permissions = perms(view_channel=True)
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).set_channel.callback(group, inter, channel, None)
    assert "Not saved" in inter.text()
    assert "cannot send messages" in inter.text()


async def test_logs_set_and_test_message(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    group = shield_cog.logs
    channel = guild.get_channel(guild.id + 101)
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).set_channel.callback(group, inter, channel, None)
    assert "log channel set" in inter.text()

    tester = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).test.callback(group, tester)
    assert "Test message sent" in tester.text()
    assert channel.sent


async def test_restore_apply_requires_token_and_confirmation(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    group = shield_cog.restore

    no_confirm = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).apply.callback(group, no_confirm, "ABCDEF", False)
    assert "not** applied" in no_confirm.text() or "not applied" in no_confirm.text()

    bad_token = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).apply.callback(group, bad_token, "ABCDEF", True)
    assert "unknown" in bad_token.text()


async def test_restore_preview_then_owner_apply(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    from shield.constants import SnapshotKind

    await bot.snapshots.capture(guild, kind=SnapshotKind.MANUAL, bypass_rate_limit=True)
    # Simulate a nuke.
    guild.roles = [r for r in guild.roles if r.name != "Admin"]

    group = shield_cog.restore
    preview = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).preview.callback(group, preview, None, None)
    text = preview.text()
    assert "Restore preview" in text
    assert "Nothing has been changed" in text
    assert "new IDs" in text

    token = text.split("token:")[1].split("`")[0].strip()

    # A delegate cannot apply - only the guild owner can.
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        await uow.trust.add(
            guild.id,
            entity_type="user",
            entity_id=MOD,
            scopes=[TrustScope.MANAGE_SHIELD],
            added_by=OWNER_A,
        )
    delegate = interaction(bot, guild, guild.members[MOD])
    await type(group).apply.callback(group, delegate, token, True)
    assert "Not authorized" in delegate.text()

    applied = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).apply.callback(group, applied, token, True)
    text = applied.text()
    assert "Restore applied" in text
    assert "Old IDs are gone" in text
    assert any(r.name == "Admin" for r in guild.roles)

    # The token is single use.
    replay = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).apply.callback(group, replay, token, True)
    assert "unknown" in replay.text()


async def test_lockdown_enable_disable_round_trip(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)
    channel.slowmode_delay = 0
    group = shield_cog.lockdown

    enable = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).enable.callback(group, enable, "raid in progress", 30, True)
    assert "Lockdown enabled" in enable.text()
    assert guild.verification_level is discord.VerificationLevel.highest
    assert channel.slowmode_delay == 30

    disable = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).disable.callback(group, disable)
    assert "Lockdown lifted" in disable.text()
    assert guild.verification_level is discord.VerificationLevel.low
    assert channel.slowmode_delay == 0, "the previous slowmode must be restored"


async def test_raid_mode_manual_toggle_never_bans(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    group = shield_cog.lockdown
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).raid.callback(group, inter, True, 30, 15)
    text = inter.text()
    assert "Raid mode enabled" in text
    assert "does **not** ban or kick" in text
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        settings = await uow.guilds.get(guild.id)
    assert settings.raid_mode_active is True


async def test_backup_create_and_inspect(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    group = shield_cog.backup

    create = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).create.callback(group, create, None)
    assert "Snapshot created" in create.text()
    assert "Not encrypted" in create.text()

    listing = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).list_snapshots.callback(group, listing, 10)
    assert "Snapshots" in listing.text()

    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        snapshot = await uow.snapshots.latest(guild.id)
    inspect = interaction(bot, guild, guild.members[OWNER_A])
    await type(group).inspect.callback(group, inspect, snapshot.id)
    text = inspect.text()
    assert "Integrity" in text and "OK" in text
    assert "NOT captured" in text


async def test_health_reports_hierarchy_and_intent_gaps(cog, harness):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    # A dangerous role above Shield.
    guild.roles.append(
        FakeRole(
            id=guild.id + 777,
            name="Untouchable",
            position=200,
            permissions=perms(administrator=True),
            guild=guild,
        )
    )
    bot.intents = discord.Intents(guilds=True, members=False, message_content=False)
    inter = interaction(bot, guild, guild.members[OWNER_A])
    await ShieldCommands.health.callback(shield_cog, inter)
    text = inter.text()
    assert "Untouchable" in text
    assert "cannot be removed from an attacker" in text
    assert "join flood and role-grant detection are OFF" in text
    assert "Known detection limits" in text


async def test_metrics_is_operator_scoped(cog, harness, shield_config):  # noqa: ANN001
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    denied = interaction(bot, guild, guild.members[MOD])
    await ShieldCommands.metrics.callback(shield_cog, denied)
    assert "Not authorized" in denied.text()

    operator = FakeMember(id=shield_config.owner_id, name="Operator", guild=guild)
    guild.members[operator.id] = operator
    allowed = interaction(bot, guild, operator)
    await ShieldCommands.metrics.callback(shield_cog, allowed)
    assert "Uptime" in allowed.text()


# -- smoke coverage: every command callback runs at least once ---------
async def test_every_command_callback_executes(cog, harness):  # noqa: ANN001
    """Walk the whole surface so no command path is shipped unexercised."""
    shield_cog, bot = cog
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    owner = guild.members[OWNER_A]
    from shield.constants import SnapshotKind

    await bot.snapshots.capture(guild, kind=SnapshotKind.MANUAL, bypass_rate_limit=True)

    mass_ban = app_commands.Choice(name="mass ban", value="mass_ban")
    checked: list[str] = []

    async def run(label: str, coro) -> FakeInteraction:  # noqa: ANN001
        checked.append(label)
        return await coro

    # Top level.
    for label, callback, args in (
        ("status", ShieldCommands.status, ()),
        ("health", ShieldCommands.health, ()),
        ("metrics", ShieldCommands.metrics, ()),
    ):
        inter = interaction(bot, guild, owner)
        await run(label, callback.callback(shield_cog, inter, *args))
        assert inter.replies, label

    # thresholds
    group = shield_cog.thresholds
    for label, coro_factory in (
        ("thresholds view (all)", lambda i: type(group).view.callback(group, i, None)),
        ("thresholds view (one)", lambda i: type(group).view.callback(group, i, mass_ban)),
        ("thresholds reset", lambda i: type(group).reset.callback(group, i)),
    ):
        inter = interaction(bot, guild, owner)
        await run(label, coro_factory(inter))
        assert inter.replies, label

    # whitelist add/list/remove round trip
    group = shield_cog.whitelist
    target = guild.members[MOD]
    inter = interaction(bot, guild, owner)
    await run(
        "whitelist add",
        type(group).add.callback(group, inter, target, None, None, None, "temp", None),
    )
    inter = interaction(bot, guild, owner)
    await run("whitelist list", type(group).list_entries.callback(group, inter))
    assert "<@" in inter.text()
    inter = interaction(bot, guild, owner)
    await run("whitelist remove", type(group).remove.callback(group, inter, target, None))
    assert "Removed" in inter.text()

    # incidents
    from shield.constants import Confidence, Severity

    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        incident = await uow.incidents.create(
            guild_id=guild.id,
            correlation_id="smoke",
            action_key=ActionKey.MASS_BAN,
            actor_id=ATTACKER,
            actor_confidence=Confidence.CONFIRMED,
            severity=Severity.HIGH,
            mode_at_detection=ShieldMode.ENFORCE,
            dry_run=False,
            detected_at=datetime.now(tz=timezone.utc),
            window_start=datetime.now(tz=timezone.utc),
            event_count=2,
            threshold_count=2,
            window_seconds=15,
            policy_version=1,
            response=ResponseAction.STRIP_DANGEROUS_ROLES,
            reason="smoke incident",
        )
        incident_id = incident.id

    group = shield_cog.incidents
    for label, coro_factory in (
        ("incidents list", lambda i: type(group).list_incidents.callback(group, i, 10, None, None, 24)),
        ("incidents show", lambda i: type(group).show.callback(group, i, incident_id)),
        (
            "incidents acknowledge",
            lambda i: type(group).acknowledge.callback(group, i, incident_id, False, None),
        ),
        ("incidents export", lambda i: type(group).export.callback(group, i, 7)),
    ):
        inter = interaction(bot, guild, owner)
        await run(label, coro_factory(inter))
        assert inter.replies, label
    assert any(m.get("file") is not None for m in inter.replies), "export must attach a file"

    # backup
    group = shield_cog.backup
    inter = interaction(bot, guild, owner)
    await run("backup settings", type(group).settings.callback(group, inter, 60, 3, True))
    assert "Snapshot settings updated" in inter.text()

    # restore history
    group = shield_cog.restore
    inter = interaction(bot, guild, owner)
    await run("restore history", type(group).history.callback(group, inter))
    assert inter.replies

    # lockdown status + raid disable (not active)
    group = shield_cog.lockdown
    inter = interaction(bot, guild, owner)
    await run("lockdown status", type(group).status.callback(group, inter))
    assert "Lockdown" in inter.text()
    inter = interaction(bot, guild, owner)
    await run("lockdown raid off", type(group).raid.callback(group, inter, False, 30, 30))
    assert "not active" in inter.text()

    # mode + disable (ordered last: they change protection state)
    inter = interaction(bot, guild, owner)
    await run(
        "mode enforce",
        ShieldCommands.set_mode.callback(
            shield_cog, inter, app_commands.Choice(name="enforce", value="enforce")
        ),
    )
    assert "enforce" in inter.text()
    inter = interaction(bot, guild, owner)
    await run("disable", ShieldCommands.disable.callback(shield_cog, inter, "smoke test"))
    assert "disabled" in inter.text()

    assert len(checked) == 19
