"""Attack simulations driven through the real gateway listeners.

These tests exercise the cogs (not just the pipeline), so they cover the
normalisation each listener performs as well as the downstream decision. No
destructive action is ever taken against a real guild: every Discord call lands
on a fake that records it.

Mapping to the threat model (``docs/THREAT_MATRIX.md``):

* T1 compromised admin mass channel delete
* T2 rogue moderator mass ban
* T3 privilege escalation (role permission edit and dangerous role grant)
* T4 malicious bot addition
* T5 webhook abuse
* T6 join flood / raid
* T7 message spam and mention flood
* T8 guild identity and security setting changes
* T9 attacker above the bot in the hierarchy
* T10 legitimate administration (false-positive control)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import discord
import pytest

from shield.constants import ActionKey, EnforcementStatus
from shield.db.repositories import UnitOfWork
from shield.events.admin_events import AdminEventsCog
from shield.events.member_events import MemberEventsCog
from shield.events.message_events import MessageEventsCog
from tests.conftest import (
    ATTACKER,
    GUILD_A,
    GUILD_B,
    MOD,
    OWNER_A,
    OWNER_B,
    VICTIM,
    FakeChannel,
    FakeMember,
    FakeMessage,
    FakeRole,
    audit_entry,
    build_guild,
    enable_guild,
    perms,
    set_policy,
)


@pytest.fixture
def cogs(harness):  # noqa: ANN001, ANN201
    harness.bot.pipeline = harness.pipeline
    return {
        "member": MemberEventsCog(harness.bot),
        "message": MessageEventsCog(harness.bot),
        "admin": AdminEventsCog(harness.bot),
    }


async def incidents_for(db, guild_id: int):  # noqa: ANN001, ANN201
    async with db.begin() as session:
        uow = UnitOfWork(session)
        return list(await uow.incidents.list_recent(guild_id, limit=50))


def channel(guild, channel_id: int, name: str = "doomed") -> FakeChannel:  # noqa: ANN001
    return FakeChannel(id=channel_id, name=name, guild=guild)


# ---------------------------------------------------------------------
# T1: compromised admin nukes channels
# ---------------------------------------------------------------------
async def test_t1_compromised_admin_channel_nuke_is_contained(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)

    for index in range(5):
        target = channel(guild, 10_000 + index, f"general-{index}")
        guild.audit_entries.append(
            audit_entry(
                entry_id=1000 + index,
                actor_id=ATTACKER,
                target_id=target.id,
                action=discord.AuditLogAction.channel_delete,
                age_seconds=0.1,
            )
        )
        await cogs["admin"].on_guild_channel_delete(target)

    attacker = guild.members[ATTACKER]
    assert attacker.removed_roles, "the attacker's Admin role must be removed"
    assert "Admin" not in {r.name for r in attacker.roles}
    assert "Blue" in {r.name for r in attacker.roles}, "safe roles are preserved"

    rows = await incidents_for(harness.db, guild.id)
    assert len(rows) == 1, "the cooldown collapses the burst into one incident"
    assert rows[0].outcome in {EnforcementStatus.SUCCEEDED, EnforcementStatus.PARTIAL}
    assert guild.get_channel(guild.id + 101).sent

    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        events = await uow.events.recent(
            guild.id, since=datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        )
    assert len([e for e in events if e.action_key is ActionKey.CHANNEL_DELETE]) == 5


# ---------------------------------------------------------------------
# T2: rogue moderator mass ban
# ---------------------------------------------------------------------
async def test_t2_mass_ban_requires_two_events_then_acts(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    mod = guild.members[MOD]
    mod.roles.append(next(r for r in guild.roles if r.name == "Admin"))

    for index in range(2):
        victim = FakeMember(id=VICTIM + index, name=f"victim{index}")
        guild.audit_entries.append(
            audit_entry(
                entry_id=2000 + index,
                actor_id=MOD,
                target_id=victim.id,
                action=discord.AuditLogAction.ban,
                age_seconds=0.1,
            )
        )
        await cogs["member"].on_member_ban(guild, victim)

    assert mod.removed_roles, "two bans in 15s crosses the threshold"
    rows = await incidents_for(harness.db, guild.id)
    assert rows[0].action_key is ActionKey.MASS_BAN
    assert rows[0].event_count >= 2


async def test_t2_single_ban_is_not_an_incident(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    victim = FakeMember(id=VICTIM, name="victim")
    guild.audit_entries.append(
        audit_entry(
            entry_id=2100,
            actor_id=MOD,
            target_id=victim.id,
            action=discord.AuditLogAction.ban,
            age_seconds=0.1,
        )
    )
    await cogs["member"].on_member_ban(guild, victim)
    assert await incidents_for(harness.db, guild.id) == []


# ---------------------------------------------------------------------
# T2b: kick vs voluntary leave
# ---------------------------------------------------------------------
async def test_t2b_voluntary_leave_produces_no_event(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    leaver = FakeMember(id=VICTIM, name="leaver", guild=guild)
    await cogs["member"].on_member_remove(leaver)
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        events = await uow.events.recent(
            guild.id, since=datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        )
    assert events == [], "a member leaving on their own is not a security event"


async def test_t2b_kick_is_detected_through_the_audit_log(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    for index in range(2):
        victim = FakeMember(id=VICTIM + index, name=f"kicked{index}", guild=guild)
        guild.audit_entries.append(
            audit_entry(
                entry_id=2200 + index,
                actor_id=ATTACKER,
                target_id=victim.id,
                action=discord.AuditLogAction.kick,
                age_seconds=0.1,
            )
        )
        await cogs["member"].on_member_remove(victim)
    rows = await incidents_for(harness.db, guild.id)
    assert rows and rows[0].action_key is ActionKey.MASS_KICK


# ---------------------------------------------------------------------
# T3: privilege escalation
# ---------------------------------------------------------------------
async def test_t3_role_permission_elevation_is_a_single_event_incident(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    before = FakeRole(id=guild.id + 500, name="Members", position=2, guild=guild)
    after = FakeRole(
        id=guild.id + 500,
        name="Members",
        position=2,
        permissions=perms(administrator=True),
        guild=guild,
    )
    guild.audit_entries.append(
        audit_entry(
            entry_id=3000,
            actor_id=ATTACKER,
            target_id=after.id,
            action=discord.AuditLogAction.role_update,
            age_seconds=0.1,
        )
    )
    await cogs["admin"].on_guild_role_update(before, after)

    rows = await incidents_for(harness.db, guild.id)
    assert rows and rows[0].action_key is ActionKey.DANGEROUS_PERMISSION_CHANGE
    assert rows[0].details["payload"]["granted"] == ["administrator"]
    assert guild.members[ATTACKER].removed_roles


async def test_t3_harmless_role_edit_is_ignored(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    before = FakeRole(id=guild.id + 501, name="Blue", position=2, guild=guild)
    after = FakeRole(
        id=guild.id + 501, name="Blue", position=2, permissions=perms(connect=True), guild=guild
    )
    await cogs["admin"].on_guild_role_update(before, after)
    assert await incidents_for(harness.db, guild.id) == []


async def test_t3_dangerous_role_grant_to_a_member(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    everyone = guild.roles[0]
    admin = next(r for r in guild.roles if r.name == "Admin")
    before = FakeMember(id=VICTIM, name="puppet", roles=[everyone], guild=guild)
    after = FakeMember(id=VICTIM, name="puppet", roles=[everyone, admin], guild=guild)
    guild.members[VICTIM] = after
    guild.audit_entries.append(
        audit_entry(
            entry_id=3100,
            actor_id=ATTACKER,
            target_id=VICTIM,
            action=discord.AuditLogAction.member_role_update,
            age_seconds=0.1,
        )
    )
    await cogs["member"].on_member_update(before, after)
    rows = await incidents_for(harness.db, guild.id)
    assert rows and rows[0].action_key is ActionKey.DANGEROUS_ROLE_GRANT
    assert rows[0].actor_id == ATTACKER


async def test_t3_channel_overwrite_escalation_is_reported(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    victim_role = next(r for r in guild.roles if r.name == "Blue")
    before = FakeChannel(id=guild.id + 600, name="secret", guild=guild)
    after = FakeChannel(id=guild.id + 600, name="secret", guild=guild)
    after.overwrites = {victim_role: discord.PermissionOverwrite(manage_channels=True)}
    guild.audit_entries.append(
        audit_entry(
            entry_id=3200,
            actor_id=ATTACKER,
            target_id=after.id,
            action=discord.AuditLogAction.overwrite_update,
            age_seconds=0.1,
        )
    )
    await cogs["admin"].on_guild_channel_update(before, after)
    rows = await incidents_for(harness.db, guild.id)
    assert rows and rows[0].action_key is ActionKey.DANGEROUS_PERMISSION_CHANGE
    assert rows[0].details["payload"]["scope"] == "channel_overwrite"


# ---------------------------------------------------------------------
# T4: malicious bot addition
# ---------------------------------------------------------------------
async def test_t4_bot_addition_alerts_without_sanction(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    new_bot = FakeMember(id=777000000000000001, name="EvilBot", bot=True, guild=guild)
    guild.members[new_bot.id] = new_bot
    guild.audit_entries.append(
        audit_entry(
            entry_id=4000,
            actor_id=ATTACKER,
            target_id=new_bot.id,
            action=discord.AuditLogAction.bot_add,
            age_seconds=0.1,
        )
    )
    await cogs["member"].on_member_join(new_bot)

    rows = [r for r in await incidents_for(harness.db, guild.id) if r.action_key is ActionKey.BOT_ADD]
    assert rows, "a bot addition must be reported"
    assert rows[0].actor_id == ATTACKER
    assert rows[0].response.value == "alert_only"
    assert guild.members[ATTACKER].removed_roles == [], "default is alert-only, not a sanction"


# ---------------------------------------------------------------------
# T5: webhook abuse
# ---------------------------------------------------------------------
async def test_t5_webhook_creation_is_classified_from_the_audit_log(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    target = guild.get_channel(guild.id + 100)
    guild.audit_entries.append(
        audit_entry(
            entry_id=5000,
            actor_id=ATTACKER,
            target_id=999,
            action=discord.AuditLogAction.webhook_create,
            age_seconds=0.1,
        )
    )
    await cogs["admin"].on_webhooks_update(target)
    rows = await incidents_for(harness.db, guild.id)
    assert rows and rows[0].action_key is ActionKey.WEBHOOK_CREATE
    assert rows[0].actor_id == ATTACKER
    assert "classified from audit entry" in rows[0].details["payload"]["classification"]


async def test_t5_webhook_change_without_audit_access_is_still_reported(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(
        build_guild(bot_permissions=perms(manage_roles=True, send_messages=True, embed_links=True))
    )
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    await cogs["admin"].on_webhooks_update(guild.get_channel(guild.id + 100))
    rows = await incidents_for(harness.db, guild.id)
    assert rows and rows[0].action_key is ActionKey.WEBHOOK_UPDATE
    assert rows[0].actor_id is None
    assert "not readable" in rows[0].details["payload"]["classification"]


async def test_t5_suspicious_webhook_message_is_alerted_not_punished(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    target = guild.get_channel(guild.id + 100)
    message = FakeMessage(
        id=5100,
        author=FakeMember(id=888000000000000001, name="Webhook"),
        channel=target,
        guild=guild,
        content="@everyone free nitro",
        mention_everyone=True,
        webhook_id=5200,
    )
    await cogs["message"].on_message(message)
    rows = await incidents_for(harness.db, guild.id)
    assert rows and rows[0].action_key is ActionKey.WEBHOOK_UPDATE
    assert rows[0].details["payload"]["suspicious_webhook_message"] is True
    assert rows[0].actor_id is None


# ---------------------------------------------------------------------
# T6: join flood / raid
# ---------------------------------------------------------------------
async def test_t6_join_flood_enables_raid_mode_and_bans_nobody(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    guild.features.append("SUPPORTS_INVITE_TOGGLE")
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    channel_obj = guild.get_channel(guild.id + 100)

    joiners = []
    for index in range(8):
        member = FakeMember(
            id=600000000000000000 + index,
            name=f"raider{index}",
            guild=guild,
            created_at=datetime.now(tz=timezone.utc) - timedelta(days=200),
        )
        guild.members[member.id] = member
        joiners.append(member)
        await cogs["member"].on_member_join(member)

    rows = [r for r in await incidents_for(harness.db, guild.id) if r.action_key is ActionKey.JOIN_FLOOD]
    assert rows, "a join flood must raise an incident"
    assert any("verification_level" in edit for edit in guild.edits)
    assert channel_obj.slowmode_delay > 0
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        settings = await uow.guilds.get(guild.id)
    assert settings.raid_mode_active is True
    for member in joiners:
        assert member.removed_roles == [] and member.timeouts == []


async def test_t6_raid_mode_expires_and_restores_settings(harness, cogs, shield_config):  # noqa: ANN001
    from shield.bot import ShieldBot

    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel_obj = guild.get_channel(guild.id + 100)

    result, until = await harness.lockdown.enable_raid_mode(
        guild, reason="simulated flood", minutes=1, slowmode_seconds=30
    )
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        await uow.guilds.update(
            guild.id,
            raid_mode_active=True,
            raid_mode_until=datetime.now(tz=timezone.utc) - timedelta(minutes=1),
            raid_mode_state=result.previous_state,
        )
    assert channel_obj.slowmode_delay == 30

    # Drive the real maintenance tick without connecting to Discord.
    class TickBot(ShieldBot):
        """ShieldBot with the gateway-backed attributes stubbed out."""

        @property
        def guilds(self):  # noqa: ANN201 - read-only property on discord.Client
            return self._fake_guilds

        def get_guild(self, guild_id):  # noqa: ANN001, ANN201
            return next((g for g in self._fake_guilds if g.id == int(guild_id)), None)

    bot = TickBot.__new__(TickBot)
    bot.shield_config = shield_config
    bot.db = harness.db
    bot.lockdown = harness.lockdown
    bot.notifier = harness.notifier
    bot.pipeline = harness.pipeline
    bot._fake_guilds = [guild]
    bot._maintenance_ticks = 0
    report = await bot.maintenance_tick()

    assert report["raid_modes_expired"] == 1
    assert channel_obj.slowmode_delay == 0
    assert guild.verification_level is discord.VerificationLevel.low
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        settings = await uow.guilds.get(guild.id)
    assert settings.raid_mode_active is False


# ---------------------------------------------------------------------
# T7: spam and mention floods
# ---------------------------------------------------------------------
async def test_t7_message_spam_is_timed_out_not_role_stripped(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    target = guild.get_channel(guild.id + 100)
    target.purge_result = [object()] * 6
    spammer = guild.members[MOD]

    for index in range(6):
        await cogs["message"].on_message(
            FakeMessage(
                id=7000 + index,
                author=spammer,
                channel=target,
                guild=guild,
                content=f"message {index}",
            )
        )

    assert spammer.timeouts, "spam is answered with a timeout"
    assert spammer.removed_roles == [], "spam must never strip roles"
    assert target.purged, "a bounded cleanup should run"
    rows = [r for r in await incidents_for(harness.db, guild.id) if r.action_key is ActionKey.MESSAGE_SPAM]
    assert rows


async def test_t7_identical_messages_trip_duplicate_spam(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    await set_policy(harness.db, guild.id, ActionKey.MESSAGE_SPAM, enabled=False)
    harness.pipeline.state_cache.invalidate(guild.id)
    target = guild.get_channel(guild.id + 100)
    spammer = guild.members[MOD]

    for index in range(4):
        await cogs["message"].on_message(
            FakeMessage(
                id=7100 + index,
                author=spammer,
                channel=target,
                guild=guild,
                content="JOIN MY DISCORD http://example.invalid",
            )
        )
    rows = [
        r for r in await incidents_for(harness.db, guild.id) if r.action_key is ActionKey.DUPLICATE_SPAM
    ]
    assert rows
    assert spammer.timeouts


async def test_t7_everyone_mention_from_untrusted_member(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    target = guild.get_channel(guild.id + 100)
    offender = guild.members[MOD]
    await cogs["message"].on_message(
        FakeMessage(
            id=7200,
            author=offender,
            channel=target,
            guild=guild,
            content="@everyone look at this",
            mention_everyone=True,
        )
    )
    rows = [r for r in await incidents_for(harness.db, guild.id) if r.action_key is ActionKey.MASS_MENTION]
    assert rows and offender.timeouts


async def test_t7_shield_never_polices_itself(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    target = guild.get_channel(guild.id + 100)
    for index in range(10):
        await cogs["message"].on_message(
            FakeMessage(
                id=7300 + index,
                author=harness.bot.user,
                channel=target,
                guild=guild,
                content="incident report",
            )
        )
    assert await incidents_for(harness.db, guild.id) == []


# ---------------------------------------------------------------------
# T8: guild identity / security settings
# ---------------------------------------------------------------------
async def test_t8_guild_settings_change_is_reported(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    before = build_guild()
    before.name = "Test Guild"
    before.verification_level = discord.VerificationLevel.low
    guild.name = "Nuked Guild"
    guild.verification_level = discord.VerificationLevel.none
    guild.audit_entries.append(
        audit_entry(
            entry_id=8000,
            actor_id=ATTACKER,
            target_id=None,
            action=discord.AuditLogAction.guild_update,
            age_seconds=0.1,
        )
    )
    await cogs["admin"].on_guild_update(before, guild)
    rows = await incidents_for(harness.db, guild.id)
    assert rows and rows[0].action_key is ActionKey.GUILD_SETTINGS_CHANGE
    changed = rows[0].details["payload"]["changed_fields"]
    assert "name" in changed and "verification_level" in changed
    assert rows[0].response.value == "alert_only", "guild updates alert by default"


async def test_t8_vanity_url_change_uses_its_own_policy(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    guild.features.append("VANITY_URL")
    await enable_guild(harness.db, guild)
    before = build_guild()
    before.vanity_url_code = "goodserver"
    guild.vanity_url_code = "hacked"
    guild.audit_entries.append(
        audit_entry(
            entry_id=8100,
            actor_id=ATTACKER,
            target_id=None,
            action=discord.AuditLogAction.guild_update,
            age_seconds=0.1,
        )
    )
    await cogs["admin"].on_guild_update(before, guild)
    rows = await incidents_for(harness.db, guild.id)
    assert any(r.action_key is ActionKey.VANITY_URL_CHANGE for r in rows)


# ---------------------------------------------------------------------
# T9: attacker above the bot
# ---------------------------------------------------------------------
async def test_t9_attacker_above_the_bot_is_not_falsely_contained(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    top_role = FakeRole(
        id=guild.id + 950,
        name="Founder",
        position=500,
        permissions=perms(administrator=True),
        guild=guild,
    )
    guild.roles.append(top_role)
    attacker = guild.members[ATTACKER]
    attacker.roles = [guild.roles[0], top_role]

    target = channel(guild, 9000)
    guild.audit_entries.append(
        audit_entry(
            entry_id=9000,
            actor_id=ATTACKER,
            target_id=target.id,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=0.1,
        )
    )
    await cogs["admin"].on_guild_channel_delete(target)

    assert attacker.removed_roles == []
    rows = await incidents_for(harness.db, guild.id)
    assert rows and rows[0].severity.value == "critical"
    assert "reach" in rows[0].reason or "above Shield" in rows[0].reason
    posted = str(guild.get_channel(guild.id + 101).sent[0].title)
    assert "CONTAINMENT FAILED" in posted


async def test_t9_owner_nuke_alerts_without_sanction(harness, cogs):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    target = channel(guild, 9100)
    guild.audit_entries.append(
        audit_entry(
            entry_id=9100,
            actor_id=OWNER_A,
            target_id=target.id,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=0.1,
        )
    )
    await cogs["admin"].on_guild_channel_delete(target)
    assert guild.members[OWNER_A].removed_roles == []
    posted = str(guild.get_channel(guild.id + 101).sent[0].title)
    assert "OWNER ACTION" in posted


# ---------------------------------------------------------------------
# T10: false-positive control - legitimate administration
# ---------------------------------------------------------------------
async def test_t10_allowlisted_admin_restructuring_is_silent(harness, cogs):  # noqa: ANN001
    from shield.constants import TrustScope

    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        await uow.trust.add(
            guild.id,
            entity_type="user",
            entity_id=MOD,
            scopes=[TrustScope.DESTRUCTIVE],
            added_by=OWNER_A,
            reason="server restructure window",
        )
    harness.pipeline.state_cache.invalidate(guild.id)

    for index in range(6):
        target = channel(guild, 10_500 + index)
        guild.audit_entries.append(
            audit_entry(
                entry_id=10_500 + index,
                actor_id=MOD,
                target_id=target.id,
                action=discord.AuditLogAction.channel_delete,
                age_seconds=0.1,
            )
        )
        await cogs["admin"].on_guild_channel_delete(target)

    assert await incidents_for(harness.db, guild.id) == []
    assert guild.members[MOD].removed_roles == []
    assert guild.get_channel(guild.id + 101).sent == []


async def test_t10_alert_only_rollout_never_acts(harness, cogs):  # noqa: ANN001
    """The documented safe rollout: alert-only first, nothing is ever changed."""
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, mode="alert_only", log_channel_id=guild.id + 101)
    for index in range(4):
        target = channel(guild, 11_000 + index)
        guild.audit_entries.append(
            audit_entry(
                entry_id=11_000 + index,
                actor_id=ATTACKER,
                target_id=target.id,
                action=discord.AuditLogAction.channel_delete,
                age_seconds=0.1,
            )
        )
        await cogs["admin"].on_guild_channel_delete(target)
    rows = await incidents_for(harness.db, guild.id)
    assert rows, "incidents are still recorded for tuning"
    assert all(r.dry_run for r in rows)
    assert guild.members[ATTACKER].removed_roles == []
    assert guild.get_channel(guild.id + 101).sent


# ---------------------------------------------------------------------
# Cross-guild and resilience
# ---------------------------------------------------------------------
async def test_simultaneous_attacks_on_two_guilds_stay_isolated(harness, cogs):  # noqa: ANN001
    guild_a = harness.register_guild(build_guild(GUILD_A, OWNER_A))
    guild_b = harness.register_guild(build_guild(GUILD_B, OWNER_B))
    await enable_guild(harness.db, guild_a)
    await enable_guild(harness.db, guild_b, mode="alert_only")

    async def nuke(guild, base: int) -> None:  # noqa: ANN001
        for index in range(3):
            target = channel(guild, base + index)
            guild.audit_entries.append(
                audit_entry(
                    entry_id=base + index,
                    actor_id=ATTACKER,
                    target_id=target.id,
                    action=discord.AuditLogAction.channel_delete,
                    age_seconds=0.1,
                )
            )
            await cogs["admin"].on_guild_channel_delete(target)

    await asyncio.gather(nuke(guild_a, 12_000), nuke(guild_b, 13_000))

    assert guild_a.members[ATTACKER].removed_roles, "guild A enforces"
    assert guild_b.members[ATTACKER].removed_roles == [], "guild B is alert-only"

    rows_a = await incidents_for(harness.db, guild_a.id)
    rows_b = await incidents_for(harness.db, guild_b.id)
    assert {r.guild_id for r in rows_a} == {guild_a.id}
    assert {r.guild_id for r in rows_b} == {guild_b.id}
    assert all(not r.dry_run for r in rows_a)
    assert all(r.dry_run for r in rows_b)


async def test_restart_during_an_attack_keeps_counting(harness, cogs):  # noqa: ANN001
    """Simulate a crash after one ban: the second ban must still trip the policy."""
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)

    first_victim = FakeMember(id=VICTIM, name="v1")
    guild.audit_entries.append(
        audit_entry(
            entry_id=14_000,
            actor_id=ATTACKER,
            target_id=first_victim.id,
            action=discord.AuditLogAction.ban,
            age_seconds=0.1,
        )
    )
    await cogs["member"].on_member_ban(guild, first_victim)
    assert guild.members[ATTACKER].removed_roles == []

    # "Restart": throw away all in-memory detection state.
    harness.pipeline.windows.drop_guild(guild.id)
    harness.pipeline.state_cache.invalidate_all()
    harness.correlator.forget_guild(guild.id)
    restored = await harness.pipeline.rehydrate_windows(guild.id)
    assert restored >= 1

    second_victim = FakeMember(id=VICTIM + 1, name="v2")
    guild.audit_entries.append(
        audit_entry(
            entry_id=14_001,
            actor_id=ATTACKER,
            target_id=second_victim.id,
            action=discord.AuditLogAction.ban,
            age_seconds=0.1,
        )
    )
    await cogs["member"].on_member_ban(guild, second_victim)
    assert guild.members[ATTACKER].removed_roles, "the pre-restart ban still counted"


async def test_restoration_burst_does_not_trigger_self_protection(harness, cogs):  # noqa: ANN001
    """Shield recreating 10 channels must not look like a creation flood."""
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    harness.selfguard.register(guild.id, "channel_create", None, count=10)

    for index in range(10):
        created = channel(guild, 15_000 + index, f"restored-{index}")
        guild.channels.append(created)
        await cogs["admin"].on_guild_channel_create(created)

    assert await incidents_for(harness.db, guild.id) == []
    assert guild.members[ATTACKER].removed_roles == []
