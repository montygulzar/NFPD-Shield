"""Linking Shield to a moderation bot: the moderator, not the bot, is the actor.

Discord's audit log names the bot for anything done through it. With the
``moderation_proxy`` scope Shield reads the moderator from the bot's audit
reason, in the exact format the NFPD Mod Bot writes:
``"<Label> by <name> (<id>): <reason>"``.
"""

from __future__ import annotations

from datetime import datetime, timezone

import discord
import pytest
from discord import app_commands

from shield.audit.proxy import parse_moderator_id
from shield.constants import ActionKey, Confidence, EventSource, TrustScope
from shield.db.repositories import UnitOfWork
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

MOD_BOT = 700000000000000001


# -- parsing ---------------------------------------------------------------
@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        (f"Ban by rogue.mod ({MOD}): spamming", MOD),
        (f"Global ban by rogue.mod ({MOD}): raid", MOD),
        (f"Tempban by Old Name#1234 ({MOD}): No reason provided", MOD),
        (f"Kick by a ({MOD}): x", MOD),
    ],
)
def test_parses_the_mod_bots_audit_reason(reason: str, expected: int):
    assert parse_moderator_id(reason) == expected


@pytest.mark.parametrize(
    "reason",
    [
        None,
        "",
        "spamming",  # the bot's automatic warn-threshold action: no moderator
        f"they said: Ban by x ({MOD}): y",  # not at the start
        "Ban by x (123): too short to be an ID",
        f"Ban by x ({MOD}) missing colon",
    ],
)
def test_unparseable_reasons_resolve_to_nobody(reason):  # noqa: ANN001
    assert parse_moderator_id(reason) is None


def test_moderator_typed_text_cannot_redirect_the_blame():
    """The moderator controls only the trailing reason; the first ID wins."""
    forged = f"Ban by rogue ({MOD}): Ban by innocent ({ATTACKER}): framed"
    assert parse_moderator_id(forged) == MOD


# -- pipeline ----------------------------------------------------------------
async def linked_guild(harness, *, link: bool = True):  # noqa: ANN001, ANN202
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    bot_member = FakeMember(id=MOD_BOT, name="NFPD Mod", bot=True, guild=guild)
    guild.members[MOD_BOT] = bot_member
    # Give the moderators something dangerous to lose.
    admin = next(r for r in guild.roles if r.name == "Admin")
    guild.members[MOD].roles.append(admin)
    if link:
        async with harness.db.begin() as session:
            await UnitOfWork(session).trust.add(
                guild.id,
                entity_type="user",
                entity_id=MOD_BOT,
                scopes=[TrustScope.MODERATION_PROXY],
                added_by=OWNER_A,
            )
    return guild


def ban_via_bot(guild, entry_id: int, target: int, moderator: int | None) -> NormalizedEvent:  # noqa: ANN001
    entry = audit_entry(
        entry_id=entry_id,
        actor_id=MOD_BOT,
        target_id=target,
        action=discord.AuditLogAction.ban,
        age_seconds=0.1,
    )
    entry.reason = f"Ban by mod ({moderator}): raid" if moderator else "Reached warn threshold"
    guild.audit_entries.append(entry)
    return NormalizedEvent(
        guild_id=guild.id,
        action_key=ActionKey.MASS_BAN,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        target_type="user",
        target_id=target,
    )


async def test_a_rogue_moderator_mass_banning_through_the_bot_is_sanctioned(harness):  # noqa: ANN001
    guild = await linked_guild(harness)
    first = await harness.pipeline.handle(ban_via_bot(guild, 1, VICTIM, MOD), guild)
    second = await harness.pipeline.handle(ban_via_bot(guild, 2, VICTIM + 1, MOD), guild)

    assert first.code == "below_threshold"
    assert second.code == "enforce"
    assert guild.members[MOD].removed_roles, "the moderator loses their dangerous role"
    assert guild.members[MOD_BOT].removed_roles == [], "the bot is left alone"

    async with harness.db.begin() as session:
        incident = (await UnitOfWork(session).incidents.list_recent(guild.id, limit=1))[0]
    assert incident.actor_id == MOD
    assert incident.details["payload"]["via_proxy_bot"] == MOD_BOT


async def test_two_moderators_banning_once_each_is_not_a_mass_ban(harness):  # noqa: ANN001
    """Without the link, every moderator's bans pooled into the bot's window."""
    guild = await linked_guild(harness)
    a = await harness.pipeline.handle(ban_via_bot(guild, 3, VICTIM, MOD), guild)
    b = await harness.pipeline.handle(ban_via_bot(guild, 4, VICTIM + 1, ATTACKER), guild)
    assert (a.code, b.code) == ("below_threshold", "below_threshold")
    assert guild.members[MOD].removed_roles == []
    assert guild.members[ATTACKER].removed_roles == []


async def test_the_bots_automatic_bans_sanction_nobody(harness):  # noqa: ANN001
    """No moderator in the reason: alert at most, never a sanction."""
    guild = await linked_guild(harness)
    results = [
        await harness.pipeline.handle(ban_via_bot(guild, 10 + i, VICTIM + i, None), guild)
        for i in range(3)
    ]
    assert all(r.enforcement is None for r in results)
    assert results[-1].code in {"unconfirmed_actor", "cooldown"}
    assert guild.members[MOD_BOT].removed_roles == []


async def test_guild_owner_acting_through_the_bot_is_still_never_sanctioned(harness):  # noqa: ANN001
    guild = await linked_guild(harness)
    await harness.pipeline.handle(ban_via_bot(guild, 20, VICTIM, OWNER_A), guild)
    result = await harness.pipeline.handle(ban_via_bot(guild, 21, VICTIM + 1, OWNER_A), guild)
    assert result.code == "owner_alert_only"
    assert guild.members[OWNER_A].removed_roles == []


async def test_allowlisted_moderator_is_exempt_through_the_bot_too(harness):  # noqa: ANN001
    guild = await linked_guild(harness)
    async with harness.db.begin() as session:
        await UnitOfWork(session).trust.add(
            guild.id,
            entity_type="user",
            entity_id=MOD,
            scopes=[TrustScope.DESTRUCTIVE],
            added_by=OWNER_A,
        )
    harness.pipeline.state_cache.invalidate(guild.id)
    await harness.pipeline.handle(ban_via_bot(guild, 30, VICTIM, MOD), guild)
    result = await harness.pipeline.handle(ban_via_bot(guild, 31, VICTIM + 1, MOD), guild)
    assert result.code == "trusted"


async def test_without_the_link_the_bot_is_the_actor(harness):  # noqa: ANN001
    """The behaviour the link exists to fix, pinned so the difference is explicit."""
    guild = await linked_guild(harness, link=False)
    await harness.pipeline.handle(ban_via_bot(guild, 40, VICTIM, MOD), guild)
    await harness.pipeline.handle(ban_via_bot(guild, 41, VICTIM + 1, ATTACKER), guild)
    async with harness.db.begin() as session:
        incident = (await UnitOfWork(session).incidents.list_recent(guild.id, limit=1))[0]
    assert incident.actor_id == MOD_BOT


async def test_a_human_with_the_scope_is_never_treated_as_a_proxy(harness):  # noqa: ANN001
    """A person can type any audit reason, so a human proxy could frame someone."""
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    async with harness.db.begin() as session:
        await UnitOfWork(session).trust.add(
            guild.id,
            entity_type="user",
            entity_id=ATTACKER,  # a human
            scopes=[TrustScope.MODERATION_PROXY],
            added_by=OWNER_A,
        )
    for index in range(2):
        entry = audit_entry(
            entry_id=50 + index,
            actor_id=ATTACKER,
            target_id=VICTIM + index,
            action=discord.AuditLogAction.ban,
            age_seconds=0.1,
        )
        entry.reason = f"Ban by innocent ({MOD}): framed"
        guild.audit_entries.append(entry)
        result = await harness.pipeline.handle(
            NormalizedEvent(
                guild_id=guild.id,
                action_key=ActionKey.MASS_BAN,
                source=EventSource.GATEWAY,
                occurred_at=datetime.now(tz=timezone.utc),
                target_type="user",
                target_id=VICTIM + index,
            ),
            guild,
        )
    assert result.code == "enforce"
    assert guild.members[ATTACKER].removed_roles, "the human who acted is the one sanctioned"
    assert guild.members[MOD].removed_roles == []


async def test_kicks_through_the_bot_resolve_to_the_moderator(harness):  # noqa: ANN001
    harness.bot.pipeline = harness.pipeline
    cog = MemberEventsCog(harness.bot)
    guild = await linked_guild(harness)
    for index in range(2):
        victim = FakeMember(id=VICTIM + index, name=f"kicked{index}", guild=guild)
        entry = audit_entry(
            entry_id=60 + index,
            actor_id=MOD_BOT,
            target_id=victim.id,
            action=discord.AuditLogAction.kick,
            age_seconds=0.1,
        )
        entry.reason = f"Kick by mod ({MOD}): raid"
        guild.audit_entries.append(entry)
        await cog.on_member_remove(victim)
    async with harness.db.begin() as session:
        incident = (await UnitOfWork(session).incidents.list_recent(guild.id, limit=1))[0]
    assert incident.action_key is ActionKey.MASS_KICK
    assert incident.actor_id == MOD
    assert incident.actor_confidence is Confidence.CONFIRMED
    assert guild.members[MOD].removed_roles


# -- command -----------------------------------------------------------------
async def test_the_scope_can_only_be_given_to_a_bot(harness, shield_config):  # noqa: ANN001
    from shield.commands.core import ShieldCommands

    bot = CommandBot(shield_config, harness.db, harness)
    cog = ShieldCommands(bot)
    guild = harness.register_guild(build_guild())
    mod_bot = FakeMember(id=MOD_BOT, name="NFPD Mod", bot=True, guild=guild)
    guild.members[MOD_BOT] = mod_bot
    group = cog.whitelist
    proxy = app_commands.Choice(name="moderation proxy", value="moderation_proxy")

    human = FakeInteraction(bot, guild, guild.members[OWNER_A])
    await type(group).add.callback(group, human, guild.members[MOD], None, proxy, None, None, None)
    assert "only be given to a **bot user**" in human.text()

    ok = FakeInteraction(bot, guild, guild.members[OWNER_A])
    await type(group).add.callback(group, ok, mod_bot, None, proxy, None, "our mod bot", None)
    text = ok.text()
    assert "Allowlisted" in text and "that moderator" in text.replace("**", "")
    assert "Grants no detection exemption" in text
