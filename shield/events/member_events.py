"""Member gateway listeners: joins, departures, bans and role grants.

Intent requirements
-------------------
* ``on_member_join`` / ``on_member_remove`` / ``on_member_update`` require the
  privileged **Guild Members** intent. Without it these detectors are inert and
  ``/shield health`` reports them as unavailable.
* ``on_member_ban`` requires the ``Guilds`` + ``Moderation`` (bans) intents,
  which discord.py enables with ``Intents.bans``/``moderation``.

Attribution notes
-----------------
* A **join** has no actor to blame - that is the point of the join-flood policy
  being a raid-mode trigger rather than a sanction.
* A **departure** is indistinguishable from a kick on the gateway. Shield
  consults the audit log and only raises a ``mass_kick`` event when a matching
  kick entry exists; a voluntary leave therefore produces no event at all.
"""

from __future__ import annotations

from datetime import datetime, timezone

import discord
from discord.ext import commands

from shield.constants import ActionKey, EventSource
from shield.enforcement.safety import permissions_set
from shield.events.normalize import NormalizedEvent
from shield.observability.logging import get_logger

log = get_logger("events.member")


class MemberEventsCog(commands.Cog):
    """Direct gateway signals about members."""

    def __init__(self, bot) -> None:  # noqa: ANN001
        self.bot = bot

    @property
    def pipeline(self):  # noqa: ANN201
        return self.bot.pipeline

    # -- joins ---------------------------------------------------------
    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        guild = member.guild
        if guild is None:
            return
        created = getattr(member, "created_at", None)
        age_hours = None
        if isinstance(created, datetime):
            reference = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
            age_hours = max(
                0.0, (datetime.now(tz=timezone.utc) - reference).total_seconds() / 3600.0
            )

        join_event = NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.JOIN_FLOOD,
            source=EventSource.GATEWAY,
            occurred_at=datetime.now(tz=timezone.utc),
            target_type="member",
            target_id=member.id,
            payload={
                "target_name": str(member),
                "is_bot": bool(member.bot),
                "account_age_hours": round(age_hours, 2) if age_hours is not None else None,
            },
        )
        await self.pipeline.handle(join_event, guild)

        if member.bot:
            # A bot joining is an integration install. The authorising member is
            # only discoverable through the audit log, so attribution runs in the
            # pipeline and a sanction requires CONFIRMED attribution.
            bot_event = NormalizedEvent(
                guild_id=guild.id,
                action_key=ActionKey.BOT_ADD,
                source=EventSource.GATEWAY,
                occurred_at=datetime.now(tz=timezone.utc),
                target_type="bot",
                target_id=member.id,
                payload={"target_name": str(member), "bot_id": member.id},
            )
            await self.pipeline.handle(bot_event, guild)

    # -- departures ----------------------------------------------------
    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member) -> None:
        """Distinguish a kick from a voluntary leave using the audit log."""
        guild = member.guild
        if guild is None:
            return
        attribution = await self.pipeline.correlator.attribute(
            guild,
            action_key=ActionKey.MASS_KICK,
            target_id=member.id,
            occurred_at=datetime.now(tz=timezone.utc),
            # Most departures are voluntary, so "no entry" is the normal answer;
            # one retry covers audit-log lag without tripling the API cost of
            # every leave.
            max_attempts=2,
        )
        if not attribution.confirmed:
            # No kick entry naming THIS member -> they left on their own (or the
            # audit log is unreadable). A fresh kick entry for someone else is
            # not evidence about this departure, so LIKELY is not enough.
            if attribution.degraded:
                log.info(
                    "member departure could not be classified (audit log unreadable)",
                    extra={"guild_id": guild.id, "member_id": member.id},
                )
            return
        event = NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.MASS_KICK,
            source=EventSource.AUDIT_LOG,
            occurred_at=datetime.now(tz=timezone.utc),
            actor_id=attribution.actor_id,
            actor_confidence=attribution.confidence,
            audit_entry_id=attribution.audit_entry_id,
            target_type="member",
            target_id=member.id,
            payload={
                "target_name": str(member),
                "attribution_reason": attribution.reason,
            },
        )
        await self.pipeline.handle(event, guild)

    @commands.Cog.listener()
    async def on_member_ban(self, guild: discord.Guild, user: discord.User) -> None:
        event = NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.MASS_BAN,
            source=EventSource.GATEWAY,
            occurred_at=datetime.now(tz=timezone.utc),
            target_type="user",
            target_id=user.id,
            payload={"target_name": str(user)},
        )
        await self.pipeline.handle(event, guild)

    # -- role grants ---------------------------------------------------
    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member) -> None:
        """Detect the grant of a dangerous role to a member."""
        guild = after.guild
        if guild is None:
            return
        before_ids = {r.id for r in before.roles}
        gained = [r for r in after.roles if r.id not in before_ids]
        if not gained:
            return
        from shield.constants import CRITICAL_PERMISSIONS

        dangerous: list[discord.Role] = []
        for role in gained:
            granted = permissions_set(getattr(role, "permissions", None))
            if any(perm in granted for perm in CRITICAL_PERMISSIONS):
                dangerous.append(role)
        if not dangerous:
            return

        event = NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.DANGEROUS_ROLE_GRANT,
            source=EventSource.GATEWAY,
            occurred_at=datetime.now(tz=timezone.utc),
            target_type="member",
            target_id=after.id,
            payload={
                "target_name": str(after),
                "granted_roles": [
                    {
                        "id": r.id,
                        "name": r.name,
                        "dangerous_permissions": sorted(
                            p
                            for p in CRITICAL_PERMISSIONS
                            if p in permissions_set(getattr(r, "permissions", None))
                        ),
                    }
                    for r in dangerous
                ],
            },
        )
        await self.pipeline.handle(event, guild)


async def setup(bot) -> None:  # noqa: ANN001
    await bot.add_cog(MemberEventsCog(bot))
