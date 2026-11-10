"""``/shield whitelist`` - explicit, scoped allowlist management.

Nothing is implicitly trusted. Adding an entry is an owner-level action because
an allowlist entry is a hole in the defences: a compromised allowlisted account
can nuke the guild without tripping a single detector.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import discord
from discord import app_commands

from shield.commands.authz import Authority, require, respond
from shield.constants import SCOPE_ACTIONS, TrustScope
from shield.db.repositories import UnitOfWork

SCOPE_CHOICES = [
    app_commands.Choice(name=scope.value.replace("_", " "), value=scope.value)
    for scope in TrustScope
]


class WhitelistGroup(
    app_commands.Group,
    name="whitelist",
    description="Manage the explicit Shield allowlist for this guild",
):
    @app_commands.command(name="add", description="Allowlist a user or role for specific scopes")
    @app_commands.describe(
        user="User to allowlist (supply either user or role)",
        role="Role to allowlist (every holder is exempt)",
        scope="Scope to grant (default: all)",
        extra_scope="A second scope to grant",
        reason="Why this entry exists (recorded in the audit trail)",
        expires_in_hours="Auto-expire after N hours (recommended for temporary work)",
    )
    @app_commands.choices(scope=SCOPE_CHOICES, extra_scope=SCOPE_CHOICES)
    async def add(
        self,
        interaction: discord.Interaction,
        user: discord.Member | None = None,
        role: discord.Role | None = None,
        scope: app_commands.Choice[str] | None = None,
        extra_scope: app_commands.Choice[str] | None = None,
        reason: app_commands.Range[str, 1, 400] | None = None,
        expires_in_hours: app_commands.Range[int, 1, 8760] | None = None,
    ) -> None:
        params = {
            "user": getattr(user, "id", None),
            "role": getattr(role, "id", None),
            "scope": scope.value if scope else None,
            "extra_scope": extra_scope.value if extra_scope else None,
            "expires_in_hours": expires_in_hours,
        }
        if not await require(
            interaction, Authority.OWNER, command="shield whitelist add", parameters=params
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)

        if (user is None) == (role is None):
            await respond(
                interaction, "Supply exactly one of `user` or `role`."
            )
            return

        scopes = {TrustScope(scope.value) if scope else TrustScope.ALL}
        if extra_scope:
            scopes.add(TrustScope(extra_scope.value))

        if TrustScope.MODERATION_PROXY in scopes and not (user is not None and user.bot):
            await respond(
                interaction,
                "`moderation_proxy` can only be given to a **bot user**. It tells Shield "
                "to trust the moderator ID that bot writes into its audit reasons - a "
                "person can type any reason they like, so a human proxy could frame "
                "someone else.",
            )
            return

        entity_type = "user" if user is not None else "role"
        entity_id = int(user.id) if user is not None else int(role.id)
        guild = interaction.guild

        if entity_type == "role" and role is not None and role.is_default():
            await respond(
                interaction,
                "Refusing to allowlist `@everyone`: that would disable protection for "
                "the entire guild.",
            )
            return

        expires_at = (
            datetime.now(tz=timezone.utc) + timedelta(hours=int(expires_in_hours))
            if expires_in_hours
            else None
        )

        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(guild.id)
            await uow.trust.add(
                guild.id,
                entity_type=entity_type,
                entity_id=entity_id,
                scopes=scopes,
                added_by=int(interaction.user.id),
                reason=reason,
                expires_at=expires_at,
            )
        bot.pipeline.state_cache.invalidate(guild.id)

        covered = sorted(
            {
                key.value
                for s in scopes
                for key in SCOPE_ACTIONS.get(s, frozenset())
            }
        )
        mention = f"<@{entity_id}>" if entity_type == "user" else f"<@&{entity_id}>"
        note = ""
        if TrustScope.MANAGE_SHIELD in scopes:
            note = (
                "\n`manage_shield` grants **command authority only** - the delegate is "
                "still policed by every detector."
            )
        if TrustScope.MODERATION_PROXY in scopes:
            note += (
                "\n`moderation_proxy`: Shield now reads the moderator behind each of this "
                "bot's bans and kicks from its audit reason and applies the normal "
                "thresholds to **that moderator**, not the bot. The bot itself gets no "
                "exemption from this scope."
            )
        detection_note = (
            f"\nExempt from **{len(covered)}** detector(s): `{', '.join(covered)}`"
            if covered
            else "\nGrants no detection exemption."
        )
        await respond(
            interaction,
            f"**Allowlisted** {mention} ({entity_type}) with scopes "
            f"`{', '.join(sorted(s.value for s in scopes))}`."
            + detection_note
            + note
            + (f"\nExpires <t:{int(expires_at.timestamp())}:R>." if expires_at else "")
            + "\n\n**Reminder:** an allowlisted principal can bypass Shield entirely. "
            "Prefer narrow scopes and expiries.",
        )

    @app_commands.command(name="remove", description="Remove an allowlist entry")
    @app_commands.describe(user="Allowlisted user to remove", role="Allowlisted role to remove")
    async def remove(
        self,
        interaction: discord.Interaction,
        user: discord.User | None = None,
        role: discord.Role | None = None,
    ) -> None:
        params = {"user": getattr(user, "id", None), "role": getattr(role, "id", None)}
        if not await require(
            interaction, Authority.OWNER, command="shield whitelist remove", parameters=params
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        if (user is None) == (role is None):
            await respond(interaction, "Supply exactly one of `user` or `role`.")
            return
        entity_type = "user" if user is not None else "role"
        entity_id = int(user.id) if user is not None else int(role.id)
        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            removed = await uow.trust.remove(interaction.guild_id, entity_type, entity_id)
        bot.pipeline.state_cache.invalidate(interaction.guild_id)
        await respond(
            interaction,
            "**Removed** from the allowlist." if removed else "That entry was not allowlisted.",
        )

    @app_commands.command(name="list", description="List this guild's allowlist")
    async def list_entries(self, interaction: discord.Interaction) -> None:
        if not await require(
            interaction, Authority.DELEGATE, command="shield whitelist list"
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild = interaction.guild
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(guild.id)
            entries = await uow.trust.list_for_guild(guild.id, include_expired=True)

        if not entries:
            await respond(
                interaction,
                "The allowlist is **empty**. Only the Discord guild owner and Shield "
                "itself are implicitly exempt.",
            )
            return

        now = datetime.now(tz=timezone.utc)
        lines = [f"**Allowlist** ({len(entries)} entr{'y' if len(entries) == 1 else 'ies'})"]
        lines.append(
            f"Guild owner <@{guild.owner_id}> is implicitly exempt from sanctions "
            "(but always alerted on)."
        )
        for entry in entries:
            mention = (
                f"<@{entry.entity_id}>" if entry.entity_type == "user" else f"<@&{entry.entity_id}>"
            )
            expired = entry.expires_at is not None and entry.expires_at <= now
            status = " **(EXPIRED)**" if expired else ""
            expiry = (
                f", expires <t:{int(entry.expires_at.timestamp())}:R>" if entry.expires_at else ""
            )
            lines.append(
                f"- {mention} `{entry.entity_type}` scopes "
                f"`{', '.join(str(s) for s in (entry.scopes or []))}`"
                f" added by <@{entry.added_by}>{expiry}{status}"
                + (f"\n  reason: {entry.reason}" if entry.reason else "")
            )
        await respond(interaction, "\n".join(lines))
