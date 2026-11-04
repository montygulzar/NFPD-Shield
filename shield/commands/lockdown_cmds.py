"""``/shield lockdown`` - manual protective mode control (guild owner only)."""

from __future__ import annotations

import discord
from discord import app_commands

from shield.commands.authz import Authority, require, respond
from shield.db.repositories import UnitOfWork


class LockdownGroup(
    app_commands.Group, name="lockdown", description="Manually enter or leave protective lockdown"
):
    @app_commands.command(name="enable", description="Lock the guild down now")
    @app_commands.describe(
        reason="Why (recorded and shown in the log channel)",
        slowmode="Slowmode in seconds to apply to text channels (0 to skip)",
        pause_invites="Also pause invites (requires Manage Guild)",
    )
    async def enable(
        self,
        interaction: discord.Interaction,
        reason: app_commands.Range[str, 1, 400] = "manual lockdown",
        slowmode: app_commands.Range[int, 0, 21600] = 30,
        pause_invites: bool = True,
    ) -> None:
        if not await require(
            interaction,
            Authority.OWNER,
            command="shield lockdown enable",
            parameters={"reason": reason, "slowmode": slowmode, "pause_invites": pause_invites},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild = interaction.guild
        result = await bot.lockdown.enable_lockdown(
            guild,
            reason=f"{reason} (by {interaction.user})",
            slowmode_seconds=int(slowmode),
            pause_invites=pause_invites,
        )
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(guild.id)
            await uow.guilds.update(
                guild.id,
                lockdown_active=True,
                lockdown_reason=f"{reason} (by {interaction.user.id})",
                lockdown_state=result.previous_state,
                protective_mode="lockdown",
            )
        bot.pipeline.state_cache.invalidate(guild.id)
        body = f"**Lockdown enabled.**\n{result.summary()}"
        if result.failed:
            body += (
                "\n\n**Some steps failed** - the guild is only partially locked down. "
                "Check Shield's role position and permissions."
            )
        if result.unsupported:
            body += "\n\nSome measures are unavailable with Shield's current permissions."
        await respond(interaction, body)

    @app_commands.command(name="disable", description="Lift lockdown and restore prior settings")
    async def disable(self, interaction: discord.Interaction) -> None:
        if not await require(
            interaction, Authority.OWNER, command="shield lockdown disable"
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild = interaction.guild
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            settings = await uow.guilds.ensure(guild.id)
            previous = dict(settings.lockdown_state or {})
            was_active = settings.lockdown_active
        if not was_active:
            await respond(interaction, "This guild is not in lockdown.")
            return
        result = await bot.lockdown.disable_lockdown(guild, previous)
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.update(
                guild.id,
                lockdown_active=False,
                lockdown_reason=None,
                lockdown_state=None,
                protective_mode=None,
            )
        bot.pipeline.state_cache.invalidate(guild.id)
        body = f"**Lockdown lifted.**\n{result.summary()}"
        if result.failed:
            body += (
                "\n\n**Some settings could not be restored** - review verification level "
                "and channel slowmode manually."
            )
        await respond(interaction, body)

    @app_commands.command(
        name="status", description="Show lockdown and raid-mode state for this guild"
    )
    async def status(self, interaction: discord.Interaction) -> None:
        if not await require(
            interaction, Authority.DELEGATE, command="shield lockdown status"
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            settings = await uow.guilds.ensure(interaction.guild_id)
            state = {
                "lockdown_active": settings.lockdown_active,
                "lockdown_reason": settings.lockdown_reason,
                "raid_mode_active": settings.raid_mode_active,
                "raid_mode_until": settings.raid_mode_until,
                "protective_mode": settings.protective_mode,
            }
        lines = [
            f"Lockdown: **{'ACTIVE' if state['lockdown_active'] else 'inactive'}**",
        ]
        if state["lockdown_reason"]:
            lines.append(f"Reason: {state['lockdown_reason']}")
        lines.append(
            f"Raid mode: **{'ACTIVE' if state['raid_mode_active'] else 'inactive'}**"
            + (
                f" until <t:{int(state['raid_mode_until'].timestamp())}:R>"
                if state["raid_mode_until"]
                else ""
            )
        )
        if state["protective_mode"]:
            lines.append(f"Protective mode: `{state['protective_mode']}`")
        await respond(interaction, "\n".join(lines))

    @app_commands.command(
        name="raid", description="Manually enable or disable raid mode (join-flood posture)"
    )
    @app_commands.describe(
        enable="True to enable, false to disable",
        minutes="How long raid mode should last",
        slowmode="Slowmode in seconds while raid mode is active",
    )
    async def raid(
        self,
        interaction: discord.Interaction,
        enable: bool,
        minutes: app_commands.Range[int, 1, 1440] = 30,
        slowmode: app_commands.Range[int, 0, 21600] = 30,
    ) -> None:
        if not await require(
            interaction,
            Authority.OWNER,
            command="shield lockdown raid",
            parameters={"enable": enable, "minutes": minutes, "slowmode": slowmode},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild = interaction.guild
        if enable:
            result, until = await bot.lockdown.enable_raid_mode(
                guild,
                reason=f"manual raid mode by {interaction.user}",
                minutes=int(minutes),
                slowmode_seconds=int(slowmode),
            )
            async with bot.db.begin() as session:
                uow = UnitOfWork(session)
                await uow.guilds.ensure(guild.id)
                await uow.guilds.update(
                    guild.id,
                    raid_mode_active=True,
                    raid_mode_until=until,
                    raid_mode_state=result.previous_state,
                    protective_mode="raid",
                )
            bot.pipeline.state_cache.invalidate(guild.id)
            await respond(
                interaction,
                f"**Raid mode enabled** until <t:{int(until.timestamp())}:R>.\n"
                f"{result.summary()}\n\n"
                "Shield does **not** ban or kick recent joiners: a join flood is not "
                "proof that any individual joiner is malicious.",
            )
            return

        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            settings = await uow.guilds.ensure(guild.id)
            previous = dict(settings.raid_mode_state or {})
            active = settings.raid_mode_active
        if not active:
            await respond(interaction, "Raid mode is not active.")
            return
        result = await bot.lockdown.disable_raid_mode(guild, previous)
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.update(
                guild.id,
                raid_mode_active=False,
                raid_mode_until=None,
                raid_mode_state=None,
                protective_mode=None,
            )
        bot.pipeline.state_cache.invalidate(guild.id)
        await respond(interaction, f"**Raid mode disabled.**\n{result.summary()}")
