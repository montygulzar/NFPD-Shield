"""``/shield thresholds`` - view and tune detection policy."""

from __future__ import annotations

import discord
from discord import app_commands

from shield.commands.authz import Authority, require, respond
from shield.constants import ActionKey, ResponseAction, Severity
from shield.db.repositories import UnitOfWork
from shield.policies.defaults import DEFAULTS_BY_KEY

ACTION_CHOICES = [
    app_commands.Choice(name=key.value.replace("_", " "), value=key.value)
    for key in list(ActionKey)[:25]
]
RESPONSE_CHOICES = [
    app_commands.Choice(name=r.value.replace("_", " "), value=r.value) for r in ResponseAction
]
SEVERITY_CHOICES = [app_commands.Choice(name=s.value, value=s.value) for s in Severity]


class ThresholdsGroup(
    app_commands.Group,
    name="thresholds",
    description="View and tune NFPD Shield detection thresholds",
):
    @app_commands.command(name="view", description="Show this guild's detection thresholds")
    @app_commands.describe(action="Limit the output to one detector")
    @app_commands.choices(action=ACTION_CHOICES)
    async def view(
        self,
        interaction: discord.Interaction,
        action: app_commands.Choice[str] | None = None,
    ) -> None:
        if not await require(
            interaction,
            Authority.DELEGATE,
            command="shield thresholds view",
            parameters={"action": action.value if action else None},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild_id = interaction.guild_id
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(guild_id)
            policies = await uow.policies.list_for_guild(guild_id)

        wanted = ActionKey(action.value) if action else None
        lines: list[str] = []
        for policy in policies:
            if wanted is not None and policy.action_key is not wanted:
                continue
            default = DEFAULTS_BY_KEY.get(policy.action_key)
            changed = default is not None and (
                policy.threshold_count != default.threshold_count
                or policy.window_seconds != default.window_seconds
                or policy.response is not default.response
            )
            flag = " *(customised)*" if changed else ""
            state = "on" if policy.enabled else "**off**"
            dry = " [dry-run]" if policy.dry_run else ""
            lines.append(
                f"`{policy.action_key.value}` {state}{dry}{flag}\n"
                f"  threshold **{policy.threshold_count}** / **{policy.window_seconds}s**, "
                f"cooldown {policy.cooldown_seconds}s, response `{policy.response.value}`, "
                f"severity `{policy.severity.value}`, "
                f"confirmed-actor required: {policy.requires_confirmed_actor}"
            )
            if wanted is not None:
                if default is not None and default.note:
                    lines.append(f"  _note:_ {default.note}")
                if policy.options:
                    lines.append(f"  _options:_ `{policy.options}`")

        if not lines:
            await respond(interaction, "No policies found for this guild.")
            return

        header = "**Detection thresholds**\n"
        if wanted is None:
            header += (
                "_Single-event policies (threshold 1) carry a high false-positive risk; "
                "validate them in a staging guild before enforcing._\n"
            )
        await _send_chunks(interaction, header, lines)

    @app_commands.command(name="set", description="Change a detector's threshold or response")
    @app_commands.describe(
        action="Detector to change",
        threshold="Events needed to trigger (>= 1)",
        window="Window in seconds (1-3600)",
        cooldown="Cooldown per actor/action in seconds (0-86400)",
        response="What Shield should do when it triggers",
        severity="Reported severity",
        enabled="Enable or disable this detector",
        dry_run="Simulate this detector only (overrides the guild setting)",
        require_confirmed_actor="Require confirmed audit-log attribution before enforcing",
    )
    @app_commands.choices(action=ACTION_CHOICES, response=RESPONSE_CHOICES, severity=SEVERITY_CHOICES)
    async def set_values(
        self,
        interaction: discord.Interaction,
        action: app_commands.Choice[str],
        threshold: app_commands.Range[int, 1, 10000] | None = None,
        window: app_commands.Range[int, 1, 3600] | None = None,
        cooldown: app_commands.Range[int, 0, 86400] | None = None,
        response: app_commands.Choice[str] | None = None,
        severity: app_commands.Choice[str] | None = None,
        enabled: bool | None = None,
        dry_run: bool | None = None,
        require_confirmed_actor: bool | None = None,
    ) -> None:
        params = {
            "action": action.value,
            "threshold": threshold,
            "window": window,
            "cooldown": cooldown,
            "response": response.value if response else None,
            "severity": severity.value if severity else None,
            "enabled": enabled,
            "dry_run": dry_run,
            "require_confirmed_actor": require_confirmed_actor,
        }
        if not await require(
            interaction, Authority.DELEGATE, command="shield thresholds set", parameters=params
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)

        if all(
            value is None
            for value in (
                threshold,
                window,
                cooldown,
                response,
                severity,
                enabled,
                dry_run,
                require_confirmed_actor,
            )
        ):
            await respond(interaction, "Nothing to change: supply at least one field.")
            return

        bot = interaction.client
        guild_id = interaction.guild_id
        action_key = ActionKey(action.value)
        warnings: list[str] = []
        if threshold == 1:
            warnings.append(
                "threshold 1 fires on a single event, which is the highest "
                "false-positive risk setting"
            )
        if response is not None and response.value != ResponseAction.ALERT_ONLY.value:
            warnings.append(
                "enforcement responses should be validated with `dry_run: true` "
                "in a staging guild first"
            )

        try:
            async with bot.db.begin() as session:
                uow = UnitOfWork(session)
                await uow.guilds.ensure(guild_id)
                updated = await uow.policies.set_values(
                    guild_id,
                    action_key,
                    updated_by=int(interaction.user.id),
                    threshold_count=threshold,
                    window_seconds=window,
                    cooldown_seconds=cooldown,
                    response=ResponseAction(response.value) if response else None,
                    severity=Severity(severity.value) if severity else None,
                    enabled=enabled,
                    dry_run=dry_run,
                    requires_confirmed_actor=require_confirmed_actor,
                )
                if updated is None:
                    await respond(interaction, f"No policy row for `{action_key.value}`.")
                    return
                new_version = await uow.guilds.bump_policy_version(guild_id)
                summary = (
                    f"`{updated.action_key.value}`: threshold **{updated.threshold_count}** / "
                    f"**{updated.window_seconds}s**, cooldown {updated.cooldown_seconds}s, "
                    f"response `{updated.response.value}`, severity `{updated.severity.value}`, "
                    f"enabled {updated.enabled}, dry-run {updated.dry_run}"
                )
        except ValueError as exc:
            await respond(interaction, f"**Rejected:** {exc}")
            return

        bot.pipeline.state_cache.invalidate(guild_id)
        message = f"**Policy updated** (policy version {new_version}).\n{summary}"
        if warnings:
            message += "\n\n**Warnings:**\n" + "\n".join(f"- {w}" for w in warnings)
        await respond(interaction, message)

    @app_commands.command(
        name="reset", description="Reset every detector in this guild to Shield's defaults"
    )
    async def reset(self, interaction: discord.Interaction) -> None:
        if not await require(
            interaction, Authority.OWNER, command="shield thresholds reset"
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild_id = interaction.guild_id
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            count = await uow.policies.reset_to_defaults(guild_id, int(interaction.user.id))
            version = await uow.guilds.bump_policy_version(guild_id)
        bot.pipeline.state_cache.invalidate(guild_id)
        await respond(
            interaction,
            f"Reset **{count}** policies to the strict defaults (policy version {version}).",
        )


async def _send_chunks(
    interaction: discord.Interaction, header: str, lines: list[str]
) -> None:
    """Send a long listing as several ephemeral messages.

    Discord caps a message at 2000 characters, and the threshold listing for a
    guild with every detector enabled exceeds that.
    """
    chunks: list[str] = []
    buffer = header
    for line in lines:
        if len(buffer) + len(line) + 1 > 1800:
            chunks.append(buffer)
            buffer = ""
        buffer += line + "\n"
    if buffer.strip():
        chunks.append(buffer)

    for index, chunk in enumerate(chunks):
        if index == 0:
            await respond(interaction, chunk)
        else:
            await interaction.followup.send(chunk[:1990], ephemeral=True)
