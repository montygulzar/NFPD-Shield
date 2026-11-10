"""Top-level ``/shield`` command group.

Every subgroup is attached here so the whole surface is one coherent command
tree, and every handler re-checks authority on the server through
:mod:`shield.commands.authz`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import discord
from discord import app_commands
from discord.ext import commands

from shield.audit.mapping import LIMITATIONS
from shield.commands.authz import Authority, require, respond
from shield.commands.backup_cmds import BackupGroup
from shield.commands.incidents import IncidentsGroup
from shield.commands.lockdown_cmds import LockdownGroup
from shield.commands.restore_cmds import RestoreGroup
from shield.commands.thresholds import ThresholdsGroup
from shield.commands.whitelist import WhitelistGroup
from shield.constants import ShieldMode
from shield.db.repositories import UnitOfWork
from shield.observability.metrics import METRICS

MODE_CHOICES = [
    app_commands.Choice(name="alert only (detect and report, never act)", value="alert_only"),
    app_commands.Choice(name="enforce (act on confirmed, unauthorised actors)", value="enforce"),
    app_commands.Choice(name="lockdown (enforce + stay in protective posture)", value="lockdown"),
]

#: Permissions Shield needs, and what breaks without each one.
REQUIRED_PERMISSIONS: dict[str, str] = {
    "view_audit_log": "actor attribution for every destructive event (anti-nuke core)",
    "manage_roles": "removing dangerous roles from an attacker",
    "manage_channels": "slowmode during lockdown and channel restoration",
    "manage_guild": "verification level, invite pause and guild-setting restore",
    "moderate_members": "timeouts for spam and mention floods",
    "manage_messages": "bounded cleanup of spam messages",
    "manage_webhooks": "reading webhook metadata for snapshots",
    "send_messages": "posting incident reports to the log channel",
    "embed_links": "incident report embeds",
    "read_message_history": "bounded spam cleanup",
}


class LogsGroup(app_commands.Group, name="logs", description="Configure Shield's logging channels"):
    @app_commands.command(name="set", description="Set the incident log / alert channel")
    @app_commands.describe(
        channel="Channel for all incident reports",
        alert_channel="Optional separate channel for high-severity alerts",
    )
    async def set_channel(
        self,
        interaction: discord.Interaction,
        channel: discord.TextChannel,
        alert_channel: discord.TextChannel | None = None,
    ) -> None:
        if not await require(
            interaction,
            Authority.DELEGATE,
            command="shield logs set",
            parameters={
                "channel": channel.id,
                "alert_channel": getattr(alert_channel, "id", None),
            },
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)

        problems: list[str] = []
        for target, label in ((channel, "log channel"), (alert_channel, "alert channel")):
            if target is None:
                continue
            perms = target.permissions_for(interaction.guild.me)
            if not perms.send_messages:
                problems.append(f"Shield cannot send messages in {target.mention} ({label})")
            elif not perms.embed_links:
                problems.append(f"Shield cannot embed links in {target.mention} ({label})")
        if problems:
            await respond(
                interaction,
                "**Not saved.** Fix these first:\n" + "\n".join(f"- {p}" for p in problems),
            )
            return

        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(interaction.guild_id)
            await uow.guilds.update(
                interaction.guild_id,
                log_channel_id=int(channel.id),
                alert_channel_id=int(alert_channel.id) if alert_channel else None,
            )
        bot.pipeline.state_cache.invalidate(interaction.guild_id)
        await respond(
            interaction,
            f"Incident log channel set to {channel.mention}"
            + (f", alerts to {alert_channel.mention}" if alert_channel else "")
            + ".",
        )

    @app_commands.command(name="test", description="Post a test message to the log channel")
    async def test(self, interaction: discord.Interaction) -> None:
        if not await require(interaction, Authority.DELEGATE, command="shield logs test"):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            settings = await uow.guilds.ensure(interaction.guild_id)
            channel_id = settings.log_channel_id
        if not channel_id:
            await respond(interaction, "No log channel configured. Run `/shield logs set`.")
            return
        ok = await bot.notifier.send_text(
            interaction.guild,
            channel_id,
            f"NFPD Shield logging test requested by {interaction.user.mention}. "
            "If you can read this, incident reports will arrive here.",
        )
        await respond(
            interaction,
            "Test message sent." if ok else "**Failed** to post - check channel permissions.",
        )


@app_commands.guild_only()
class ShieldCommands(
    commands.GroupCog,
    name="shield",
    description="NFPD Shield anti-raid and anti-nuke controls",
):
    """The whole ``/shield`` surface."""

    thresholds = ThresholdsGroup()
    whitelist = WhitelistGroup()
    incidents = IncidentsGroup()
    backup = BackupGroup()
    restore = RestoreGroup()
    lockdown = LockdownGroup()
    logs = LogsGroup()

    def __init__(self, bot) -> None:  # noqa: ANN001
        self.bot = bot
        super().__init__()

    # -- status --------------------------------------------------------
    @app_commands.command(name="status", description="Shield's status for this guild")
    async def status(self, interaction: discord.Interaction) -> None:
        if not await require(interaction, Authority.DELEGATE, command="shield status"):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild = interaction.guild
        since = datetime.now(tz=timezone.utc) - timedelta(days=7)
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            settings = await uow.guilds.ensure(
                guild.id, guild_name=guild.name, owner_id=guild.owner_id
            )
            policies = await uow.policies.list_for_guild(guild.id)
            recent = await uow.incidents.list_recent(guild.id, limit=5)
            counts = await uow.incidents.counts_by_status(guild.id, since)
            fp_rate = await uow.incidents.false_positive_rate(guild.id, since)
            snapshot = await uow.snapshots.latest(guild.id, validated_only=True)
            trust_count = len(await uow.trust.list_for_guild(guild.id))

        enabled_detectors = [p.action_key.value for p in policies if p.enabled]
        dry_detectors = [p.action_key.value for p in policies if p.dry_run]

        colour = 0x3BA55D if settings.enabled and not settings.paused else 0xFAA61A
        embed = discord.Embed(
            title=f"NFPD Shield - {guild.name}",
            description=(
                "**PAUSED by the guild owner - no detection responses at all.**"
                if settings.paused
                else (
                    "Protection is **enabled**."
                    if settings.enabled
                    else "Protection is **not enabled**: Shield observes and reports only. "
                    "Run `/shield enable` when you are ready."
                )
            ),
            colour=colour,
        )
        embed.add_field(name="Mode", value=f"`{settings.mode.value}`", inline=True)
        embed.add_field(
            name="Dry run",
            value=("guild-wide" if settings.dry_run else "off")
            + (" + global" if bot.shield_config.global_dry_run else ""),
            inline=True,
        )
        embed.add_field(name="Policy version", value=str(settings.policy_version), inline=True)
        embed.add_field(
            name="Detectors",
            value=f"{len(enabled_detectors)}/{len(policies)} enabled, "
            f"{len(dry_detectors)} in per-policy dry-run",
            inline=True,
        )
        embed.add_field(name="Allowlist entries", value=str(trust_count), inline=True)
        embed.add_field(
            name="Log channel",
            value=(f"<#{settings.log_channel_id}>" if settings.log_channel_id else "**not set**"),
            inline=True,
        )
        embed.add_field(
            name="Protective state",
            value=(
                f"lockdown: {'ACTIVE' if settings.lockdown_active else 'off'}\n"
                f"raid mode: {'ACTIVE' if settings.raid_mode_active else 'off'}"
            ),
            inline=True,
        )
        embed.add_field(
            name="Latest snapshot",
            value=(
                f"v{snapshot.version} <t:{int(snapshot.taken_at.timestamp())}:R>"
                if snapshot
                else "**none** - run `/shield backup create`"
            ),
            inline=True,
        )
        embed.add_field(
            name="Incidents (7d)",
            value=(", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none")
            + f"\nfalse-positive rate: {fp_rate:.0%}",
            inline=False,
        )
        if recent:
            embed.add_field(
                name="Most recent",
                value="\n".join(
                    f"`#{r.id}` <t:{int(r.detected_at.timestamp())}:R> {r.action_key.value} "
                    f"({r.outcome.value})"
                    for r in recent
                )[:1000],
                inline=False,
            )
        intents = bot.intents
        embed.add_field(
            name="Runtime",
            value=(
                f"instance `{bot.shield_config.instance_id}`, "
                f"uptime {int(METRICS.uptime_seconds())}s, "
                f"latency {bot.latency * 1000:.0f}ms\n"
                f"intents: members={intents.members}, message_content={intents.message_content}\n"
                f"database: {'OK' if bot.db.healthy else '**DEGRADED**'}"
            ),
            inline=False,
        )
        embed.set_footer(text="Use /shield health for a full permission and intent audit.")
        await respond(interaction, embed=embed)

    # -- enable / disable ---------------------------------------------
    @app_commands.command(
        name="enable", description="Enable Shield protection for this guild (owner only)"
    )
    @app_commands.describe(
        mode="Start in alert_only (recommended) or enforce",
        dry_run="Keep simulating responses without acting (recommended for the first week)",
    )
    @app_commands.choices(mode=MODE_CHOICES[:2])
    async def enable(
        self,
        interaction: discord.Interaction,
        mode: app_commands.Choice[str] | None = None,
        dry_run: bool = True,
    ) -> None:
        if not await require(
            interaction,
            Authority.OWNER,
            command="shield enable",
            parameters={"mode": mode.value if mode else None, "dry_run": dry_run},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        target_mode = ShieldMode(mode.value) if mode else ShieldMode.ALERT_ONLY
        bot = interaction.client
        guild = interaction.guild
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(guild.id, guild_name=guild.name, owner_id=guild.owner_id)
            await uow.guilds.update(
                guild.id,
                enabled=True,
                mode=target_mode,
                dry_run=bool(dry_run),
                paused=False,
                pause_reason=None,
                enabled_by=int(interaction.user.id),
                enabled_at=datetime.now(tz=timezone.utc),
            )
            settings = await uow.guilds.get(guild.id)
            log_set = bool(settings.log_channel_id)
        bot.pipeline.state_cache.invalidate(guild.id)

        warnings = []
        if not log_set:
            warnings.append("No log channel is set - run `/shield logs set` so you see incidents.")
        missing = _missing_permissions(guild)
        if missing:
            warnings.append(
                "Missing permissions: "
                + ", ".join(f"`{p}`" for p in missing)
                + ". Some detectors and responses will be unavailable."
            )
        if target_mode is ShieldMode.ENFORCE and not dry_run:
            warnings.append(
                "You enabled **live enforcement** immediately. Shield's defaults are "
                "deliberately strict; validate them in a staging guild first."
            )
        await respond(
            interaction,
            f"**Protection enabled** in `{target_mode.value}`"
            + (" with dry-run on (nothing will be changed)." if dry_run else ".")
            + ("\n\n**Warnings:**\n" + "\n".join(f"- {w}" for w in warnings) if warnings else ""),
        )

    @app_commands.command(
        name="disable", description="Disable Shield protection for this guild (owner only)"
    )
    @app_commands.describe(reason="Recorded with the change")
    async def disable(
        self,
        interaction: discord.Interaction,
        reason: app_commands.Range[str, 1, 400] | None = None,
    ) -> None:
        if not await require(
            interaction, Authority.OWNER, command="shield disable", parameters={"reason": reason}
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(interaction.guild_id)
            await uow.guilds.update(
                interaction.guild_id,
                enabled=False,
                mode=ShieldMode.ALERT_ONLY,
                pause_reason=reason,
            )
        bot.pipeline.state_cache.invalidate(interaction.guild_id)
        await respond(
            interaction,
            "**Protection disabled.** Shield continues to record events and post "
            "incident reports, but will never act. Snapshots continue so a restore "
            "stays possible.",
        )

    @app_commands.command(name="mode", description="Change Shield's mode (owner only)")
    @app_commands.choices(mode=MODE_CHOICES)
    async def set_mode(
        self, interaction: discord.Interaction, mode: app_commands.Choice[str]
    ) -> None:
        if not await require(
            interaction, Authority.OWNER, command="shield mode", parameters={"mode": mode.value}
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        target = ShieldMode(mode.value)
        bot = interaction.client
        guild = interaction.guild
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            settings = await uow.guilds.ensure(guild.id)
            if not settings.enabled and target is not ShieldMode.ALERT_ONLY:
                await respond(
                    interaction,
                    "Protection is not enabled for this guild, so only `alert_only` has "
                    "any effect. Run `/shield enable` first.",
                )
                return
            await uow.guilds.update(guild.id, mode=target)
        bot.pipeline.state_cache.invalidate(guild.id)

        extra = ""
        if target is ShieldMode.LOCKDOWN:
            result = await bot.lockdown.enable_lockdown(
                guild, reason=f"mode set to lockdown by {interaction.user}"
            )
            async with bot.db.begin() as session:
                uow = UnitOfWork(session)
                await uow.guilds.enter_protective_mode(
                    guild.id, "lockdown", result.previous_state,
                    lockdown_reason=f"mode lockdown by {interaction.user.id}",
                )
            extra = f"\n{result.summary()}"
        await respond(interaction, f"Mode set to `{target.value}`.{extra}")

    # -- emergency pause ----------------------------------------------
    @app_commands.command(
        name="pause",
        description="EMERGENCY: stop all automated responses immediately (owner only)",
    )
    @app_commands.describe(reason="Why protection is being paused")
    async def pause(
        self,
        interaction: discord.Interaction,
        reason: app_commands.Range[str, 1, 400] = "emergency pause",
    ) -> None:
        if not await require(
            interaction, Authority.OWNER, command="shield pause", parameters={"reason": reason}
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(interaction.guild_id)
            await uow.guilds.update(
                interaction.guild_id,
                paused=True,
                pause_reason=reason,
                paused_by=int(interaction.user.id),
                paused_at=datetime.now(tz=timezone.utc),
            )
        bot.pipeline.state_cache.invalidate(interaction.guild_id)
        await respond(
            interaction,
            "**PAUSED.** Shield will record events but take no action and send no "
            "incident notifications until `/shield resume`. Use this if Shield is "
            "misbehaving during an operation.",
        )

    @app_commands.command(name="resume", description="Resume after a pause (owner only)")
    async def resume(self, interaction: discord.Interaction) -> None:
        if not await require(interaction, Authority.OWNER, command="shield resume"):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(interaction.guild_id)
            await uow.guilds.update(
                interaction.guild_id, paused=False, pause_reason=None, paused_by=None, paused_at=None
            )
        bot.pipeline.state_cache.invalidate(interaction.guild_id)
        await respond(interaction, "**Resumed.** Detection responses are active again.")

    # -- health --------------------------------------------------------
    @app_commands.command(
        name="health", description="Audit intents, permissions, hierarchy, database and audit log"
    )
    async def health(self, interaction: discord.Interaction) -> None:
        if not await require(interaction, Authority.OPERATOR, command="shield health"):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild = interaction.guild
        me = guild.me

        db_ok, db_error = await bot.db.ping()
        db_note = ""
        settings = None
        if db_ok:
            try:
                async with bot.db.begin() as session:
                    uow = UnitOfWork(session)
                    settings = await uow.guilds.ensure(guild.id)
            except Exception as exc:  # noqa: BLE001
                db_note = f" (query failed: {type(exc).__name__})"

        perms = me.guild_permissions
        missing = [p for p in REQUIRED_PERMISSIONS if not getattr(perms, p, False)]
        if perms.administrator:
            missing = []

        # Hierarchy: how many members hold a dangerous role Shield cannot touch.
        from shield.constants import CRITICAL_PERMISSIONS

        bot_top = me.top_role.position
        unreachable = [
            r
            for r in guild.roles
            if r.position >= bot_top
            and not r.is_default()
            and any(getattr(r.permissions, p, False) for p in CRITICAL_PERMISSIONS)
            and r.id != me.top_role.id
        ]

        audit_ok = perms.view_audit_log or perms.administrator
        audit_note = bot.pipeline.correlator.degraded_guilds.get(guild.id)

        embed = discord.Embed(
            title=f"Shield health - {guild.name}",
            colour=0x3BA55D if (db_ok and not missing and audit_ok) else 0xED4245,
        )
        embed.add_field(
            name="Database",
            value=("OK" if db_ok else f"**FAILED**: {db_error}") + db_note,
            inline=False,
        )
        intents = bot.intents
        embed.add_field(
            name="Gateway intents",
            value=(
                f"guilds: {intents.guilds}\n"
                f"members (privileged): {intents.members}"
                + ("" if intents.members else " - join flood and role-grant detection are OFF")
                + f"\nmessage_content (privileged): {intents.message_content}"
                + (
                    ""
                    if intents.message_content
                    else " - duplicate-spam detection degrades to rate only"
                )
                + f"\nmoderation/bans: {getattr(intents, 'moderation', getattr(intents, 'bans', False))}"
            ),
            inline=False,
        )
        embed.add_field(
            name="Permissions",
            value=(
                "All required permissions present."
                if not missing
                else "**Missing:**\n"
                + "\n".join(f"- `{p}`: {REQUIRED_PERMISSIONS[p]}" for p in missing)
            ),
            inline=False,
        )
        embed.add_field(
            name="Role hierarchy",
            value=(
                f"Shield's highest role: **{me.top_role.name}** (position {bot_top})\n"
                + (
                    f"**{len(unreachable)} dangerous role(s) are at or above Shield** and "
                    "cannot be removed from an attacker: "
                    + ", ".join(f"`{r.name}`" for r in unreachable[:8])
                    + "\nMove Shield's role above them, or accept that those actors can only "
                    "be alerted on."
                    if unreachable
                    else "Shield can reach every dangerous role below it."
                )
            ),
            inline=False,
        )
        embed.add_field(
            name="Audit log access",
            value=(
                "OK - actor attribution is possible."
                if audit_ok
                else "**MISSING View Audit Log** - no destructive action can be attributed, "
                "so Shield will alert but never sanction."
            )
            + (f"\nLast error: {audit_note}" if audit_note else ""),
            inline=False,
        )
        if settings is not None:
            embed.add_field(
                name="Guild configuration",
                value=(
                    f"enabled: {settings.enabled}, mode: `{settings.mode.value}`, "
                    f"dry-run: {settings.dry_run}, paused: {settings.paused}\n"
                    f"log channel: "
                    + (f"<#{settings.log_channel_id}>" if settings.log_channel_id else "not set")
                ),
                inline=False,
            )
        notes = [f"`{k.value}`: {v}" for k, v in list(LIMITATIONS.items())[:6]]
        embed.add_field(
            name="Known detection limits",
            value="\n".join(f"- {n}" for n in notes)[:1000],
            inline=False,
        )
        embed.set_footer(
            text=(
                f"instance {bot.shield_config.instance_id} | "
                f"shards {bot.shard_count or 1} | "
                f"guilds {len(bot.guilds)}"
            )
        )
        await respond(interaction, embed=embed)

    @app_commands.command(
        name="metrics", description="Process metrics (bot operator diagnostics)"
    )
    async def metrics(self, interaction: discord.Interaction) -> None:
        if not await require(interaction, Authority.OPERATOR, command="shield metrics"):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        snapshot = METRICS.snapshot()
        counters = snapshot["counters"]
        top = sorted(counters.items(), key=lambda kv: -kv[1])[:20]
        body = (
            f"**Uptime:** {snapshot['uptime_seconds']}s\n"
            f"**Detection windows in memory:** "
            f"{interaction.client.pipeline.windows.size()}\n"
            f"**Pending self-action suppressions:** "
            f"{interaction.client.selfguard.pending()}\n\n"
            + ("\n".join(f"`{k}` = {v:g}" for k, v in top) or "no counters yet")
        )
        await respond(interaction, body)


def _missing_permissions(guild: discord.Guild) -> list[str]:
    perms = guild.me.guild_permissions
    if perms.administrator:
        return []
    return [p for p in REQUIRED_PERMISSIONS if not getattr(perms, p, False)]


async def setup(bot) -> None:  # noqa: ANN001
    await bot.add_cog(ShieldCommands(bot))
