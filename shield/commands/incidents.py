"""``/shield incidents`` - review, inspect and triage incidents.

Every read is guild-scoped in the repository layer, so an incident ID from
another guild simply does not resolve. That is the cross-guild IDOR defence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import discord
from discord import app_commands

from shield.commands.authz import Authority, require, respond
from shield.constants import ActionKey, IncidentStatus
from shield.db.repositories import UnitOfWork

STATUS_CHOICES = [app_commands.Choice(name=s.value, value=s.value) for s in IncidentStatus]
ACTION_CHOICES = [
    app_commands.Choice(name=key.value.replace("_", " "), value=key.value)
    for key in list(ActionKey)[:25]
]


class IncidentsGroup(
    app_commands.Group, name="incidents", description="Review NFPD Shield incidents"
):
    @app_commands.command(name="list", description="List recent incidents")
    @app_commands.describe(
        limit="How many to show (1-25)",
        status="Filter by status",
        action="Filter by detector",
        hours="Only incidents from the last N hours",
    )
    @app_commands.choices(status=STATUS_CHOICES, action=ACTION_CHOICES)
    async def list_incidents(
        self,
        interaction: discord.Interaction,
        limit: app_commands.Range[int, 1, 25] = 10,
        status: app_commands.Choice[str] | None = None,
        action: app_commands.Choice[str] | None = None,
        hours: app_commands.Range[int, 1, 8760] | None = None,
    ) -> None:
        if not await require(
            interaction,
            Authority.DELEGATE,
            command="shield incidents list",
            parameters={
                "limit": limit,
                "status": status.value if status else None,
                "action": action.value if action else None,
                "hours": hours,
            },
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild_id = interaction.guild_id
        since = datetime.now(tz=timezone.utc) - timedelta(hours=hours) if hours else None
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            rows = await uow.incidents.list_recent(
                guild_id,
                limit=limit,
                status=IncidentStatus(status.value) if status else None,
                action_key=ActionKey(action.value) if action else None,
                since=since,
            )
            counts = await uow.incidents.counts_by_status(
                guild_id, datetime.now(tz=timezone.utc) - timedelta(days=7)
            )

        if not rows:
            await respond(interaction, "No incidents match that filter.")
            return

        lines = [
            "**Recent incidents**",
            "Last 7 days by status: "
            + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"),
            "",
        ]
        for row in rows:
            flags = []
            if row.dry_run:
                flags.append("dry-run")
            if row.actor_confidence.value != "confirmed":
                flags.append(f"attribution:{row.actor_confidence.value}")
            flag_text = f" `[{', '.join(flags)}]`" if flags else ""
            actor = f"<@{row.actor_id}>" if row.actor_id else "unidentified"
            lines.append(
                f"`#{row.id}` <t:{int(row.detected_at.timestamp())}:R> "
                f"**{row.action_key.value}** by {actor} - "
                f"{row.severity.value}/{row.status.value}, outcome `{row.outcome.value}`{flag_text}"
            )
        await respond(interaction, "\n".join(lines))

    @app_commands.command(name="show", description="Show one incident in full")
    @app_commands.describe(incident_id="Incident number from /shield incidents list")
    async def show(
        self, interaction: discord.Interaction, incident_id: app_commands.Range[int, 1, None]
    ) -> None:
        if not await require(
            interaction,
            Authority.DELEGATE,
            command="shield incidents show",
            parameters={"incident_id": incident_id},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild_id = interaction.guild_id
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            incident = await uow.incidents.get(guild_id, int(incident_id))
            actions = (
                await uow.enforcement.list_for_incident(guild_id, int(incident_id))
                if incident is not None
                else []
            )
        if incident is None:
            # Deliberately indistinguishable from "exists in another guild".
            await respond(interaction, f"No incident `#{incident_id}` in this guild.")
            return

        details = dict(incident.details or {})
        payload = details.pop("payload", {})
        embed = discord.Embed(
            title=f"Incident #{incident.id} - {incident.action_key.value}",
            description=incident.reason[:2000],
            colour=0xED4245 if not incident.dry_run else 0xFAA61A,
        )
        embed.add_field(name="Status", value=incident.status.value, inline=True)
        embed.add_field(name="Severity", value=incident.severity.value, inline=True)
        embed.add_field(name="Outcome", value=incident.outcome.value, inline=True)
        embed.add_field(
            name="Actor",
            value=(
                f"<@{incident.actor_id}> (`{incident.actor_id}`)"
                if incident.actor_id
                else "unidentified"
            ),
            inline=True,
        )
        embed.add_field(name="Attribution", value=incident.actor_confidence.value, inline=True)
        embed.add_field(name="Mode", value=incident.mode_at_detection.value, inline=True)
        embed.add_field(
            name="Evidence",
            value=(
                f"{incident.event_count} event(s), threshold {incident.threshold_count} / "
                f"{incident.window_seconds}s, policy version {incident.policy_version}"
            ),
            inline=False,
        )
        embed.add_field(
            name="Detected", value=f"<t:{int(incident.detected_at.timestamp())}:F>", inline=True
        )
        if incident.target_id:
            embed.add_field(
                name="Target",
                value=f"{incident.target_type or 'object'} `{incident.target_id}`",
                inline=True,
            )
        if actions:
            embed.add_field(
                name="Enforcement steps",
                value="\n".join(
                    f"`{a.action_type}` -> {a.status.value}"
                    + (f": {a.detail}" if a.detail else "")
                    + (f" ERROR: {a.error}" if a.error else "")
                    for a in actions
                )[:1000],
                inline=False,
            )
        else:
            embed.add_field(
                name="Enforcement steps", value="none recorded", inline=False
            )
        if payload:
            embed.add_field(name="Payload", value=f"```json\n{str(payload)[:900]}\n```", inline=False)
        if incident.acknowledged_by:
            embed.add_field(
                name="Acknowledged",
                value=(
                    f"by <@{incident.acknowledged_by}> "
                    f"<t:{int(incident.acknowledged_at.timestamp())}:R>"
                    + (f"\n{incident.acknowledgement_note}" if incident.acknowledgement_note else "")
                ),
                inline=False,
            )
        embed.set_footer(text=f"correlation {incident.correlation_id}")
        await respond(interaction, embed=embed)

    @app_commands.command(
        name="acknowledge",
        description="Acknowledge an incident, or mark it as a false positive",
    )
    @app_commands.describe(
        incident_id="Incident number",
        false_positive="Mark as a false positive (feeds the tuning report)",
        note="Optional note stored with the incident",
    )
    async def acknowledge(
        self,
        interaction: discord.Interaction,
        incident_id: app_commands.Range[int, 1, None],
        false_positive: bool = False,
        note: app_commands.Range[str, 1, 500] | None = None,
    ) -> None:
        if not await require(
            interaction,
            Authority.DELEGATE,
            command="shield incidents acknowledge",
            parameters={"incident_id": incident_id, "false_positive": false_positive},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild_id = interaction.guild_id
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            incident = await uow.incidents.acknowledge(
                guild_id,
                int(incident_id),
                user_id=int(interaction.user.id),
                note=note,
                false_positive=false_positive,
            )
            rate = await uow.incidents.false_positive_rate(
                guild_id, datetime.now(tz=timezone.utc) - timedelta(days=7)
            )
            # Clear the cooldown so a corrected policy can fire again immediately.
            if incident is not None and false_positive:
                await uow.cooldowns.clear(
                    guild_id,
                    f"{incident.action_key.value}:"
                    f"{incident.actor_id if incident.actor_id is not None else 'unattributed'}",
                )
        if incident is None:
            await respond(interaction, f"No incident `#{incident_id}` in this guild.")
            return
        message = (
            f"Incident `#{incident.id}` marked **{incident.status.value}**."
        )
        if false_positive:
            message += (
                f"\n7-day false-positive rate: **{rate:.0%}**."
                "\nIf this detector keeps misfiring, raise its threshold or set its "
                "response to `alert_only` with `/shield thresholds set`."
            )
        await respond(interaction, message)

    @app_commands.command(
        name="export", description="Export recent incidents as a JSON attachment"
    )
    @app_commands.describe(days="How many days to export (1-365)")
    async def export(
        self, interaction: discord.Interaction, days: app_commands.Range[int, 1, 365] = 30
    ) -> None:
        if not await require(
            interaction,
            Authority.OWNER,
            command="shield incidents export",
            parameters={"days": days},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        import io
        import json

        bot = interaction.client
        guild_id = interaction.guild_id
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            rows = await uow.incidents.export(
                guild_id, datetime.now(tz=timezone.utc) - timedelta(days=days)
            )
        buffer = io.BytesIO(json.dumps(rows, indent=2).encode("utf-8"))
        file = discord.File(
            buffer, filename=f"shield-incidents-{guild_id}-{days}d.json"
        )
        await respond(
            interaction,
            f"Exported **{len(rows)}** incident(s) from the last {days} day(s). "
            "The export contains no message content and no secrets.",
            file=file,
        )
