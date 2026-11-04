"""``/shield restore`` - previewable, approval-gated restoration.

Flow:

1. ``/shield restore preview`` builds a diff against the live guild and returns
   a short-lived approval token. Nothing is written.
2. ``/shield restore apply`` takes that token, re-checks it against the *current*
   guild state (so a concurrent change cannot be clobbered), takes a
   ``PRE_RESTORE`` snapshot, and then applies the plan.

Only the guild owner may apply. The token is guild-scoped, single-use and
expires, so it cannot be replayed or used from another guild.
"""

from __future__ import annotations

import discord
from discord import app_commands

from shield.commands.authz import Authority, require, respond
from shield.constants import RestoreMode, RestoreStatus, SnapshotKind
from shield.db.repositories import UnitOfWork
from shield.restore.applier import RestoreApplier
from shield.restore.planner import build_plan, live_state_from_guild

SCOPE_CHOICES = [
    app_commands.Choice(name="everything", value="roles,categories,channels,overwrites,settings"),
    app_commands.Choice(name="roles only", value="roles"),
    app_commands.Choice(name="channels only", value="categories,channels,overwrites"),
    app_commands.Choice(name="guild settings only", value="settings"),
]


class RestoreGroup(
    app_commands.Group, name="restore", description="Preview and apply a snapshot restore"
):
    @app_commands.command(
        name="preview", description="Show exactly what a restore would change (no writes)"
    )
    @app_commands.describe(
        snapshot_id="Snapshot id from /shield backup list (default: newest valid)",
        scope="Limit what the restore touches",
    )
    @app_commands.choices(scope=SCOPE_CHOICES)
    async def preview(
        self,
        interaction: discord.Interaction,
        snapshot_id: app_commands.Range[int, 1, None] | None = None,
        scope: app_commands.Choice[str] | None = None,
    ) -> None:
        if not await require(
            interaction,
            Authority.DELEGATE,
            command="shield restore preview",
            parameters={"snapshot_id": snapshot_id, "scope": scope.value if scope else None},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        guild = interaction.guild

        try:
            loaded = (
                await bot.snapshots.load(guild.id, int(snapshot_id))
                if snapshot_id is not None
                else await bot.snapshots.latest_valid(guild.id)
            )
        except Exception as exc:  # noqa: BLE001
            await respond(interaction, f"**Could not read the snapshot:** {exc}")
            return
        if loaded is None:
            await respond(
                interaction,
                "No usable snapshot found for this guild. Take one with "
                "`/shield backup create`.",
            )
            return
        meta, payload = loaded
        if not meta["validated"]:
            await respond(
                interaction,
                f"Snapshot v{meta['version']} failed validation and will not be restored:\n"
                + "\n".join(f"- {e}" for e in meta["validation_errors"]),
            )
            return

        scope_set = set((scope.value if scope else SCOPE_CHOICES[0].value).split(","))
        roles, channels = live_state_from_guild(guild)
        plan = build_plan(
            guild_id=guild.id,
            snapshot_version=meta["version"],
            payload=payload,
            live_roles=roles,
            live_channels=channels,
            scope=scope_set,
        )

        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            job = await uow.restores.create(
                guild_id=guild.id,
                snapshot_id=int(meta["id"]),
                mode=RestoreMode.PREVIEW,
                status=RestoreStatus.PREVIEWED,
                requested_by=int(interaction.user.id),
                plan=plan.as_dict(),
                scope=sorted(scope_set),
            )
            token = job.approval_token
            expires = job.token_expires_at

        body = (
            f"**Restore preview** from snapshot v{meta['version']} "
            f"(taken <t:{int(meta['taken_at'].timestamp())}:R>)\n\n"
            + plan.render()
            + "\n\n**Nothing has been changed.**\n"
            f"To apply, the **guild owner** must run:\n"
            f"`/shield restore apply token:{token}`\n"
            + (f"The token expires <t:{int(expires.timestamp())}:R>.\n" if expires else "")
            + "\n**Understand before approving:** recreated objects get **new IDs**; "
            "message history, invites, threads, integrations and webhook tokens "
            "cannot be restored by any bot."
        )
        await respond(interaction, body)

    @app_commands.command(
        name="apply", description="Apply a previously previewed restore (guild owner only)"
    )
    @app_commands.describe(
        token="Approval token from /shield restore preview",
        confirm="Type true to confirm you have read the preview",
    )
    async def apply(
        self,
        interaction: discord.Interaction,
        token: app_commands.Range[str, 4, 32],
        confirm: bool = False,
    ) -> None:
        if not await require(
            interaction,
            Authority.OWNER,
            command="shield restore apply",
            parameters={"token": "***", "confirm": confirm},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        if not confirm:
            await respond(
                interaction,
                "Restore **not** applied: pass `confirm: true` to acknowledge the preview.",
            )
            return

        bot = interaction.client
        guild = interaction.guild
        if not bot.limiter.allow("restore", guild.id):
            await respond(
                interaction,
                "Restore rate limit reached for this guild. Wait a few minutes before "
                "retrying - this guard exists so a restore loop cannot run away.",
            )
            return

        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            job = await uow.restores.find_pending_token(guild.id, str(token))
            snapshot_id = job.snapshot_id if job else None
            scope = set(job.scope or []) if job else set()
            job_id = job.id if job else None
        if job_id is None:
            await respond(
                interaction,
                "That approval token is unknown, already used, expired, or belongs to "
                "another guild. Run `/shield restore preview` again.",
            )
            return

        try:
            loaded = await bot.snapshots.load(guild.id, int(snapshot_id))
        except Exception as exc:  # noqa: BLE001
            await respond(interaction, f"**Could not read the snapshot:** {exc}")
            return
        if loaded is None:
            await respond(interaction, "The snapshot behind that token no longer exists.")
            return
        meta, payload = loaded

        # Safety snapshot first: a restore must itself be reversible.
        pre = await bot.snapshots.capture(
            guild,
            kind=SnapshotKind.PRE_RESTORE,
            taken_by=int(interaction.user.id),
            bypass_rate_limit=True,
        )

        # Re-plan against *current* state so concurrent legitimate edits are not
        # clobbered and the diff the owner approved is still accurate.
        roles, channels = live_state_from_guild(guild)
        plan = build_plan(
            guild_id=guild.id,
            snapshot_version=meta["version"],
            payload=payload,
            live_roles=roles,
            live_channels=channels,
            scope=scope or None,
        )
        if plan.write_count == 0:
            async with bot.db.begin() as session:
                uow = UnitOfWork(session)
                await uow.restores.finish(
                    job_id,
                    guild_id=guild.id,
                    status=RestoreStatus.COMPLETED,
                    result={"writes": 0, "note": "guild already matches the snapshot"},
                    approved_by=int(interaction.user.id),
                )
            await respond(
                interaction,
                "Nothing to restore: the guild already matches the snapshot. "
                f"A pre-restore snapshot was still taken ({pre.message}).",
            )
            return

        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.restores.finish(
                job_id,
                guild_id=guild.id,
                status=RestoreStatus.APPLYING,
                result=None,
                approved_by=int(interaction.user.id),
            )

        applier = RestoreApplier(selfguard=bot.selfguard)
        outcome = await applier.apply(
            guild,
            plan,
            reason=(
                f"NFPD Shield restore of snapshot v{meta['version']} approved by "
                f"{interaction.user} ({interaction.user.id})"
            ),
        )

        status_map = {
            "completed": RestoreStatus.COMPLETED,
            "partial": RestoreStatus.PARTIAL,
            "failed": RestoreStatus.FAILED,
        }
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.restores.finish(
                job_id,
                guild_id=guild.id,
                status=status_map[outcome.status_label],
                result=outcome.as_dict(),
                id_map=outcome.id_map,
                approved_by=int(interaction.user.id),
            )

        await respond(
            interaction,
            f"**Restore applied** from snapshot v{meta['version']}.\n"
            f"Pre-restore safety snapshot: {pre.message}\n\n"
            + outcome.render()
            + "\n\n**Old IDs are gone for good** - any bot, webhook or external "
            "integration that referenced the previous channel/role IDs must be "
            "reconfigured. The old -> new ID map is stored on this restore job.",
        )

    @app_commands.command(name="history", description="Show recent restore jobs")
    async def history(self, interaction: discord.Interaction) -> None:
        if not await require(
            interaction, Authority.DELEGATE, command="shield restore history"
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            jobs = await uow.restores.list_for_guild(interaction.guild_id, limit=10)
        if not jobs:
            await respond(interaction, "No restore jobs recorded for this guild.")
            return
        lines = ["**Restore history**"]
        for job in jobs:
            result = job.result or {}
            lines.append(
                f"`#{job.id}` <t:{int(job.created_at.timestamp())}:R> `{job.mode.value}` -> "
                f"**{job.status.value}** by <@{job.requested_by}>"
                + (f", {result.get('writes', 0)} write(s)" if result else "")
            )
        await respond(interaction, "\n".join(lines))
