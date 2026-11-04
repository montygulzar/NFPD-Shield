"""``/shield backup`` - create, list and inspect structural snapshots."""

from __future__ import annotations

import discord
from discord import app_commands

from shield.commands.authz import Authority, require, respond
from shield.constants import SnapshotKind
from shield.db.repositories import UnitOfWork


class BackupGroup(
    app_commands.Group, name="backup", description="Manage NFPD Shield structural snapshots"
):
    @app_commands.command(name="create", description="Take a snapshot of this guild now")
    @app_commands.describe(
        include_webhooks="Include webhook metadata (names/channels only, never tokens)"
    )
    async def create(
        self, interaction: discord.Interaction, include_webhooks: bool | None = None
    ) -> None:
        if not await require(
            interaction,
            Authority.DELEGATE,
            command="shield backup create",
            parameters={"include_webhooks": include_webhooks},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        result = await bot.snapshots.capture(
            interaction.guild,
            kind=SnapshotKind.MANUAL,
            taken_by=int(interaction.user.id),
            include_webhooks=include_webhooks,
        )
        prefix = "**Snapshot created.**" if result.snapshot_id else "**Snapshot failed.**"
        await respond(
            interaction,
            f"{prefix} {result.message}"
            + (
                "\nStored encrypted at rest."
                if result.encrypted
                else "\n**Not encrypted:** set `SNAPSHOT_ENCRYPTION_KEY` to encrypt "
                "snapshots at rest."
            ),
        )

    @app_commands.command(name="list", description="List stored snapshots")
    @app_commands.describe(limit="How many to show (1-25)")
    async def list_snapshots(
        self, interaction: discord.Interaction, limit: app_commands.Range[int, 1, 25] = 10
    ) -> None:
        if not await require(
            interaction, Authority.DELEGATE, command="shield backup list", parameters={"limit": limit}
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(interaction.guild_id)
            rows = await uow.snapshots.list_for_guild(interaction.guild_id, limit=limit)
            settings = await uow.guilds.get(interaction.guild_id)
            retention = settings.snapshot_retention if settings else 12
        if not rows:
            await respond(
                interaction,
                "No snapshots stored yet. Shield snapshots at startup and on a schedule; "
                "use `/shield backup create` to take one now.",
            )
            return
        lines = [f"**Snapshots** (retaining the newest {retention})"]
        for row in rows:
            flag = "" if row.validated else " **INVALID - cannot be restored**"
            lock = " [encrypted]" if row.encrypted else ""
            summary = row.summary or {}
            lines.append(
                f"`v{row.version}` id `{row.id}` <t:{int(row.taken_at.timestamp())}:R> "
                f"`{row.kind.value}`{lock}{flag}\n"
                f"  {summary.get('roles', '?')} roles, {summary.get('categories', '?')} categories, "
                f"{summary.get('channels', '?')} channels, {summary.get('webhooks', 0)} webhooks"
            )
        await respond(interaction, "\n".join(lines))

    @app_commands.command(
        name="inspect", description="Inspect one snapshot and verify its integrity"
    )
    @app_commands.describe(snapshot_id="Snapshot id from /shield backup list")
    async def inspect(
        self, interaction: discord.Interaction, snapshot_id: app_commands.Range[int, 1, None]
    ) -> None:
        if not await require(
            interaction,
            Authority.DELEGATE,
            command="shield backup inspect",
            parameters={"snapshot_id": snapshot_id},
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        try:
            loaded = await bot.snapshots.load(interaction.guild_id, int(snapshot_id))
        except Exception as exc:  # noqa: BLE001 - e.g. missing encryption key
            await respond(interaction, f"**Could not read the snapshot:** {exc}")
            return
        if loaded is None:
            await respond(interaction, f"No snapshot `{snapshot_id}` in this guild.")
            return
        meta, payload = loaded
        ok, integrity = await bot.snapshots.verify_integrity(
            interaction.guild_id, int(snapshot_id)
        )

        guild_block = payload.get("guild", {})
        embed = discord.Embed(
            title=f"Snapshot v{meta['version']} (id {meta['id']})",
            description=f"Taken <t:{int(meta['taken_at'].timestamp())}:F> - `{meta['kind']}`",
            colour=0x3BA55D if ok and meta["validated"] else 0xED4245,
        )
        embed.add_field(
            name="Integrity", value=("OK - " if ok else "**MISMATCH** - ") + integrity, inline=False
        )
        embed.add_field(
            name="Contents",
            value=(
                f"roles: {len(payload.get('roles', []))}\n"
                f"categories: {len(payload.get('categories', []))}\n"
                f"channels: {len(payload.get('channels', []))}\n"
                f"webhook metadata: {len(payload.get('webhooks', []))}"
            ),
            inline=True,
        )
        embed.add_field(
            name="Guild settings",
            value=(
                f"name: {guild_block.get('name')}\n"
                f"verification: {guild_block.get('verification_level')}\n"
                f"content filter: {guild_block.get('explicit_content_filter')}\n"
                f"vanity: {guild_block.get('vanity_url_code') or 'n/a'}"
            ),
            inline=True,
        )
        embed.add_field(
            name="Encrypted at rest", value=str(meta["encrypted"]), inline=True
        )
        if meta["validation_errors"]:
            embed.add_field(
                name="Validation errors",
                value="\n".join(f"- {e}" for e in meta["validation_errors"])[:1000],
                inline=False,
            )
        embed.add_field(
            name="NOT captured (unrecoverable)",
            value="\n".join(f"- {n}" for n in payload.get("not_captured", []))[:1000]
            or "n/a",
            inline=False,
        )
        await respond(interaction, embed=embed)

    @app_commands.command(
        name="settings", description="Change snapshot cadence and retention for this guild"
    )
    @app_commands.describe(
        interval_minutes="Minutes between scheduled snapshots (5-10080)",
        retention="How many snapshots to keep (1-500)",
        include_webhooks="Include webhook metadata in future snapshots",
    )
    async def settings(
        self,
        interaction: discord.Interaction,
        interval_minutes: app_commands.Range[int, 5, 10080] | None = None,
        retention: app_commands.Range[int, 1, 500] | None = None,
        include_webhooks: bool | None = None,
    ) -> None:
        params = {
            "interval_minutes": interval_minutes,
            "retention": retention,
            "include_webhooks": include_webhooks,
        }
        if not await require(
            interaction, Authority.OWNER, command="shield backup settings", parameters=params
        ):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        updates = {}
        if interval_minutes is not None:
            updates["snapshot_interval_minutes"] = int(interval_minutes)
        if retention is not None:
            updates["snapshot_retention"] = int(retention)
        if include_webhooks is not None:
            updates["snapshot_include_webhooks"] = bool(include_webhooks)
        if not updates:
            await respond(interaction, "Nothing to change.")
            return
        bot = interaction.client
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.ensure(interaction.guild_id)
            settings = await uow.guilds.update(interaction.guild_id, **updates)
            if retention is not None:
                await uow.snapshots.enforce_retention(interaction.guild_id, int(retention))
        bot.pipeline.state_cache.invalidate(interaction.guild_id)
        await respond(
            interaction,
            "**Snapshot settings updated.** "
            f"Interval {settings.snapshot_interval_minutes}m, retention "
            f"{settings.snapshot_retention}, webhooks "
            f"{settings.snapshot_include_webhooks}.",
        )
