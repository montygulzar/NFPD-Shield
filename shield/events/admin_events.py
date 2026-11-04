"""Administrative gateway listeners (destructive / structural changes).

These events are the anti-nuke core. Every one of them arrives WITHOUT an actor:
Discord's gateway tells a bot *that* a channel was deleted, never *who* deleted
it. Attribution therefore happens inside the pipeline through
:class:`~shield.audit.correlator.AuditCorrelator`, and no sanction is possible
without ``View Audit Log``.

Observability limits, stated honestly:

* ``on_webhooks_update`` fires for create, delete *and* edit, and names only the
  channel. Shield inspects the audit log to decide which happened; without
  ``View Audit Log`` it can only report "webhooks changed in #channel".
* ``on_guild_update`` does not say which field changed in a machine-readable
  way, so Shield diffs the before/after objects itself.
* Vanity URL changes are only visible on guilds with the VANITY_URL feature.
* Channel permission *overwrite* changes arrive as ``on_guild_channel_update``;
  Shield reports them only when the diff grants a dangerous permission.
"""

from __future__ import annotations

from datetime import datetime, timezone

import discord
from discord.ext import commands

from shield.constants import (
    CRITICAL_PERMISSIONS,
    PROTECTED_GUILD_FIELDS,
    ActionKey,
    EventSource,
)
from shield.enforcement.safety import dangerous_grants, permissions_set
from shield.events.normalize import NormalizedEvent
from shield.observability.logging import get_logger

log = get_logger("events.admin")


class AdminEventsCog(commands.Cog):
    def __init__(self, bot) -> None:  # noqa: ANN001
        self.bot = bot

    @property
    def pipeline(self):  # noqa: ANN201
        return self.bot.pipeline

    async def _emit(self, guild: discord.Guild, event: NormalizedEvent) -> None:
        await self.pipeline.handle(event, guild)

    # -- channels ------------------------------------------------------
    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        guild = channel.guild
        await self._emit(
            guild,
            NormalizedEvent(
                guild_id=guild.id,
                action_key=ActionKey.CHANNEL_DELETE,
                source=EventSource.GATEWAY,
                occurred_at=datetime.now(tz=timezone.utc),
                target_type="channel",
                target_id=int(channel.id),
                payload={
                    "target_name": str(getattr(channel, "name", "")),
                    "channel_type": str(getattr(getattr(channel, "type", None), "name", "")),
                    "category": str(getattr(getattr(channel, "category", None), "name", "") or ""),
                },
            ),
        )

    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        guild = channel.guild
        await self._emit(
            guild,
            NormalizedEvent(
                guild_id=guild.id,
                action_key=ActionKey.CHANNEL_CREATE_FLOOD,
                source=EventSource.GATEWAY,
                occurred_at=datetime.now(tz=timezone.utc),
                target_type="channel",
                target_id=int(channel.id),
                payload={
                    "target_name": str(getattr(channel, "name", "")),
                    "channel_type": str(getattr(getattr(channel, "type", None), "name", "")),
                },
            ),
        )

    @commands.Cog.listener()
    async def on_guild_channel_update(
        self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel
    ) -> None:
        """Report channel overwrite changes that grant dangerous permissions."""
        guild = after.guild
        before_overwrites = getattr(before, "overwrites", {}) or {}
        after_overwrites = getattr(after, "overwrites", {}) or {}
        escalations: list[dict[str, object]] = []
        for target, overwrite in after_overwrites.items():
            previous = before_overwrites.get(target)
            try:
                new_allow, _ = overwrite.pair()
                old_allow = previous.pair()[0] if previous is not None else discord.Permissions.none()
            except Exception:  # noqa: BLE001
                continue
            gained = dangerous_grants(permissions_set(old_allow), permissions_set(new_allow))
            if gained:
                escalations.append(
                    {
                        "target_id": int(getattr(target, "id", 0) or 0),
                        "target_name": str(getattr(target, "name", ""))[:100],
                        "granted": list(gained),
                    }
                )
        if not escalations:
            return
        await self._emit(
            guild,
            NormalizedEvent(
                guild_id=guild.id,
                action_key=ActionKey.DANGEROUS_PERMISSION_CHANGE,
                source=EventSource.GATEWAY,
                occurred_at=datetime.now(tz=timezone.utc),
                target_type="channel",
                target_id=int(after.id),
                payload={
                    "target_name": str(getattr(after, "name", "")),
                    "overwrite_escalations": escalations,
                    "scope": "channel_overwrite",
                },
            ),
        )

    # -- roles ---------------------------------------------------------
    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role) -> None:
        guild = role.guild
        await self._emit(
            guild,
            NormalizedEvent(
                guild_id=guild.id,
                action_key=ActionKey.ROLE_DELETE,
                source=EventSource.GATEWAY,
                occurred_at=datetime.now(tz=timezone.utc),
                target_type="role",
                target_id=int(role.id),
                payload={
                    "target_name": str(getattr(role, "name", "")),
                    "was_dangerous": sorted(
                        p
                        for p in CRITICAL_PERMISSIONS
                        if p in permissions_set(getattr(role, "permissions", None))
                    ),
                    "member_count": len(getattr(role, "members", []) or []),
                },
            ),
        )

    @commands.Cog.listener()
    async def on_guild_role_create(self, role: discord.Role) -> None:
        guild = role.guild
        await self._emit(
            guild,
            NormalizedEvent(
                guild_id=guild.id,
                action_key=ActionKey.ROLE_CREATE_FLOOD,
                source=EventSource.GATEWAY,
                occurred_at=datetime.now(tz=timezone.utc),
                target_type="role",
                target_id=int(role.id),
                payload={"target_name": str(getattr(role, "name", ""))},
            ),
        )

    @commands.Cog.listener()
    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        """Report elevation of a role to a dangerous permission set."""
        guild = after.guild
        gained = dangerous_grants(
            permissions_set(getattr(before, "permissions", None)),
            permissions_set(getattr(after, "permissions", None)),
        )
        if not gained:
            return
        await self._emit(
            guild,
            NormalizedEvent(
                guild_id=guild.id,
                action_key=ActionKey.DANGEROUS_PERMISSION_CHANGE,
                source=EventSource.GATEWAY,
                occurred_at=datetime.now(tz=timezone.utc),
                target_type="role",
                target_id=int(after.id),
                payload={
                    "target_name": str(getattr(after, "name", "")),
                    "granted": list(gained),
                    "scope": "role_permissions",
                    "member_count": len(getattr(after, "members", []) or []),
                },
            ),
        )

    # -- webhooks ------------------------------------------------------
    @commands.Cog.listener()
    async def on_webhooks_update(self, channel: discord.abc.GuildChannel) -> None:
        """Classify a webhook change via the audit log.

        The gateway event carries no webhook ID and no actor, so the audit log is
        the only source. Without ``View Audit Log`` Shield emits a generic
        ``webhook_update`` event so the change is still visible.
        """
        guild = channel.guild
        action_key = ActionKey.WEBHOOK_UPDATE
        actor_id = None
        entry_id = None
        confidence = None
        detail = "webhooks changed; audit log not readable"
        try:
            if _can_read_audit(guild):
                async for entry in guild.audit_logs(limit=5):
                    name = str(getattr(getattr(entry, "action", None), "name", ""))
                    if name not in {"webhook_create", "webhook_delete", "webhook_update"}:
                        continue
                    created = getattr(entry, "created_at", None)
                    if created is None:
                        continue
                    created = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
                    age = (datetime.now(tz=timezone.utc) - created).total_seconds()
                    if age > self.pipeline.correlator.window:
                        continue
                    action_key = {
                        "webhook_create": ActionKey.WEBHOOK_CREATE,
                        "webhook_delete": ActionKey.WEBHOOK_DELETE,
                        "webhook_update": ActionKey.WEBHOOK_UPDATE,
                    }[name]
                    actor_id = int(getattr(getattr(entry, "user", None), "id", 0) or 0) or None
                    entry_id = int(getattr(entry, "id", 0) or 0) or None
                    from shield.constants import Confidence

                    confidence = Confidence.CONFIRMED if actor_id else Confidence.UNKNOWN
                    detail = f"classified from audit entry {entry_id} ({age:.1f}s old)"
                    break
        except Exception as exc:  # noqa: BLE001
            detail = f"audit classification failed: {type(exc).__name__}"

        from shield.constants import Confidence

        event = NormalizedEvent(
            guild_id=guild.id,
            action_key=action_key,
            source=EventSource.AUDIT_LOG if entry_id else EventSource.GATEWAY,
            occurred_at=datetime.now(tz=timezone.utc),
            actor_id=actor_id,
            actor_confidence=confidence or Confidence.UNKNOWN,
            audit_entry_id=entry_id,
            target_type="channel",
            target_id=int(channel.id),
            channel_id=int(channel.id),
            payload={
                "target_name": f"#{getattr(channel, 'name', channel.id)}",
                "classification": detail,
            },
        )
        await self._emit(guild, event)

    # -- guild settings ------------------------------------------------
    @commands.Cog.listener()
    async def on_guild_update(self, before: discord.Guild, after: discord.Guild) -> None:
        changed: dict[str, object] = {}
        for field in PROTECTED_GUILD_FIELDS:
            old = getattr(before, field, None)
            new = getattr(after, field, None)
            if _render(old) != _render(new):
                changed[field] = {"before": _render(old), "after": _render(new)}
        if not changed:
            return

        vanity_changed = "vanity_url_code" in changed
        action_key = (
            ActionKey.VANITY_URL_CHANGE if vanity_changed else ActionKey.GUILD_SETTINGS_CHANGE
        )
        await self._emit(
            after,
            NormalizedEvent(
                guild_id=after.id,
                action_key=action_key,
                source=EventSource.GATEWAY,
                occurred_at=datetime.now(tz=timezone.utc),
                target_type="guild",
                target_id=int(after.id),
                payload={
                    "target_name": str(getattr(after, "name", "")),
                    "changed_fields": sorted(changed),
                    "changes": changed,
                    "note": (
                        "security-relevant guild settings changed; Discord's audit "
                        "coverage of guild_update is partial, so attribution may be "
                        "unavailable"
                    ),
                },
            ),
        )
        if vanity_changed and len(changed) > 1:
            # Report the non-vanity part of the diff under its own policy too.
            others = {k: v for k, v in changed.items() if k != "vanity_url_code"}
            await self._emit(
                after,
                NormalizedEvent(
                    guild_id=after.id,
                    action_key=ActionKey.GUILD_SETTINGS_CHANGE,
                    source=EventSource.GATEWAY,
                    occurred_at=datetime.now(tz=timezone.utc),
                    target_type="guild",
                    target_id=int(after.id),
                    payload={
                        "target_name": str(getattr(after, "name", "")),
                        "changed_fields": sorted(others),
                        "changes": others,
                    },
                ),
            )


def _can_read_audit(guild) -> bool:  # noqa: ANN001
    perms = getattr(getattr(guild, "me", None), "guild_permissions", None)
    return bool(
        getattr(perms, "view_audit_log", False) or getattr(perms, "administrator", False)
    )


def _render(value: object) -> object:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    name = getattr(value, "name", None)
    if name is not None and not callable(name):
        return str(name)
    url = getattr(value, "url", None)
    if url is not None:
        return str(url)
    return str(value)[:200]


async def setup(bot) -> None:  # noqa: ANN001
    await bot.add_cog(AdminEventsCog(bot))
