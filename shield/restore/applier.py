"""Restore application.

Safety properties:

* A ``PRE_RESTORE`` snapshot is taken first, so a restore is itself reversible.
* Every Discord write is registered with the :class:`SelfActionGuard` *before*
  it happens, so Shield's repair work cannot trigger its own detectors.
* Operations are ordered roles -> categories -> channels -> overwrites ->
  settings, because later steps depend on the IDs produced by earlier ones.
* An ``id_map`` records old snowflake -> new snowflake for every recreated
  object; permission overwrites are rewritten through it, and any overwrite
  referencing an object that no longer exists is reported, not silently dropped.
* Failures are per-item. One failed channel does not abort the restore; the
  result lists exactly what was and was not restored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shield.constants import MAX_RESTORE_WRITES
from shield.enforcement.ratelimit import call_with_retry
from shield.enforcement.selfguard import SelfActionGuard
from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS
from shield.restore.planner import RestorePlan

log = get_logger("restore")


@dataclass(slots=True)
class RestoreOutcome:
    restored: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    unrecoverable: list[str] = field(default_factory=list)
    id_map: dict[str, int] = field(default_factory=dict)
    writes: int = 0

    @property
    def status_label(self) -> str:
        if self.failed and self.restored:
            return "partial"
        if self.failed:
            return "failed"
        return "completed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status_label,
            "writes": self.writes,
            "restored": self.restored,
            "failed": self.failed,
            "skipped": self.skipped,
            "unrecoverable": self.unrecoverable,
            "id_map": self.id_map,
        }

    def render(self, limit: int = 15) -> str:
        lines = [
            f"**Result:** {self.status_label} - {len(self.restored)} restored, "
            f"{len(self.failed)} failed, {len(self.skipped)} skipped "
            f"({self.writes} Discord writes)."
        ]
        for entry in self.restored[:limit]:
            lines.append(f"- restored: {entry}")
        if len(self.restored) > limit:
            lines.append(f"- ... and {len(self.restored) - limit} more")
        for entry in self.failed[:limit]:
            lines.append(f"- FAILED: {entry}")
        if self.unrecoverable:
            lines.append("**NOT recoverable:** " + "; ".join(self.unrecoverable[:6]))
        return "\n".join(lines)


class RestoreApplier:
    def __init__(self, *, selfguard: SelfActionGuard) -> None:
        self.selfguard = selfguard

    async def apply(
        self,
        guild,  # noqa: ANN001
        plan: RestorePlan,
        *,
        reason: str = "NFPD Shield restore",
        max_writes: int = MAX_RESTORE_WRITES,
    ) -> RestoreOutcome:
        outcome = RestoreOutcome(unrecoverable=list(plan.unrecoverable), skipped=list(plan.skipped))
        audit_reason = reason[:400]
        id_map: dict[int, int] = {}

        # Pre-register a wildcard suppression for the whole repair burst so the
        # creation flood detectors ignore Shield's own work.
        creates = sum(
            1 for i in plan.items if i.op in {"create_role", "create_category", "create_channel"}
        )
        if creates:
            self.selfguard.register(guild.id, "role_create", None, count=creates)
            self.selfguard.register(guild.id, "channel_create", None, count=creates)
            self.selfguard.register(guild.id, "guild_update", None, count=creates)

        ordered = sorted(plan.items, key=lambda i: _ORDER.get(i.op, 99))
        deferred_overwrites: list[tuple[Any, list[dict[str, Any]], str]] = []

        for item in ordered:
            if outcome.writes >= max_writes:
                outcome.skipped.append(
                    f"write cap of {max_writes} reached; {item.op} '{item.label}' deferred"
                )
                continue
            try:
                if item.op == "create_role":
                    new_id = await self._create_role(guild, item.detail, audit_reason)
                    if new_id:
                        id_map[int(item.detail["old_id"])] = new_id
                        outcome.restored.append(f"role '{item.detail['name']}' -> {new_id}")
                        outcome.writes += 1
                elif item.op == "create_category":
                    channel, new_id = await self._create_category(guild, item.detail, audit_reason)
                    if new_id:
                        id_map[int(item.detail["old_id"])] = new_id
                        outcome.restored.append(f"category '{item.detail['name']}' -> {new_id}")
                        outcome.writes += 1
                        if item.detail.get("overwrites"):
                            deferred_overwrites.append(
                                (channel, item.detail["overwrites"], f"category '{item.detail['name']}'")
                            )
                elif item.op == "create_channel":
                    channel, new_id = await self._create_channel(
                        guild, item.detail, audit_reason, id_map
                    )
                    if new_id:
                        id_map[int(item.detail["old_id"])] = new_id
                        outcome.restored.append(
                            f"{item.detail['type']} channel '{item.detail['name']}' -> {new_id}"
                        )
                        outcome.writes += 1
                        if item.detail.get("overwrites"):
                            deferred_overwrites.append(
                                (channel, item.detail["overwrites"], f"channel '{item.detail['name']}'")
                            )
                elif item.op == "restore_setting":
                    changed = await self._restore_setting(guild, item.detail, audit_reason)
                    if changed:
                        outcome.restored.append(
                            f"guild {item.detail['field']} -> {item.detail['value']}"
                        )
                        outcome.writes += 1
                    else:
                        outcome.skipped.append(
                            f"guild {item.detail['field']} already matches the snapshot"
                        )
                else:
                    outcome.skipped.append(f"unknown operation '{item.op}' ignored")
            except Exception as exc:  # noqa: BLE001 - per-item isolation
                METRICS.incr("restore_item_errors_total", op=item.op)
                outcome.failed.append(f"{item.op} '{item.label}': {type(exc).__name__}: {exc}")
                log.warning(
                    "restore item failed",
                    extra={"guild_id": guild.id, "op": item.op, "error": str(exc)},
                )

        # Overwrites last: they reference role IDs that only exist now.
        for channel, overwrites, label in deferred_overwrites:
            if outcome.writes >= max_writes:
                outcome.skipped.append(f"permission overwrites for {label} deferred (write cap)")
                continue
            applied, problems = await self._apply_overwrites(
                guild, channel, overwrites, id_map, audit_reason
            )
            outcome.writes += 1 if applied else 0
            if applied:
                outcome.restored.append(f"{applied} permission overwrite(s) on {label}")
            for problem in problems:
                outcome.failed.append(f"overwrite on {label}: {problem}")

        outcome.id_map = {str(k): v for k, v in id_map.items()}
        METRICS.incr("restores_total", status=outcome.status_label)
        log.warning(
            "restore applied",
            extra={
                "guild_id": guild.id,
                "status": outcome.status_label,
                "restored": len(outcome.restored),
                "failed": len(outcome.failed),
                "writes": outcome.writes,
            },
        )
        return outcome

    # -- operations ----------------------------------------------------
    async def _create_role(self, guild, detail: dict[str, Any], reason: str) -> int | None:  # noqa: ANN001
        import discord

        permissions = discord.Permissions(int(detail.get("permissions", 0) or 0))
        colour = discord.Colour(int(detail.get("color", 0) or 0))
        self.selfguard.register(guild.id, "role_create")
        role = await call_with_retry(
            lambda: guild.create_role(
                name=str(detail["name"])[:100],
                permissions=permissions,
                colour=colour,
                hoist=bool(detail.get("hoist")),
                mentionable=bool(detail.get("mentionable")),
                reason=reason,
            ),
            description="create role",
        )
        return int(role.id) if role is not None else None

    async def _create_category(self, guild, detail: dict[str, Any], reason: str):  # noqa: ANN001, ANN202
        self.selfguard.register(guild.id, "channel_create")
        category = await call_with_retry(
            lambda: guild.create_category(
                name=str(detail["name"])[:100],
                position=int(detail.get("position", 0) or 0),
                reason=reason,
            ),
            description="create category",
        )
        return category, (int(category.id) if category is not None else None)

    async def _create_channel(  # noqa: ANN202
        self, guild, detail: dict[str, Any], reason: str, id_map: dict[int, int]
    ):  # noqa: ANN001
        kind = str(detail.get("type", "text"))
        old_parent = detail.get("old_parent_id")
        parent = None
        if old_parent:
            new_parent_id = id_map.get(int(old_parent), int(old_parent))
            parent = guild.get_channel(new_parent_id) if hasattr(guild, "get_channel") else None

        kwargs: dict[str, Any] = {
            "name": str(detail["name"])[:100],
            "reason": reason,
        }
        if parent is not None:
            kwargs["category"] = parent
        self.selfguard.register(guild.id, "channel_create")

        if kind in {"text", "news"}:
            if detail.get("topic"):
                kwargs["topic"] = str(detail["topic"])[:1024]
            if detail.get("slowmode_delay"):
                kwargs["slowmode_delay"] = int(detail["slowmode_delay"])
            if detail.get("nsfw") is not None:
                kwargs["nsfw"] = bool(detail["nsfw"])
            channel = await call_with_retry(
                lambda: guild.create_text_channel(**kwargs), description="create text channel"
            )
        elif kind == "voice":
            if detail.get("bitrate"):
                kwargs["bitrate"] = int(detail["bitrate"])
            if detail.get("user_limit"):
                kwargs["user_limit"] = int(detail["user_limit"])
            channel = await call_with_retry(
                lambda: guild.create_voice_channel(**kwargs), description="create voice channel"
            )
        elif kind == "stage_voice":
            channel = await call_with_retry(
                lambda: guild.create_stage_channel(**kwargs), description="create stage channel"
            )
        elif kind == "forum":
            if detail.get("topic"):
                kwargs["topic"] = str(detail["topic"])[:4096]
            channel = await call_with_retry(
                lambda: guild.create_forum(**kwargs), description="create forum channel"
            )
        else:
            raise ValueError(f"channel type '{kind}' is not restorable")
        return channel, (int(channel.id) if channel is not None else None)

    async def _restore_setting(self, guild, detail: dict[str, Any], reason: str) -> bool:  # noqa: ANN001
        import discord

        field = str(detail["field"])
        value = detail["value"]
        if field == "name":
            if str(getattr(guild, "name", "")) == str(value):
                return False
            self.selfguard.register(guild.id, "guild_update")
            await call_with_retry(
                lambda: guild.edit(name=str(value)[:100], reason=reason),
                description="restore guild name",
            )
            return True
        enum_map = {
            "verification_level": discord.VerificationLevel,
            "explicit_content_filter": discord.ContentFilter,
            "default_notifications": discord.NotificationLevel,
        }
        enum_cls = enum_map.get(field)
        if enum_cls is None:
            raise ValueError(f"setting '{field}' is not restorable")
        target = getattr(enum_cls, str(value), None)
        if target is None:
            raise ValueError(f"unknown {field} value {value!r}")
        if getattr(guild, field, None) == target:
            return False
        self.selfguard.register(guild.id, "guild_update")
        await call_with_retry(
            lambda: guild.edit(**{field: target}, reason=reason),
            description=f"restore {field}",
        )
        return True

    async def _apply_overwrites(  # noqa: ANN202
        self,
        guild,  # noqa: ANN001
        channel,  # noqa: ANN001
        overwrites: list[dict[str, Any]],
        id_map: dict[int, int],
        reason: str,
    ):
        import discord

        if channel is None:
            return 0, ["channel object unavailable"]
        mapping: dict[Any, Any] = {}
        problems: list[str] = []
        for entry in overwrites:
            old_id = int(entry.get("target_id", 0) or 0)
            new_id = id_map.get(old_id, old_id)
            target = None
            if entry.get("target_type") == "role":
                target = guild.get_role(new_id) if hasattr(guild, "get_role") else None
            else:
                target = guild.get_member(new_id) if hasattr(guild, "get_member") else None
            if target is None:
                problems.append(
                    f"target {entry.get('target_name') or old_id} "
                    f"({entry.get('target_type')}) no longer exists; overwrite skipped"
                )
                continue
            mapping[target] = discord.PermissionOverwrite.from_pair(
                discord.Permissions(int(entry.get("allow", 0) or 0)),
                discord.Permissions(int(entry.get("deny", 0) or 0)),
            )
        if not mapping:
            return 0, problems
        self.selfguard.register(guild.id, "channel_update", int(getattr(channel, "id", 0) or 0))
        try:
            await call_with_retry(
                lambda: channel.edit(overwrites=mapping, reason=reason),
                description="apply overwrites",
            )
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{type(exc).__name__}: {exc}")
            return 0, problems
        return len(mapping), problems


_ORDER = {
    "create_role": 0,
    "create_category": 1,
    "create_channel": 2,
    "restore_setting": 3,
}
