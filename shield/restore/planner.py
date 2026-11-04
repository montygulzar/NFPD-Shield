"""Restore planning: a preflight diff between a snapshot and the live guild.

Principles:

* **Additive only.** The planner never proposes deleting or renaming anything
  that exists now. If a moderator legitimately created a channel after the
  snapshot was taken, it is reported as "left untouched", not removed.
* **Honest about IDs.** Discord assigns new snowflakes to recreated objects. The
  plan therefore carries an ``id_map`` of old -> new filled in during apply, and
  the preview states plainly that old IDs are gone forever.
* **Explicit unrecoverables.** Everything Discord cannot restore is listed in
  the plan so the approver sees it before confirming.
* **Bounded.** The plan is capped at :data:`MAX_RESTORE_WRITES` operations;
  anything beyond that is reported as deferred rather than silently dropped.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from shield.constants import MAX_RESTORE_WRITES

#: Channel types Shield can recreate through the bot API.
SUPPORTED_CHANNEL_TYPES = {
    "text",
    "news",
    "voice",
    "stage_voice",
    "forum",
    "category",
}

#: Channel types that exist but cannot be recreated by a bot.
UNSUPPORTED_CHANNEL_TYPES = {
    "public_thread": "threads cannot be recreated from a snapshot (no history to attach)",
    "private_thread": "threads cannot be recreated from a snapshot",
    "news_thread": "threads cannot be recreated from a snapshot",
    "media": "media channels require guild features Shield cannot guarantee",
    "directory": "directory channels belong to Student Hubs and are not restorable",
}


@dataclass(slots=True)
class PlanItem:
    op: str
    label: str
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"op": self.op, "label": self.label, "detail": self.detail}


@dataclass(slots=True)
class RestorePlan:
    guild_id: int
    snapshot_version: int
    items: list[PlanItem] = field(default_factory=list)
    untouched: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    unrecoverable: list[str] = field(default_factory=list)
    deferred: int = 0

    @property
    def write_count(self) -> int:
        return len(self.items)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for item in self.items:
            out[item.op] = out.get(item.op, 0) + 1
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "guild_id": self.guild_id,
            "snapshot_version": self.snapshot_version,
            "write_count": self.write_count,
            "counts": self.counts(),
            "items": [i.as_dict() for i in self.items],
            "untouched": self.untouched,
            "skipped": self.skipped,
            "unrecoverable": self.unrecoverable,
            "deferred": self.deferred,
        }

    def render(self, limit: int = 20) -> str:
        """Human-readable preview for the Discord reply."""
        lines: list[str] = []
        counts = self.counts()
        if counts:
            lines.append(
                "**Planned operations:** "
                + ", ".join(f"{op} x{n}" for op, n in sorted(counts.items()))
            )
        else:
            lines.append("**Planned operations:** none - the guild already matches the snapshot.")
        for item in self.items[:limit]:
            lines.append(f"- `{item.op}` {item.label}")
        if self.write_count > limit:
            lines.append(f"- ... and {self.write_count - limit} more")
        if self.deferred:
            lines.append(
                f"**Deferred:** {self.deferred} operation(s) exceed the "
                f"{MAX_RESTORE_WRITES}-write safety cap and need a second run."
            )
        if self.untouched:
            lines.append("**Left untouched (created after the snapshot):** " + ", ".join(self.untouched[:10]))
        if self.skipped:
            lines.append("**Skipped:** " + "; ".join(self.skipped[:10]))
        if self.unrecoverable:
            lines.append("**NOT recoverable:** " + "; ".join(self.unrecoverable))
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class LiveRole:
    id: int
    name: str
    managed: bool = False
    is_default: bool = False


@dataclass(frozen=True, slots=True)
class LiveChannel:
    id: int
    name: str
    type: str
    parent_id: int | None = None


def live_state_from_guild(guild) -> tuple[list[LiveRole], list[LiveChannel]]:  # noqa: ANN001
    roles = [
        LiveRole(
            id=int(r.id),
            name=str(getattr(r, "name", "")),
            managed=bool(getattr(r, "managed", False)),
            is_default=bool(
                r.is_default() if callable(getattr(r, "is_default", None)) else False
            ),
        )
        for r in getattr(guild, "roles", []) or []
    ]
    channels: list[LiveChannel] = []
    for c in getattr(guild, "channels", []) or []:
        kind = getattr(getattr(c, "type", None), "name", None) or c.__class__.__name__.replace(
            "Channel", ""
        ).lower()
        channels.append(
            LiveChannel(
                id=int(c.id),
                name=str(getattr(c, "name", "")),
                type=str(kind),
                parent_id=int(getattr(getattr(c, "category", None), "id", 0) or 0) or None,
            )
        )
    return roles, channels


def build_plan(
    *,
    guild_id: int,
    snapshot_version: int,
    payload: dict[str, Any],
    live_roles: Iterable[LiveRole],
    live_channels: Iterable[LiveChannel],
    scope: set[str] | None = None,
    restore_overwrites: bool = True,
) -> RestorePlan:
    """Diff a snapshot payload against live state and produce an ordered plan."""
    wanted = scope or {"roles", "categories", "channels", "overwrites", "settings"}
    plan = RestorePlan(guild_id=guild_id, snapshot_version=snapshot_version)
    plan.unrecoverable = list(payload.get("not_captured", []))

    live_role_by_id = {r.id: r for r in live_roles}
    live_role_by_name = {r.name.casefold(): r for r in live_role_by_id.values()}
    live_channel_by_id = {c.id: c for c in live_channels}
    live_channel_by_key = {
        (c.name.casefold(), c.type, c.parent_id): c for c in live_channel_by_id.values()
    }

    snapshot_role_ids = {int(r["id"]) for r in payload.get("roles", []) if r.get("id")}
    snapshot_channel_ids = {
        int(c["id"])
        for c in list(payload.get("categories", [])) + list(payload.get("channels", []))
        if c.get("id")
    }

    # --- roles --------------------------------------------------------
    if "roles" in wanted:
        for role in sorted(
            payload.get("roles", []), key=lambda r: int(r.get("position", 0)), reverse=True
        ):
            name = str(role.get("name", ""))
            if role.get("is_default"):
                plan.skipped.append("@everyone is never recreated (it always exists)")
                continue
            if role.get("managed") or role.get("is_premium_subscriber"):
                plan.skipped.append(
                    f"role '{name}' is managed by an integration and cannot be recreated by a bot"
                )
                continue
            role_id = int(role.get("id", 0) or 0)
            if role_id in live_role_by_id:
                continue
            if name.casefold() in live_role_by_name:
                plan.untouched.append(f"role '{name}' already exists under a new ID")
                continue
            plan.items.append(
                PlanItem(
                    op="create_role",
                    label=f"recreate role '{name}' (permissions 0x{int(role.get('permissions', 0)):x})",
                    detail={
                        "old_id": role_id,
                        "name": name,
                        "permissions": int(role.get("permissions", 0) or 0),
                        "color": int(role.get("color", 0) or 0),
                        "hoist": bool(role.get("hoist")),
                        "mentionable": bool(role.get("mentionable")),
                        "position": int(role.get("position", 0) or 0),
                    },
                )
            )

    # --- categories ---------------------------------------------------
    if "categories" in wanted:
        for category in sorted(payload.get("categories", []), key=lambda c: int(c.get("position", 0))):
            cat_id = int(category.get("id", 0) or 0)
            name = str(category.get("name", ""))
            if cat_id in live_channel_by_id:
                continue
            if (name.casefold(), "category", None) in live_channel_by_key:
                plan.untouched.append(f"category '{name}' already exists under a new ID")
                continue
            plan.items.append(
                PlanItem(
                    op="create_category",
                    label=f"recreate category '{name}'",
                    detail={
                        "old_id": cat_id,
                        "name": name,
                        "position": int(category.get("position", 0) or 0),
                        "overwrites": category.get("overwrites", []) if restore_overwrites else [],
                    },
                )
            )

    # --- channels -----------------------------------------------------
    if "channels" in wanted:
        for channel in sorted(
            payload.get("channels", []),
            key=lambda c: (int(c.get("parent_id") or 0), int(c.get("position", 0))),
        ):
            ch_id = int(channel.get("id", 0) or 0)
            name = str(channel.get("name", ""))
            kind = str(channel.get("type", "text"))
            if ch_id in live_channel_by_id:
                continue
            if kind in UNSUPPORTED_CHANNEL_TYPES:
                plan.skipped.append(f"channel '{name}': {UNSUPPORTED_CHANNEL_TYPES[kind]}")
                continue
            if kind not in SUPPORTED_CHANNEL_TYPES:
                plan.skipped.append(
                    f"channel '{name}' has unsupported type '{kind}' and will not be recreated"
                )
                continue
            parent = int(channel.get("parent_id") or 0) or None
            if (name.casefold(), kind, parent) in live_channel_by_key:
                plan.untouched.append(f"channel '{name}' already exists under a new ID")
                continue
            plan.items.append(
                PlanItem(
                    op="create_channel",
                    label=f"recreate {kind} channel '{name}'",
                    detail={
                        "old_id": ch_id,
                        "name": name,
                        "type": kind,
                        "old_parent_id": parent,
                        "position": int(channel.get("position", 0) or 0),
                        "topic": channel.get("topic"),
                        "slowmode_delay": channel.get("slowmode_delay"),
                        "nsfw": channel.get("nsfw"),
                        "bitrate": channel.get("bitrate"),
                        "user_limit": channel.get("user_limit"),
                        "overwrites": channel.get("overwrites", []) if restore_overwrites else [],
                    },
                )
            )

    # --- guild settings -----------------------------------------------
    if "settings" in wanted:
        snap_guild = payload.get("guild", {})
        for field_name in ("verification_level", "explicit_content_filter", "default_notifications"):
            value = snap_guild.get(field_name)
            if value:
                plan.items.append(
                    PlanItem(
                        op="restore_setting",
                        label=f"set {field_name} back to {value}",
                        detail={"field": field_name, "value": value},
                    )
                )
        if snap_guild.get("name"):
            plan.items.append(
                PlanItem(
                    op="restore_setting",
                    label=f"set guild name back to '{snap_guild['name']}'",
                    detail={"field": "name", "value": snap_guild["name"]},
                )
            )

    # --- things created after the snapshot ----------------------------
    for role in live_role_by_id.values():
        if role.is_default or role.managed:
            continue
        if role.id not in snapshot_role_ids and role.name.casefold() not in {
            str(r.get("name", "")).casefold() for r in payload.get("roles", [])
        }:
            plan.untouched.append(f"role '{role.name}' is newer than the snapshot: left alone")
    for channel in live_channel_by_id.values():
        if channel.id not in snapshot_channel_ids:
            known_names = {
                str(c.get("name", "")).casefold()
                for c in list(payload.get("categories", [])) + list(payload.get("channels", []))
            }
            if channel.name.casefold() not in known_names:
                plan.untouched.append(
                    f"channel '{channel.name}' is newer than the snapshot: left alone"
                )

    if "webhooks" in (payload.get("counts") or {}) and payload["counts"].get("webhooks"):
        plan.unrecoverable.append(
            f"{payload['counts']['webhooks']} webhook(s) were recorded by name/channel only; "
            "their tokens were never stored, so each must be recreated manually and its URL "
            "re-entered in the consuming service"
        )

    if plan.write_count > MAX_RESTORE_WRITES:
        plan.deferred = plan.write_count - MAX_RESTORE_WRITES
        plan.items = plan.items[:MAX_RESTORE_WRITES]

    return plan
