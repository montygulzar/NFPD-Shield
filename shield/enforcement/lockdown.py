"""Protective modes: guild lockdown and raid mode.

Both are **reversible and state-recording**: the previous verification level,
invite state and per-channel slowmode values are written to
``guild_settings.lockdown_state`` / ``raid_mode_state`` before anything is
changed, so ``/shield lockdown disable`` restores exactly what was there.

What these modes deliberately do NOT do:

* They never ban, kick or mass-remove members.
* They never delete anything.
* They never touch the guild owner or role hierarchy.

Discord capability notes:

* ``verification_level`` is editable with Manage Guild.
* Pausing invites (``invites_disabled``) requires Manage Guild and is only
  available on API v10 era libraries; Shield feature-detects it and reports
  honestly when it is unavailable.
* Slowmode applies to text channels only, and a thread inherits its parent's
  rate limit rather than exposing its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from shield.enforcement.ratelimit import RateLimiter, call_with_retry
from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS

log = get_logger("lockdown")

#: Upper bound on channels touched by one lockdown/raid-mode transition.
MAX_CHANNELS_TOUCHED = 50


@dataclass(slots=True)
class ProtectiveResult:
    """Exactly what was changed, what failed, and what is not supported."""

    applied: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    previous_state: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return bool(self.applied) and not self.failed

    def summary(self) -> str:
        parts = []
        if self.applied:
            parts.append("applied: " + ", ".join(self.applied))
        if self.failed:
            parts.append("FAILED: " + ", ".join(self.failed))
        if self.unsupported:
            parts.append("unsupported: " + ", ".join(self.unsupported))
        return "; ".join(parts) or "nothing to do"

    def as_dict(self) -> dict[str, Any]:
        return {
            "applied": self.applied,
            "failed": self.failed,
            "unsupported": self.unsupported,
            "previous_state": self.previous_state,
        }


class LockdownManager:
    """Applies and reverts protective modes for a guild."""

    def __init__(self, *, limiter: RateLimiter, selfguard=None) -> None:  # noqa: ANN001
        self.limiter = limiter
        self.selfguard = selfguard

    # -- lockdown ------------------------------------------------------
    async def enable_lockdown(
        self,
        guild,  # noqa: ANN001
        *,
        reason: str,
        slowmode_seconds: int = 30,
        raise_verification: bool = True,
        pause_invites: bool = True,
        correlation_id: str | None = None,
    ) -> ProtectiveResult:
        result = ProtectiveResult()
        perms = getattr(getattr(guild, "me", None), "guild_permissions", None)
        can_manage_guild = bool(
            getattr(perms, "manage_guild", False) or getattr(perms, "administrator", False)
        )
        can_manage_channels = bool(
            getattr(perms, "manage_channels", False) or getattr(perms, "administrator", False)
        )
        audit_reason = f"NFPD Shield lockdown: {reason}"[:400]

        if raise_verification:
            if can_manage_guild:
                await self._set_verification(guild, result, audit_reason, highest=True)
            else:
                result.unsupported.append("verification_level (missing Manage Guild)")

        if pause_invites:
            if can_manage_guild:
                await self._set_invites(guild, result, audit_reason, disabled=True)
            else:
                result.unsupported.append("invites_disabled (missing Manage Guild)")

        if slowmode_seconds > 0:
            if can_manage_channels:
                await self._apply_slowmode(guild, result, audit_reason, slowmode_seconds)
            else:
                result.unsupported.append("slowmode (missing Manage Channels)")

        METRICS.incr("lockdown_enabled_total")
        log.warning(
            "lockdown applied",
            extra={
                "guild_id": guild.id,
                "correlation_id": correlation_id,
                "result": result.summary(),
            },
        )
        return result

    async def disable_lockdown(
        self,
        guild,  # noqa: ANN001
        previous_state: dict[str, Any] | None,
        *,
        reason: str = "lockdown lifted",
        correlation_id: str | None = None,
    ) -> ProtectiveResult:
        """Restore the state captured when lockdown was enabled."""
        result = ProtectiveResult()
        state = previous_state or {}
        audit_reason = f"NFPD Shield: {reason}"[:400]

        if "verification_level" in state:
            await self._restore_verification(guild, result, audit_reason, state["verification_level"])
        if "invites_disabled" in state:
            await self._set_invites(
                guild, result, audit_reason, disabled=bool(state["invites_disabled"]), restoring=True
            )
        channel_state = state.get("channels") or {}
        restored = 0
        for raw_id, previous in list(channel_state.items())[:MAX_CHANNELS_TOUCHED]:
            channel = guild.get_channel(int(raw_id)) if hasattr(guild, "get_channel") else None
            if channel is None:
                result.failed.append(f"channel {raw_id} no longer exists")
                continue
            try:
                self._register_self(guild.id, "channel_update", int(raw_id))
                await call_with_retry(
                    lambda c=channel, v=previous: c.edit(slowmode_delay=int(v), reason=audit_reason),
                    description="restore slowmode",
                )
                restored += 1
            except Exception as exc:  # noqa: BLE001
                result.failed.append(f"slowmode on {raw_id}: {type(exc).__name__}")
        if restored:
            result.applied.append(f"restored slowmode on {restored} channel(s)")

        METRICS.incr("lockdown_disabled_total")
        log.warning(
            "lockdown lifted",
            extra={
                "guild_id": guild.id,
                "correlation_id": correlation_id,
                "result": result.summary(),
            },
        )
        return result

    # -- raid mode -----------------------------------------------------
    async def enable_raid_mode(
        self,
        guild,  # noqa: ANN001
        *,
        reason: str,
        minutes: int = 30,
        slowmode_seconds: int = 30,
        raise_verification: bool = True,
        correlation_id: str | None = None,
    ) -> tuple[ProtectiveResult, datetime]:
        """Tighten verification + slowmode for a bounded period.

        Never bans or kicks recent joiners: a join flood is not proof that any
        individual joiner is malicious.
        """
        result = ProtectiveResult()
        perms = getattr(getattr(guild, "me", None), "guild_permissions", None)
        audit_reason = f"NFPD Shield raid mode: {reason}"[:400]
        if raise_verification:
            if getattr(perms, "manage_guild", False) or getattr(perms, "administrator", False):
                await self._set_verification(guild, result, audit_reason, highest=False)
            else:
                result.unsupported.append("verification_level (missing Manage Guild)")
        if slowmode_seconds > 0:
            if getattr(perms, "manage_channels", False) or getattr(perms, "administrator", False):
                await self._apply_slowmode(guild, result, audit_reason, slowmode_seconds)
            else:
                result.unsupported.append("slowmode (missing Manage Channels)")
        until = datetime.now(tz=timezone.utc) + timedelta(minutes=max(1, minutes))
        METRICS.incr("raid_mode_enabled_total")
        log.warning(
            "raid mode enabled",
            extra={
                "guild_id": guild.id,
                "until": until.isoformat(),
                "correlation_id": correlation_id,
                "result": result.summary(),
            },
        )
        return result, until

    async def disable_raid_mode(
        self,
        guild,  # noqa: ANN001
        previous_state: dict[str, Any] | None,
        *,
        correlation_id: str | None = None,
    ) -> ProtectiveResult:
        return await self.disable_lockdown(
            guild, previous_state, reason="raid mode expired", correlation_id=correlation_id
        )

    # -- primitives ----------------------------------------------------
    async def _set_verification(
        self,
        guild,  # noqa: ANN001
        result: ProtectiveResult,
        audit_reason: str,
        *,
        highest: bool,
    ) -> None:
        import discord

        current = getattr(guild, "verification_level", None)
        target = discord.VerificationLevel.highest if highest else discord.VerificationLevel.high
        if current is not None:
            result.previous_state["verification_level"] = getattr(current, "name", str(current))
        if current is not None and current == target:
            result.applied.append(f"verification level already {target.name}")
            return
        try:
            self._register_self(guild.id, "guild_update")
            await call_with_retry(
                lambda: guild.edit(verification_level=target, reason=audit_reason),
                description="raise verification level",
            )
            result.applied.append(f"verification level -> {target.name}")
        except Exception as exc:  # noqa: BLE001
            result.failed.append(f"verification level: {type(exc).__name__}: {exc}")

    async def _restore_verification(
        self,
        guild,  # noqa: ANN001
        result: ProtectiveResult,
        audit_reason: str,
        level_name: Any,
    ) -> None:
        import discord

        target = getattr(discord.VerificationLevel, str(level_name), None)
        if target is None:
            result.failed.append(f"unknown verification level {level_name!r}")
            return
        try:
            self._register_self(guild.id, "guild_update")
            await call_with_retry(
                lambda: guild.edit(verification_level=target, reason=audit_reason),
                description="restore verification level",
            )
            result.applied.append(f"verification level -> {level_name}")
        except Exception as exc:  # noqa: BLE001
            result.failed.append(f"verification level: {type(exc).__name__}: {exc}")

    async def _set_invites(
        self,
        guild,  # noqa: ANN001
        result: ProtectiveResult,
        audit_reason: str,
        *,
        disabled: bool,
        restoring: bool = False,
    ) -> None:
        features = set(getattr(guild, "features", ()) or ())
        if not restoring:
            result.previous_state["invites_disabled"] = "INVITES_DISABLED" in features
        try:
            self._register_self(guild.id, "guild_update")
            await call_with_retry(
                lambda: guild.edit(invites_disabled=disabled, reason=audit_reason),
                description="toggle invites",
            )
            result.applied.append(f"invites_disabled={disabled}")
        except TypeError:
            result.unsupported.append(
                "invites_disabled (not supported by this discord.py version)"
            )
        except Exception as exc:  # noqa: BLE001
            result.failed.append(f"invites_disabled: {type(exc).__name__}: {exc}")

    async def _apply_slowmode(
        self,
        guild,  # noqa: ANN001
        result: ProtectiveResult,
        audit_reason: str,
        seconds: int,
    ) -> None:
        channels = [
            c
            for c in getattr(guild, "text_channels", []) or []
            if hasattr(c, "edit") and hasattr(c, "slowmode_delay")
        ][:MAX_CHANNELS_TOUCHED]
        previous: dict[str, int] = {}
        changed = 0
        for channel in channels:
            current = int(getattr(channel, "slowmode_delay", 0) or 0)
            if current >= seconds:
                continue
            previous[str(channel.id)] = current
            try:
                self._register_self(guild.id, "channel_update", int(channel.id))
                await call_with_retry(
                    lambda c=channel: c.edit(slowmode_delay=seconds, reason=audit_reason),
                    description="apply slowmode",
                )
                changed += 1
            except Exception as exc:  # noqa: BLE001
                result.failed.append(f"slowmode on {channel.id}: {type(exc).__name__}")
        if previous:
            result.previous_state.setdefault("channels", {}).update(previous)
        if changed:
            result.applied.append(f"slowmode {seconds}s on {changed} channel(s)")
        elif not result.failed:
            result.applied.append("slowmode already at or above target")

    def _register_self(self, guild_id: int, kind: str, object_id: int | None = None) -> None:
        if self.selfguard is not None:
            self.selfguard.register(guild_id, kind, object_id)
