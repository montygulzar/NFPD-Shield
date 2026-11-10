"""Audit-log correlation: turning a destructive gateway event into an actor.

Why this is hard, and what Shield promises:

* Discord does **not** tell a bot who deleted a channel. The gateway event
  carries only the object. The actor lives in the audit log, which is eventually
  consistent - typically available within a second, occasionally several.
* Therefore Shield waits ``AUDIT_CORRELATION_DELAY`` seconds, then polls with
  bounded exponential backoff up to ``AUDIT_MAX_ATTEMPTS`` times.
* An entry is only accepted when its ``target`` matches the event's target and
  its ``created_at`` is inside ``AUDIT_CORRELATION_WINDOW``. That yields
  :attr:`Confidence.CONFIRMED`.
* A fresh entry of the right action type whose target cannot be matched yields
  :attr:`Confidence.LIKELY` - which never authorises a sanction.
* A stale entry, a missing entry or ``Forbidden`` yields
  :attr:`Confidence.UNKNOWN`.
* Each audit entry ID is consumed at most once per guild, so a single audit
  entry cannot be used to blame an actor for two separate gateway events.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from shield.audit.mapping import GATEWAY_ONLY, resolve_audit_actions
from shield.constants import ActionKey, Confidence
from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS

log = get_logger("audit")

#: How many consumed audit entry IDs to remember per guild.
CONSUMED_CACHE_SIZE = 2048


@dataclass(slots=True)
class Attribution:
    """Result of an attribution attempt."""

    actor_id: int | None
    confidence: Confidence
    audit_entry_id: int | None = None
    reason: str = ""
    changes: dict[str, Any] = field(default_factory=dict)
    #: True when the audit log could not be read at all (permissions/outage).
    degraded: bool = False

    @property
    def confirmed(self) -> bool:
        return self.confidence is Confidence.CONFIRMED and self.actor_id is not None


class _ConsumedEntries:
    """Bounded per-guild LRU of audit entry IDs already used."""

    def __init__(self, capacity: int = CONSUMED_CACHE_SIZE) -> None:
        self._capacity = capacity
        self._store: dict[int, OrderedDict[int, None]] = {}

    def seen(self, guild_id: int, entry_id: int) -> bool:
        return entry_id in self._store.get(guild_id, {})

    def mark(self, guild_id: int, entry_id: int) -> None:
        bucket = self._store.setdefault(guild_id, OrderedDict())
        bucket[entry_id] = None
        bucket.move_to_end(entry_id)
        while len(bucket) > self._capacity:
            bucket.popitem(last=False)

    def drop_guild(self, guild_id: int) -> None:
        self._store.pop(guild_id, None)


class AuditCorrelator:
    """Correlates gateway events with audit-log entries."""

    def __init__(
        self,
        *,
        delay: float = 1.5,
        window: float = 20.0,
        max_attempts: int = 3,
        sleeper=None,  # noqa: ANN001 - injected for tests
        clock=None,  # noqa: ANN001
    ) -> None:
        self.delay = delay
        self.window = window
        self.max_attempts = max(1, max_attempts)
        self._sleep = sleeper or asyncio.sleep
        self._now = clock or (lambda: datetime.now(tz=timezone.utc))
        self._consumed = _ConsumedEntries()
        #: Guilds where the audit log is unreadable; surfaced by /shield health.
        self.degraded_guilds: dict[int, str] = {}

    def forget_guild(self, guild_id: int) -> None:
        self._consumed.drop_guild(guild_id)
        self.degraded_guilds.pop(guild_id, None)

    async def attribute(
        self,
        guild,  # noqa: ANN001 - discord.Guild
        *,
        action_key: ActionKey,
        target_id: int | None,
        occurred_at: datetime,
        extra_target_ids: Iterable[int] = (),
        max_attempts: int | None = None,
    ) -> Attribution:
        """Find the actor behind a destructive event.

        ``max_attempts`` overrides the configured retry budget for callers that
        expect "no entry" to be the common answer.
        """
        attempts_allowed = max(1, max_attempts or self.max_attempts)
        if action_key in GATEWAY_ONLY:
            return Attribution(
                None,
                Confidence.UNKNOWN,
                reason="action is gateway-only and not present in the audit log",
            )

        actions = resolve_audit_actions(action_key)
        if not actions:
            return Attribution(
                None, Confidence.UNKNOWN, reason=f"no audit action mapped for {action_key.value}"
            )

        if not self._can_read_audit_log(guild):
            self.degraded_guilds[guild.id] = "missing View Audit Log permission"
            METRICS.incr("audit_denied_total", guild_id=guild.id)
            return Attribution(
                None,
                Confidence.UNKNOWN,
                reason=(
                    "Shield lacks the View Audit Log permission in this guild, so the "
                    "actor cannot be determined. Grant it to enable attribution."
                ),
                degraded=True,
            )

        candidate_targets = {t for t in (target_id, *extra_target_ids) if t is not None}
        await self._sleep(self.delay)

        backoff = 1.0
        best_loose: Attribution | None = None
        for attempt in range(1, attempts_allowed + 1):
            try:
                entries = await self._fetch(guild, actions)
            except Exception as exc:  # noqa: BLE001 - normalised below
                kind = type(exc).__name__
                if kind == "Forbidden":
                    self.degraded_guilds[guild.id] = "View Audit Log denied by Discord"
                    METRICS.incr("audit_denied_total", guild_id=guild.id)
                    return Attribution(
                        None,
                        Confidence.UNKNOWN,
                        reason="Discord denied the audit-log read (Forbidden)",
                        degraded=True,
                    )
                retry_after = getattr(getattr(exc, "response", None), "headers", {})
                METRICS.incr("audit_fetch_errors_total")
                log.warning(
                    "audit log fetch failed",
                    extra={
                        "guild_id": guild.id,
                        "attempt": attempt,
                        "error": f"{kind}: {exc}",
                        "retry_after": retry_after.get("Retry-After") if retry_after else None,
                    },
                )
                if attempt >= attempts_allowed:
                    return Attribution(
                        None,
                        Confidence.UNKNOWN,
                        reason=f"audit-log read failed after {attempt} attempt(s): {kind}",
                        degraded=True,
                    )
                await self._sleep(min(backoff, 8.0))
                backoff *= 2
                continue

            self.degraded_guilds.pop(guild.id, None)
            now = self._now()
            for entry in entries:
                entry_id = int(getattr(entry, "id", 0) or 0)
                if not entry_id or self._consumed.seen(guild.id, entry_id):
                    continue
                created = _aware(getattr(entry, "created_at", None))
                if created is None:
                    continue
                age = (now - created).total_seconds()
                if age > self.window or age < -5:
                    continue  # stale (or clock-skewed) entry: refuse to attribute
                user = getattr(entry, "user", None)
                actor_id = int(getattr(user, "id", 0) or 0) or None
                if actor_id is None:
                    continue
                entry_target_id = _entry_target_id(entry)
                changes = _entry_changes(entry)
                if candidate_targets and entry_target_id in candidate_targets:
                    self._consumed.mark(guild.id, entry_id)
                    METRICS.incr("audit_confirmed_total", action=action_key.value)
                    return Attribution(
                        actor_id=actor_id,
                        confidence=Confidence.CONFIRMED,
                        audit_entry_id=entry_id,
                        reason=(
                            f"audit entry {entry_id} targets {entry_target_id} "
                            f"({age:.1f}s old)"
                        ),
                        changes=changes,
                    )
                if not candidate_targets:
                    # Guild-level events (guild_update) have no discrete target.
                    self._consumed.mark(guild.id, entry_id)
                    METRICS.incr("audit_confirmed_total", action=action_key.value)
                    return Attribution(
                        actor_id=actor_id,
                        confidence=Confidence.CONFIRMED,
                        audit_entry_id=entry_id,
                        reason=f"guild-level audit entry {entry_id} ({age:.1f}s old)",
                        changes=changes,
                    )
                if best_loose is None:
                    best_loose = Attribution(
                        actor_id=actor_id,
                        confidence=Confidence.LIKELY,
                        audit_entry_id=entry_id,
                        reason=(
                            "fresh audit entry of the right type but the target did not "
                            "match; attribution is not confirmed"
                        ),
                        changes=changes,
                    )

            if attempt < attempts_allowed:
                await self._sleep(min(backoff, 8.0))
                backoff *= 2

        if best_loose is not None:
            METRICS.incr("audit_likely_total", action=action_key.value)
            return best_loose
        METRICS.incr("audit_unknown_total", action=action_key.value)
        return Attribution(
            None,
            Confidence.UNKNOWN,
            reason=(
                "no matching audit-log entry within "
                f"{self.window:.0f}s after {attempts_allowed} attempt(s); "
                "the action will be logged and alerted but nobody will be sanctioned"
            ),
        )

    # -- helpers -------------------------------------------------------
    @staticmethod
    def _can_read_audit_log(guild) -> bool:  # noqa: ANN001
        me = getattr(guild, "me", None)
        perms = getattr(me, "guild_permissions", None)
        if perms is None:
            return False
        return bool(getattr(perms, "view_audit_log", False) or getattr(perms, "administrator", False))

    async def _fetch(self, guild, actions) -> list[Any]:  # noqa: ANN001
        """Read the most recent audit entries for the given actions.

        ``limit`` is deliberately small: Shield only cares about the last few
        seconds, and a small page keeps the call cheap against Discord's
        rate limits.
        """
        collected: list[Any] = []
        for action in actions:
            async for entry in guild.audit_logs(limit=10, action=action):
                collected.append(entry)
        collected.sort(key=lambda e: int(getattr(e, "id", 0) or 0), reverse=True)
        return collected


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _entry_target_id(entry) -> int | None:  # noqa: ANN001
    target = getattr(entry, "target", None)
    target_id = getattr(target, "id", None)
    if target_id is None:
        target_id = getattr(entry, "target_id", None)
    try:
        return int(target_id) if target_id is not None else None
    except (TypeError, ValueError):
        return None


def _entry_changes(entry) -> dict[str, Any]:  # noqa: ANN001
    """Flatten ``entry.before``/``entry.after`` into a JSON-safe dict."""
    out: dict[str, Any] = {}
    for side in ("before", "after"):
        diff = getattr(entry, side, None)
        if diff is None:
            continue
        values: dict[str, Any] = {}
        for key in getattr(diff, "__slots__", ()) or ():
            try:
                value = getattr(diff, key)
            except AttributeError:
                continue
            if value is None:
                continue
            values[key] = _jsonable(value)
        if not values and hasattr(diff, "__dict__"):
            for key, value in vars(diff).items():
                if value is not None:
                    values[key] = _jsonable(value)
        if values:
            out[side] = values
    extra = getattr(entry, "extra", None)
    if extra is not None:
        out["extra"] = _jsonable(extra)
    reason = getattr(entry, "reason", None)
    if reason:
        out["reason"] = str(reason)[:400]
    return out


def _jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    # discord.Permissions and similar objects
    if hasattr(value, "value") and isinstance(value.value, int):
        return int(value.value)
    if hasattr(value, "id"):
        return {"id": int(value.id), "name": str(getattr(value, "name", ""))[:100]}
    return str(value)[:200]
