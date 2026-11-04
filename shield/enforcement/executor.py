"""Idempotent execution of enforcement responses.

Guarantees provided here:

* **Idempotency.** Every step claims a unique ``idempotency_key`` in
  ``enforcement_actions`` before touching Discord. A replayed decision (retry,
  duplicate event, process restart) finds the claim taken and does nothing.
* **Before/after state.** Each step records what it saw and what it changed, so
  a false positive can be reversed by hand from the incident record.
* **Honesty.** When containment is impossible (hierarchy, permissions, owner),
  the step is recorded as ``SKIPPED``/``PARTIAL`` with the exact reason and the
  caller is told ``residual_risk=True``. Shield never reports success it did not
  achieve.
* **Minimal collateral damage.** Role stripping removes only dangerous,
  reachable roles; message policies delete a bounded number of messages and
  prefer timeouts over role changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from shield.constants import (
    MAX_SPAM_DELETE,
    EnforcementStatus,
    ResponseAction,
)
from shield.db.repositories import UnitOfWork
from shield.enforcement.lockdown import LockdownManager
from shield.enforcement.ratelimit import RateLimiter, call_with_retry
from shield.enforcement.safety import (
    MemberView,
    permissions_set,
    plan_role_strip,
    role_views_from_member,
)
from shield.enforcement.selfguard import SelfActionGuard
from shield.events.normalize import NormalizedEvent
from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS
from shield.policies.engine import Decision, PolicyView

log = get_logger("enforcement")


@dataclass(slots=True)
class Step:
    action_type: str
    status: EnforcementStatus
    detail: str
    target_id: int | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action_type,
            "status": self.status.value,
            "detail": self.detail,
            "target_id": self.target_id,
            "error": self.error,
        }


@dataclass(slots=True)
class ExecutionReport:
    status: EnforcementStatus
    steps: list[Step] = field(default_factory=list)
    residual_risk: bool = False
    recommend_lockdown: bool = False
    summary: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "residual_risk": self.residual_risk,
            "recommend_lockdown": self.recommend_lockdown,
            "summary": self.summary,
            "steps": [s.as_dict() for s in self.steps],
        }


class ResponseExecutor:
    """Turns a :class:`Decision` into bounded, recorded Discord side effects."""

    def __init__(
        self,
        *,
        db,  # noqa: ANN001 - shield.db.session.Database
        limiter: RateLimiter,
        selfguard: SelfActionGuard,
        lockdown: LockdownManager,
        global_dry_run: bool = False,
    ) -> None:
        self.db = db
        self.limiter = limiter
        self.selfguard = selfguard
        self.lockdown = lockdown
        self.global_dry_run = global_dry_run

    async def execute(
        self,
        *,
        guild,  # noqa: ANN001
        event: NormalizedEvent,
        decision: Decision,
        policy: PolicyView,
        incident_id: int | None,
    ) -> ExecutionReport:
        """Run the decision's response. Safe to call twice with the same inputs."""
        if not decision.enforce or self.global_dry_run:
            return ExecutionReport(
                status=EnforcementStatus.DRY_RUN,
                summary=(
                    "no Discord write performed "
                    f"(would have done: {decision.response.value})"
                ),
            )

        if not self.limiter.allow("enforce", guild.id):
            report = ExecutionReport(
                status=EnforcementStatus.SKIPPED,
                summary=(
                    "enforcement budget exhausted for this guild; suppressing further "
                    "automated writes to avoid a loop. Escalating to an alert."
                ),
                residual_risk=True,
                recommend_lockdown=True,
            )
            await self._record_step(
                guild.id,
                incident_id,
                Step("rate_limited", EnforcementStatus.SKIPPED, report.summary),
                event,
            )
            return report

        handlers = {
            ResponseAction.ALERT_ONLY: self._alert_only,
            ResponseAction.STRIP_DANGEROUS_ROLES: self._strip_roles,
            ResponseAction.TIMEOUT: self._timeout_member,
            ResponseAction.DELETE_MESSAGES: self._delete_messages,
            ResponseAction.LOCKDOWN: self._lockdown,
            ResponseAction.RAID_MODE: self._raid_mode,
        }
        handler = handlers.get(decision.response, self._alert_only)
        try:
            report = await handler(
                guild=guild, event=event, decision=decision, policy=policy, incident_id=incident_id
            )
        except Exception as exc:  # noqa: BLE001 - never let enforcement kill the loop
            METRICS.incr("enforcement_errors_total", action=decision.response.value)
            log.exception(
                "enforcement failed",
                extra={"guild_id": guild.id, "correlation_id": event.correlation_id},
            )
            report = ExecutionReport(
                status=EnforcementStatus.FAILED,
                residual_risk=True,
                recommend_lockdown=True,
                summary=f"enforcement raised {type(exc).__name__}: {exc}",
            )
            await self._record_step(
                guild.id,
                incident_id,
                Step(
                    decision.response.value,
                    EnforcementStatus.FAILED,
                    "unhandled exception",
                    error=f"{type(exc).__name__}: {exc}",
                ),
                event,
            )
        METRICS.incr(
            "enforcement_total", action=decision.response.value, status=report.status.value
        )
        return report

    # -- handlers ------------------------------------------------------
    async def _alert_only(self, **kw: Any) -> ExecutionReport:
        event: NormalizedEvent = kw["event"]
        guild = kw["guild"]
        step = Step(
            "alert_only",
            EnforcementStatus.SKIPPED,
            "policy response is alert-only; no Discord write performed",
        )
        await self._record_step(guild.id, kw["incident_id"], step, event)
        return ExecutionReport(status=EnforcementStatus.SKIPPED, steps=[step], summary=step.detail)

    async def _strip_roles(self, **kw: Any) -> ExecutionReport:
        guild = kw["guild"]
        event: NormalizedEvent = kw["event"]
        incident_id = kw["incident_id"]

        member = await self._resolve_member(guild, event.actor_id)
        if member is None:
            step = Step(
                "strip_dangerous_roles",
                EnforcementStatus.SKIPPED,
                "actor is no longer a member of the guild (or could not be fetched)",
                target_id=event.actor_id,
            )
            await self._record_step(guild.id, incident_id, step, event)
            return ExecutionReport(
                status=EnforcementStatus.SKIPPED,
                steps=[step],
                residual_risk=False,
                summary=step.detail,
            )

        me = getattr(guild, "me", None)
        bot_top = int(getattr(getattr(me, "top_role", None), "position", 0) or 0)
        bot_perms = permissions_set(getattr(me, "guild_permissions", None))
        view: MemberView = role_views_from_member(member, guild.id)
        plan = plan_role_strip(
            actor=view,
            bot_top_position=bot_top,
            guild_owner_id=getattr(guild, "owner_id", None),
            bot_user_id=getattr(me, "id", None),
            guild_id=guild.id,
        )

        if "administrator" not in bot_perms and "manage_roles" not in bot_perms:
            step = Step(
                "strip_dangerous_roles",
                EnforcementStatus.SKIPPED,
                "Shield lacks Manage Roles; containment NOT achieved",
                target_id=member.id,
                before=plan.as_dict(),
            )
            await self._record_step(guild.id, incident_id, step, event)
            return ExecutionReport(
                status=EnforcementStatus.SKIPPED,
                steps=[step],
                residual_risk=True,
                recommend_lockdown=True,
                summary=step.detail,
            )

        if not plan.removable:
            status = (
                EnforcementStatus.SKIPPED if not plan.residual_risk else EnforcementStatus.FAILED
            )
            step = Step(
                "strip_dangerous_roles",
                status,
                plan.reason,
                target_id=member.id,
                before=plan.as_dict(),
            )
            await self._record_step(guild.id, incident_id, step, event)
            return ExecutionReport(
                status=status,
                steps=[step],
                residual_risk=plan.residual_risk,
                recommend_lockdown=plan.residual_risk,
                summary=plan.reason,
            )

        key = f"{guild.id}:{incident_id}:strip:{member.id}"
        claimed, record_id = await self._claim(
            guild.id,
            incident_id,
            key,
            "strip_dangerous_roles",
            target_id=member.id,
            before_state=plan.as_dict(),
        )
        if not claimed:
            step = Step(
                "strip_dangerous_roles",
                EnforcementStatus.SKIPPED,
                "already executed for this incident (idempotency guard)",
                target_id=member.id,
            )
            return ExecutionReport(
                status=EnforcementStatus.SKIPPED, steps=[step], summary=step.detail
            )

        role_objects = [
            r for r in getattr(member, "roles", ()) if int(r.id) in set(plan.removable_ids)
        ]
        reason = f"NFPD Shield: {event.action_key.value} ({event.correlation_id})"[:400]
        self.selfguard.register(guild.id, "member_role_update", int(member.id))
        try:
            await call_with_retry(
                lambda: member.remove_roles(*role_objects, reason=reason),
                description="remove dangerous roles",
            )
        except Exception as exc:  # noqa: BLE001
            await self._finish(
                record_id,
                guild.id,
                EnforcementStatus.FAILED,
                error=f"{type(exc).__name__}: {exc}",
            )
            step = Step(
                "strip_dangerous_roles",
                EnforcementStatus.FAILED,
                "Discord rejected the role removal",
                target_id=member.id,
                error=f"{type(exc).__name__}: {exc}",
            )
            return ExecutionReport(
                status=EnforcementStatus.FAILED,
                steps=[step],
                residual_risk=True,
                recommend_lockdown=True,
                summary=step.detail,
            )

        after = {
            "removed": [{"id": r.id, "name": r.name} for r in plan.removable],
            "preserved": [{"id": r.id, "name": r.name} for r in plan.preserved_safe],
            "blocked": plan.as_dict()["blocked"],
        }
        status = EnforcementStatus.PARTIAL if plan.residual_risk else EnforcementStatus.SUCCEEDED
        await self._finish(record_id, guild.id, status, after_state=after, detail=plan.reason)
        step = Step(
            "strip_dangerous_roles",
            status,
            plan.reason,
            target_id=member.id,
            before=plan.as_dict(),
            after=after,
        )
        return ExecutionReport(
            status=status,
            steps=[step],
            residual_risk=plan.residual_risk,
            recommend_lockdown=plan.residual_risk,
            summary=plan.reason,
        )

    async def _timeout_member(self, **kw: Any) -> ExecutionReport:
        guild = kw["guild"]
        event: NormalizedEvent = kw["event"]
        policy: PolicyView = kw["policy"]
        incident_id = kw["incident_id"]
        steps: list[Step] = []

        options = policy.options or {}
        seconds = int(options.get("timeout_seconds", 600))
        seconds = max(10, min(seconds, 28 * 24 * 3600 - 60))  # Discord caps at 28 days

        member = await self._resolve_member(guild, event.actor_id)
        if member is None:
            step = Step(
                "timeout",
                EnforcementStatus.SKIPPED,
                "member left the guild before the timeout could be applied",
                target_id=event.actor_id,
            )
            await self._record_step(guild.id, incident_id, step, event)
            return ExecutionReport(EnforcementStatus.SKIPPED, [step], summary=step.detail)

        me = getattr(guild, "me", None)
        bot_perms = permissions_set(getattr(me, "guild_permissions", None))
        if "administrator" not in bot_perms and "moderate_members" not in bot_perms:
            step = Step(
                "timeout",
                EnforcementStatus.SKIPPED,
                "Shield lacks Moderate Members (Timeout) permission",
                target_id=member.id,
            )
            await self._record_step(guild.id, incident_id, step, event)
            return ExecutionReport(
                EnforcementStatus.SKIPPED, [step], residual_risk=True, summary=step.detail
            )
        if int(getattr(member, "id", 0)) == int(getattr(guild, "owner_id", 0) or 0):
            step = Step(
                "timeout",
                EnforcementStatus.SKIPPED,
                "target is the guild owner; Shield never sanctions the owner",
                target_id=member.id,
            )
            await self._record_step(guild.id, incident_id, step, event)
            return ExecutionReport(EnforcementStatus.SKIPPED, [step], summary=step.detail)
        member_top = int(getattr(getattr(member, "top_role", None), "position", 0) or 0)
        bot_top = int(getattr(getattr(me, "top_role", None), "position", 0) or 0)
        if member_top >= bot_top:
            step = Step(
                "timeout",
                EnforcementStatus.SKIPPED,
                f"target's highest role ({member_top}) is at or above Shield's ({bot_top})",
                target_id=member.id,
            )
            await self._record_step(guild.id, incident_id, step, event)
            return ExecutionReport(
                EnforcementStatus.SKIPPED,
                [step],
                residual_risk=True,
                recommend_lockdown=True,
                summary=step.detail,
            )

        key = f"{guild.id}:{incident_id}:timeout:{member.id}"
        claimed, record_id = await self._claim(
            guild.id,
            incident_id,
            key,
            "timeout",
            target_id=member.id,
            before_state={
                "timed_out_until": _iso(getattr(member, "timed_out_until", None)),
            },
        )
        if not claimed:
            step = Step(
                "timeout",
                EnforcementStatus.SKIPPED,
                "already executed for this incident (idempotency guard)",
                target_id=member.id,
            )
            return ExecutionReport(EnforcementStatus.SKIPPED, [step], summary=step.detail)

        until = datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)
        reason = f"NFPD Shield: {event.action_key.value} ({event.correlation_id})"[:400]
        self.selfguard.register(guild.id, "member_update", int(member.id))
        try:
            await call_with_retry(
                lambda: member.timeout(until, reason=reason), description="timeout member"
            )
            await self._finish(
                record_id,
                guild.id,
                EnforcementStatus.SUCCEEDED,
                after_state={"timed_out_until": until.isoformat()},
                detail=f"timed out for {seconds}s",
            )
            steps.append(
                Step(
                    "timeout",
                    EnforcementStatus.SUCCEEDED,
                    f"timed out for {seconds}s (until {until.isoformat()})",
                    target_id=member.id,
                    after={"timed_out_until": until.isoformat()},
                )
            )
        except Exception as exc:  # noqa: BLE001
            await self._finish(
                record_id, guild.id, EnforcementStatus.FAILED, error=f"{type(exc).__name__}: {exc}"
            )
            steps.append(
                Step(
                    "timeout",
                    EnforcementStatus.FAILED,
                    "Discord rejected the timeout",
                    target_id=member.id,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

        if (policy.options or {}).get("delete_messages", False):
            cleanup = await self._delete_messages(
                guild=guild,
                event=event,
                decision=kw["decision"],
                policy=policy,
                incident_id=incident_id,
            )
            steps.extend(cleanup.steps)

        status = (
            EnforcementStatus.SUCCEEDED
            if any(s.status is EnforcementStatus.SUCCEEDED for s in steps)
            else EnforcementStatus.FAILED
        )
        if any(s.status is EnforcementStatus.FAILED for s in steps) and (
            status is EnforcementStatus.SUCCEEDED
        ):
            status = EnforcementStatus.PARTIAL
        return ExecutionReport(
            status=status,
            steps=steps,
            residual_risk=status is not EnforcementStatus.SUCCEEDED,
            summary="; ".join(s.detail for s in steps),
        )

    async def _delete_messages(self, **kw: Any) -> ExecutionReport:
        guild = kw["guild"]
        event: NormalizedEvent = kw["event"]
        policy: PolicyView = kw["policy"]
        incident_id = kw["incident_id"]
        options = policy.options or {}
        limit = max(1, min(int(options.get("max_delete", MAX_SPAM_DELETE)), MAX_SPAM_DELETE))

        channel = None
        if event.channel_id and hasattr(guild, "get_channel"):
            channel = guild.get_channel(int(event.channel_id))
        if channel is None or not hasattr(channel, "purge"):
            step = Step(
                "delete_messages",
                EnforcementStatus.SKIPPED,
                "origin channel is unavailable or does not support bulk deletion",
                target_id=event.channel_id,
            )
            await self._record_step(guild.id, incident_id, step, event)
            return ExecutionReport(EnforcementStatus.SKIPPED, [step], summary=step.detail)

        me = getattr(guild, "me", None)
        perms = getattr(channel, "permissions_for", None)
        channel_perms = permissions_set(perms(me)) if callable(perms) and me else frozenset()
        if "administrator" not in channel_perms and "manage_messages" not in channel_perms:
            step = Step(
                "delete_messages",
                EnforcementStatus.SKIPPED,
                "Shield lacks Manage Messages in the origin channel",
                target_id=int(channel.id),
            )
            await self._record_step(guild.id, incident_id, step, event)
            return ExecutionReport(EnforcementStatus.SKIPPED, [step], summary=step.detail)

        key = f"{guild.id}:{incident_id}:purge:{channel.id}"
        claimed, record_id = await self._claim(
            guild.id, incident_id, key, "delete_messages", target_id=int(channel.id)
        )
        if not claimed:
            step = Step(
                "delete_messages",
                EnforcementStatus.SKIPPED,
                "already executed for this incident (idempotency guard)",
                target_id=int(channel.id),
            )
            return ExecutionReport(EnforcementStatus.SKIPPED, [step], summary=step.detail)

        actor_id = event.actor_id
        after = datetime.now(tz=timezone.utc) - timedelta(
            seconds=max(policy.window_seconds * 3, 60)
        )
        reason = f"NFPD Shield: {event.action_key.value} cleanup ({event.correlation_id})"[:400]
        self.selfguard.register(guild.id, "message_bulk_delete", int(channel.id))
        try:
            deleted = await call_with_retry(
                lambda: channel.purge(
                    limit=limit,
                    check=lambda m: actor_id is not None
                    and int(getattr(getattr(m, "author", None), "id", 0) or 0) == int(actor_id),
                    after=after,
                    reason=reason,
                ),
                description="purge spam messages",
            )
            count = len(deleted or [])
            await self._finish(
                record_id,
                guild.id,
                EnforcementStatus.SUCCEEDED,
                after_state={"deleted": count, "limit": limit},
                detail=f"deleted {count} message(s)",
            )
            step = Step(
                "delete_messages",
                EnforcementStatus.SUCCEEDED,
                f"deleted {count} of at most {limit} recent message(s) from the actor",
                target_id=int(channel.id),
                after={"deleted": count},
            )
            return ExecutionReport(EnforcementStatus.SUCCEEDED, [step], summary=step.detail)
        except Exception as exc:  # noqa: BLE001
            await self._finish(
                record_id, guild.id, EnforcementStatus.FAILED, error=f"{type(exc).__name__}: {exc}"
            )
            step = Step(
                "delete_messages",
                EnforcementStatus.FAILED,
                "bulk deletion failed",
                target_id=int(channel.id),
                error=f"{type(exc).__name__}: {exc}",
            )
            return ExecutionReport(
                EnforcementStatus.FAILED, [step], residual_risk=True, summary=step.detail
            )

    async def _lockdown(self, **kw: Any) -> ExecutionReport:
        guild = kw["guild"]
        event: NormalizedEvent = kw["event"]
        incident_id = kw["incident_id"]
        key = f"{guild.id}:{incident_id}:lockdown"
        claimed, record_id = await self._claim(guild.id, incident_id, key, "lockdown")
        if not claimed:
            step = Step(
                "lockdown",
                EnforcementStatus.SKIPPED,
                "lockdown already applied for this incident (idempotency guard)",
            )
            return ExecutionReport(EnforcementStatus.SKIPPED, [step], summary=step.detail)

        result = await self.lockdown.enable_lockdown(
            guild,
            reason=f"incident {incident_id} ({event.action_key.value})",
            correlation_id=event.correlation_id,
        )
        async with self.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.update(
                guild.id,
                lockdown_active=True,
                lockdown_reason=f"incident {incident_id}: {event.action_key.value}",
                lockdown_state=result.previous_state,
                protective_mode="lockdown",
            )
        status = (
            EnforcementStatus.SUCCEEDED
            if result.success
            else (EnforcementStatus.PARTIAL if result.applied else EnforcementStatus.FAILED)
        )
        await self._finish(
            record_id, guild.id, status, after_state=result.as_dict(), detail=result.summary()
        )
        step = Step("lockdown", status, result.summary(), after=result.as_dict())
        return ExecutionReport(
            status=status,
            steps=[step],
            residual_risk=bool(result.failed or result.unsupported),
            summary=result.summary(),
        )

    async def _raid_mode(self, **kw: Any) -> ExecutionReport:
        guild = kw["guild"]
        event: NormalizedEvent = kw["event"]
        policy: PolicyView = kw["policy"]
        incident_id = kw["incident_id"]
        options = policy.options or {}
        key = f"{guild.id}:{incident_id}:raid_mode"
        claimed, record_id = await self._claim(guild.id, incident_id, key, "raid_mode")
        if not claimed:
            step = Step(
                "raid_mode",
                EnforcementStatus.SKIPPED,
                "raid mode already enabled for this incident (idempotency guard)",
            )
            return ExecutionReport(EnforcementStatus.SKIPPED, [step], summary=step.detail)

        result, until = await self.lockdown.enable_raid_mode(
            guild,
            reason=f"join flood (incident {incident_id})",
            minutes=int(options.get("raid_mode_minutes", 30)),
            slowmode_seconds=int(options.get("slowmode_seconds", 30)),
            raise_verification=bool(options.get("raise_verification_level", True)),
            correlation_id=event.correlation_id,
        )
        async with self.db.begin() as session:
            uow = UnitOfWork(session)
            await uow.guilds.update(
                guild.id,
                raid_mode_active=True,
                raid_mode_until=until,
                raid_mode_state=result.previous_state,
                protective_mode="raid",
            )
        status = (
            EnforcementStatus.SUCCEEDED
            if result.success
            else (EnforcementStatus.PARTIAL if result.applied else EnforcementStatus.FAILED)
        )
        detail = f"{result.summary()} (until {until.isoformat()})"
        await self._finish(record_id, guild.id, status, after_state=result.as_dict(), detail=detail)
        step = Step("raid_mode", status, detail, after=result.as_dict())
        return ExecutionReport(
            status=status,
            steps=[step],
            residual_risk=bool(result.failed),
            summary=detail,
        )

    # -- helpers -------------------------------------------------------
    async def _resolve_member(self, guild, user_id: int | None):  # noqa: ANN001, ANN202
        if user_id is None:
            return None
        member = guild.get_member(int(user_id)) if hasattr(guild, "get_member") else None
        if member is not None:
            return member
        fetch = getattr(guild, "fetch_member", None)
        if fetch is None:
            return None
        try:
            return await call_with_retry(
                lambda: fetch(int(user_id)), attempts=2, description="fetch member"
            )
        except Exception:  # noqa: BLE001 - member left, or no Members intent
            return None

    async def _claim(
        self,
        guild_id: int,
        incident_id: int | None,
        key: str,
        action_type: str,
        *,
        target_id: int | None = None,
        before_state: dict[str, Any] | None = None,
    ) -> tuple[bool, int | None]:
        try:
            async with self.db.begin() as session:
                uow = UnitOfWork(session)
                record, claimed = await uow.enforcement.claim(
                    guild_id=guild_id,
                    incident_id=incident_id,
                    idempotency_key=key,
                    action_type=action_type,
                    target_id=target_id,
                    before_state=before_state,
                )
                return claimed, record.id
        except Exception:  # noqa: BLE001 - database outage must not block containment
            log.exception(
                "could not claim enforcement step; proceeding without idempotency record",
                extra={"guild_id": guild_id, "action_type": action_type},
            )
            return True, None

    async def _finish(
        self,
        record_id: int | None,
        guild_id: int,
        status: EnforcementStatus,
        *,
        after_state: dict[str, Any] | None = None,
        error: str | None = None,
        detail: str | None = None,
    ) -> None:
        if record_id is None:
            return
        try:
            async with self.db.begin() as session:
                uow = UnitOfWork(session)
                await uow.enforcement.finish(
                    record_id,
                    guild_id=guild_id,
                    status=status,
                    after_state=after_state,
                    error=error,
                    detail=detail,
                    attempts=1,
                )
        except Exception:  # noqa: BLE001
            log.exception("could not persist enforcement outcome", extra={"guild_id": guild_id})

    async def _record_step(
        self, guild_id: int, incident_id: int | None, step: Step, event: NormalizedEvent
    ) -> None:
        """Persist a step that performed no Discord write (skip/fail reasons)."""
        key = f"{guild_id}:{incident_id}:{step.action_type}:{step.target_id or 0}:noop"
        claimed, record_id = await self._claim(
            guild_id,
            incident_id,
            key,
            step.action_type,
            target_id=step.target_id,
            before_state=step.before,
        )
        if claimed:
            await self._finish(
                record_id,
                guild_id,
                step.status,
                after_state=step.after,
                error=step.error,
                detail=step.detail,
            )


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return None
