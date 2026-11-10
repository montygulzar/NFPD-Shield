"""Repository layer.

Rules enforced here, deliberately in one place:

* **Every** query is scoped by ``guild_id``. There is no repository method that
  can read or mutate another guild's rows, which closes cross-guild IDOR from
  slash commands by construction.
* All SQL is parameterised through SQLAlchemy Core/ORM constructs - no string
  interpolation of user input.
* Upserts use real unique constraints (``ON CONFLICT`` on PostgreSQL, a
  select-then-insert fallback elsewhere) so duplicate gateway deliveries cannot
  create duplicate rows.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from shield.constants import (
    ActionKey,
    Confidence,
    EnforcementStatus,
    EventSource,
    IncidentStatus,
    ResponseAction,
    RestoreMode,
    RestoreStatus,
    Severity,
    ShieldMode,
    SnapshotKind,
    TrustScope,
)
from shield.db.models import (
    CommandAudit,
    CooldownRecord,
    EnforcementRecord,
    EventRecord,
    GuildPolicy,
    GuildSettings,
    Incident,
    RestoreJob,
    Snapshot,
    TrustedEntity,
    utcnow,
)
from shield.policies.defaults import DEFAULT_POLICIES


def _is_postgres(session: AsyncSession) -> bool:
    bind = session.get_bind()
    return bind.dialect.name == "postgresql"


def merge_previous_state(
    original: dict[str, Any] | None, captured: dict[str, Any] | None
) -> dict[str, Any]:
    """Combine saved pre-protection state with a newer capture; the original wins.

    When a protective mode is applied while one is already active, the "current"
    values captured are the already-tightened ones. Saving those would make
    lifting protection "restore" the raised verification level and slowmode
    forever. So anything already recorded is kept, and the new capture only
    contributes things not seen before (e.g. a channel created since).
    """
    original = dict(original or {})
    captured = dict(captured or {})
    merged = {**captured, **original}
    channels = {**(captured.get("channels") or {}), **(original.get("channels") or {})}
    if channels:
        merged["channels"] = channels
    return merged


class GuildRepository:
    """Guild settings + policy bootstrap."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, guild_id: int) -> GuildSettings | None:
        return await self.session.get(GuildSettings, guild_id)

    async def ensure(
        self,
        guild_id: int,
        *,
        guild_name: str | None = None,
        owner_id: int | None = None,
        default_mode: ShieldMode = ShieldMode.ALERT_ONLY,
        snapshot_interval_minutes: int = 360,
        snapshot_retention: int = 12,
        snapshot_include_webhooks: bool = True,
    ) -> GuildSettings:
        """Fetch-or-create the guild row and seed its default policies.

        A brand-new guild is created **disabled**, in ``alert_only`` and with
        ``dry_run=True``: Shield observes and reports but never acts until a
        guild owner explicitly enables protection.
        """
        settings = await self.session.get(GuildSettings, guild_id)
        if settings is None:
            settings = GuildSettings(
                guild_id=guild_id,
                guild_name=guild_name,
                owner_id=owner_id,
                enabled=False,
                mode=default_mode,
                dry_run=True,
                snapshot_interval_minutes=snapshot_interval_minutes,
                snapshot_retention=snapshot_retention,
                snapshot_include_webhooks=snapshot_include_webhooks,
            )
            try:
                # Savepoint: losing a creation race must not poison the
                # caller's transaction.
                async with self.session.begin_nested():
                    self.session.add(settings)
            except IntegrityError:
                # Another instance created it concurrently.
                settings = await self.session.get(GuildSettings, guild_id)
                assert settings is not None
            await self.seed_policies(guild_id)
        else:
            changed = False
            if guild_name and settings.guild_name != guild_name:
                settings.guild_name = guild_name
                changed = True
            if owner_id and settings.owner_id != owner_id:
                settings.owner_id = owner_id
                changed = True
            if changed:
                await self.session.flush()
            await self.seed_policies(guild_id)
        return settings

    async def seed_policies(self, guild_id: int) -> int:
        """Insert any missing default policy rows. Idempotent."""
        existing = set(
            (
                await self.session.execute(
                    sa.select(GuildPolicy.action_key).where(GuildPolicy.guild_id == guild_id)
                )
            )
            .scalars()
            .all()
        )
        inserted = 0
        for default in DEFAULT_POLICIES:
            if default.action_key in existing:
                continue
            self.session.add(
                GuildPolicy(
                    guild_id=guild_id,
                    action_key=default.action_key,
                    enabled=default.enabled,
                    threshold_count=default.threshold_count,
                    window_seconds=default.window_seconds,
                    cooldown_seconds=default.cooldown_seconds,
                    response=default.response,
                    severity=default.severity,
                    requires_confirmed_actor=default.requires_confirmed_actor,
                    options=dict(default.options),
                )
            )
            inserted += 1
        if inserted:
            await self.session.flush()
        return inserted

    async def update(self, guild_id: int, **fields: Any) -> GuildSettings | None:
        settings = await self.session.get(GuildSettings, guild_id)
        if settings is None:
            return None
        allowed = {c.key for c in sa.inspect(GuildSettings).column_attrs}
        for key, value in fields.items():
            if key not in allowed:
                raise ValueError(f"unknown guild setting {key!r}")
            setattr(settings, key, value)
        settings.updated_at = utcnow()
        await self.session.flush()
        return settings

    async def enter_protective_mode(
        self, guild_id: int, kind: str, captured: dict[str, Any] | None, **fields: Any
    ) -> GuildSettings | None:
        """Mark lockdown (``kind="lockdown"``) or raid mode (``"raid_mode"``) active.

        The pre-protection state is merged, not overwritten, so re-entering a
        mode that is already active keeps the true original values.
        """
        settings = await self.session.get(GuildSettings, guild_id)
        if settings is None:
            return None
        already_active = bool(getattr(settings, f"{kind}_active"))
        original = getattr(settings, f"{kind}_state") if already_active else None
        return await self.update(
            guild_id,
            **{
                f"{kind}_active": True,
                f"{kind}_state": merge_previous_state(original, captured),
                "protective_mode": "lockdown" if kind == "lockdown" else "raid",
            },
            **fields,
        )

    async def bump_policy_version(self, guild_id: int) -> int:
        settings = await self.session.get(GuildSettings, guild_id)
        if settings is None:
            return 0
        settings.policy_version += 1
        settings.updated_at = utcnow()
        await self.session.flush()
        return settings.policy_version

    async def list_enabled(self) -> Sequence[GuildSettings]:
        result = await self.session.execute(
            sa.select(GuildSettings).where(GuildSettings.enabled.is_(True))
        )
        return result.scalars().all()

    async def list_all(self) -> Sequence[GuildSettings]:
        result = await self.session.execute(sa.select(GuildSettings))
        return result.scalars().all()


class PolicyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for_guild(self, guild_id: int) -> Sequence[GuildPolicy]:
        result = await self.session.execute(
            sa.select(GuildPolicy)
            .where(GuildPolicy.guild_id == guild_id)
            .order_by(GuildPolicy.action_key)
        )
        return result.scalars().all()

    async def get(self, guild_id: int, action_key: ActionKey) -> GuildPolicy | None:
        result = await self.session.execute(
            sa.select(GuildPolicy).where(
                GuildPolicy.guild_id == guild_id, GuildPolicy.action_key == action_key
            )
        )
        return result.scalar_one_or_none()

    async def set_values(
        self,
        guild_id: int,
        action_key: ActionKey,
        *,
        updated_by: int,
        threshold_count: int | None = None,
        window_seconds: int | None = None,
        cooldown_seconds: int | None = None,
        response: ResponseAction | None = None,
        severity: Severity | None = None,
        enabled: bool | None = None,
        dry_run: bool | None = None,
        requires_confirmed_actor: bool | None = None,
        options: dict[str, Any] | None = None,
    ) -> GuildPolicy | None:
        policy = await self.get(guild_id, action_key)
        if policy is None:
            return None
        if threshold_count is not None:
            if threshold_count < 1:
                raise ValueError("threshold_count must be >= 1")
            policy.threshold_count = threshold_count
        if window_seconds is not None:
            if not (1 <= window_seconds <= 3600):
                raise ValueError("window_seconds must be between 1 and 3600")
            policy.window_seconds = window_seconds
        if cooldown_seconds is not None:
            if not (0 <= cooldown_seconds <= 86400):
                raise ValueError("cooldown_seconds must be between 0 and 86400")
            policy.cooldown_seconds = cooldown_seconds
        if response is not None:
            policy.response = response
        if severity is not None:
            policy.severity = severity
        if enabled is not None:
            policy.enabled = enabled
        if dry_run is not None:
            policy.dry_run = dry_run
        if requires_confirmed_actor is not None:
            policy.requires_confirmed_actor = requires_confirmed_actor
        if options is not None:
            merged = dict(policy.options or {})
            merged.update(options)
            policy.options = merged
        policy.updated_by = updated_by
        policy.updated_at = utcnow()
        await self.session.flush()
        return policy

    async def reset_to_defaults(self, guild_id: int, updated_by: int) -> int:
        await self.session.execute(
            sa.delete(GuildPolicy).where(GuildPolicy.guild_id == guild_id)
        )
        count = await GuildRepository(self.session).seed_policies(guild_id)
        await self.session.execute(
            sa.update(GuildPolicy)
            .where(GuildPolicy.guild_id == guild_id)
            .values(updated_by=updated_by)
        )
        return count


class TrustRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for_guild(
        self, guild_id: int, *, include_expired: bool = False
    ) -> Sequence[TrustedEntity]:
        stmt = sa.select(TrustedEntity).where(TrustedEntity.guild_id == guild_id)
        if not include_expired:
            stmt = stmt.where(
                sa.or_(
                    TrustedEntity.expires_at.is_(None),
                    TrustedEntity.expires_at > utcnow(),
                )
            )
        result = await self.session.execute(stmt.order_by(TrustedEntity.created_at))
        return result.scalars().all()

    async def add(
        self,
        guild_id: int,
        *,
        entity_type: str,
        entity_id: int,
        scopes: Iterable[TrustScope],
        added_by: int,
        reason: str | None = None,
        expires_at: datetime | None = None,
    ) -> TrustedEntity:
        if entity_type not in {"user", "role"}:
            raise ValueError("entity_type must be 'user' or 'role'")
        scope_values = sorted({s.value for s in scopes}) or [TrustScope.ALL.value]
        existing = await self.session.execute(
            sa.select(TrustedEntity).where(
                TrustedEntity.guild_id == guild_id,
                TrustedEntity.entity_type == entity_type,
                TrustedEntity.entity_id == entity_id,
            )
        )
        row = existing.scalar_one_or_none()
        if row is not None:
            row.scopes = scope_values
            row.reason = reason
            row.added_by = added_by
            row.expires_at = expires_at
            row.updated_at = utcnow()
            await self.session.flush()
            return row
        row = TrustedEntity(
            guild_id=guild_id,
            entity_type=entity_type,
            entity_id=entity_id,
            scopes=scope_values,
            reason=reason,
            added_by=added_by,
            expires_at=expires_at,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def remove(self, guild_id: int, entity_type: str, entity_id: int) -> bool:
        result = await self.session.execute(
            sa.delete(TrustedEntity).where(
                TrustedEntity.guild_id == guild_id,
                TrustedEntity.entity_type == entity_type,
                TrustedEntity.entity_id == entity_id,
            )
        )
        return bool(result.rowcount)

    async def purge_expired(self, guild_id: int | None = None) -> int:
        stmt = sa.delete(TrustedEntity).where(
            TrustedEntity.expires_at.is_not(None), TrustedEntity.expires_at <= utcnow()
        )
        if guild_id is not None:
            stmt = stmt.where(TrustedEntity.guild_id == guild_id)
        result = await self.session.execute(stmt)
        return int(result.rowcount or 0)


class EventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        *,
        guild_id: int,
        correlation_id: str,
        dedupe_key: str,
        action_key: ActionKey,
        source: EventSource,
        occurred_at: datetime,
        actor_id: int | None = None,
        actor_confidence: Confidence = Confidence.UNKNOWN,
        target_type: str | None = None,
        target_id: int | None = None,
        channel_id: int | None = None,
        audit_entry_id: int | None = None,
        payload: dict[str, Any] | None = None,
        instance_id: str | None = None,
    ) -> tuple[EventRecord | None, bool]:
        """Insert an event, collapsing duplicates on ``dedupe_key``.

        Returns ``(row, inserted)``. ``inserted=False`` means the event was a
        duplicate delivery and must not be counted again by any detector.
        """
        values = {
            "guild_id": guild_id,
            "correlation_id": correlation_id,
            "dedupe_key": dedupe_key,
            "action_key": action_key,
            "source": source,
            "actor_id": actor_id,
            "actor_confidence": actor_confidence,
            "target_type": target_type,
            "target_id": target_id,
            "channel_id": channel_id,
            "occurred_at": occurred_at,
            "audit_entry_id": audit_entry_id,
            "payload": payload or {},
            "instance_id": instance_id,
        }
        if _is_postgres(self.session):
            stmt = (
                pg_insert(EventRecord)
                .values(**values)
                .on_conflict_do_nothing(index_elements=[EventRecord.dedupe_key])
                .returning(EventRecord.id)
            )
            result = await self.session.execute(stmt)
            new_id = result.scalar_one_or_none()
            if new_id is None:
                return await self.get_by_dedupe(guild_id, dedupe_key), False
            row = await self.session.get(EventRecord, new_id)
            return row, True

        existing = await self.get_by_dedupe(guild_id, dedupe_key)
        if existing is not None:
            return existing, False
        row = EventRecord(**values)
        try:
            async with self.session.begin_nested():
                self.session.add(row)
        except IntegrityError:
            return await self.get_by_dedupe(guild_id, dedupe_key), False
        return row, True

    async def get_by_dedupe(self, guild_id: int, dedupe_key: str) -> EventRecord | None:
        result = await self.session.execute(
            sa.select(EventRecord).where(
                EventRecord.guild_id == guild_id, EventRecord.dedupe_key == dedupe_key
            )
        )
        return result.scalar_one_or_none()

    async def attach_attribution(
        self,
        event_id: int,
        *,
        guild_id: int,
        actor_id: int | None,
        confidence: Confidence,
        audit_entry_id: int | None,
    ) -> None:
        await self.session.execute(
            sa.update(EventRecord)
            .where(EventRecord.id == event_id, EventRecord.guild_id == guild_id)
            .values(
                actor_id=actor_id,
                actor_confidence=confidence,
                audit_entry_id=audit_entry_id,
            )
        )

    async def recent(
        self,
        guild_id: int,
        *,
        since: datetime,
        action_keys: Iterable[ActionKey] | None = None,
        limit: int = 5000,
    ) -> Sequence[EventRecord]:
        stmt = sa.select(EventRecord).where(
            EventRecord.guild_id == guild_id, EventRecord.occurred_at >= since
        )
        keys = list(action_keys or [])
        if keys:
            stmt = stmt.where(EventRecord.action_key.in_(keys))
        result = await self.session.execute(
            stmt.order_by(EventRecord.occurred_at).limit(limit)
        )
        return result.scalars().all()

    async def count_in_window(
        self,
        guild_id: int,
        action_key: ActionKey,
        *,
        since: datetime,
        actor_id: int | None = None,
    ) -> int:
        stmt = sa.select(sa.func.count(EventRecord.id)).where(
            EventRecord.guild_id == guild_id,
            EventRecord.action_key == action_key,
            EventRecord.occurred_at >= since,
        )
        if actor_id is not None:
            stmt = stmt.where(EventRecord.actor_id == actor_id)
        result = await self.session.execute(stmt)
        return int(result.scalar_one() or 0)

    async def prune(self, older_than_days: int) -> int:
        if older_than_days <= 0:
            return 0
        cutoff = utcnow() - timedelta(days=older_than_days)
        result = await self.session.execute(
            sa.delete(EventRecord).where(EventRecord.occurred_at < cutoff)
        )
        return int(result.rowcount or 0)


class IncidentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        guild_id: int,
        correlation_id: str,
        action_key: ActionKey,
        actor_id: int | None,
        actor_confidence: Confidence,
        severity: Severity,
        mode_at_detection: ShieldMode,
        dry_run: bool,
        detected_at: datetime,
        window_start: datetime | None,
        event_count: int,
        threshold_count: int,
        window_seconds: int,
        policy_version: int,
        response: ResponseAction,
        reason: str,
        target_type: str | None = None,
        target_id: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> Incident:
        incident = Incident(
            guild_id=guild_id,
            correlation_id=correlation_id,
            action_key=action_key,
            actor_id=actor_id,
            actor_confidence=actor_confidence,
            severity=severity,
            status=IncidentStatus.OPEN,
            mode_at_detection=mode_at_detection,
            dry_run=dry_run,
            detected_at=detected_at,
            window_start=window_start,
            event_count=event_count,
            threshold_count=threshold_count,
            window_seconds=window_seconds,
            policy_version=policy_version,
            response=response,
            outcome=EnforcementStatus.PENDING,
            reason=reason,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
        )
        self.session.add(incident)
        await self.session.flush()
        return incident

    async def get(self, guild_id: int, incident_id: int) -> Incident | None:
        """Guild-scoped fetch. Never fetch by primary key alone - that is the
        cross-guild IDOR hole."""
        result = await self.session.execute(
            sa.select(Incident).where(
                Incident.id == incident_id, Incident.guild_id == guild_id
            )
        )
        return result.scalar_one_or_none()

    async def list_recent(
        self,
        guild_id: int,
        *,
        limit: int = 10,
        status: IncidentStatus | None = None,
        action_key: ActionKey | None = None,
        since: datetime | None = None,
    ) -> Sequence[Incident]:
        stmt = sa.select(Incident).where(Incident.guild_id == guild_id)
        if status is not None:
            stmt = stmt.where(Incident.status == status)
        if action_key is not None:
            stmt = stmt.where(Incident.action_key == action_key)
        if since is not None:
            stmt = stmt.where(Incident.detected_at >= since)
        result = await self.session.execute(
            stmt.order_by(Incident.detected_at.desc()).limit(max(1, min(limit, 100)))
        )
        return result.scalars().all()

    async def set_outcome(
        self,
        guild_id: int,
        incident_id: int,
        outcome: EnforcementStatus,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        values: dict[str, Any] = {"outcome": outcome, "updated_at": utcnow()}
        if details is not None:
            values["details"] = details
        await self.session.execute(
            sa.update(Incident)
            .where(Incident.id == incident_id, Incident.guild_id == guild_id)
            .values(**values)
        )

    async def acknowledge(
        self,
        guild_id: int,
        incident_id: int,
        *,
        user_id: int,
        note: str | None = None,
        false_positive: bool = False,
    ) -> Incident | None:
        incident = await self.get(guild_id, incident_id)
        if incident is None:
            return None
        incident.status = (
            IncidentStatus.FALSE_POSITIVE if false_positive else IncidentStatus.ACKNOWLEDGED
        )
        incident.acknowledged_by = user_id
        incident.acknowledged_at = utcnow()
        incident.acknowledgement_note = note
        incident.updated_at = utcnow()
        await self.session.flush()
        return incident

    async def mark_notified(self, guild_id: int, incident_id: int) -> None:
        await self.session.execute(
            sa.update(Incident)
            .where(Incident.id == incident_id, Incident.guild_id == guild_id)
            .values(notified_at=utcnow())
        )

    async def last_for_scope(
        self, guild_id: int, action_key: ActionKey, actor_id: int | None
    ) -> Incident | None:
        stmt = sa.select(Incident).where(
            Incident.guild_id == guild_id, Incident.action_key == action_key
        )
        stmt = (
            stmt.where(Incident.actor_id == actor_id)
            if actor_id is not None
            else stmt.where(Incident.actor_id.is_(None))
        )
        result = await self.session.execute(stmt.order_by(Incident.detected_at.desc()).limit(1))
        return result.scalar_one_or_none()

    async def counts_by_status(self, guild_id: int, since: datetime) -> dict[str, int]:
        result = await self.session.execute(
            sa.select(Incident.status, sa.func.count(Incident.id))
            .where(Incident.guild_id == guild_id, Incident.detected_at >= since)
            .group_by(Incident.status)
        )
        return {
            (status.value if hasattr(status, "value") else str(status)): int(count)
            for status, count in result.all()
        }

    async def false_positive_rate(self, guild_id: int, since: datetime) -> float:
        counts = await self.counts_by_status(guild_id, since)
        total = sum(counts.values())
        if not total:
            return 0.0
        return counts.get(IncidentStatus.FALSE_POSITIVE.value, 0) / total

    async def prune(self, older_than_days: int) -> int:
        if older_than_days <= 0:
            return 0
        cutoff = utcnow() - timedelta(days=older_than_days)
        result = await self.session.execute(
            sa.delete(Incident).where(Incident.detected_at < cutoff)
        )
        return int(result.rowcount or 0)

    EXPORT_LIMIT = 5000

    async def export(self, guild_id: int, since: datetime) -> list[dict[str, Any]]:
        """Newest-first incident metadata, capped at :attr:`EXPORT_LIMIT` rows."""
        result = await self.session.execute(
            sa.select(Incident)
            .where(Incident.guild_id == guild_id, Incident.detected_at >= since)
            .order_by(Incident.detected_at.desc())
            .limit(self.EXPORT_LIMIT)
        )
        rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "guild_id": r.guild_id,
                "correlation_id": r.correlation_id,
                "action": r.action_key.value,
                "actor_id": r.actor_id,
                "confidence": r.actor_confidence.value,
                "severity": r.severity.value,
                "status": r.status.value,
                "mode": r.mode_at_detection.value,
                "dry_run": r.dry_run,
                "detected_at": r.detected_at.isoformat(),
                "event_count": r.event_count,
                "threshold": r.threshold_count,
                "window_seconds": r.window_seconds,
                "policy_version": r.policy_version,
                "response": r.response.value,
                "outcome": r.outcome.value,
                "reason": r.reason,
            }
            for r in rows
        ]


class EnforcementRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def claim(
        self,
        *,
        guild_id: int,
        incident_id: int | None,
        idempotency_key: str,
        action_type: str,
        target_type: str | None = None,
        target_id: int | None = None,
        before_state: dict[str, Any] | None = None,
    ) -> tuple[EnforcementRecord, bool]:
        """Reserve an enforcement step.

        Returns ``(record, claimed)``. ``claimed=False`` means another task (or
        a previous run before a restart) already owns this step, so the caller
        must not execute the Discord side effect again. This is the idempotency
        guarantee for every automated response.
        """
        values = {
            "guild_id": guild_id,
            "incident_id": incident_id,
            "idempotency_key": idempotency_key,
            "action_type": action_type,
            "target_type": target_type,
            "target_id": target_id,
            "status": EnforcementStatus.PENDING,
            "attempts": 0,
            "before_state": before_state,
            "started_at": utcnow(),
        }
        if _is_postgres(self.session):
            stmt = (
                pg_insert(EnforcementRecord)
                .values(**values)
                .on_conflict_do_nothing(index_elements=[EnforcementRecord.idempotency_key])
                .returning(EnforcementRecord.id)
            )
            result = await self.session.execute(stmt)
            new_id = result.scalar_one_or_none()
            if new_id is None:
                existing = await self.get_by_key(guild_id, idempotency_key)
                assert existing is not None
                return existing, False
            row = await self.session.get(EnforcementRecord, new_id)
            assert row is not None
            return row, True

        existing = await self.get_by_key(guild_id, idempotency_key)
        if existing is not None:
            return existing, False
        row = EnforcementRecord(**values)
        try:
            async with self.session.begin_nested():
                self.session.add(row)
        except IntegrityError:
            existing = await self.get_by_key(guild_id, idempotency_key)
            assert existing is not None
            return existing, False
        return row, True

    async def get_by_key(self, guild_id: int, idempotency_key: str) -> EnforcementRecord | None:
        result = await self.session.execute(
            sa.select(EnforcementRecord).where(
                EnforcementRecord.guild_id == guild_id,
                EnforcementRecord.idempotency_key == idempotency_key,
            )
        )
        return result.scalar_one_or_none()

    async def finish(
        self,
        record_id: int,
        *,
        guild_id: int,
        status: EnforcementStatus,
        after_state: dict[str, Any] | None = None,
        error: str | None = None,
        detail: str | None = None,
        attempts: int | None = None,
    ) -> None:
        values: dict[str, Any] = {
            "status": status,
            "after_state": after_state,
            "error": error,
            "detail": detail,
            "finished_at": utcnow(),
            "updated_at": utcnow(),
        }
        if attempts is not None:
            values["attempts"] = attempts
        await self.session.execute(
            sa.update(EnforcementRecord)
            .where(EnforcementRecord.id == record_id, EnforcementRecord.guild_id == guild_id)
            .values(**values)
        )

    async def list_for_incident(
        self, guild_id: int, incident_id: int
    ) -> Sequence[EnforcementRecord]:
        result = await self.session.execute(
            sa.select(EnforcementRecord)
            .where(
                EnforcementRecord.guild_id == guild_id,
                EnforcementRecord.incident_id == incident_id,
            )
            .order_by(EnforcementRecord.id)
        )
        return result.scalars().all()


class CooldownRepository:
    """Durable cooldown + escalation state."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def check_and_set(
        self, guild_id: int, scope_key: str, cooldown_seconds: int
    ) -> tuple[bool, int]:
        """Atomically test the cooldown and arm it.

        Returns ``(allowed, escalation_level)``. ``allowed=False`` means the
        scope is still cooling down and the caller must suppress the response.
        """
        now = utcnow()
        expiry = now + timedelta(seconds=max(cooldown_seconds, 0))
        # Row lock: two tasks seeing the same expired cooldown must not both
        # be allowed through. (SQLite ignores FOR UPDATE and serialises writes.)
        row = await self.session.get(
            CooldownRecord, (guild_id, scope_key), with_for_update=True
        )
        if row is None:
            try:
                async with self.session.begin_nested():
                    self.session.add(
                        CooldownRecord(
                            guild_id=guild_id,
                            scope_key=scope_key,
                            expires_at=expiry,
                            hits=1,
                            escalation_level=0,
                        )
                    )
            except IntegrityError:
                # Lost the race to arm it: the winner's response is in flight.
                return False, 0
            return True, 0

        active = row.expires_at > now
        row.hits += 1
        row.updated_at = now
        if active:
            await self.session.flush()
            return False, row.escalation_level
        row.escalation_level = min(row.escalation_level + 1, 10)
        row.expires_at = expiry
        await self.session.flush()
        return True, row.escalation_level

    async def peek(self, guild_id: int, scope_key: str) -> CooldownRecord | None:
        return await self.session.get(CooldownRecord, (guild_id, scope_key))

    async def clear(self, guild_id: int, scope_key: str | None = None) -> int:
        stmt = sa.delete(CooldownRecord).where(CooldownRecord.guild_id == guild_id)
        if scope_key is not None:
            stmt = stmt.where(CooldownRecord.scope_key == scope_key)
        result = await self.session.execute(stmt)
        return int(result.rowcount or 0)

    async def purge_expired(self) -> int:
        result = await self.session.execute(
            sa.delete(CooldownRecord).where(CooldownRecord.expires_at < utcnow())
        )
        return int(result.rowcount or 0)


class SnapshotRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def next_version(self, guild_id: int) -> int:
        result = await self.session.execute(
            sa.select(sa.func.coalesce(sa.func.max(Snapshot.version), 0)).where(
                Snapshot.guild_id == guild_id
            )
        )
        return int(result.scalar_one()) + 1

    async def create(
        self,
        *,
        guild_id: int,
        kind: SnapshotKind,
        checksum: str,
        summary: dict[str, Any],
        payload: dict[str, Any] | None = None,
        payload_ciphertext: bytes | None = None,
        encrypted: bool = False,
        taken_by: int | None = None,
        validated: bool = True,
        validation_errors: list[Any] | None = None,
        schema_version: int = 1,
    ) -> Snapshot:
        version = await self.next_version(guild_id)
        snap = Snapshot(
            guild_id=guild_id,
            version=version,
            kind=kind,
            checksum=checksum,
            summary=summary,
            payload=payload,
            payload_ciphertext=payload_ciphertext,
            encrypted=encrypted,
            taken_by=taken_by,
            validated=validated,
            validation_errors=validation_errors,
            schema_version=schema_version,
        )
        self.session.add(snap)
        await self.session.flush()
        return snap

    async def get(self, guild_id: int, snapshot_id: int) -> Snapshot | None:
        result = await self.session.execute(
            sa.select(Snapshot).where(Snapshot.id == snapshot_id, Snapshot.guild_id == guild_id)
        )
        return result.scalar_one_or_none()

    async def get_by_version(self, guild_id: int, version: int) -> Snapshot | None:
        result = await self.session.execute(
            sa.select(Snapshot).where(Snapshot.guild_id == guild_id, Snapshot.version == version)
        )
        return result.scalar_one_or_none()

    async def latest(self, guild_id: int, *, validated_only: bool = True) -> Snapshot | None:
        stmt = sa.select(Snapshot).where(Snapshot.guild_id == guild_id)
        if validated_only:
            stmt = stmt.where(Snapshot.validated.is_(True))
        result = await self.session.execute(stmt.order_by(Snapshot.version.desc()).limit(1))
        return result.scalar_one_or_none()

    async def list_for_guild(self, guild_id: int, limit: int = 20) -> Sequence[Snapshot]:
        result = await self.session.execute(
            sa.select(Snapshot)
            .where(Snapshot.guild_id == guild_id)
            .order_by(Snapshot.version.desc())
            .limit(max(1, min(limit, 100)))
        )
        return result.scalars().all()

    async def enforce_retention(self, guild_id: int, keep: int) -> int:
        """Delete all but the newest ``keep`` snapshots for one guild."""
        keep = max(1, keep)
        result = await self.session.execute(
            sa.select(Snapshot.version)
            .where(Snapshot.guild_id == guild_id)
            .order_by(Snapshot.version.desc())
            .limit(keep)
        )
        keep_versions = list(result.scalars().all())
        if not keep_versions:
            return 0
        deleted = await self.session.execute(
            sa.delete(Snapshot).where(
                Snapshot.guild_id == guild_id, Snapshot.version < min(keep_versions)
            )
        )
        return int(deleted.rowcount or 0)


class RestoreRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        guild_id: int,
        snapshot_id: int,
        mode: RestoreMode,
        status: RestoreStatus,
        requested_by: int,
        plan: dict[str, Any] | None = None,
        scope: list[Any] | None = None,
        token_ttl_seconds: int = 900,
    ) -> RestoreJob:
        token = secrets.token_hex(6).upper() if mode is RestoreMode.PREVIEW else None
        job = RestoreJob(
            guild_id=guild_id,
            snapshot_id=snapshot_id,
            mode=mode,
            status=status,
            requested_by=requested_by,
            plan=plan,
            scope=scope,
            approval_token=token,
            token_expires_at=(
                utcnow() + timedelta(seconds=token_ttl_seconds) if token else None
            ),
        )
        self.session.add(job)
        await self.session.flush()
        return job

    async def get(self, guild_id: int, job_id: int) -> RestoreJob | None:
        result = await self.session.execute(
            sa.select(RestoreJob).where(
                RestoreJob.id == job_id, RestoreJob.guild_id == guild_id
            )
        )
        return result.scalar_one_or_none()

    async def find_pending_token(self, guild_id: int, token: str) -> RestoreJob | None:
        """Look up an approval token, guild-scoped and constant-key compared."""
        result = await self.session.execute(
            sa.select(RestoreJob)
            .where(
                RestoreJob.guild_id == guild_id,
                RestoreJob.mode == RestoreMode.PREVIEW,
                RestoreJob.status.in_(
                    [RestoreStatus.PREVIEWED, RestoreStatus.AWAITING_APPROVAL]
                ),
            )
            .order_by(RestoreJob.created_at.desc())
            .limit(25)
        )
        candidate = token.strip().upper()
        for job in result.scalars().all():
            if job.approval_token and secrets.compare_digest(job.approval_token, candidate):
                if job.token_expires_at and job.token_expires_at <= utcnow():
                    job.status = RestoreStatus.EXPIRED
                    await self.session.flush()
                    return None
                return job
        return None

    async def finish(
        self,
        job_id: int,
        *,
        guild_id: int,
        status: RestoreStatus,
        result: dict[str, Any] | None = None,
        id_map: dict[str, Any] | None = None,
        approved_by: int | None = None,
    ) -> None:
        values: dict[str, Any] = {
            "status": status,
            "result": result,
            "id_map": id_map,
            "finished_at": utcnow(),
            "updated_at": utcnow(),
        }
        if approved_by is not None:
            values["approved_by"] = approved_by
        await self.session.execute(
            sa.update(RestoreJob)
            .where(RestoreJob.id == job_id, RestoreJob.guild_id == guild_id)
            .values(**values)
        )

    async def list_for_guild(self, guild_id: int, limit: int = 10) -> Sequence[RestoreJob]:
        result = await self.session.execute(
            sa.select(RestoreJob)
            .where(RestoreJob.guild_id == guild_id)
            .order_by(RestoreJob.created_at.desc())
            .limit(max(1, min(limit, 50)))
        )
        return result.scalars().all()


class CommandAuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        *,
        user_id: int,
        command: str,
        allowed: bool,
        guild_id: int | None = None,
        authority: str | None = None,
        reason: str | None = None,
        parameters: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> None:
        self.session.add(
            CommandAudit(
                guild_id=guild_id,
                user_id=user_id,
                command=command,
                allowed=allowed,
                authority=authority,
                reason=reason,
                parameters=parameters or {},
                correlation_id=correlation_id,
            )
        )
        await self.session.flush()

    async def recent(self, guild_id: int, limit: int = 20) -> Sequence[CommandAudit]:
        result = await self.session.execute(
            sa.select(CommandAudit)
            .where(CommandAudit.guild_id == guild_id)
            .order_by(CommandAudit.created_at.desc())
            .limit(max(1, min(limit, 100)))
        )
        return result.scalars().all()


class UnitOfWork:
    """Convenience bundle of every repository over one session."""

    EXPORT_LIMIT = IncidentRepository.EXPORT_LIMIT

    __slots__ = (
        "session",
        "guilds",
        "policies",
        "trust",
        "events",
        "incidents",
        "enforcement",
        "cooldowns",
        "snapshots",
        "restores",
        "command_audit",
    )

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.guilds = GuildRepository(session)
        self.policies = PolicyRepository(session)
        self.trust = TrustRepository(session)
        self.events = EventRepository(session)
        self.incidents = IncidentRepository(session)
        self.enforcement = EnforcementRepository(session)
        self.cooldowns = CooldownRepository(session)
        self.snapshots = SnapshotRepository(session)
        self.restores = RestoreRepository(session)
        self.command_audit = CommandAuditRepository(session)
