"""SQLAlchemy 2.x ORM models (async-ready).

Portability note: enumerations are declared with ``native_enum=False`` so the
schema is a ``VARCHAR`` plus a ``CHECK`` constraint. That keeps PostgreSQL
migrations simple (adding a value needs no ``ALTER TYPE``) and lets the
integration suite run on SQLite.

Every tenant-scoped table carries ``guild_id`` and is indexed by it. The
repository layer never issues a query without a ``guild_id`` predicate, which
is the core defence against cross-guild data leaks / IDOR.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

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
)

#: JSONB on PostgreSQL, plain JSON elsewhere (tests).
JSONType = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

#: BIGSERIAL on PostgreSQL. SQLite only auto-increments INTEGER primary keys,
#: so the test dialect gets a plain INTEGER - the Python-side type is identical.
BigIntPK = sa.BigInteger().with_variant(sa.Integer, "sqlite")


def _enum(enum_cls: type, name: str) -> sa.Enum:
    return sa.Enum(
        enum_cls,
        name=name,
        native_enum=False,
        values_callable=lambda cls: [member.value for member in cls],
        length=64,
    )


class UTCDateTime(sa.types.TypeDecorator):
    """Timestamp column that is always timezone-aware UTC in Python.

    PostgreSQL ``TIMESTAMPTZ`` already round-trips an offset, but SQLite (used
    by the integration suite) returns naive datetimes. Normalising in a type
    decorator keeps every comparison in the codebase safe regardless of
    dialect, which is the persistence invariant: *UTC everywhere*.
    """

    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001, ANN201
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):  # noqa: ANN001, ANN201
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONType, list[Any]: JSONType}


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=sa.func.now(),
    )


class GuildSettings(TimestampMixin, Base):
    """Per-guild configuration. One row per guild; the tenancy root."""

    __tablename__ = "guild_settings"

    guild_id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=False)
    guild_name: Mapped[str | None] = mapped_column(sa.String(128))
    owner_id: Mapped[int | None] = mapped_column(sa.BigInteger)

    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    mode: Mapped[ShieldMode] = mapped_column(
        _enum(ShieldMode, "shield_mode"), nullable=False, default=ShieldMode.ALERT_ONLY
    )
    dry_run: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    paused: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    pause_reason: Mapped[str | None] = mapped_column(sa.Text)
    paused_by: Mapped[int | None] = mapped_column(sa.BigInteger)
    paused_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    log_channel_id: Mapped[int | None] = mapped_column(sa.BigInteger)
    alert_channel_id: Mapped[int | None] = mapped_column(sa.BigInteger)

    lockdown_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    lockdown_reason: Mapped[str | None] = mapped_column(sa.Text)
    lockdown_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    lockdown_state: Mapped[dict[str, Any] | None] = mapped_column(JSONType)

    raid_mode_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    raid_mode_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    raid_mode_state: Mapped[dict[str, Any] | None] = mapped_column(JSONType)

    protective_mode: Mapped[str | None] = mapped_column(sa.String(32))

    policy_version: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    snapshot_interval_minutes: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=360)
    snapshot_retention: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=12)
    snapshot_include_webhooks: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=True
    )

    incident_cooldown_seconds: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=60)

    enabled_by: Mapped[int | None] = mapped_column(sa.BigInteger)
    enabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    __table_args__ = (
        sa.CheckConstraint("policy_version >= 1", name="ck_guild_policy_version"),
        sa.CheckConstraint("snapshot_retention >= 1", name="ck_guild_snapshot_retention"),
        sa.CheckConstraint(
            "incident_cooldown_seconds >= 0", name="ck_guild_incident_cooldown"
        ),
    )


class GuildPolicy(TimestampMixin, Base):
    """Threshold + response configuration for one detector in one guild."""

    __tablename__ = "guild_policies"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    guild_id: Mapped[int] = mapped_column(
        sa.BigInteger,
        sa.ForeignKey("guild_settings.guild_id", ondelete="CASCADE"),
        nullable=False,
    )
    action_key: Mapped[ActionKey] = mapped_column(_enum(ActionKey, "action_key"), nullable=False)
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    threshold_count: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    window_seconds: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    cooldown_seconds: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=60)
    response: Mapped[ResponseAction] = mapped_column(
        _enum(ResponseAction, "response_action"), nullable=False
    )
    severity: Mapped[Severity] = mapped_column(
        _enum(Severity, "severity"), nullable=False, default=Severity.HIGH
    )
    dry_run: Mapped[bool | None] = mapped_column(sa.Boolean)
    requires_confirmed_actor: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=True
    )
    options: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    updated_by: Mapped[int | None] = mapped_column(sa.BigInteger)

    __table_args__ = (
        sa.UniqueConstraint("guild_id", "action_key", name="uq_guild_policy"),
        sa.CheckConstraint("threshold_count >= 1", name="ck_policy_threshold"),
        sa.CheckConstraint("window_seconds >= 1", name="ck_policy_window"),
        sa.CheckConstraint("cooldown_seconds >= 0", name="ck_policy_cooldown"),
        sa.Index("ix_guild_policies_guild", "guild_id"),
    )


class TrustedEntity(TimestampMixin, Base):
    """Explicit allowlist entry (user or role) scoped to one guild.

    Nothing is implicitly trusted here: administrators, bots and Manage Guild
    holders must be added deliberately by the guild owner or an authorised
    delegate.
    """

    __tablename__ = "trusted_entities"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    guild_id: Mapped[int] = mapped_column(
        sa.BigInteger,
        sa.ForeignKey("guild_settings.guild_id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_type: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    entity_id: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    scopes: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    reason: Mapped[str | None] = mapped_column(sa.Text)
    added_by: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    __table_args__ = (
        sa.UniqueConstraint("guild_id", "entity_type", "entity_id", name="uq_trusted_entity"),
        sa.CheckConstraint("entity_type IN ('user','role')", name="ck_trusted_entity_type"),
        sa.Index("ix_trusted_entities_guild", "guild_id"),
    )


class EventRecord(Base):
    """Normalised, deduplicated event log.

    ``dedupe_key`` is globally unique and is how duplicate gateway deliveries
    (reconnects, multiple shards, audit-log replays) are collapsed. It also
    allows a restarted process to rehydrate its in-memory detection windows.
    """

    __tablename__ = "event_records"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    guild_id: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    correlation_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    action_key: Mapped[ActionKey] = mapped_column(_enum(ActionKey, "action_key"), nullable=False)
    source: Mapped[EventSource] = mapped_column(_enum(EventSource, "event_source"), nullable=False)
    actor_id: Mapped[int | None] = mapped_column(sa.BigInteger)
    actor_confidence: Mapped[Confidence] = mapped_column(
        _enum(Confidence, "confidence"), nullable=False, default=Confidence.UNKNOWN
    )
    target_type: Mapped[str | None] = mapped_column(sa.String(32))
    target_id: Mapped[int | None] = mapped_column(sa.BigInteger)
    channel_id: Mapped[int | None] = mapped_column(sa.BigInteger)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, server_default=sa.func.now()
    )
    audit_entry_id: Mapped[int | None] = mapped_column(sa.BigInteger)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    instance_id: Mapped[str | None] = mapped_column(sa.String(64))

    __table_args__ = (
        sa.UniqueConstraint("dedupe_key", name="uq_event_dedupe"),
        sa.Index("ix_event_guild_action_time", "guild_id", "action_key", "occurred_at"),
        sa.Index("ix_event_guild_actor_time", "guild_id", "actor_id", "occurred_at"),
        sa.Index("ix_event_correlation", "correlation_id"),
    )


class Incident(TimestampMixin, Base):
    """A policy violation that crossed its threshold."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    guild_id: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    correlation_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    action_key: Mapped[ActionKey] = mapped_column(_enum(ActionKey, "action_key"), nullable=False)
    actor_id: Mapped[int | None] = mapped_column(sa.BigInteger)
    actor_confidence: Mapped[Confidence] = mapped_column(
        _enum(Confidence, "confidence"), nullable=False
    )
    target_type: Mapped[str | None] = mapped_column(sa.String(32))
    target_id: Mapped[int | None] = mapped_column(sa.BigInteger)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(
        _enum(IncidentStatus, "incident_status"), nullable=False, default=IncidentStatus.OPEN
    )
    mode_at_detection: Mapped[ShieldMode] = mapped_column(
        _enum(ShieldMode, "shield_mode"), nullable=False
    )
    dry_run: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    window_start: Mapped[datetime | None] = mapped_column(UTCDateTime)
    event_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    threshold_count: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    window_seconds: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    policy_version: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    response: Mapped[ResponseAction] = mapped_column(
        _enum(ResponseAction, "response_action"), nullable=False
    )
    outcome: Mapped[EnforcementStatus] = mapped_column(
        _enum(EnforcementStatus, "enforcement_status"),
        nullable=False,
        default=EnforcementStatus.PENDING,
    )
    reason: Mapped[str] = mapped_column(sa.Text, nullable=False)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    acknowledged_by: Mapped[int | None] = mapped_column(sa.BigInteger)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    acknowledgement_note: Mapped[str | None] = mapped_column(sa.Text)
    notified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    actions: Mapped[list[EnforcementRecord]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        sa.Index("ix_incidents_guild_time", "guild_id", "detected_at"),
        sa.Index("ix_incidents_guild_status", "guild_id", "status"),
        sa.Index("ix_incidents_guild_actor", "guild_id", "actor_id"),
        sa.Index("ix_incidents_correlation", "correlation_id"),
    )


class EnforcementRecord(TimestampMixin, Base):
    """One idempotent enforcement step taken (or deliberately not taken)."""

    __tablename__ = "enforcement_actions"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    guild_id: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    incident_id: Mapped[int | None] = mapped_column(
        sa.BigInteger, sa.ForeignKey("incidents.id", ondelete="CASCADE")
    )
    idempotency_key: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    action_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(sa.String(32))
    target_id: Mapped[int | None] = mapped_column(sa.BigInteger)
    status: Mapped[EnforcementStatus] = mapped_column(
        _enum(EnforcementStatus, "enforcement_status"),
        nullable=False,
        default=EnforcementStatus.PENDING,
    )
    attempts: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    before_state: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    after_state: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    error: Mapped[str | None] = mapped_column(sa.Text)
    detail: Mapped[str | None] = mapped_column(sa.Text)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    incident: Mapped[Incident | None] = relationship(back_populates="actions")

    __table_args__ = (
        sa.UniqueConstraint("idempotency_key", name="uq_enforcement_idempotency"),
        sa.Index("ix_enforcement_guild", "guild_id", "created_at"),
        sa.Index("ix_enforcement_incident", "incident_id"),
    )


class Snapshot(Base):
    """Versioned structural backup of a guild."""

    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    guild_id: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    version: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    kind: Mapped[SnapshotKind] = mapped_column(_enum(SnapshotKind, "snapshot_kind"), nullable=False)
    taken_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, server_default=sa.func.now()
    )
    taken_by: Mapped[int | None] = mapped_column(sa.BigInteger)
    checksum: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    encrypted: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    payload_ciphertext: Mapped[bytes | None] = mapped_column(sa.LargeBinary)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    schema_version: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    validated: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    validation_errors: Mapped[list[Any] | None] = mapped_column(JSONType)

    __table_args__ = (
        sa.UniqueConstraint("guild_id", "version", name="uq_snapshot_version"),
        sa.Index("ix_snapshots_guild_time", "guild_id", "taken_at"),
        sa.CheckConstraint("version >= 1", name="ck_snapshot_version"),
    )


class RestoreJob(TimestampMixin, Base):
    """Preview or apply run of a snapshot restoration."""

    __tablename__ = "restore_jobs"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    guild_id: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    snapshot_id: Mapped[int] = mapped_column(
        sa.BigInteger, sa.ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False
    )
    mode: Mapped[RestoreMode] = mapped_column(_enum(RestoreMode, "restore_mode"), nullable=False)
    status: Mapped[RestoreStatus] = mapped_column(
        _enum(RestoreStatus, "restore_status"), nullable=False
    )
    requested_by: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    approved_by: Mapped[int | None] = mapped_column(sa.BigInteger)
    approval_token: Mapped[str | None] = mapped_column(sa.String(32))
    token_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    scope: Mapped[list[Any] | None] = mapped_column(JSONType)
    plan: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    id_map: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    __table_args__ = (
        sa.Index("ix_restore_guild_time", "guild_id", "created_at"),
        sa.Index("ix_restore_token", "guild_id", "approval_token"),
    )


class CommandAudit(Base):
    """Every privileged slash-command invocation, allowed or denied."""

    __tablename__ = "command_audit"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    guild_id: Mapped[int | None] = mapped_column(sa.BigInteger)
    user_id: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    command: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    allowed: Mapped[bool] = mapped_column(sa.Boolean, nullable=False)
    authority: Mapped[str | None] = mapped_column(sa.String(32))
    reason: Mapped[str | None] = mapped_column(sa.Text)
    parameters: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    correlation_id: Mapped[str | None] = mapped_column(sa.String(64))
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.Index("ix_command_audit_guild_time", "guild_id", "created_at"),
        sa.Index("ix_command_audit_user", "user_id", "created_at"),
    )


class CooldownRecord(Base):
    """Durable escalation/cooldown state, survives restarts and shard moves."""

    __tablename__ = "cooldowns"

    guild_id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=False)
    scope_key: Mapped[str] = mapped_column(sa.String(160), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    hits: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    escalation_level: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, server_default=sa.func.now()
    )

    __table_args__ = (sa.Index("ix_cooldowns_expiry", "expires_at"),)


ALL_TABLES = (
    GuildSettings.__table__,
    GuildPolicy.__table__,
    TrustedEntity.__table__,
    EventRecord.__table__,
    Incident.__table__,
    EnforcementRecord.__table__,
    Snapshot.__table__,
    RestoreJob.__table__,
    CommandAudit.__table__,
    CooldownRecord.__table__,
)
