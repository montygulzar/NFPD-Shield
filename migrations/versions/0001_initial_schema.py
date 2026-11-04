"""Initial NFPD Shield schema.

Creates every table, index, unique constraint and check constraint the
application relies on. The unique constraints are load-bearing, not cosmetic:

* ``event_records.dedupe_key`` collapses duplicate gateway deliveries.
* ``enforcement_actions.idempotency_key`` makes every automated response
  execute at most once.
* ``guild_policies (guild_id, action_key)`` and
  ``trusted_entities (guild_id, entity_type, entity_id)`` keep per-guild
  configuration single-valued.
* ``snapshots (guild_id, version)`` keeps snapshot versions monotonic per guild.

Revision ID: 0001_initial
Revises: (none - this is the base revision)
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# UTCDateTime is Shield's timezone-normalising column type; importing it keeps
# the generated DDL identical to the ORM definition.
import shield.db.models

revision: str = '0001_initial'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('audit_cursors',
    sa.Column('guild_id', sa.BigInteger(), autoincrement=False, nullable=False),
    sa.Column('audit_action', sa.String(length=64), nullable=False),
    sa.Column('last_entry_id', sa.BigInteger(), nullable=False),
    sa.Column('updated_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('guild_id', 'audit_action')
    )
    op.create_table('command_audit',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('guild_id', sa.BigInteger(), nullable=True),
    sa.Column('user_id', sa.BigInteger(), nullable=False),
    sa.Column('command', sa.String(length=128), nullable=False),
    sa.Column('allowed', sa.Boolean(), nullable=False),
    sa.Column('authority', sa.String(length=32), nullable=True),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('parameters', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('correlation_id', sa.String(length=64), nullable=True),
    sa.Column('created_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_command_audit_guild_time', 'command_audit', ['guild_id', 'created_at'], unique=False)
    op.create_index('ix_command_audit_user', 'command_audit', ['user_id', 'created_at'], unique=False)
    op.create_table('cooldowns',
    sa.Column('guild_id', sa.BigInteger(), autoincrement=False, nullable=False),
    sa.Column('scope_key', sa.String(length=160), nullable=False),
    sa.Column('expires_at', shield.db.models.UTCDateTime(timezone=True), nullable=False),
    sa.Column('hits', sa.Integer(), nullable=False),
    sa.Column('escalation_level', sa.Integer(), nullable=False),
    sa.Column('updated_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('guild_id', 'scope_key')
    )
    op.create_index('ix_cooldowns_expiry', 'cooldowns', ['expires_at'], unique=False)
    op.create_table('event_records',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('guild_id', sa.BigInteger(), nullable=False),
    sa.Column('correlation_id', sa.String(length=64), nullable=False),
    sa.Column('dedupe_key', sa.String(length=200), nullable=False),
    sa.Column('action_key', sa.Enum('mass_ban', 'mass_kick', 'channel_delete', 'channel_create_flood', 'role_delete', 'role_create_flood', 'dangerous_permission_change', 'dangerous_role_grant', 'bot_add', 'webhook_create', 'webhook_delete', 'webhook_update', 'mass_mention', 'join_flood', 'message_spam', 'duplicate_spam', 'guild_settings_change', 'vanity_url_change', name='action_key', native_enum=False, length=64), nullable=False),
    sa.Column('source', sa.Enum('gateway', 'audit_log', 'synthetic', name='event_source', native_enum=False, length=64), nullable=False),
    sa.Column('actor_id', sa.BigInteger(), nullable=True),
    sa.Column('actor_confidence', sa.Enum('confirmed', 'likely', 'unknown', name='confidence', native_enum=False, length=64), nullable=False),
    sa.Column('target_type', sa.String(length=32), nullable=True),
    sa.Column('target_id', sa.BigInteger(), nullable=True),
    sa.Column('channel_id', sa.BigInteger(), nullable=True),
    sa.Column('occurred_at', shield.db.models.UTCDateTime(timezone=True), nullable=False),
    sa.Column('recorded_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('audit_entry_id', sa.BigInteger(), nullable=True),
    sa.Column('payload', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('instance_id', sa.String(length=64), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('dedupe_key', name='uq_event_dedupe')
    )
    op.create_index('ix_event_correlation', 'event_records', ['correlation_id'], unique=False)
    op.create_index('ix_event_guild_action_time', 'event_records', ['guild_id', 'action_key', 'occurred_at'], unique=False)
    op.create_index('ix_event_guild_actor_time', 'event_records', ['guild_id', 'actor_id', 'occurred_at'], unique=False)
    op.create_table('guild_settings',
    sa.Column('guild_id', sa.BigInteger(), autoincrement=False, nullable=False),
    sa.Column('guild_name', sa.String(length=128), nullable=True),
    sa.Column('owner_id', sa.BigInteger(), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('mode', sa.Enum('alert_only', 'enforce', 'lockdown', name='shield_mode', native_enum=False, length=64), nullable=False),
    sa.Column('dry_run', sa.Boolean(), nullable=False),
    sa.Column('paused', sa.Boolean(), nullable=False),
    sa.Column('pause_reason', sa.Text(), nullable=True),
    sa.Column('paused_by', sa.BigInteger(), nullable=True),
    sa.Column('paused_at', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('log_channel_id', sa.BigInteger(), nullable=True),
    sa.Column('alert_channel_id', sa.BigInteger(), nullable=True),
    sa.Column('lockdown_active', sa.Boolean(), nullable=False),
    sa.Column('lockdown_reason', sa.Text(), nullable=True),
    sa.Column('lockdown_until', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('lockdown_state', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('raid_mode_active', sa.Boolean(), nullable=False),
    sa.Column('raid_mode_until', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('raid_mode_state', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('protective_mode', sa.String(length=32), nullable=True),
    sa.Column('policy_version', sa.Integer(), nullable=False),
    sa.Column('snapshot_interval_minutes', sa.Integer(), nullable=False),
    sa.Column('snapshot_retention', sa.Integer(), nullable=False),
    sa.Column('snapshot_include_webhooks', sa.Boolean(), nullable=False),
    sa.Column('incident_cooldown_seconds', sa.Integer(), nullable=False),
    sa.Column('min_account_age_hours', sa.Integer(), nullable=False),
    sa.Column('enabled_by', sa.BigInteger(), nullable=True),
    sa.Column('enabled_at', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('created_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('incident_cooldown_seconds >= 0', name='ck_guild_incident_cooldown'),
    sa.CheckConstraint('policy_version >= 1', name='ck_guild_policy_version'),
    sa.CheckConstraint('snapshot_retention >= 1', name='ck_guild_snapshot_retention'),
    sa.PrimaryKeyConstraint('guild_id')
    )
    op.create_table('incidents',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('guild_id', sa.BigInteger(), nullable=False),
    sa.Column('correlation_id', sa.String(length=64), nullable=False),
    sa.Column('action_key', sa.Enum('mass_ban', 'mass_kick', 'channel_delete', 'channel_create_flood', 'role_delete', 'role_create_flood', 'dangerous_permission_change', 'dangerous_role_grant', 'bot_add', 'webhook_create', 'webhook_delete', 'webhook_update', 'mass_mention', 'join_flood', 'message_spam', 'duplicate_spam', 'guild_settings_change', 'vanity_url_change', name='action_key', native_enum=False, length=64), nullable=False),
    sa.Column('actor_id', sa.BigInteger(), nullable=True),
    sa.Column('actor_confidence', sa.Enum('confirmed', 'likely', 'unknown', name='confidence', native_enum=False, length=64), nullable=False),
    sa.Column('target_type', sa.String(length=32), nullable=True),
    sa.Column('target_id', sa.BigInteger(), nullable=True),
    sa.Column('severity', sa.Enum('low', 'medium', 'high', 'critical', name='severity', native_enum=False, length=64), nullable=False),
    sa.Column('status', sa.Enum('open', 'acknowledged', 'resolved', 'false_positive', name='incident_status', native_enum=False, length=64), nullable=False),
    sa.Column('mode_at_detection', sa.Enum('alert_only', 'enforce', 'lockdown', name='shield_mode', native_enum=False, length=64), nullable=False),
    sa.Column('dry_run', sa.Boolean(), nullable=False),
    sa.Column('detected_at', shield.db.models.UTCDateTime(timezone=True), nullable=False),
    sa.Column('window_start', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('event_count', sa.Integer(), nullable=False),
    sa.Column('threshold_count', sa.Integer(), nullable=False),
    sa.Column('window_seconds', sa.Integer(), nullable=False),
    sa.Column('policy_version', sa.Integer(), nullable=False),
    sa.Column('response', sa.Enum('alert_only', 'strip_dangerous_roles', 'timeout', 'delete_messages', 'lockdown', 'raid_mode', name='response_action', native_enum=False, length=64), nullable=False),
    sa.Column('outcome', sa.Enum('pending', 'succeeded', 'partial', 'failed', 'skipped', 'dry_run', name='enforcement_status', native_enum=False, length=64), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('acknowledged_by', sa.BigInteger(), nullable=True),
    sa.Column('acknowledged_at', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('acknowledgement_note', sa.Text(), nullable=True),
    sa.Column('notified_at', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('created_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_incidents_correlation', 'incidents', ['correlation_id'], unique=False)
    op.create_index('ix_incidents_guild_actor', 'incidents', ['guild_id', 'actor_id'], unique=False)
    op.create_index('ix_incidents_guild_status', 'incidents', ['guild_id', 'status'], unique=False)
    op.create_index('ix_incidents_guild_time', 'incidents', ['guild_id', 'detected_at'], unique=False)
    op.create_table('snapshots',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('guild_id', sa.BigInteger(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('kind', sa.Enum('startup', 'scheduled', 'manual', 'pre_change', 'pre_restore', name='snapshot_kind', native_enum=False, length=64), nullable=False),
    sa.Column('taken_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('taken_by', sa.BigInteger(), nullable=True),
    sa.Column('checksum', sa.String(length=64), nullable=False),
    sa.Column('encrypted', sa.Boolean(), nullable=False),
    sa.Column('payload', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('payload_ciphertext', sa.LargeBinary(), nullable=True),
    sa.Column('summary', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('schema_version', sa.Integer(), nullable=False),
    sa.Column('validated', sa.Boolean(), nullable=False),
    sa.Column('validation_errors', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.CheckConstraint('version >= 1', name='ck_snapshot_version'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('guild_id', 'version', name='uq_snapshot_version')
    )
    op.create_index('ix_snapshots_guild_time', 'snapshots', ['guild_id', 'taken_at'], unique=False)
    op.create_table('enforcement_actions',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('guild_id', sa.BigInteger(), nullable=False),
    sa.Column('incident_id', sa.BigInteger(), nullable=True),
    sa.Column('idempotency_key', sa.String(length=200), nullable=False),
    sa.Column('action_type', sa.String(length=64), nullable=False),
    sa.Column('target_type', sa.String(length=32), nullable=True),
    sa.Column('target_id', sa.BigInteger(), nullable=True),
    sa.Column('status', sa.Enum('pending', 'succeeded', 'partial', 'failed', 'skipped', 'dry_run', name='enforcement_status', native_enum=False, length=64), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('before_state', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('after_state', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('detail', sa.Text(), nullable=True),
    sa.Column('started_at', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('finished_at', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('created_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('idempotency_key', name='uq_enforcement_idempotency')
    )
    op.create_index('ix_enforcement_guild', 'enforcement_actions', ['guild_id', 'created_at'], unique=False)
    op.create_index('ix_enforcement_incident', 'enforcement_actions', ['incident_id'], unique=False)
    op.create_table('guild_policies',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('guild_id', sa.BigInteger(), nullable=False),
    sa.Column('action_key', sa.Enum('mass_ban', 'mass_kick', 'channel_delete', 'channel_create_flood', 'role_delete', 'role_create_flood', 'dangerous_permission_change', 'dangerous_role_grant', 'bot_add', 'webhook_create', 'webhook_delete', 'webhook_update', 'mass_mention', 'join_flood', 'message_spam', 'duplicate_spam', 'guild_settings_change', 'vanity_url_change', name='action_key', native_enum=False, length=64), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('threshold_count', sa.Integer(), nullable=False),
    sa.Column('window_seconds', sa.Integer(), nullable=False),
    sa.Column('cooldown_seconds', sa.Integer(), nullable=False),
    sa.Column('response', sa.Enum('alert_only', 'strip_dangerous_roles', 'timeout', 'delete_messages', 'lockdown', 'raid_mode', name='response_action', native_enum=False, length=64), nullable=False),
    sa.Column('severity', sa.Enum('low', 'medium', 'high', 'critical', name='severity', native_enum=False, length=64), nullable=False),
    sa.Column('dry_run', sa.Boolean(), nullable=True),
    sa.Column('requires_confirmed_actor', sa.Boolean(), nullable=False),
    sa.Column('options', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('updated_by', sa.BigInteger(), nullable=True),
    sa.Column('created_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('cooldown_seconds >= 0', name='ck_policy_cooldown'),
    sa.CheckConstraint('threshold_count >= 1', name='ck_policy_threshold'),
    sa.CheckConstraint('window_seconds >= 1', name='ck_policy_window'),
    sa.ForeignKeyConstraint(['guild_id'], ['guild_settings.guild_id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('guild_id', 'action_key', name='uq_guild_policy')
    )
    op.create_index('ix_guild_policies_guild', 'guild_policies', ['guild_id'], unique=False)
    op.create_table('restore_jobs',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('guild_id', sa.BigInteger(), nullable=False),
    sa.Column('snapshot_id', sa.BigInteger(), nullable=False),
    sa.Column('mode', sa.Enum('preview', 'apply', name='restore_mode', native_enum=False, length=64), nullable=False),
    sa.Column('status', sa.Enum('previewed', 'awaiting_approval', 'applying', 'completed', 'partial', 'failed', 'expired', name='restore_status', native_enum=False, length=64), nullable=False),
    sa.Column('requested_by', sa.BigInteger(), nullable=False),
    sa.Column('approved_by', sa.BigInteger(), nullable=True),
    sa.Column('approval_token', sa.String(length=32), nullable=True),
    sa.Column('token_expires_at', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('scope', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('plan', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('result', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('id_map', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('finished_at', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('created_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['snapshot_id'], ['snapshots.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_restore_guild_time', 'restore_jobs', ['guild_id', 'created_at'], unique=False)
    op.create_index('ix_restore_token', 'restore_jobs', ['guild_id', 'approval_token'], unique=False)
    op.create_table('trusted_entities',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('guild_id', sa.BigInteger(), nullable=False),
    sa.Column('entity_type', sa.String(length=16), nullable=False),
    sa.Column('entity_id', sa.BigInteger(), nullable=False),
    sa.Column('scopes', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('added_by', sa.BigInteger(), nullable=False),
    sa.Column('expires_at', shield.db.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('created_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', shield.db.models.UTCDateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("entity_type IN ('user','role')", name='ck_trusted_entity_type'),
    sa.ForeignKeyConstraint(['guild_id'], ['guild_settings.guild_id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('guild_id', 'entity_type', 'entity_id', name='uq_trusted_entity')
    )
    op.create_index('ix_trusted_entities_guild', 'trusted_entities', ['guild_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_trusted_entities_guild', table_name='trusted_entities')
    op.drop_table('trusted_entities')
    op.drop_index('ix_restore_token', table_name='restore_jobs')
    op.drop_index('ix_restore_guild_time', table_name='restore_jobs')
    op.drop_table('restore_jobs')
    op.drop_index('ix_guild_policies_guild', table_name='guild_policies')
    op.drop_table('guild_policies')
    op.drop_index('ix_enforcement_incident', table_name='enforcement_actions')
    op.drop_index('ix_enforcement_guild', table_name='enforcement_actions')
    op.drop_table('enforcement_actions')
    op.drop_index('ix_snapshots_guild_time', table_name='snapshots')
    op.drop_table('snapshots')
    op.drop_index('ix_incidents_guild_time', table_name='incidents')
    op.drop_index('ix_incidents_guild_status', table_name='incidents')
    op.drop_index('ix_incidents_guild_actor', table_name='incidents')
    op.drop_index('ix_incidents_correlation', table_name='incidents')
    op.drop_table('incidents')
    op.drop_table('guild_settings')
    op.drop_index('ix_event_guild_actor_time', table_name='event_records')
    op.drop_index('ix_event_guild_action_time', table_name='event_records')
    op.drop_index('ix_event_correlation', table_name='event_records')
    op.drop_table('event_records')
    op.drop_index('ix_cooldowns_expiry', table_name='cooldowns')
    op.drop_table('cooldowns')
    op.drop_index('ix_command_audit_user', table_name='command_audit')
    op.drop_index('ix_command_audit_guild_time', table_name='command_audit')
    op.drop_table('command_audit')
    op.drop_table('audit_cursors')
