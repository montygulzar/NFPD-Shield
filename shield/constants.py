"""Shared enumerations and constants for NFPD Shield.

This module must stay free of third-party imports so that it can be used by
configuration validation, the database layer, the policy engine and the tests
without pulling in discord.py or SQLAlchemy.
"""

from __future__ import annotations

import enum


class ShieldMode(str, enum.Enum):
    """Per-guild operating mode."""

    ALERT_ONLY = "alert_only"
    ENFORCE = "enforce"
    LOCKDOWN = "lockdown"


class ActionKey(str, enum.Enum):
    """Canonical detector / policy identifiers.

    The string values are stable: they are persisted in PostgreSQL and accepted
    as slash-command arguments. Never rename a value without a migration.
    """

    MASS_BAN = "mass_ban"
    MASS_KICK = "mass_kick"
    CHANNEL_DELETE = "channel_delete"
    CHANNEL_CREATE_FLOOD = "channel_create_flood"
    ROLE_DELETE = "role_delete"
    ROLE_CREATE_FLOOD = "role_create_flood"
    DANGEROUS_PERMISSION_CHANGE = "dangerous_permission_change"
    DANGEROUS_ROLE_GRANT = "dangerous_role_grant"
    BOT_ADD = "bot_add"
    WEBHOOK_CREATE = "webhook_create"
    WEBHOOK_DELETE = "webhook_delete"
    WEBHOOK_UPDATE = "webhook_update"
    MASS_MENTION = "mass_mention"
    JOIN_FLOOD = "join_flood"
    MESSAGE_SPAM = "message_spam"
    DUPLICATE_SPAM = "duplicate_spam"
    GUILD_SETTINGS_CHANGE = "guild_settings_change"
    VANITY_URL_CHANGE = "vanity_url_change"

    @classmethod
    def from_value(cls, value: str) -> ActionKey:
        try:
            return cls(value.strip().lower())
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(
                f"unknown action key {value!r}; valid keys: "
                + ", ".join(sorted(k.value for k in cls))
            ) from exc


#: Detectors driven purely by gateway signals (no audit-log correlation needed).
DIRECT_GATEWAY_ACTIONS: frozenset[ActionKey] = frozenset(
    {
        ActionKey.MASS_MENTION,
        ActionKey.JOIN_FLOOD,
        ActionKey.MESSAGE_SPAM,
        ActionKey.DUPLICATE_SPAM,
    }
)

#: Detectors for destructive administrative events that require audit-log
#: correlation before an actor may be blamed.
AUDIT_CORRELATED_ACTIONS: frozenset[ActionKey] = frozenset(
    set(ActionKey) - set(DIRECT_GATEWAY_ACTIONS)
)


class ResponseAction(str, enum.Enum):
    """What enforcement is allowed to do for a policy."""

    ALERT_ONLY = "alert_only"
    STRIP_DANGEROUS_ROLES = "strip_dangerous_roles"
    TIMEOUT = "timeout"
    DELETE_MESSAGES = "delete_messages"
    LOCKDOWN = "lockdown"
    RAID_MODE = "raid_mode"


class Confidence(str, enum.Enum):
    """Actor attribution confidence.

    Only ``CONFIRMED`` may ever lead to a sanction against a member.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNKNOWN = "unknown"


class EventSource(str, enum.Enum):
    GATEWAY = "gateway"
    AUDIT_LOG = "audit_log"
    SYNTHETIC = "synthetic"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EnforcementStatus(str, enum.Enum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    DRY_RUN = "dry_run"


class SnapshotKind(str, enum.Enum):
    STARTUP = "startup"
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    PRE_CHANGE = "pre_change"
    PRE_RESTORE = "pre_restore"


class RestoreMode(str, enum.Enum):
    PREVIEW = "preview"
    APPLY = "apply"


class RestoreStatus(str, enum.Enum):
    PREVIEWED = "previewed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPLYING = "applying"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    EXPIRED = "expired"


class TrustScope(str, enum.Enum):
    """Granular allowlist scopes.

    ``ALL`` exempts an entity from every detector. Narrower scopes keep the
    blast radius of an allowlist entry small (e.g. a logging bot that only
    needs webhook exemption).
    """

    ALL = "all"
    DESTRUCTIVE = "destructive"
    #: Command authority only. Grants NO detection exemption whatsoever - it
    #: lets a delegate configure Shield, not bypass it.
    MANAGE_SHIELD = "manage_shield"
    #: Marks a moderation BOT whose actions are really a human moderator's. It
    #: grants no exemption: Shield reads the moderator out of the bot's audit
    #: reason and holds that person to the normal policies instead of the bot.
    MODERATION_PROXY = "moderation_proxy"
    WEBHOOKS = "webhooks"
    MESSAGES = "messages"
    BOTS = "bots"
    GUILD_SETTINGS = "guild_settings"


#: Scope -> action keys covered by that scope.
SCOPE_ACTIONS: dict[TrustScope, frozenset[ActionKey]] = {
    TrustScope.ALL: frozenset(ActionKey),
    # Deliberately empty: an administrative delegate is still policed.
    TrustScope.MANAGE_SHIELD: frozenset(),
    # Deliberately empty: the moderator behind the bot is policed in its place.
    TrustScope.MODERATION_PROXY: frozenset(),
    TrustScope.DESTRUCTIVE: frozenset(
        {
            ActionKey.MASS_BAN,
            ActionKey.MASS_KICK,
            ActionKey.CHANNEL_DELETE,
            ActionKey.CHANNEL_CREATE_FLOOD,
            ActionKey.ROLE_DELETE,
            ActionKey.ROLE_CREATE_FLOOD,
            ActionKey.DANGEROUS_PERMISSION_CHANGE,
            ActionKey.DANGEROUS_ROLE_GRANT,
        }
    ),
    TrustScope.WEBHOOKS: frozenset(
        {ActionKey.WEBHOOK_CREATE, ActionKey.WEBHOOK_DELETE, ActionKey.WEBHOOK_UPDATE}
    ),
    TrustScope.MESSAGES: frozenset(
        {ActionKey.MASS_MENTION, ActionKey.MESSAGE_SPAM, ActionKey.DUPLICATE_SPAM}
    ),
    TrustScope.BOTS: frozenset({ActionKey.BOT_ADD}),
    TrustScope.GUILD_SETTINGS: frozenset(
        {ActionKey.GUILD_SETTINGS_CHANGE, ActionKey.VANITY_URL_CHANGE}
    ),
}


#: Discord permissions treated as dangerous. Any role carrying one of these is
#: a candidate for stripping and any grant of one is a single-event policy hit.
DANGEROUS_PERMISSIONS: tuple[str, ...] = (
    "administrator",
    "manage_guild",
    "manage_roles",
    "manage_channels",
    "manage_webhooks",
    "ban_members",
    "kick_members",
    "moderate_members",
    "manage_messages",
    "mention_everyone",
    "manage_nicknames",
    "manage_emojis_and_stickers",
    "manage_events",
    "manage_threads",
    "view_audit_log",
)

#: The subset whose unauthorized grant is, on its own, an incident.
CRITICAL_PERMISSIONS: tuple[str, ...] = (
    "administrator",
    "manage_guild",
    "manage_roles",
    "manage_channels",
    "manage_webhooks",
    "ban_members",
    "kick_members",
)

#: Guild-level fields whose modification is security relevant.
PROTECTED_GUILD_FIELDS: tuple[str, ...] = (
    "name",
    "icon",
    "verification_level",
    "explicit_content_filter",
    "mfa_level",
    "default_notifications",
    "system_channel",
    "afk_channel",
    "owner",
    "vanity_url_code",
    "premium_progress_bar_enabled",
    "discovery_splash",
    "banner",
    "splash",
    "rules_channel",
    "public_updates_channel",
    "safety_alerts_channel",
)

#: Hard ceiling on how many Discord write calls a single enforcement or restore
#: job may make, regardless of configuration. Prevents runaway loops.
MAX_ENFORCEMENT_WRITES = 50
MAX_RESTORE_WRITES = 400

#: Maximum messages a bounded spam cleanup may delete.
MAX_SPAM_DELETE = 25

SNOWFLAKE_MIN = 10_000_000_000_000_000  # 17 digits
SNOWFLAKE_MAX = 9_223_372_036_854_775_807  # bigint max
