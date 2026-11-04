"""Default strict policy set.

These are *starting values*, not guarantees. Every single-event policy
(threshold_count == 1) is high false-positive risk by construction, which is
why the default response for those is ``ALERT_ONLY`` even in enforce mode until
an operator deliberately raises it, and why a new guild starts in
``alert_only`` + ``dry_run``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shield.constants import ActionKey, ResponseAction, Severity


@dataclass(frozen=True, slots=True)
class PolicyDefault:
    action_key: ActionKey
    threshold_count: int
    window_seconds: int
    response: ResponseAction
    severity: Severity
    cooldown_seconds: int = 60
    enabled: bool = True
    requires_confirmed_actor: bool = True
    #: Extra knobs interpreted by the matching detector.
    options: dict[str, Any] = field(default_factory=dict)
    #: Why this default is risky / how it should be tuned. Shown by
    #: ``/shield thresholds view``.
    note: str = ""


DEFAULT_POLICIES: tuple[PolicyDefault, ...] = (
    PolicyDefault(
        ActionKey.MASS_BAN,
        threshold_count=2,
        window_seconds=15,
        response=ResponseAction.STRIP_DANGEROUS_ROLES,
        severity=Severity.CRITICAL,
        note="Two bans in 15s by one actor. Raise for large guilds with active mod teams.",
    ),
    PolicyDefault(
        ActionKey.MASS_KICK,
        threshold_count=2,
        window_seconds=15,
        response=ResponseAction.STRIP_DANGEROUS_ROLES,
        severity=Severity.CRITICAL,
        note="Two kicks in 15s by one actor.",
    ),
    PolicyDefault(
        ActionKey.CHANNEL_DELETE,
        threshold_count=1,
        window_seconds=15,
        response=ResponseAction.STRIP_DANGEROUS_ROLES,
        severity=Severity.CRITICAL,
        note="Single-event policy: HIGH false-positive risk during legitimate restructuring. "
        "Validate in a staging guild before enforcing.",
    ),
    PolicyDefault(
        ActionKey.CHANNEL_CREATE_FLOOD,
        threshold_count=4,
        window_seconds=20,
        response=ResponseAction.STRIP_DANGEROUS_ROLES,
        severity=Severity.HIGH,
        note="Four channel creations in 20s.",
    ),
    PolicyDefault(
        ActionKey.ROLE_DELETE,
        threshold_count=1,
        window_seconds=15,
        response=ResponseAction.STRIP_DANGEROUS_ROLES,
        severity=Severity.CRITICAL,
        note="Single-event policy: HIGH false-positive risk. See channel_delete.",
    ),
    PolicyDefault(
        ActionKey.ROLE_CREATE_FLOOD,
        threshold_count=4,
        window_seconds=20,
        response=ResponseAction.STRIP_DANGEROUS_ROLES,
        severity=Severity.HIGH,
        note="Four role creations in 20s.",
    ),
    PolicyDefault(
        ActionKey.DANGEROUS_PERMISSION_CHANGE,
        threshold_count=1,
        window_seconds=15,
        response=ResponseAction.STRIP_DANGEROUS_ROLES,
        severity=Severity.CRITICAL,
        note="Elevation of a role to a dangerous permission. Single event by design; "
        "allowlist your role-management bots.",
    ),
    PolicyDefault(
        ActionKey.DANGEROUS_ROLE_GRANT,
        threshold_count=1,
        window_seconds=15,
        response=ResponseAction.STRIP_DANGEROUS_ROLES,
        severity=Severity.CRITICAL,
        note="Granting Administrator / Manage Roles / Manage Channels / Ban / Kick / "
        "Manage Webhooks / Manage Guild to a member.",
    ),
    PolicyDefault(
        ActionKey.BOT_ADD,
        threshold_count=1,
        window_seconds=60,
        response=ResponseAction.ALERT_ONLY,
        severity=Severity.HIGH,
        note="Alert-only by default: integration installs are frequently legitimate and "
        "attribution must be confirmed from the audit log before any sanction.",
    ),
    PolicyDefault(
        ActionKey.WEBHOOK_CREATE,
        threshold_count=1,
        window_seconds=15,
        response=ResponseAction.ALERT_ONLY,
        severity=Severity.MEDIUM,
        note="Alert-only: legitimate automation creates webhooks routinely. Allowlist "
        "known integrations, then raise the response if desired.",
    ),
    PolicyDefault(
        ActionKey.WEBHOOK_DELETE,
        threshold_count=1,
        window_seconds=15,
        response=ResponseAction.ALERT_ONLY,
        severity=Severity.MEDIUM,
    ),
    PolicyDefault(
        ActionKey.WEBHOOK_UPDATE,
        threshold_count=1,
        window_seconds=15,
        response=ResponseAction.ALERT_ONLY,
        severity=Severity.LOW,
    ),
    PolicyDefault(
        ActionKey.MASS_MENTION,
        threshold_count=5,
        window_seconds=10,
        response=ResponseAction.TIMEOUT,
        severity=Severity.MEDIUM,
        cooldown_seconds=30,
        requires_confirmed_actor=False,
        options={
            "everyone_is_violation": True,
            "timeout_seconds": 600,
            "delete_messages": True,
            "exempt_channel_ids": [],
        },
        note=">=5 unique mentions or any @everyone/@here from a non-allowlisted member "
        "in 10s. Author attribution is direct, so no audit correlation is needed.",
    ),
    PolicyDefault(
        ActionKey.JOIN_FLOOD,
        threshold_count=8,
        window_seconds=20,
        response=ResponseAction.RAID_MODE,
        severity=Severity.HIGH,
        cooldown_seconds=120,
        requires_confirmed_actor=False,
        options={
            "raid_mode_minutes": 30,
            "slowmode_seconds": 30,
            "raise_verification_level": True,
            "new_account_hours": 24,
            "new_account_weight": 2,
        },
        note="Never bans joiners. Enables a reversible raid mode (verification level + "
        "slowmode) for the configured duration.",
    ),
    PolicyDefault(
        ActionKey.MESSAGE_SPAM,
        threshold_count=6,
        window_seconds=8,
        response=ResponseAction.TIMEOUT,
        severity=Severity.LOW,
        cooldown_seconds=30,
        requires_confirmed_actor=False,
        options={
            "timeout_seconds": 300,
            "delete_messages": True,
            "max_delete": 25,
            "exempt_channel_ids": [],
        },
        note=">=6 messages in 8s per user. Add busy/bot channels to exempt_channel_ids.",
    ),
    PolicyDefault(
        ActionKey.DUPLICATE_SPAM,
        threshold_count=4,
        window_seconds=15,
        response=ResponseAction.TIMEOUT,
        severity=Severity.LOW,
        cooldown_seconds=30,
        requires_confirmed_actor=False,
        options={
            "timeout_seconds": 300,
            "delete_messages": True,
            "max_delete": 25,
            "min_length": 3,
            "exempt_channel_ids": [],
        },
        note=">=4 identical messages in 15s per user. Requires the Message Content intent.",
    ),
    PolicyDefault(
        ActionKey.GUILD_SETTINGS_CHANGE,
        threshold_count=1,
        window_seconds=15,
        response=ResponseAction.ALERT_ONLY,
        severity=Severity.HIGH,
        note="Name/icon/verification/security changes. Alert-only: Discord's audit "
        "coverage of guild updates is partial and attribution can be missing.",
    ),
    PolicyDefault(
        ActionKey.VANITY_URL_CHANGE,
        threshold_count=1,
        window_seconds=15,
        response=ResponseAction.ALERT_ONLY,
        severity=Severity.HIGH,
        note="Only observable on guilds with the VANITY_URL feature, and only when the "
        "audit log exposes the change.",
    ),
)

DEFAULTS_BY_KEY: dict[ActionKey, PolicyDefault] = {p.action_key: p for p in DEFAULT_POLICIES}

#: Bumped whenever DEFAULT_POLICIES changes semantics. Persisted on every
#: incident so historical decisions remain explainable.
POLICY_SCHEMA_VERSION = 1


def default_for(action_key: ActionKey) -> PolicyDefault:
    return DEFAULTS_BY_KEY[action_key]


def single_event_actions() -> tuple[ActionKey, ...]:
    """Policies that fire on one event - the high false-positive set."""
    return tuple(p.action_key for p in DEFAULT_POLICIES if p.threshold_count == 1)
