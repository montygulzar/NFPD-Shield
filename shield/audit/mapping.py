"""Mapping between Shield action keys and Discord audit-log actions.

Observability caveats are documented inline because they drive what Shield can
honestly promise:

* ``bot_add`` surfaces as ``AuditLogAction.bot_add``. The *actor* is the member
  who authorised the OAuth2 install. It is reliably present only when the bot
  has ``View Audit Log``.
* Webhook ``update`` entries expose changed fields but never the token.
* ``guild_update`` lumps many fields together; Discord does not emit a distinct
  audit action per field, so Shield inspects ``entry.changes``.
* ``vanity_url_code`` appears inside ``guild_update`` changes and only on guilds
  that have the VANITY_URL feature.
* Message *content* is never in the audit log; spam detection is gateway-only.
"""

from __future__ import annotations

from shield.constants import ActionKey

#: ActionKey -> attribute name on ``discord.AuditLogAction``.
#: Resolved lazily so this module imports without discord.py (used by tests).
AUDIT_ACTION_NAMES: dict[ActionKey, tuple[str, ...]] = {
    ActionKey.MASS_BAN: ("ban",),
    ActionKey.MASS_KICK: ("kick",),
    ActionKey.CHANNEL_DELETE: ("channel_delete",),
    ActionKey.CHANNEL_CREATE_FLOOD: ("channel_create",),
    ActionKey.ROLE_DELETE: ("role_delete",),
    ActionKey.ROLE_CREATE_FLOOD: ("role_create",),
    ActionKey.DANGEROUS_PERMISSION_CHANGE: ("role_update", "overwrite_update"),
    ActionKey.DANGEROUS_ROLE_GRANT: ("member_role_update",),
    ActionKey.BOT_ADD: ("bot_add",),
    ActionKey.WEBHOOK_CREATE: ("webhook_create",),
    ActionKey.WEBHOOK_DELETE: ("webhook_delete",),
    ActionKey.WEBHOOK_UPDATE: ("webhook_update",),
    ActionKey.GUILD_SETTINGS_CHANGE: ("guild_update",),
    ActionKey.VANITY_URL_CHANGE: ("guild_update",),
}

#: Detectors that cannot be attributed through the audit log at all.
GATEWAY_ONLY: frozenset[ActionKey] = frozenset(
    {
        ActionKey.MASS_MENTION,
        ActionKey.MESSAGE_SPAM,
        ActionKey.DUPLICATE_SPAM,
        ActionKey.JOIN_FLOOD,
    }
)


def audit_action_names(action_key: ActionKey) -> tuple[str, ...]:
    return AUDIT_ACTION_NAMES.get(action_key, ())


def resolve_audit_actions(action_key: ActionKey):  # noqa: ANN201
    """Return the ``discord.AuditLogAction`` members for an action key."""
    import discord

    resolved = []
    for name in audit_action_names(action_key):
        member = getattr(discord.AuditLogAction, name, None)
        if member is not None:
            resolved.append(member)
    return tuple(resolved)


#: Human-readable limitation notes, surfaced by ``/shield health``.
LIMITATIONS: dict[ActionKey, str] = {
    ActionKey.BOT_ADD: (
        "Requires View Audit Log. Shield cannot distinguish an authorised "
        "integration install from a malicious one without an allowlist, so the "
        "default response is alert-only."
    ),
    ActionKey.WEBHOOK_UPDATE: (
        "Webhook tokens are never exposed to bots. Suspicious webhook *messages* "
        "are only observable when the webhook posts in a channel Shield can read."
    ),
    ActionKey.GUILD_SETTINGS_CHANGE: (
        "Discord emits a single guild_update audit action for many fields; "
        "per-field attribution depends on entry.changes being populated."
    ),
    ActionKey.VANITY_URL_CHANGE: (
        "Only observable on guilds with the VANITY_URL feature, and only through "
        "guild_update audit changes. Not emitted as a gateway event."
    ),
    ActionKey.DANGEROUS_PERMISSION_CHANGE: (
        "Channel-level overwrite changes (overwrite_update) are attributable, but "
        "Shield only alerts on them when the resulting permissions are dangerous."
    ),
    ActionKey.MESSAGE_SPAM: (
        "Requires the Message Content privileged intent for duplicate detection; "
        "without it only message rate is observable."
    ),
    ActionKey.MASS_MENTION: (
        "Mention targets are available without Message Content, but matching "
        "@everyone/@here reliably requires it."
    ),
}
