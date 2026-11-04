"""Snapshot serialisation, checksums and optional encryption.

Privacy / scope decisions (deliberate, documented in README):

* **No message content is ever snapshotted.** Discord does not let a bot
  restore message history, so storing it would be risk without benefit.
* **No webhook tokens.** A webhook token is a bearer credential for posting as
  the server. Shield stores only ``id``, ``name``, ``channel_id`` and ``type``,
  and only when the guild opts in (``snapshot_include_webhooks``).
* **No invite codes, no member lists, no audit text.**
* Everything stored is structural metadata needed to rebuild roles and channels.

Payloads are JSON. With ``SNAPSHOT_ENCRYPTION_KEY`` set, the JSON is gzipped
and encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before it reaches
PostgreSQL, so a database dump does not leak guild structure.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

SNAPSHOT_SCHEMA_VERSION = 1

#: Channel attributes captured per channel type. Anything Discord will not let
#: a bot recreate is excluded rather than silently dropped later.
TEXT_FIELDS = ("topic", "slowmode_delay", "nsfw", "default_auto_archive_duration")
VOICE_FIELDS = ("bitrate", "user_limit", "rtc_region")
FORUM_FIELDS = ("topic", "slowmode_delay", "nsfw", "default_thread_slowmode_delay")


class SnapshotEncryptionError(RuntimeError):
    pass


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def checksum(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def encrypt_payload(payload: dict[str, Any], key: str) -> bytes:
    from cryptography.fernet import Fernet

    try:
        fernet = Fernet(key.encode("ascii"))
    except Exception as exc:  # noqa: BLE001
        raise SnapshotEncryptionError(
            "SNAPSHOT_ENCRYPTION_KEY is not a valid Fernet key"
        ) from exc
    return fernet.encrypt(gzip.compress(canonical_json(payload)))


def decrypt_payload(ciphertext: bytes, key: str) -> dict[str, Any]:
    from cryptography.fernet import Fernet, InvalidToken

    try:
        fernet = Fernet(key.encode("ascii"))
        plain = fernet.decrypt(ciphertext)
    except InvalidToken as exc:
        raise SnapshotEncryptionError(
            "snapshot could not be decrypted: the encryption key does not match the "
            "key used when the snapshot was taken"
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise SnapshotEncryptionError(f"snapshot decryption failed: {exc}") from exc
    return json.loads(gzip.decompress(plain).decode("utf-8"))


def load_snapshot_payload(row, key: str | None) -> dict[str, Any]:
    """Return the plaintext payload for a snapshot row."""
    if getattr(row, "encrypted", False):
        if not key:
            raise SnapshotEncryptionError(
                "this snapshot is encrypted but SNAPSHOT_ENCRYPTION_KEY is not set in "
                "the environment; restore is impossible until the key is restored"
            )
        return decrypt_payload(row.payload_ciphertext or b"", key)
    return dict(row.payload or {})


# ---------------------------------------------------------------------
# Discord -> snapshot
# ---------------------------------------------------------------------
def serialize_role(role) -> dict[str, Any]:  # noqa: ANN001
    return {
        "id": int(role.id),
        "name": str(getattr(role, "name", "")),
        "permissions": int(getattr(getattr(role, "permissions", None), "value", 0) or 0),
        "color": int(getattr(getattr(role, "color", None), "value", 0) or 0),
        "hoist": bool(getattr(role, "hoist", False)),
        "mentionable": bool(getattr(role, "mentionable", False)),
        "position": int(getattr(role, "position", 0)),
        "managed": bool(getattr(role, "managed", False)),
        "is_default": bool(_call_or_attr(role, "is_default")),
        "is_premium_subscriber": bool(_call_or_attr(role, "is_premium_subscriber")),
        "icon": None,  # role icons require a boosted guild; not restorable by bots
    }


def overwrite_target_type(target) -> str:  # noqa: ANN001
    """Classify a permission-overwrite target as ``role`` or ``member``.

    Uses the real discord.py classes when available and falls back to structural
    duck-typing, so the classification is correct for every channel/role class
    (and for test doubles). Getting this wrong would make a restored overwrite
    look up a role ID in the member cache and silently drop the overwrite.
    """
    import discord

    if isinstance(target, discord.Role):
        return "role"
    if isinstance(target, (discord.Member, discord.User)):
        return "member"
    if hasattr(target, "roles") or hasattr(target, "guild_permissions"):
        return "member"
    if hasattr(target, "permissions") and hasattr(target, "position"):
        return "role"
    return "member"


def serialize_overwrites(channel) -> list[dict[str, Any]]:  # noqa: ANN001
    out: list[dict[str, Any]] = []
    overwrites = getattr(channel, "overwrites", None) or {}
    for target, overwrite in overwrites.items():
        try:
            allow, deny = overwrite.pair()
        except Exception:  # noqa: BLE001
            continue
        target_type = overwrite_target_type(target)
        out.append(
            {
                "target_id": int(getattr(target, "id", 0) or 0),
                "target_type": target_type,
                "target_name": str(getattr(target, "name", ""))[:100],
                "allow": int(getattr(allow, "value", 0) or 0),
                "deny": int(getattr(deny, "value", 0) or 0),
            }
        )
    return out


def serialize_channel(channel) -> dict[str, Any]:  # noqa: ANN001
    kind = channel.__class__.__name__
    data: dict[str, Any] = {
        "id": int(channel.id),
        "name": str(getattr(channel, "name", "")),
        "type": _channel_type_name(channel),
        "class": kind,
        "position": int(getattr(channel, "position", 0)),
        "parent_id": int(getattr(getattr(channel, "category", None), "id", 0) or 0) or None,
        "overwrites": serialize_overwrites(channel),
    }
    for field in TEXT_FIELDS + VOICE_FIELDS + FORUM_FIELDS:
        if hasattr(channel, field):
            value = getattr(channel, field)
            if value is None or isinstance(value, (str, int, bool, float)):
                data[field] = value
            else:
                data[field] = str(value)
    return data


def serialize_webhook(webhook) -> dict[str, Any]:  # noqa: ANN001
    """Metadata only - the token is never read or stored."""
    return {
        "id": int(webhook.id),
        "name": str(getattr(webhook, "name", "") or "")[:80],
        "channel_id": int(getattr(webhook, "channel_id", 0) or 0) or None,
        "type": str(getattr(getattr(webhook, "type", None), "name", "unknown")),
        "user_id": int(getattr(getattr(webhook, "user", None), "id", 0) or 0) or None,
        "created_at": _iso(getattr(webhook, "created_at", None)),
    }


def serialize_guild_settings(guild) -> dict[str, Any]:  # noqa: ANN001
    return {
        "id": int(guild.id),
        "name": str(getattr(guild, "name", "")),
        "owner_id": int(getattr(guild, "owner_id", 0) or 0) or None,
        "verification_level": _enum_name(getattr(guild, "verification_level", None)),
        "explicit_content_filter": _enum_name(getattr(guild, "explicit_content_filter", None)),
        "default_notifications": _enum_name(getattr(guild, "default_notifications", None)),
        "mfa_level": _enum_name(getattr(guild, "mfa_level", None)),
        "afk_timeout": int(getattr(guild, "afk_timeout", 0) or 0),
        "afk_channel_id": int(getattr(getattr(guild, "afk_channel", None), "id", 0) or 0) or None,
        "system_channel_id": int(getattr(getattr(guild, "system_channel", None), "id", 0) or 0)
        or None,
        "rules_channel_id": int(getattr(getattr(guild, "rules_channel", None), "id", 0) or 0)
        or None,
        "public_updates_channel_id": int(
            getattr(getattr(guild, "public_updates_channel", None), "id", 0) or 0
        )
        or None,
        "premium_progress_bar_enabled": bool(
            getattr(guild, "premium_progress_bar_enabled", False)
        ),
        "vanity_url_code": getattr(guild, "vanity_url_code", None),
        "features": sorted(str(f) for f in (getattr(guild, "features", ()) or ())),
        "icon_url": str(getattr(getattr(guild, "icon", None), "url", "") or "") or None,
        "banner_url": str(getattr(getattr(guild, "banner", None), "url", "") or "") or None,
    }


def build_snapshot(
    guild,  # noqa: ANN001
    *,
    include_webhooks: bool = True,
    webhooks: list[Any] | None = None,
) -> dict[str, Any]:
    """Serialise a guild's restorable structure."""
    roles = [
        serialize_role(r)
        for r in sorted(getattr(guild, "roles", []), key=lambda r: getattr(r, "position", 0))
    ]
    categories = [serialize_channel(c) for c in getattr(guild, "categories", []) or []]
    category_ids = {c["id"] for c in categories}
    # ``guild.channels`` includes categories; filter them out by their resolved
    # Discord channel type rather than by class name, so the split is correct
    # for every channel class.
    channels = [
        data
        for data in (serialize_channel(c) for c in getattr(guild, "channels", []) or [])
        if data["type"] != "category" and data["id"] not in category_ids
    ]
    payload: dict[str, Any] = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "taken_at": datetime.now(tz=timezone.utc).isoformat(),
        "guild": serialize_guild_settings(guild),
        "roles": roles,
        "categories": sorted(categories, key=lambda c: c["position"]),
        "channels": sorted(channels, key=lambda c: (c["parent_id"] or 0, c["position"])),
        "webhooks": (
            [serialize_webhook(w) for w in (webhooks or [])] if include_webhooks else []
        ),
        "counts": {
            "roles": len(roles),
            "categories": len(categories),
            "channels": len(channels),
            "members": int(getattr(guild, "member_count", 0) or 0),
            "webhooks": len(webhooks or []) if include_webhooks else 0,
        },
        "not_captured": [
            "message history and attachments (Discord provides no restore API)",
            "channel, role, emoji and sticker IDs (new objects always get new IDs)",
            "invites and their vanity analytics",
            "threads and forum posts",
            "webhook tokens (bearer credentials; intentionally never stored)",
            "integrations, app commands and bot configurations",
            "member role assignments (restored roles are empty by design)",
            "audit log history",
        ],
    }
    return payload


def summarize(payload: dict[str, Any]) -> dict[str, Any]:
    counts = payload.get("counts", {})
    guild = payload.get("guild", {})
    return {
        "guild_name": guild.get("name"),
        "roles": counts.get("roles", 0),
        "categories": counts.get("categories", 0),
        "channels": counts.get("channels", 0),
        "webhooks": counts.get("webhooks", 0),
        "members": counts.get("members", 0),
        "schema_version": payload.get("schema_version", SNAPSHOT_SCHEMA_VERSION),
    }


def validate(payload: dict[str, Any]) -> list[str]:
    """Structural validation. A snapshot that fails is stored but marked invalid
    so it can never be chosen as the source of a restore."""
    errors: list[str] = []
    if payload.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        errors.append(
            f"unsupported schema_version {payload.get('schema_version')!r} "
            f"(expected {SNAPSHOT_SCHEMA_VERSION})"
        )
    guild = payload.get("guild")
    if not isinstance(guild, dict) or not guild.get("id"):
        errors.append("guild block is missing or has no id")
    for key in ("roles", "categories", "channels"):
        if not isinstance(payload.get(key), list):
            errors.append(f"{key} must be a list")
    roles = payload.get("roles") or []
    if isinstance(roles, list):
        if not any(r.get("is_default") for r in roles if isinstance(r, dict)):
            errors.append("no @everyone role present; snapshot looks truncated")
        for role in roles:
            if not isinstance(role, dict) or "name" not in role or "permissions" not in role:
                errors.append("a role entry is malformed")
                break
    for channel in payload.get("channels") or []:
        if not isinstance(channel, dict) or "name" not in channel or "type" not in channel:
            errors.append("a channel entry is malformed")
            break
    return errors


# -- small helpers ----------------------------------------------------
def _call_or_attr(obj, name: str) -> Any:  # noqa: ANN001
    value = getattr(obj, name, False)
    if callable(value):
        try:
            return value()
        except Exception:  # noqa: BLE001
            return False
    return value


def _enum_name(value: Any) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "name", value))


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return None


def _channel_type_name(channel) -> str:  # noqa: ANN001
    kind = getattr(channel, "type", None)
    name = getattr(kind, "name", None)
    if name:
        return str(name)
    return channel.__class__.__name__.replace("Channel", "").lower() or "text"
