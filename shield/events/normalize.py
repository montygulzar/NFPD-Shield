"""Event normalisation and deduplication keys.

Every gateway or audit-log signal is converted into exactly one
:class:`NormalizedEvent` before any detector sees it. The pipeline is:

    ingest -> normalize -> deduplicate -> audit attribution -> policy
    evaluation -> incident creation -> response -> snapshot/restore -> notify

The dedupe key is the contract that makes the pipeline safe against Discord
redelivering an event (gateway resume, multiple shards, a second process
observing the same guild). It must be derived only from stable facts about the
event, never from the receive time.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from shield.constants import ActionKey, Confidence, EventSource
from shield.observability.correlation import new_correlation_id

#: Width of the coarse time bucket used by dedupe keys for events whose target
#: can legitimately be acted on more than once.
DEDUPE_BUCKET_SECONDS = 10

#: Actions whose target can legitimately recur (a user can be banned twice, a
#: guild can be edited twice). Their dedupe key carries a time bucket.
REPEATABLE_TARGET_ACTIONS: frozenset[ActionKey] = frozenset(
    {
        ActionKey.MASS_BAN,
        ActionKey.MASS_KICK,
        ActionKey.JOIN_FLOOD,
        ActionKey.BOT_ADD,
        ActionKey.WEBHOOK_CREATE,
        ActionKey.WEBHOOK_DELETE,
        ActionKey.WEBHOOK_UPDATE,
        ActionKey.GUILD_SETTINGS_CHANGE,
        ActionKey.VANITY_URL_CHANGE,
        ActionKey.DANGEROUS_ROLE_GRANT,
        ActionKey.DANGEROUS_PERMISSION_CHANGE,
    }
)


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


@dataclass(slots=True)
class NormalizedEvent:
    """A single security-relevant occurrence in one guild."""

    guild_id: int
    action_key: ActionKey
    source: EventSource
    occurred_at: datetime
    #: Monotonic receive time, used for every rate window.
    monotonic: float = field(default_factory=time.monotonic)
    actor_id: int | None = None
    actor_confidence: Confidence = Confidence.UNKNOWN
    target_type: str | None = None
    target_id: int | None = None
    channel_id: int | None = None
    audit_entry_id: int | None = None
    correlation_id: str = field(default_factory=lambda: new_correlation_id("evt"))
    payload: dict[str, Any] = field(default_factory=dict)
    #: Populated for message events when the Message Content intent is enabled.
    content_hash: str | None = None
    #: Unique mention targets observed on this message.
    mention_ids: tuple[int, ...] = ()
    mentions_everyone: bool = False
    #: True when the event was produced by Shield's own restoration /
    #: enforcement writes and must never feed a detector.
    self_inflicted: bool = False

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None:
            self.occurred_at = self.occurred_at.replace(tzinfo=timezone.utc)
        else:
            self.occurred_at = self.occurred_at.astimezone(timezone.utc)

    @property
    def dedupe_key(self) -> str:
        """Stable identity of this occurrence.

        The key must be derivable from facts that are identical across a
        redelivery, which is why it deliberately does **not** include the actor:
        attribution happens after deduplication and may differ between a first
        delivery and a replay (the audit entry is consumed once).

        Preference order:

        1. The audit-log entry ID - globally unique per administrative action.
        2. The target object ID. For a target that can only be acted on once
           (a channel or role deletion, a specific message) that alone is
           unique forever.
        3. The target ID plus a coarse time bucket, for targets that can
           legitimately repeat (the same user banned twice, webhooks changed in
           the same channel twice, the guild edited twice).
        4. A content hash of the remaining salient fields plus the time bucket.

        Trade-off, stated plainly: the time bucket means two genuinely distinct
        actions on the same target inside :data:`DEDUPE_BUCKET_SECONDS` collapse
        into one event, and a redelivery that straddles a bucket boundary is
        counted twice. Both are preferable to an attacker evading detection, and
        the audit-entry path (used for most administrative actions) is exact.
        """
        if self.audit_entry_id:
            return f"{self.guild_id}:{self.action_key.value}:audit:{self.audit_entry_id}"
        if self.target_id is not None:
            base = f"{self.guild_id}:{self.action_key.value}:tgt:{self.target_id}"
            if self.action_key in REPEATABLE_TARGET_ACTIONS:
                base += f":b{self._bucket}"
            return base
        digest = hashlib.sha256(
            "|".join(
                [
                    str(self.guild_id),
                    self.action_key.value,
                    str(self.channel_id or ""),
                    self.content_hash or "",
                    str(self._bucket),
                ]
            ).encode("utf-8")
        ).hexdigest()[:40]
        return f"{self.guild_id}:{self.action_key.value}:h:{digest}"

    @property
    def _bucket(self) -> int:
        return int(self.occurred_at.timestamp() // DEDUPE_BUCKET_SECONDS)

    def scope_key(self) -> str:
        """Cooldown / escalation scope: one actor and one action."""
        actor = self.actor_id if self.actor_id is not None else "unattributed"
        return f"{self.action_key.value}:{actor}"

    def as_log_context(self) -> dict[str, Any]:
        return {
            "guild_id": self.guild_id,
            "action": self.action_key.value,
            "source": self.source.value,
            "actor_id": self.actor_id,
            "confidence": self.actor_confidence.value,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "channel_id": self.channel_id,
            "occurred_at": self.occurred_at.isoformat(),
            "audit_entry_id": self.audit_entry_id,
            "dedupe_key": self.dedupe_key,
        }


def hash_content(content: str) -> str:
    """Stable, non-reversible fingerprint of a message.

    Shield never persists message bodies. Duplicate-spam detection only needs
    to know that two messages were identical, so a truncated SHA-256 of the
    normalised text is stored instead of the text itself.
    """
    normalized = " ".join(content.lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]
