"""Authorisation / allowlist evaluation.

Trust model (deliberately narrow):

* The **Discord guild owner** is the only implicitly trusted principal, and
  even then only in the sense that Shield will never sanction them - their
  actions are still logged and alerted on.
* **Shield's own bot user** is exempt so that its restorative writes cannot
  trigger its own detectors.
* Everyone else must be added to ``trusted_entities`` explicitly by the guild
  owner or an authorised delegate. Administrator, Manage Guild, "is a bot" and
  "has a high role" grant **no** implicit trust: those are exactly the
  privileges a compromised-admin or malicious-bot attack abuses.
* The global bot operator (``OWNERID``) is a bot operator, not a guild
  principal. It is never exempt from a guild's protections.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from shield.constants import SCOPE_ACTIONS, ActionKey, TrustScope


@dataclass(frozen=True, slots=True)
class TrustEntry:
    """Plain, ORM-free view of one allowlist row (easy to unit test)."""

    entity_type: str  # "user" | "role"
    entity_id: int
    scopes: tuple[str, ...]
    expires_at: datetime | None = None

    def active(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return True
        moment = now or datetime.now(tz=timezone.utc)
        expires = (
            self.expires_at
            if self.expires_at.tzinfo
            else self.expires_at.replace(tzinfo=timezone.utc)
        )
        return expires > moment

    def covers(self, action_key: ActionKey) -> bool:
        for raw in self.scopes:
            try:
                scope = TrustScope(raw)
            except ValueError:
                continue
            if action_key in SCOPE_ACTIONS.get(scope, frozenset()):
                return True
        return False


@dataclass(frozen=True, slots=True)
class TrustDecision:
    """Why an actor is (or is not) exempt from one policy."""

    trusted: bool
    #: ``owner`` | ``bot_self`` | ``allowlist_user`` | ``allowlist_role`` | ``none``
    basis: str
    #: Owner actions are never punished, but they are always reported.
    alert_anyway: bool = False
    detail: str = ""

    @property
    def is_guild_owner(self) -> bool:
        return self.basis == "owner"


def entries_from_rows(rows: Iterable[object]) -> tuple[TrustEntry, ...]:
    """Adapt ORM ``TrustedEntity`` rows into :class:`TrustEntry` values."""
    out: list[TrustEntry] = []
    for row in rows:
        scopes = tuple(str(s) for s in (getattr(row, "scopes", None) or ()))
        out.append(
            TrustEntry(
                entity_type=str(row.entity_type),
                entity_id=int(row.entity_id),
                scopes=scopes or (TrustScope.ALL.value,),
                expires_at=getattr(row, "expires_at", None),
            )
        )
    return tuple(out)


def evaluate_trust(
    *,
    action_key: ActionKey,
    actor_id: int | None,
    actor_role_ids: Sequence[int] = (),
    guild_owner_id: int | None,
    bot_user_id: int | None,
    entries: Sequence[TrustEntry] = (),
    now: datetime | None = None,
) -> TrustDecision:
    """Decide whether ``actor_id`` is exempt from ``action_key``."""
    if actor_id is None:
        return TrustDecision(False, "none", detail="actor not attributed")

    if bot_user_id is not None and actor_id == bot_user_id:
        return TrustDecision(
            True, "bot_self", detail="action performed by Shield itself (self-protection)"
        )

    if guild_owner_id is not None and actor_id == guild_owner_id:
        return TrustDecision(
            True,
            "owner",
            alert_anyway=True,
            detail="actor is the Discord guild owner: alert only, never sanctioned",
        )

    role_ids = set(actor_role_ids)
    for entry in entries:
        if not entry.active(now):
            continue
        if entry.entity_type == "user" and entry.entity_id == actor_id:
            if entry.covers(action_key):
                return TrustDecision(
                    True,
                    "allowlist_user",
                    detail=f"user allowlisted for scopes {','.join(entry.scopes)}",
                )
        elif entry.entity_type == "role" and entry.entity_id in role_ids:
            if entry.covers(action_key):
                return TrustDecision(
                    True,
                    "allowlist_role",
                    detail=(
                        f"role {entry.entity_id} allowlisted for scopes "
                        f"{','.join(entry.scopes)}"
                    ),
                )

    return TrustDecision(False, "none", detail="actor is not allowlisted for this action")
