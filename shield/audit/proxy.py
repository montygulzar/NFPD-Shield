"""Seeing through a moderation bot to the moderator who used it.

When a moderator bans through a moderation bot, Discord's audit log names the
**bot** as the actor. Left alone, Shield would pool every moderator's actions
into the bot's rate window, blame the bot for a rogue moderator's mass ban, and
- because a bot's integration role cannot be removed - fail to contain anything.

A bot the guild owner marks with the ``moderation_proxy`` trust scope is treated
as a pass-through: Shield reads the moderator's ID from the audit reason the bot
wrote and holds that person to the normal policies.

Why the reason text can be trusted here, and only here:

* The scope is only ever honoured for **bot** accounts. A human can type any
  reason into Discord's own ban dialog, so a human "proxy" could frame someone.
* The bot builds the prefix itself as ``"<Label> by <name> (<id>): <reason>"``.
  The moderator controls only the trailing reason, which comes after the first
  ``(<id>): `` - and the parser takes the first, anchored at the start.
* A reason that does not parse (the bot's automatic, moderator-less actions)
  resolves to nobody. Shield then alerts without sanctioning anyone.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from shield.constants import SNOWFLAKE_MAX, SNOWFLAKE_MIN, TrustScope

#: ``Ban by someone (123456789012345678): spamming`` -> the ID in parentheses.
_PREFIX = re.compile(r"^[A-Za-z][A-Za-z ]{0,40} by .{1,80}? \((\d{17,20})\): ")


def parse_moderator_id(reason: str | None) -> int | None:
    """The moderator ID a proxy bot recorded at the start of an audit reason."""
    if not reason:
        return None
    match = _PREFIX.match(reason)
    if match is None:
        return None
    moderator_id = int(match.group(1))
    if not (SNOWFLAKE_MIN <= moderator_id <= SNOWFLAKE_MAX):
        return None
    return moderator_id


def proxy_bot_ids(entries: Iterable[object]) -> frozenset[int]:
    """User IDs carrying an unexpired ``moderation_proxy`` allowlist entry."""
    from shield.policies.trust import entries_from_rows

    return frozenset(
        entry.entity_id
        for entry in entries_from_rows(entries)
        if entry.entity_type == "user"
        and TrustScope.MODERATION_PROXY.value in entry.scopes
        and entry.active()
    )
