"""Self-action suppression.

When Shield restores 40 channels or strips a role, Discord emits the very
gateway events Shield watches for. Without suppression the bot would detect its
own repair work as a channel-creation flood and lock the guild down.

Every write Shield performs is registered here *before* the API call, with a
short TTL. The event pipeline consults :meth:`SelfActionGuard.is_self` and marks
matching events ``self_inflicted``, which makes the policy engine ignore them
while still recording them in the event log for the audit trail.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass

#: How long a registered self-action stays suppressing. Generous enough to
#: cover gateway delivery latency, short enough that an attacker cannot hide
#: inside the window.
DEFAULT_TTL = 30.0


@dataclass(slots=True)
class _Entry:
    key: tuple[int, str, int | None]
    expires: float


class SelfActionGuard:
    __slots__ = ("_entries", "_index", "_clock", "_ttl", "_bot_user_id")

    def __init__(self, ttl: float = DEFAULT_TTL, clock=None) -> None:  # noqa: ANN001
        self._entries: deque[_Entry] = deque()
        self._index: dict[tuple[int, str, int | None], int] = {}
        self._clock = clock or time.monotonic
        self._ttl = ttl
        self._bot_user_id: int | None = None

    def bind_bot(self, bot_user_id: int | None) -> None:
        self._bot_user_id = bot_user_id

    @property
    def bot_user_id(self) -> int | None:
        return self._bot_user_id

    def register(
        self, guild_id: int, kind: str, object_id: int | None = None, count: int = 1
    ) -> None:
        """Declare that Shield is about to perform ``count`` writes of ``kind``."""
        self._expire()
        key = (guild_id, kind, object_id)
        self._entries.append(_Entry(key, self._clock() + self._ttl))
        self._index[key] = self._index.get(key, 0) + max(1, count)

    def is_self(self, guild_id: int, kind: str, object_id: int | None = None) -> bool:
        """Consume one suppression credit for this event, if present.

        Matching is tried most-specific-first: an exact object ID, then a
        wildcard registration for the kind (used by bulk restores where the new
        object IDs are not known in advance).
        """
        self._expire()
        if self._bot_user_id is not None and object_id == self._bot_user_id:
            return True
        for key in ((guild_id, kind, object_id), (guild_id, kind, None)):
            count = self._index.get(key, 0)
            if count > 0:
                if count == 1:
                    del self._index[key]
                else:
                    self._index[key] = count - 1
                return True
        return False

    def pending(self, guild_id: int | None = None) -> int:
        self._expire()
        if guild_id is None:
            return sum(self._index.values())
        return sum(v for k, v in self._index.items() if k[0] == guild_id)

    def clear_guild(self, guild_id: int) -> None:
        for key in [k for k in self._index if k[0] == guild_id]:
            del self._index[key]

    def _expire(self) -> None:
        now = self._clock()
        while self._entries and self._entries[0].expires <= now:
            entry = self._entries.popleft()
            count = self._index.get(entry.key, 0)
            if count <= 1:
                self._index.pop(entry.key, None)
            else:
                self._index[entry.key] = count - 1
