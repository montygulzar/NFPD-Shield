"""Correlation identifiers.

Every ingested event carries a correlation ID. Incidents, enforcement actions,
log lines, Discord alerts and restore jobs all reference it so an operator can
reconstruct a full causal chain from a single string.
"""

from __future__ import annotations

import contextvars
import uuid

_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "shield_correlation_id", default=None
)


def new_correlation_id(prefix: str = "evt") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def get_correlation_id() -> str | None:
    return _correlation_id.get()


def set_correlation_id(value: str | None) -> contextvars.Token:
    return _correlation_id.set(value)


def reset_correlation_id(token: contextvars.Token) -> None:
    _correlation_id.reset(token)


class correlation_scope:
    """Context manager binding a correlation ID to the current task."""

    __slots__ = ("_value", "_token")

    def __init__(self, value: str | None = None, prefix: str = "evt") -> None:
        self._value = value or new_correlation_id(prefix)
        self._token: contextvars.Token | None = None

    @property
    def correlation_id(self) -> str:
        return self._value

    def __enter__(self) -> str:
        self._token = set_correlation_id(self._value)
        return self._value

    def __exit__(self, *exc: object) -> None:
        if self._token is not None:
            reset_correlation_id(self._token)
            self._token = None
