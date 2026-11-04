"""Structured JSON logging with secret redaction and log rotation.

Redaction happens in a :class:`logging.Filter` so that *every* record passing
through the root logger is scrubbed, including records emitted by discord.py,
SQLAlchemy and asyncpg, not just Shield's own calls.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import sys
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from shield.config import LoggingConfig, secret_keys
from shield.observability.correlation import get_correlation_id

REDACTED = "***redacted***"

#: Keys whose values are replaced wholesale when they appear in ``extra``.
SENSITIVE_FIELD_NAMES = frozenset(
    {
        "token",
        "discord_token",
        "bot_token",
        "password",
        "passwd",
        "secret",
        "authorization",
        "api_key",
        "webhook_token",
        "webhook_url",
        "encryption_key",
        "snapshot_encryption_key",
        "database_url",
        "dsn",
    }
)

_BOT_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{20,}\b")
_WEBHOOK_RE = re.compile(
    r"https://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+", re.IGNORECASE
)
_DSN_RE = re.compile(r"(?P<scheme>[a-z0-9+]+://)(?P<user>[^:/@\s]+):(?P<pw>[^@/\s]+)@")

_RESERVED = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
        "asctime",
    }
)


def _literal_secrets() -> tuple[str, ...]:
    """Exact secret values pulled from the environment, longest first."""
    values: list[str] = []
    for key in secret_keys():
        raw = os.environ.get(key)
        if raw and len(raw) >= 8:
            values.append(raw)
    return tuple(sorted(values, key=len, reverse=True))


def scrub(value: Any, literals: Iterable[str] = ()) -> Any:
    """Recursively redact secrets from an arbitrary log payload."""
    if isinstance(value, str):
        text = value
        for literal in literals:
            if literal and literal in text:
                text = text.replace(literal, REDACTED)
        text = _BOT_TOKEN_RE.sub(REDACTED, text)
        text = _WEBHOOK_RE.sub("https://discord.com/api/webhooks/" + REDACTED, text)
        text = _DSN_RE.sub(lambda m: f"{m.group('scheme')}{m.group('user')}:{REDACTED}@", text)
        return text
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in SENSITIVE_FIELD_NAMES:
                out[key] = REDACTED
            else:
                out[key] = scrub(item, literals)
        return out
    if isinstance(value, (list, tuple, set)):
        scrubbed = [scrub(v, literals) for v in value]
        return type(value)(scrubbed) if isinstance(value, (list, tuple)) else scrubbed
    return value


class RedactionFilter(logging.Filter):
    """Scrubs the message, args and custom attributes of every record."""

    def __init__(self) -> None:
        super().__init__(name="shield.redaction")
        self._literals = _literal_secrets()

    def refresh(self) -> None:
        self._literals = _literal_secrets()

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        literals = self._literals
        if isinstance(record.msg, str):
            record.msg = scrub(record.msg, literals)
        if record.args:
            record.args = scrub(record.args, literals)
        for key, value in list(record.__dict__.items()):
            if key in _RESERVED or key.startswith("_"):
                continue
            if key.lower() in SENSITIVE_FIELD_NAMES:
                record.__dict__[key] = REDACTED
            else:
                record.__dict__[key] = scrub(value, literals)
        return True


class CorrelationFilter(logging.Filter):
    """Attaches the ambient correlation ID when the caller did not set one."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if not getattr(record, "correlation_id", None):
            record.correlation_id = get_correlation_id()
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line, stable key order, no secrets."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        corr = getattr(record, "correlation_id", None)
        if corr:
            payload["correlation_id"] = corr
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _RESERVED
            and key not in {"correlation_id"}
            and not key.startswith("_")
        }
        if extras:
            payload["context"] = _json_safe(extras)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload, ensure_ascii=False, default=str, sort_keys=False)


class ConsoleFormatter(logging.Formatter):
    """Human-readable formatter for interactive development."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)-8s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        base = super().format(record)
        corr = getattr(record, "correlation_id", None)
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _RESERVED
            and key not in {"correlation_id"}
            and not key.startswith("_")
        }
        suffix = ""
        if corr:
            suffix += f" [{corr}]"
        if extras:
            suffix += " " + json.dumps(_json_safe(extras), default=str)
        return base + suffix


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def configure_logging(cfg: LoggingConfig) -> logging.Logger:
    """Install Shield's logging stack on the root logger. Idempotent."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - best effort
            pass

    formatter: logging.Formatter = (
        JsonFormatter() if cfg.fmt == "json" else ConsoleFormatter()
    )
    redaction = RedactionFilter()
    correlation = CorrelationFilter()

    stream = logging.StreamHandler(stream=sys.stdout)
    stream.setFormatter(formatter)
    stream.addFilter(redaction)
    stream.addFilter(correlation)
    root.addHandler(stream)

    if cfg.file is not None:
        file_handler = logging.handlers.RotatingFileHandler(
            cfg.file,
            maxBytes=cfg.max_bytes,
            backupCount=cfg.backups,
            encoding="utf-8",
            delay=True,
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redaction)
        file_handler.addFilter(correlation)
        root.addHandler(file_handler)

    root.setLevel(getattr(logging, cfg.level, logging.INFO))
    # discord.py is chatty at INFO on the gateway; keep it at WARNING unless we
    # are explicitly debugging.
    noisy = "DEBUG" if cfg.level == "DEBUG" else "WARNING"
    for name in ("discord", "discord.gateway", "discord.client", "discord.http"):
        logging.getLogger(name).setLevel(noisy)
    logging.getLogger("sqlalchemy.engine").setLevel("WARNING")
    logging.getLogger("asyncio").setLevel("WARNING")
    return logging.getLogger("shield")


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name if name.startswith("shield") else f"shield.{name}")
