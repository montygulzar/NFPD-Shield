"""Environment-driven configuration with fail-fast validation.

Design rules enforced here:

* Secrets and deployment IDs come from the Linux process environment only.
  Nothing is hard coded, and no default token/ID exists.
* ``OWNERID`` is the canonical operator variable; ``OWNER_ID`` and
  ``SHIELD_OWNER_ID`` are accepted aliases.
* Validation is exhaustive and the error message tells the operator exactly
  which variable is wrong and what a valid value looks like.
* Per-guild behaviour is NOT configured here. Environment values are only
  bootstrap defaults used the first time Shield sees a guild.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from shield.constants import SNOWFLAKE_MAX, SNOWFLAKE_MIN, ShieldMode
from shield.db.urls import ASYNC_PG_SCHEMES, build_url, to_async_url

Env = Mapping[str, str]

TRUE_VALUES = {"1", "true", "yes", "on", "y", "t"}
FALSE_VALUES = {"0", "false", "no", "off", "n", "f"}

#: Accepted SQLAlchemy URL schemes. A sync driver is rejected because the whole
#: data layer is async.
_ASYNC_PG_SCHEMES = set(ASYNC_PG_SCHEMES)
_TEST_SCHEMES = {"sqlite+aiosqlite"}

#: Hosts that are reachable without crossing a network boundary, so TLS adds
#: nothing. A single-label hostname is a container/service name on a private
#: Docker network (``nfpd-postgres``), not a routable internet host.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

_SECRET_KEYS = {
    "DISCORD_TOKEN",
    "DATABASE_URL",
    "SNAPSHOT_ENCRYPTION_KEY",
}

_DISCORD_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{20,}$")


class ConfigError(Exception):
    """Raised when the environment contract is violated.

    ``errors`` holds one actionable message per offending variable so the
    operator can fix everything in a single pass instead of boot-looping.
    """

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        body = "\n".join(f"  - {e}" for e in errors)
        super().__init__(
            "NFPD Shield configuration is invalid; refusing to start.\n"
            f"{len(errors)} problem(s) found:\n{body}\n"
            "See .env.example for the full contract."
        )


class _Collector:
    """Accumulates validation errors instead of raising on the first one."""

    def __init__(self, env: Env) -> None:
        self.env = env
        self.errors: list[str] = []

    # -- primitives ----------------------------------------------------
    def raw(self, *names: str) -> tuple[str | None, str]:
        """Return the first present, non-empty value among ``names``."""
        for name in names:
            value = self.env.get(name)
            if value is not None and value.strip() != "":
                return value.strip(), name
        return None, names[0]

    def fail(self, message: str) -> None:
        self.errors.append(message)

    def required_str(self, *names: str, hint: str = "") -> str:
        value, name = self.raw(*names)
        if value is None:
            alias = (
                f" (aliases: {', '.join(names[1:])})" if len(names) > 1 else ""
            )
            self.fail(f"{name} is required{alias}. {hint}".strip())
            return ""
        return value

    def optional_str(self, *names: str, default: str = "") -> str:
        value, _ = self.raw(*names)
        return value if value is not None else default

    def boolean(self, name: str, default: bool) -> bool:
        value, _ = self.raw(name)
        if value is None:
            return default
        low = value.lower()
        if low in TRUE_VALUES:
            return True
        if low in FALSE_VALUES:
            return False
        self.fail(
            f"{name}={value!r} is not a boolean. Use one of: "
            f"{sorted(TRUE_VALUES)} / {sorted(FALSE_VALUES)}."
        )
        return default

    def integer(
        self,
        name: str,
        default: int,
        *,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int:
        value, _ = self.raw(name)
        if value is None:
            return default
        try:
            parsed = int(value)
        except ValueError:
            self.fail(f"{name}={value!r} is not an integer (expected e.g. {default}).")
            return default
        if minimum is not None and parsed < minimum:
            self.fail(f"{name}={parsed} is below the minimum of {minimum}.")
            return default
        if maximum is not None and parsed > maximum:
            self.fail(f"{name}={parsed} is above the maximum of {maximum}.")
            return default
        return parsed

    def number(
        self,
        name: str,
        default: float,
        *,
        minimum: float | None = None,
        maximum: float | None = None,
    ) -> float:
        value, _ = self.raw(name)
        if value is None:
            return default
        try:
            parsed = float(value)
        except ValueError:
            self.fail(f"{name}={value!r} is not a number (expected e.g. {default}).")
            return default
        if minimum is not None and parsed < minimum:
            self.fail(f"{name}={parsed} is below the minimum of {minimum}.")
            return default
        if maximum is not None and parsed > maximum:
            self.fail(f"{name}={parsed} is above the maximum of {maximum}.")
            return default
        return parsed

    def snowflake(self, *names: str, required: bool = True) -> int | None:
        value, name = self.raw(*names)
        if value is None:
            if required:
                alias = f" (aliases: {', '.join(names[1:])})" if len(names) > 1 else ""
                self.fail(
                    f"{name} is required{alias} and must be a Discord snowflake "
                    "(17-20 digit numeric ID)."
                )
            return None
        return self._parse_snowflake(name, value)

    def _parse_snowflake(self, name: str, value: str) -> int | None:
        if not value.isdigit():
            self.fail(
                f"{name}={value!r} is not a valid Discord snowflake. "
                "Expected only digits, e.g. 123456789012345678. "
                "Do not wrap the value in quotes or <@...>."
            )
            return None
        parsed = int(value)
        if not (SNOWFLAKE_MIN <= parsed <= SNOWFLAKE_MAX):
            self.fail(
                f"{name}={value!r} is out of the valid snowflake range "
                f"({SNOWFLAKE_MIN}..{SNOWFLAKE_MAX}); Discord IDs are 17-20 digits."
            )
            return None
        return parsed

    def snowflake_list(self, name: str) -> tuple[int, ...]:
        value, _ = self.raw(name)
        if value is None:
            return ()
        out: list[int] = []
        for chunk in re.split(r"[,\s]+", value):
            if not chunk:
                continue
            parsed = self._parse_snowflake(name, chunk)
            if parsed is not None:
                out.append(parsed)
        return tuple(dict.fromkeys(out))

    def int_list(self, name: str) -> tuple[int, ...]:
        value, _ = self.raw(name)
        if value is None:
            return ()
        out: list[int] = []
        for chunk in re.split(r"[,\s]+", value):
            if not chunk:
                continue
            try:
                out.append(int(chunk))
            except ValueError:
                self.fail(f"{name} contains {chunk!r}, which is not an integer.")
        return tuple(dict.fromkeys(out))

    def choice(self, name: str, default: str, allowed: set[str]) -> str:
        value, _ = self.raw(name)
        if value is None:
            return default
        low = value.lower()
        if low not in allowed:
            self.fail(
                f"{name}={value!r} is invalid. Allowed values: {sorted(allowed)}."
            )
            return default
        return low


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    url: str
    pool_size: int
    max_overflow: int
    pool_timeout: int
    command_timeout: int
    requires_tls: bool
    tls_configured: bool

    @property
    def is_sqlite(self) -> bool:
        return self.url.startswith("sqlite")

    def safe_url(self) -> str:
        """DSN with the password removed, safe for logs and ``/shield health``."""
        parsed = urlparse(self.url)
        if parsed.password:
            netloc = parsed.netloc.replace(f":{parsed.password}", ":***")
            return parsed._replace(netloc=netloc).geturl()
        return self.url


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: str
    fmt: str
    file: Path | None
    max_bytes: int
    backups: int


@dataclass(frozen=True, slots=True)
class ShieldConfig:
    """Fully validated, immutable runtime configuration."""

    discord_token: str
    application_id: int
    owner_id: int
    extra_operator_ids: tuple[int, ...]
    database: DatabaseConfig
    logging: LoggingConfig

    enable_message_content: bool
    enable_guild_members: bool

    default_mode: ShieldMode
    global_dry_run: bool

    snapshot_interval_minutes: int
    snapshot_retention: int
    snapshot_encryption_key: str | None
    snapshot_include_webhooks: bool

    audit_correlation_delay: float
    audit_correlation_window: float
    audit_max_attempts: int

    notify_burst: int
    notify_refill_seconds: float
    enforce_burst: int
    enforce_refill_seconds: float

    #: Stamped in at image build time so a running container can report exactly
    #: which build it is.
    app_version: str
    git_commit: str

    health_server_enabled: bool
    health_host: str
    health_port: int

    #: When non-empty, Shield operates ONLY in these guilds.
    approved_guild_ids: tuple[int, ...]
    leave_unapproved_guilds: bool

    instance_id: str
    shard_count: int | None
    shard_ids: tuple[int, ...]
    dev_guild_ids: tuple[int, ...]

    retention_incident_days: int
    retention_event_days: int
    run_migrations_on_boot: bool

    operator_ids: frozenset[int] = field(default_factory=frozenset)

    def guild_approved(self, guild_id: int) -> bool:
        """True when Shield may operate in this guild (always, if no list is set)."""
        return not self.approved_guild_ids or guild_id in self.approved_guild_ids

    def is_operator(self, user_id: int) -> bool:
        """True for the global bot operator(s).

        Operator status grants *diagnostics and support* scope only. It never
        exempts the user from a guild's protections and never overrides a guild
        owner's decisions.
        """
        return user_id in self.operator_ids

    def redacted(self) -> dict[str, object]:
        """Config snapshot with every secret removed - safe to log at boot."""
        return {
            "application_id": self.application_id,
            "owner_id": self.owner_id,
            "extra_operator_ids": list(self.extra_operator_ids),
            "database_url": self.database.safe_url(),
            "database_pool_size": self.database.pool_size,
            "database_tls": self.database.tls_configured,
            "log_level": self.logging.level,
            "log_format": self.logging.fmt,
            "log_file": str(self.logging.file) if self.logging.file else None,
            "enable_message_content": self.enable_message_content,
            "enable_guild_members": self.enable_guild_members,
            "default_mode": self.default_mode.value,
            "global_dry_run": self.global_dry_run,
            "snapshot_interval_minutes": self.snapshot_interval_minutes,
            "snapshot_retention": self.snapshot_retention,
            "snapshot_encryption": bool(self.snapshot_encryption_key),
            "snapshot_include_webhooks": self.snapshot_include_webhooks,
            "audit_correlation_delay": self.audit_correlation_delay,
            "audit_correlation_window": self.audit_correlation_window,
            "app_version": self.app_version,
            "git_commit": self.git_commit,
            "health_server_enabled": self.health_server_enabled,
            "health_host": self.health_host,
            "health_port": self.health_port,
            "approved_guild_ids": list(self.approved_guild_ids),
            "leave_unapproved_guilds": self.leave_unapproved_guilds,
            "instance_id": self.instance_id,
            "shard_count": self.shard_count,
            "shard_ids": list(self.shard_ids),
            "dev_guild_ids": list(self.dev_guild_ids),
            "retention_incident_days": self.retention_incident_days,
            "retention_event_days": self.retention_event_days,
            "run_migrations_on_boot": self.run_migrations_on_boot,
            "discord_token": "***redacted***",
            "snapshot_encryption_key": "***redacted***" if self.snapshot_encryption_key else None,
        }


def load_dotenv(path: str | Path = ".env", env: dict[str, str] | None = None) -> dict[str, str]:
    """Minimal, dependency-free ``.env`` reader for local development.

    Deliberately conservative: it mirrors the *systemd* subset of dotenv syntax
    (``KEY=VALUE``, ``#`` comments on their own line, optional surrounding
    quotes) so that a file which works locally also works as an
    ``EnvironmentFile``. No shell expansion is performed.
    """
    target = env if env is not None else {}
    file_path = Path(path)
    if not file_path.is_file():
        return target
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if key:
            target[key] = value
    return target


def _assemble_database_url(col: _Collector) -> str:
    """``DATABASE_URL`` if set, otherwise built from discrete ``POSTGRES_*`` values.

    The discrete form exists so a compose file can reuse the same credentials it
    already passes to the PostgreSQL container instead of repeating them inside a
    second URL. Credentials are percent-encoded: an unescaped ``@`` or ``/`` in a
    password silently produces a URL pointing somewhere else entirely.
    """
    explicit, _ = col.raw("DATABASE_URL")
    if explicit:
        return explicit

    user, _ = col.raw("POSTGRES_USER")
    password, _ = col.raw("POSTGRES_PASSWORD")
    host, _ = col.raw("POSTGRES_HOST")
    database, _ = col.raw("POSTGRES_DB")
    port, _ = col.raw("POSTGRES_PORT")
    port = port or "5432"
    if not (user and password and host and database):
        return ""
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        col.fail(f"POSTGRES_PORT={port!r} is not a valid TCP port.")
        port = "5432"
    return build_url(user=user, password=password, host=host, database=database, port=port)


def _validate_database(col: _Collector) -> DatabaseConfig:
    url = _assemble_database_url(col)
    if not url:
        col.fail(
            "Database connection details are required. Set DATABASE_URL "
            "(postgresql://user:password@host:5432/dbname), or set POSTGRES_USER, "
            "POSTGRES_PASSWORD, POSTGRES_HOST and POSTGRES_DB and let the URL be "
            "assembled from them."
        )
    url = to_async_url(url)
    requires_tls = False
    tls_configured = False
    if url:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme in _TEST_SCHEMES:
            # Permitted so the integration suite can run without PostgreSQL.
            return DatabaseConfig(
                url=url,
                pool_size=col.integer("DB_POOL_SIZE", 5, minimum=1, maximum=100),
                max_overflow=col.integer("DB_MAX_OVERFLOW", 5, minimum=0, maximum=100),
                pool_timeout=col.integer("DB_POOL_TIMEOUT", 30, minimum=1, maximum=600),
                command_timeout=col.integer("DB_COMMAND_TIMEOUT", 30, minimum=1, maximum=600),
                requires_tls=False,
                tls_configured=False,
            )
        if scheme not in _ASYNC_PG_SCHEMES:
            if scheme.startswith("postgres"):
                col.fail(
                    f"DATABASE_URL uses the synchronous driver {scheme!r}. "
                    "NFPD Shield's data layer is async throughout: use "
                    "postgresql://... (upgraded automatically) or "
                    "postgresql+asyncpg://..."
                )
            else:
                col.fail(
                    f"DATABASE_URL scheme {scheme!r} is unsupported. Use "
                    "postgresql://user:password@host:port/dbname"
                )
        elif not parsed.hostname:
            col.fail("DATABASE_URL is missing a host component.")
        elif not (parsed.path or "").strip("/"):
            col.fail("DATABASE_URL is missing the database name (the /dbname part).")
        else:
            host = parsed.hostname
            query = (parsed.query or "").lower()
            tls_configured = "ssl=" in query or "sslmode=" in query
            requires_tls = _tls_expected(col, host)
            if requires_tls and not tls_configured:
                col.fail(
                    f"DATABASE_URL points at the remote host {host!r} without TLS. "
                    "Append ?ssl=require (asyncpg spelling), or set "
                    "DB_REQUIRE_TLS=false if that hop really is private."
                )
    return DatabaseConfig(
        url=url,
        pool_size=col.integer("DB_POOL_SIZE", 5, minimum=1, maximum=100),
        max_overflow=col.integer("DB_MAX_OVERFLOW", 5, minimum=0, maximum=100),
        pool_timeout=col.integer("DB_POOL_TIMEOUT", 30, minimum=1, maximum=600),
        command_timeout=col.integer("DB_COMMAND_TIMEOUT", 30, minimum=1, maximum=600),
        requires_tls=requires_tls,
        tls_configured=tls_configured,
    )


def _tls_expected(col: _Collector, host: str) -> bool:
    """Decide whether this hop must be encrypted.

    ``DB_REQUIRE_TLS`` is honoured first when set explicitly, because only the
    operator knows their network. Otherwise TLS is required for any host that
    looks routable, and not required for a loopback address, a Unix socket path
    or a single-label hostname. That last case is the common container
    deployment: ``nfpd-postgres`` is a Docker DNS name on a private bridge
    network, so demanding TLS there would reject a correct configuration.
    """
    explicit, _ = col.raw("DB_REQUIRE_TLS")
    if explicit is not None:
        return col.boolean("DB_REQUIRE_TLS", True)
    if host in _LOCAL_HOSTS or host.startswith("/"):
        return False
    if "." not in host and ":" not in host:
        return False  # single-label name: a container or LAN hostname
    return True


def _validate_logging(col: _Collector) -> LoggingConfig:
    level = col.choice(
        "LOG_LEVEL", "info", {"debug", "info", "warning", "error", "critical"}
    ).upper()
    # "text" is the spelling the other NFPD services use for the readable format.
    fmt = col.choice("LOG_FORMAT", "json", {"json", "console", "text"})
    if fmt == "text":
        fmt = "console"
    raw_file = col.optional_str("LOG_FILE")
    log_file: Path | None = None
    if raw_file:
        log_file = Path(raw_file).expanduser()
        parent = log_file.parent
        if not parent.exists():
            col.fail(
                f"LOG_FILE={raw_file!r} points into {parent}, which does not exist. "
                "Create the directory (and chown it to the service user) first."
            )
    return LoggingConfig(
        level=level,
        fmt=fmt,
        file=log_file,
        max_bytes=col.integer("LOG_FILE_MAX_BYTES", 10 * 1024 * 1024, minimum=4096),
        backups=col.integer("LOG_FILE_BACKUPS", 5, minimum=0, maximum=100),
    )


def _validate_encryption_key(col: _Collector) -> str | None:
    key = col.optional_str("SNAPSHOT_ENCRYPTION_KEY")
    if not key:
        return None
    import base64

    try:
        decoded = base64.urlsafe_b64decode(key.encode("ascii"))
    except Exception:
        col.fail(
            "SNAPSHOT_ENCRYPTION_KEY is not urlsafe-base64. Generate one with: "
            'python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        )
        return None
    if len(decoded) != 32:
        col.fail(
            f"SNAPSHOT_ENCRYPTION_KEY decodes to {len(decoded)} bytes; a Fernet key "
            "must decode to exactly 32 bytes."
        )
        return None
    return key


def load_config(env: Env | None = None, *, allow_dotenv: bool | None = None) -> ShieldConfig:
    """Build and validate the runtime configuration.

    Raises :class:`ConfigError` listing *every* problem found.
    """
    source: dict[str, str] = dict(os.environ if env is None else env)
    want_dotenv = (
        allow_dotenv
        if allow_dotenv is not None
        else source.get("SHIELD_LOAD_DOTENV", "false").strip().lower() in TRUE_VALUES
    )
    if want_dotenv:
        file_values = load_dotenv()
        # Real environment wins over the file; the file only fills the gaps.
        for key, value in file_values.items():
            source.setdefault(key, value)

    col = _Collector(source)

    token = col.required_str(
        "DISCORD_TOKEN",
        "SHIELD_DISCORD_TOKEN",
        "BOT_TOKEN",
        hint="Copy it from the Discord Developer Portal (Bot -> Reset Token).",
    )
    if token:
        if token.lower().startswith("bot "):
            col.fail("DISCORD_TOKEN must not include the 'Bot ' prefix.")
        elif token.startswith("REPLACE_ME") or token == "changeme":
            col.fail(
                "DISCORD_TOKEN still holds the placeholder from .env.example. "
                "Set a real token in the environment file."
            )
        elif not _DISCORD_TOKEN_RE.match(token):
            col.fail(
                "DISCORD_TOKEN does not look like a Discord bot token "
                "(expected three dot-separated base64url segments). "
                "Check for stray quotes, whitespace or a truncated paste."
            )

    application_id = col.snowflake("APPLICATION_ID", "SHIELD_APPLICATION_ID") or 0
    # OWNER_IDS (plural, comma-separated) is the form the other NFPD services
    # use. Its first entry stands in for OWNERID when that is unset; every entry
    # is an operator either way.
    owner_list = col.snowflake_list("OWNER_IDS")
    single, _ = col.raw("OWNERID", "OWNER_ID", "SHIELD_OWNER_ID")
    if single is None and owner_list:
        owner_id = owner_list[0]
    else:
        owner_id = col.snowflake("OWNERID", "OWNER_ID", "SHIELD_OWNER_ID") or 0
    extra_ops = tuple(
        dict.fromkeys((*col.snowflake_list("EXTRA_OPERATOR_IDS"), *owner_list))
    )
    extra_ops = tuple(i for i in extra_ops if i != owner_id)

    approved_guild_ids = col.snowflake_list("APPROVED_GUILD_IDS")
    leave_unapproved = col.boolean("LEAVE_UNAPPROVED_GUILDS", False)
    if leave_unapproved and not approved_guild_ids:
        col.fail(
            "LEAVE_UNAPPROVED_GUILDS=true with an empty APPROVED_GUILD_IDS is "
            "contradictory: Shield would leave every server. List the approved "
            "guild IDs or set LEAVE_UNAPPROVED_GUILDS=false."
        )

    database = _validate_database(col)
    logging_cfg = _validate_logging(col)

    enable_message_content = col.boolean("ENABLE_MESSAGE_CONTENT", True)
    enable_guild_members = col.boolean("ENABLE_GUILD_MEMBERS", True)

    mode_value = col.choice(
        "DEFAULT_MODE", "alert_only", {m.value for m in ShieldMode}
    )
    default_mode = ShieldMode(mode_value)
    global_dry_run = col.boolean("GLOBAL_DRY_RUN", False)

    if default_mode is ShieldMode.LOCKDOWN:
        col.fail(
            "DEFAULT_MODE=lockdown is contradictory: lockdown is an incident "
            "response state, not a bootstrap default. Use alert_only or enforce."
        )
    if not enable_guild_members:
        # Join flood and member-state detection are impossible without it.
        if default_mode is ShieldMode.ENFORCE:
            col.fail(
                "ENABLE_GUILD_MEMBERS=false is incompatible with "
                "DEFAULT_MODE=enforce: without the Guild Members intent Shield "
                "cannot resolve members, roles or joins, so enforcement cannot "
                "be performed safely. Enable the intent or use alert_only."
            )

    audit_delay = col.number("AUDIT_CORRELATION_DELAY", 1.5, minimum=0.0, maximum=30.0)
    audit_window = col.number("AUDIT_CORRELATION_WINDOW", 20.0, minimum=1.0, maximum=300.0)
    if audit_delay >= audit_window:
        col.fail(
            f"AUDIT_CORRELATION_DELAY={audit_delay} must be smaller than "
            f"AUDIT_CORRELATION_WINDOW={audit_window}; otherwise every lookup "
            "starts already stale."
        )

    snapshot_interval = col.integer(
        "SNAPSHOT_INTERVAL_MINUTES", 360, minimum=5, maximum=10080
    )
    snapshot_retention = col.integer("SNAPSHOT_RETENTION", 12, minimum=1, maximum=500)

    retention_incident_days = col.integer("RETENTION_INCIDENT_DAYS", 180, minimum=0, maximum=3650)
    retention_event_days = col.integer("RETENTION_EVENT_DAYS", 30, minimum=0, maximum=3650)
    if (
        retention_event_days
        and retention_incident_days
        and retention_event_days > retention_incident_days
    ):
        col.fail(
            f"RETENTION_EVENT_DAYS={retention_event_days} exceeds "
            f"RETENTION_INCIDENT_DAYS={retention_incident_days}; raw events must "
            "not outlive the incidents that reference them."
        )

    shard_count_raw, _ = col.raw("SHARD_COUNT")
    shard_count = (
        col.integer("SHARD_COUNT", 1, minimum=1, maximum=10000)
        if shard_count_raw is not None
        else None
    )
    shard_ids = col.int_list("SHARD_IDS")
    if shard_ids and shard_count is None:
        col.fail("SHARD_IDS is set but SHARD_COUNT is not; both are required together.")
    for sid in shard_ids:
        if shard_count is not None and not (0 <= sid < shard_count):
            col.fail(
                f"SHARD_IDS contains {sid}, which is outside the range "
                f"0..{shard_count - 1} implied by SHARD_COUNT={shard_count}."
            )

    instance_id = col.optional_str("INSTANCE_ID", default="shield-1")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", instance_id):
        col.fail(
            f"INSTANCE_ID={instance_id!r} is invalid: use 1-64 characters from "
            "[A-Za-z0-9._-]."
        )

    config = ShieldConfig(
        discord_token=token,
        application_id=application_id,
        owner_id=owner_id,
        extra_operator_ids=extra_ops,
        database=database,
        logging=logging_cfg,
        enable_message_content=enable_message_content,
        enable_guild_members=enable_guild_members,
        default_mode=default_mode,
        global_dry_run=global_dry_run,
        snapshot_interval_minutes=snapshot_interval,
        snapshot_retention=snapshot_retention,
        snapshot_encryption_key=_validate_encryption_key(col),
        snapshot_include_webhooks=col.boolean("SNAPSHOT_INCLUDE_WEBHOOKS", True),
        audit_correlation_delay=audit_delay,
        audit_correlation_window=audit_window,
        audit_max_attempts=col.integer("AUDIT_MAX_ATTEMPTS", 3, minimum=1, maximum=10),
        notify_burst=col.integer("NOTIFY_BURST", 5, minimum=1, maximum=100),
        notify_refill_seconds=col.number("NOTIFY_REFILL_SECONDS", 30.0, minimum=0.5),
        enforce_burst=col.integer("ENFORCE_BURST", 5, minimum=1, maximum=100),
        enforce_refill_seconds=col.number("ENFORCE_REFILL_SECONDS", 20.0, minimum=0.5),
        app_version=col.optional_str("APP_VERSION", default="dev"),
        git_commit=col.optional_str("GIT_COMMIT", default="unknown"),
        health_server_enabled=col.boolean("HEALTH_SERVER_ENABLED", True),
        health_host=col.optional_str("HEALTH_HOST", default="0.0.0.0"),
        health_port=col.integer("HEALTH_PORT", 8080, minimum=1, maximum=65535),
        approved_guild_ids=approved_guild_ids,
        leave_unapproved_guilds=leave_unapproved,
        instance_id=instance_id,
        shard_count=shard_count,
        shard_ids=shard_ids,
        dev_guild_ids=col.snowflake_list("DEV_GUILD_IDS"),
        retention_incident_days=retention_incident_days,
        retention_event_days=retention_event_days,
        run_migrations_on_boot=col.boolean("RUN_MIGRATIONS_ON_BOOT", True),
        operator_ids=frozenset({owner_id, *extra_ops}) - {0},
    )

    if col.errors:
        raise ConfigError(col.errors)
    return config


def secret_keys() -> frozenset[str]:
    """Environment variable names whose values must never be logged."""
    return frozenset(_SECRET_KEYS)
