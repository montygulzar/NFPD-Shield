"""Shared fixtures and Discord fakes.

No test ever touches the real Discord API. The fakes implement exactly the
surface Shield uses (attributes, coroutines and the ``audit_logs`` async
iterator) and record every mutation so tests can assert on side effects.

The database fixture uses SQLite via ``aiosqlite``: the ORM is dialect-portable
by design (see ``shield/db/models.py``), and the PostgreSQL-specific paths
(``ON CONFLICT``, advisory locks) have equivalent fallbacks that are exercised
here. The PostgreSQL paths themselves are covered by the staging test plan in
``docs/TESTING.md``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import discord
import pytest
import pytest_asyncio

from shield.audit.correlator import AuditCorrelator
from shield.config import DatabaseConfig, ShieldConfig, load_config
from shield.db.models import Base
from shield.db.session import Database
from shield.enforcement.executor import ResponseExecutor
from shield.enforcement.lockdown import LockdownManager
from shield.enforcement.ratelimit import RateLimiter
from shield.enforcement.selfguard import SelfActionGuard
from shield.events.notifier import Notifier
from shield.events.pipeline import EventPipeline
from shield.policies.engine import PolicyEngine

GUILD_A = 100000000000000001
GUILD_B = 100000000000000002
OWNER_A = 200000000000000001
OWNER_B = 200000000000000002
BOT_ID = 300000000000000001
ATTACKER = 400000000000000001
MOD = 400000000000000002
VICTIM = 400000000000000003


# ---------------------------------------------------------------------
# Discord fakes
# ---------------------------------------------------------------------
def perms(**granted: bool) -> discord.Permissions:
    return discord.Permissions(**granted)


# eq=False keeps these hashable, like real discord.py objects (needed for
# permission-overwrite dictionaries keyed by role/member).
@dataclass(eq=False)
class FakeRole:
    id: int
    name: str
    position: int = 1
    permissions: discord.Permissions = field(default_factory=discord.Permissions.none)
    managed: bool = False
    _default: bool = False
    colour: discord.Colour = field(default_factory=lambda: discord.Colour(0))
    hoist: bool = False
    mentionable: bool = False
    members: list = field(default_factory=list)
    guild: Any = None

    def is_default(self) -> bool:
        return self._default

    def is_premium_subscriber(self) -> bool:
        return False

    @property
    def color(self) -> discord.Colour:
        return self.colour


# eq=False keeps these hashable, like real discord.py objects (needed for
# permission-overwrite dictionaries keyed by role/member).
@dataclass(eq=False)
class FakeMember:
    id: int
    name: str = "member"
    roles: list[FakeRole] = field(default_factory=list)
    bot: bool = False
    guild: Any = None
    timed_out_until: datetime | None = None
    created_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc) - timedelta(days=365)
    )
    #: Recorded calls, asserted by tests.
    removed_roles: list[list[int]] = field(default_factory=list)
    timeouts: list[tuple[datetime, str]] = field(default_factory=list)
    dms: list[str] = field(default_factory=list)
    fail_remove_roles: Exception | None = None
    fail_timeout: Exception | None = None

    def __str__(self) -> str:
        return self.name

    @property
    def top_role(self) -> FakeRole:
        if not self.roles:
            return FakeRole(id=0, name="@everyone", position=0, _default=True)
        return max(self.roles, key=lambda r: r.position)

    @property
    def guild_permissions(self) -> discord.Permissions:
        value = 0
        for role in self.roles:
            value |= role.permissions.value
        return discord.Permissions(value)

    async def remove_roles(self, *roles: FakeRole, reason: str | None = None) -> None:
        if self.fail_remove_roles is not None:
            raise self.fail_remove_roles
        ids = [r.id for r in roles]
        self.removed_roles.append(ids)
        self.roles = [r for r in self.roles if r.id not in set(ids)]

    async def timeout(self, until: datetime, reason: str | None = None) -> None:
        if self.fail_timeout is not None:
            raise self.fail_timeout
        self.timed_out_until = until
        self.timeouts.append((until, reason or ""))

    async def send(self, content: str) -> None:
        self.dms.append(content)

    @property
    def mention(self) -> str:
        return f"<@{self.id}>"


# eq=False keeps these hashable, like real discord.py objects (needed for
# permission-overwrite dictionaries keyed by role/member).
@dataclass(eq=False)
class FakeChannel:
    id: int
    name: str = "general"
    guild: Any = None
    position: int = 0
    category: Any = None
    overwrites: dict = field(default_factory=dict)
    slowmode_delay: int = 0
    nsfw: bool = False
    topic: str | None = None
    kind: str = "text"
    bot_permissions: discord.Permissions = field(
        default_factory=lambda: discord.Permissions(
            send_messages=True,
            embed_links=True,
            manage_messages=True,
            read_message_history=True,
        )
    )
    sent: list[Any] = field(default_factory=list)
    purged: list[dict] = field(default_factory=list)
    edits: list[dict] = field(default_factory=list)
    purge_result: list[Any] = field(default_factory=list)
    fail_purge: Exception | None = None
    fail_edit: Exception | None = None

    @property
    def type(self):  # noqa: ANN201
        return getattr(discord.ChannelType, self.kind, discord.ChannelType.text)

    @property
    def mention(self) -> str:
        return f"<#{self.id}>"

    def permissions_for(self, member: Any) -> discord.Permissions:
        return self.bot_permissions

    async def send(self, content: str | None = None, embed: Any = None, **kwargs: Any) -> None:
        self.sent.append(embed if embed is not None else content)

    async def purge(self, **kwargs: Any) -> list[Any]:
        if self.fail_purge is not None:
            raise self.fail_purge
        self.purged.append(kwargs)
        return list(self.purge_result)

    async def edit(self, **kwargs: Any) -> None:
        if self.fail_edit is not None:
            raise self.fail_edit
        self.edits.append(kwargs)
        for key, value in kwargs.items():
            if key != "reason" and hasattr(self, key):
                setattr(self, key, value)


# eq=False keeps these hashable, like real discord.py objects (needed for
# permission-overwrite dictionaries keyed by role/member).
@dataclass(eq=False)
class FakeCategory(FakeChannel):
    kind: str = "category"


# eq=False keeps these hashable, like real discord.py objects (needed for
# permission-overwrite dictionaries keyed by role/member).
@dataclass(eq=False)
class FakeAuditEntry:
    id: int
    user: Any
    target: Any
    action: Any
    created_at: datetime
    before: Any = None
    after: Any = None
    extra: Any = None
    reason: str | None = None


# eq=False keeps these hashable, like real discord.py objects (needed for
# permission-overwrite dictionaries keyed by role/member).
@dataclass(eq=False)
class FakeGuild:
    id: int
    name: str = "Test Guild"
    owner_id: int = OWNER_A
    me: FakeMember | None = None
    roles: list[FakeRole] = field(default_factory=list)
    channels: list[FakeChannel] = field(default_factory=list)
    members: dict[int, FakeMember] = field(default_factory=dict)
    audit_entries: list[FakeAuditEntry] = field(default_factory=list)
    audit_error: Exception | None = None
    member_count: int = 50
    features: list[str] = field(default_factory=list)
    verification_level: Any = discord.VerificationLevel.low
    explicit_content_filter: Any = discord.ContentFilter.disabled
    default_notifications: Any = discord.NotificationLevel.only_mentions
    mfa_level: Any = discord.MFALevel.disabled
    afk_timeout: int = 300
    vanity_url_code: str | None = None
    edits: list[dict] = field(default_factory=list)
    created_roles: list[dict] = field(default_factory=list)
    created_channels: list[dict] = field(default_factory=list)
    webhook_list: list[Any] = field(default_factory=list)
    fail_edit: Exception | None = None
    fail_create_role: Exception | None = None
    fail_create_channel: Exception | None = None
    _next_id: int = 900000000000000000

    # -- lookups -------------------------------------------------------
    def get_member(self, user_id: int) -> FakeMember | None:
        return self.members.get(int(user_id))

    async def fetch_member(self, user_id: int) -> FakeMember:
        member = self.members.get(int(user_id))
        if member is None:
            raise discord.NotFound(_FakeResponse(404), "member not found")
        return member

    def get_role(self, role_id: int) -> FakeRole | None:
        return next((r for r in self.roles if r.id == int(role_id)), None)

    def get_channel(self, channel_id: int) -> FakeChannel | None:
        return next((c for c in self.channels if c.id == int(channel_id)), None)

    @property
    def text_channels(self) -> list[FakeChannel]:
        return [c for c in self.channels if c.kind == "text"]

    @property
    def categories(self) -> list[FakeChannel]:
        return [c for c in self.channels if c.kind == "category"]

    @property
    def owner(self) -> FakeMember | None:
        return self.members.get(self.owner_id)

    # -- audit log -----------------------------------------------------
    def audit_logs(self, limit: int = 10, action: Any = None, **kwargs: Any):  # noqa: ANN201
        entries = self.audit_entries
        error = self.audit_error

        class _Iterator:
            def __aiter__(self):  # noqa: ANN204
                return self._gen()

            async def _gen(self):  # noqa: ANN202
                if error is not None:
                    raise error
                count = 0
                for entry in sorted(entries, key=lambda e: e.id, reverse=True):
                    if action is not None and entry.action is not action:
                        continue
                    if count >= limit:
                        return
                    count += 1
                    yield entry

        return _Iterator()

    # -- writes --------------------------------------------------------
    def _mint(self) -> int:
        self._next_id += 1
        return self._next_id

    async def edit(self, reason: str | None = None, **kwargs: Any) -> None:
        if self.fail_edit is not None:
            raise self.fail_edit
        if "invites_disabled" in kwargs and "SUPPORTS_INVITE_TOGGLE" not in self.features:
            # Mirror older discord.py versions that lack the kwarg.
            raise TypeError("edit() got an unexpected keyword argument 'invites_disabled'")
        self.edits.append(kwargs)
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    async def create_role(self, **kwargs: Any) -> FakeRole:
        if self.fail_create_role is not None:
            raise self.fail_create_role
        self.created_roles.append(kwargs)
        role = FakeRole(
            id=self._mint(),
            name=kwargs.get("name", "role"),
            position=len(self.roles),
            permissions=kwargs.get("permissions", discord.Permissions.none()),
            guild=self,
        )
        self.roles.append(role)
        return role

    async def create_category(self, **kwargs: Any) -> FakeCategory:
        if self.fail_create_channel is not None:
            raise self.fail_create_channel
        self.created_channels.append({"type": "category", **kwargs})
        category = FakeCategory(id=self._mint(), name=kwargs.get("name", "cat"), guild=self)
        self.channels.append(category)
        return category

    async def create_text_channel(self, **kwargs: Any) -> FakeChannel:
        if self.fail_create_channel is not None:
            raise self.fail_create_channel
        self.created_channels.append({"type": "text", **kwargs})
        channel = FakeChannel(
            id=self._mint(),
            name=kwargs.get("name", "chan"),
            guild=self,
            category=kwargs.get("category"),
            topic=kwargs.get("topic"),
            slowmode_delay=int(kwargs.get("slowmode_delay", 0) or 0),
        )
        self.channels.append(channel)
        return channel

    async def create_voice_channel(self, **kwargs: Any) -> FakeChannel:
        if self.fail_create_channel is not None:
            raise self.fail_create_channel
        self.created_channels.append({"type": "voice", **kwargs})
        channel = FakeChannel(
            id=self._mint(), name=kwargs.get("name", "voice"), guild=self, kind="voice"
        )
        self.channels.append(channel)
        return channel

    async def create_stage_channel(self, **kwargs: Any) -> FakeChannel:
        return await self.create_voice_channel(**kwargs)

    async def create_forum(self, **kwargs: Any) -> FakeChannel:
        self.created_channels.append({"type": "forum", **kwargs})
        channel = FakeChannel(
            id=self._mint(), name=kwargs.get("name", "forum"), guild=self, kind="forum"
        )
        self.channels.append(channel)
        return channel

    async def webhooks(self) -> list[Any]:
        return list(self.webhook_list)


class _FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status
        self.reason = "fake"
        self.headers: dict[str, str] = {}


def make_http_error(status: int, retry_after: float | None = None) -> Exception:
    """Build a discord.HTTPException-like error with a status code."""
    if status == 403:
        exc = discord.Forbidden(_FakeResponse(403), "missing permissions")
    elif status == 404:
        exc = discord.NotFound(_FakeResponse(404), "not found")
    else:
        exc = discord.HTTPException(_FakeResponse(status), "boom")
    if retry_after is not None:
        exc.retry_after = retry_after  # type: ignore[attr-defined]
    return exc


def build_guild(
    guild_id: int = GUILD_A,
    owner_id: int = OWNER_A,
    *,
    bot_permissions: discord.Permissions | None = None,
    bot_role_position: int = 50,
) -> FakeGuild:
    """A guild with @everyone, a Shield role, an Admin role, and one channel."""
    guild = FakeGuild(id=guild_id, owner_id=owner_id)
    everyone = FakeRole(id=guild_id, name="@everyone", position=0, _default=True, guild=guild)
    shield_role = FakeRole(
        id=guild_id + 1,
        name="Shield",
        position=bot_role_position,
        permissions=bot_permissions
        or perms(
            administrator=False,
            view_audit_log=True,
            manage_roles=True,
            manage_channels=True,
            manage_guild=True,
            moderate_members=True,
            manage_messages=True,
            manage_webhooks=True,
            send_messages=True,
            embed_links=True,
            read_message_history=True,
        ),
        guild=guild,
    )
    admin_role = FakeRole(
        id=guild_id + 2,
        name="Admin",
        position=10,
        permissions=perms(administrator=True, ban_members=True, manage_channels=True),
        guild=guild,
    )
    colour_role = FakeRole(id=guild_id + 3, name="Blue", position=5, guild=guild)
    guild.roles = [everyone, colour_role, admin_role, shield_role]

    bot_member = FakeMember(id=BOT_ID, name="Shield", roles=[everyone, shield_role], bot=True, guild=guild)
    guild.me = bot_member
    guild.members[BOT_ID] = bot_member

    owner = FakeMember(id=owner_id, name="Owner", roles=[everyone, admin_role], guild=guild)
    guild.members[owner_id] = owner

    attacker = FakeMember(
        id=ATTACKER, name="Attacker", roles=[everyone, admin_role, colour_role], guild=guild
    )
    guild.members[ATTACKER] = attacker

    moderator = FakeMember(id=MOD, name="Mod", roles=[everyone, colour_role], guild=guild)
    guild.members[MOD] = moderator

    channel = FakeChannel(id=guild_id + 100, name="general", guild=guild)
    log_channel = FakeChannel(id=guild_id + 101, name="shield-log", guild=guild)
    guild.channels = [channel, log_channel]
    return guild


def audit_entry(
    *,
    entry_id: int,
    actor_id: int,
    target_id: int | None,
    action: Any,
    age_seconds: float = 0.5,
    before: Any = None,
    after: Any = None,
) -> FakeAuditEntry:
    return FakeAuditEntry(
        id=entry_id,
        user=FakeMember(id=actor_id, name=f"user{actor_id}"),
        target=FakeMember(id=target_id, name="target") if target_id is not None else None,
        action=action,
        created_at=datetime.now(tz=timezone.utc) - timedelta(seconds=age_seconds),
        before=before,
        after=after,
    )


# ---------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------
# A syntactically valid but entirely fake bot token. It is assembled at runtime
# rather than written as one literal so that secret scanners (and GitHub push
# protection) do not flag the test suite: the validator and the redaction filter
# both need something that matches Discord's token shape.
FAKE_DISCORD_TOKEN = ".".join(
    ["MTIzNDU2Nzg5MDEyMzQ1Njc4", "GabcdE", "abcdefghijklmnopqrstuvwxyz0123"]
)

TEST_ENV = {
    "DISCORD_TOKEN": FAKE_DISCORD_TOKEN,
    "APPLICATION_ID": "123456789012345678",
    "OWNERID": "123456789012345679",
    "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
    "LOG_FORMAT": "console",
    "RUN_MIGRATIONS_ON_BOOT": "false",
}


@pytest.fixture
def shield_config() -> ShieldConfig:
    return load_config(TEST_ENV, allow_dotenv=False)


@pytest_asyncio.fixture
async def db(tmp_path):  # noqa: ANN001, ANN201
    """Fresh database with the full schema created from the ORM.

    A temporary *file* is used rather than ``:memory:`` so that concurrent
    sessions get real connections (``:memory:`` collapses onto one shared
    connection, which would mask the concurrency the tests exercise). WAL mode
    plus SQLite's busy timeout give readers and writers room to overlap.
    """
    import sqlalchemy as sa

    path = tmp_path / "shield-test.sqlite3"
    cfg = DatabaseConfig(
        url=f"sqlite+aiosqlite:///{path}",
        pool_size=5,
        max_overflow=5,
        pool_timeout=10,
        command_timeout=10,
        requires_tls=False,
        tls_configured=False,
    )
    database = Database(cfg)
    async with database.engine.begin() as conn:
        await conn.execute(sa.text("PRAGMA journal_mode=WAL"))
        await conn.run_sync(Base.metadata.create_all)
    database.healthy = True
    yield database
    await database.dispose()


class FakeBot:
    """Minimal stand-in for ShieldBot used by pipeline/executor tests."""

    def __init__(self, config: ShieldConfig, db: Database) -> None:
        self.shield_config = config
        self.db = db
        self.user = FakeMember(id=BOT_ID, name="Shield", bot=True)
        self.guilds: list[FakeGuild] = []
        self.latency = 0.05
        self.shard_count = 1

    def get_guild(self, guild_id: int) -> FakeGuild | None:
        return next((g for g in self.guilds if g.id == int(guild_id)), None)

    async def wait_until_ready(self) -> None:
        return None

    def is_closed(self) -> bool:
        return False


@dataclass
class Harness:
    """Fully wired pipeline over fakes, for end-to-end assertions."""

    bot: FakeBot
    db: Database
    config: ShieldConfig
    pipeline: EventPipeline
    selfguard: SelfActionGuard
    limiter: RateLimiter
    correlator: AuditCorrelator
    executor: ResponseExecutor
    notifier: Notifier
    lockdown: LockdownManager

    def register_guild(self, guild: FakeGuild) -> FakeGuild:
        self.bot.guilds.append(guild)
        return guild


@pytest_asyncio.fixture
async def harness(db, shield_config) -> Harness:  # noqa: ANN001
    bot = FakeBot(shield_config, db)
    selfguard = SelfActionGuard()
    selfguard.bind_bot(BOT_ID)
    limiter = RateLimiter(
        enforce_burst=50, enforce_refill=1.0, notify_burst=50, notify_refill=1.0
    )
    lockdown = LockdownManager(limiter=limiter, selfguard=selfguard)
    notifier = Notifier(limiter=limiter)
    correlator = AuditCorrelator(
        delay=0.0, window=20.0, max_attempts=1, sleeper=_no_sleep
    )
    executor = ResponseExecutor(
        db=db, limiter=limiter, selfguard=selfguard, lockdown=lockdown
    )
    pipeline = EventPipeline(
        bot=bot,
        db=db,
        config=shield_config,
        correlator=correlator,
        engine=PolicyEngine(),
        executor=executor,
        notifier=notifier,
        selfguard=selfguard,
        limiter=limiter,
    )
    return Harness(
        bot=bot,
        db=db,
        config=shield_config,
        pipeline=pipeline,
        selfguard=selfguard,
        limiter=limiter,
        correlator=correlator,
        executor=executor,
        notifier=notifier,
        lockdown=lockdown,
    )


async def _no_sleep(_seconds: float) -> None:
    await asyncio.sleep(0)


@pytest.fixture
def no_sleep():  # noqa: ANN201
    return _no_sleep


async def enable_guild(
    db: Database,
    guild: FakeGuild,
    *,
    mode: str = "enforce",
    dry_run: bool = False,
    log_channel_id: int | None = None,
) -> None:
    """Create the guild row and switch protection on, as the owner would."""
    from shield.constants import ShieldMode
    from shield.db.repositories import UnitOfWork

    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.guilds.ensure(guild.id, guild_name=guild.name, owner_id=guild.owner_id)
        await uow.guilds.update(
            guild.id,
            enabled=True,
            mode=ShieldMode(mode),
            dry_run=dry_run,
            log_channel_id=log_channel_id,
        )


async def set_policy(db: Database, guild_id: int, action_key: Any, **values: Any) -> None:
    from shield.db.repositories import UnitOfWork

    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.guilds.ensure(guild_id)
        await uow.policies.set_values(guild_id, action_key, updated_by=1, **values)


# ---------------------------------------------------------------------
# Interaction fake (slash-command tests)
# ---------------------------------------------------------------------
class FakeResponseProxy:
    def __init__(self) -> None:
        self._done = False
        self.messages: list[dict] = []
        self.deferred = False

    def is_done(self) -> bool:
        return self._done

    async def defer(self, **kwargs: Any) -> None:
        self.deferred = True
        self._done = True

    async def send_message(self, content: str | None = None, **kwargs: Any) -> None:
        self._done = True
        self.messages.append({"content": content, **kwargs})


class FakeFollowup:
    def __init__(self, sink: list[dict]) -> None:
        self._sink = sink

    async def send(self, content: str | None = None, **kwargs: Any) -> None:
        self._sink.append({"content": content, **kwargs})


class FakeInteraction:
    """Implements the slice of ``discord.Interaction`` Shield's commands use."""

    def __init__(self, bot: Any, guild: FakeGuild, user: FakeMember) -> None:
        self.client = bot
        self.guild = guild
        self.guild_id = guild.id if guild is not None else None
        self.user = user
        self.response = FakeResponseProxy()
        self.sent: list[dict] = []
        self.followup = FakeFollowup(self.sent)

    @property
    def replies(self) -> list[dict]:
        return self.response.messages + self.sent

    def text(self) -> str:
        parts: list[str] = []
        for message in self.replies:
            if message.get("content"):
                parts.append(str(message["content"]))
            embed = message.get("embed")
            if embed is not None:
                parts.append(str(getattr(embed, "title", "")))
                parts.append(str(getattr(embed, "description", "")))
                for field in getattr(embed, "fields", []) or []:
                    parts.append(f"{field.name}: {field.value}")
        return "\n".join(parts)


class CommandBot(FakeBot):
    """FakeBot plus the attributes the command layer reaches for."""

    def __init__(self, config: ShieldConfig, db: Database, harness: Harness) -> None:
        super().__init__(config, db)
        self.pipeline = harness.pipeline
        self.snapshots = __import__(
            "shield.backup.snapshot", fromlist=["SnapshotService"]
        ).SnapshotService(
            db=db,
            limiter=harness.limiter,
            encryption_key=config.snapshot_encryption_key,
        )
        self.limiter = harness.limiter
        self.selfguard = harness.selfguard
        self.lockdown = harness.lockdown
        self.notifier = harness.notifier
        self.intents = discord.Intents.all()


# eq=False keeps these hashable, like real discord.py objects.
@dataclass(eq=False)
class FakeMessage:
    """The slice of ``discord.Message`` the message cog reads."""

    id: int
    author: Any
    channel: Any
    guild: Any
    content: str = ""
    mentions: list = field(default_factory=list)
    role_mentions: list = field(default_factory=list)
    mention_everyone: bool = False
    webhook_id: int | None = None


@dataclass(eq=False)
class FakeWebhook:
    id: int
    name: str = "logger"
    channel_id: int | None = None
    user: Any = None
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    @property
    def type(self):  # noqa: ANN201
        return discord.WebhookType.incoming
