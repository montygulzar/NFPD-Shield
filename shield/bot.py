"""The Shield bot: wiring, lifecycle and background maintenance."""

from __future__ import annotations

import asyncio
import pathlib
from datetime import datetime, timezone

import discord
from discord.ext import commands

from shield.audit.correlator import AuditCorrelator
from shield.backup.snapshot import SnapshotScheduler, SnapshotService
from shield.config import ShieldConfig
from shield.constants import SnapshotKind
from shield.db.repositories import UnitOfWork
from shield.db.session import Database
from shield.enforcement.executor import ResponseExecutor
from shield.enforcement.lockdown import LockdownManager
from shield.enforcement.ratelimit import RateLimiter
from shield.enforcement.selfguard import SelfActionGuard
from shield.events.notifier import Notifier
from shield.events.pipeline import EventPipeline
from shield.health import HealthServer
from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS
from shield.policies.engine import PolicyEngine

log = get_logger("bot")

#: Cog modules loaded at startup, in order.
EXTENSIONS = (
    "shield.commands.core",
    "shield.events.member_events",
    "shield.events.message_events",
    "shield.events.admin_events",
)

#: How often the maintenance loop runs.
MAINTENANCE_INTERVAL = 60.0


def build_intents(config: ShieldConfig) -> discord.Intents:
    """Least-privilege intents.

    ``guilds`` is mandatory. ``members`` and ``message_content`` are privileged
    and must be enabled in the Discord Developer Portal (and approved by Discord
    for bots in 100+ guilds). Everything else stays off.
    """
    intents = discord.Intents.none()
    intents.guilds = True
    intents.guild_messages = True
    intents.moderation = True  # ban/unban events (formerly Intents.bans)
    intents.webhooks = True
    intents.members = config.enable_guild_members
    intents.message_content = config.enable_message_content
    return intents


class ShieldBot(commands.Bot):
    """Multi-guild anti-raid / anti-nuke bot.

    Every component is created here and exposed as an attribute so cogs and
    commands can reach them through ``interaction.client`` without globals.
    """

    def __init__(self, config: ShieldConfig) -> None:
        self.shield_config = config
        super().__init__(
            command_prefix=commands.when_mentioned,  # slash-only; prefix is unused
            intents=build_intents(config),
            application_id=config.application_id,
            help_command=None,
            chunk_guilds_at_startup=False,
            max_messages=None,  # Shield keeps no message cache
            shard_count=config.shard_count,
            shard_ids=list(config.shard_ids) or None,
        )

        self.db = Database(config.database)
        self.selfguard = SelfActionGuard()
        self.limiter = RateLimiter(
            enforce_burst=config.enforce_burst,
            enforce_refill=config.enforce_refill_seconds,
            notify_burst=config.notify_burst,
            notify_refill=config.notify_refill_seconds,
        )
        self.lockdown = LockdownManager(limiter=self.limiter, selfguard=self.selfguard)
        self.notifier = Notifier(limiter=self.limiter)
        self.correlator = AuditCorrelator(
            delay=config.audit_correlation_delay,
            window=config.audit_correlation_window,
            max_attempts=config.audit_max_attempts,
        )
        self.engine = PolicyEngine(global_dry_run=config.global_dry_run)
        self.executor = ResponseExecutor(
            db=self.db,
            limiter=self.limiter,
            selfguard=self.selfguard,
            lockdown=self.lockdown,
            global_dry_run=config.global_dry_run,
        )
        self.pipeline = EventPipeline(
            bot=self,
            db=self.db,
            config=config,
            correlator=self.correlator,
            engine=self.engine,
            executor=self.executor,
            notifier=self.notifier,
            selfguard=self.selfguard,
            limiter=self.limiter,
        )
        self.snapshots = SnapshotService(
            db=self.db,
            limiter=self.limiter,
            encryption_key=config.snapshot_encryption_key,
            include_webhooks_default=config.snapshot_include_webhooks,
        )
        self.snapshot_scheduler = SnapshotScheduler(
            bot=self, service=self.snapshots, db=self.db
        )
        self.health = HealthServer(self)
        self._maintenance_task: asyncio.Task | None = None
        self._bootstrapped = False

    # -- lifecycle -----------------------------------------------------
    async def setup_hook(self) -> None:
        log.info("shield starting", extra={"config": self.shield_config.redacted()})

        # Started first so /health answers probes immediately and /ready reports
        # 503 while PostgreSQL or the gateway is still coming up. A container
        # that cannot reach the database must be observably unhealthy, not
        # silently unreachable.
        await self.health.start()

        ok, error = await self.db.ping()
        if not ok:
            # Fail loudly: Shield without PostgreSQL cannot guarantee
            # idempotency, dedupe, cooldowns or incident records.
            raise RuntimeError(
                "Cannot reach PostgreSQL at "
                f"{self.shield_config.database.safe_url()}: {error}. "
                "Check DATABASE_URL, that the server is running, and that TLS is "
                "configured for remote hosts."
            )

        if self.shield_config.run_migrations_on_boot:
            await self.run_migrations()

        for extension in EXTENSIONS:
            await self.load_extension(extension)
            log.info("extension loaded", extra={"extension": extension})

        if self.shield_config.dev_guild_ids:
            for guild_id in self.shield_config.dev_guild_ids:
                guild = discord.Object(id=guild_id)
                self.tree.copy_global_to(guild=guild)
                synced = await self.tree.sync(guild=guild)
                log.info(
                    "commands synced to dev guild",
                    extra={"guild_id": guild_id, "commands": len(synced)},
                )
        else:
            synced = await self.tree.sync()
            log.info("global commands synced", extra={"commands": len(synced)})

        self.snapshot_scheduler.start()
        self._maintenance_task = asyncio.create_task(
            self._maintenance_loop(), name="shield-maintenance"
        )

    async def run_migrations(self) -> None:
        """Apply Alembic migrations in a worker thread.

        Alembic's API is synchronous; running it off the event loop keeps the
        gateway heartbeat alive on a large migration.
        """
        from alembic import command as alembic_command
        from alembic.config import Config as AlembicConfig

        root = pathlib.Path(__file__).resolve().parent.parent
        ini_path = root / "alembic.ini"
        if not ini_path.is_file():
            log.warning(
                "alembic.ini not found; skipping automatic migrations",
                extra={"expected": str(ini_path)},
            )
            return

        def _upgrade() -> None:
            cfg = AlembicConfig(str(ini_path))
            cfg.set_main_option("script_location", str(root / "migrations"))
            cfg.set_main_option("sqlalchemy.url", self.shield_config.database.url)
            alembic_command.upgrade(cfg, "head")

        await asyncio.to_thread(_upgrade)
        log.info("database migrations applied")

    async def on_ready(self) -> None:
        self.health.note_connected()
        self.selfguard.bind_bot(getattr(self.user, "id", None))
        METRICS.gauge("guilds", len(self.guilds))
        log.info(
            "shield ready",
            extra={
                "user": str(self.user),
                "guilds": len(self.guilds),
                "shards": self.shard_count or 1,
            },
        )
        if not self._bootstrapped:
            self._bootstrapped = True
            await self._bootstrap_guilds()

    async def on_resumed(self) -> None:
        self.health.note_connected()
        log.info("gateway session resumed")

    async def on_disconnect(self) -> None:
        # Fires on every brief gateway drop; discord.py reconnects by itself, so
        # readiness tolerates this for DISCORD_GRACE_SECONDS before reporting 503.
        self.health.note_disconnected()
        log.debug("disconnected from the gateway")

    async def _bootstrap_guilds(self) -> None:
        """Ensure a row per guild, take startup snapshots, rehydrate windows."""
        for guild in list(self.guilds):
            try:
                async with self.db.begin() as session:
                    uow = UnitOfWork(session)
                    await uow.guilds.ensure(
                        guild.id,
                        guild_name=guild.name,
                        owner_id=guild.owner_id,
                        default_mode=self.shield_config.default_mode,
                        snapshot_interval_minutes=self.shield_config.snapshot_interval_minutes,
                        snapshot_retention=self.shield_config.snapshot_retention,
                        snapshot_include_webhooks=self.shield_config.snapshot_include_webhooks,
                    )
                await self.pipeline.rehydrate_windows(guild.id)
                await self.snapshots.capture(
                    guild, kind=SnapshotKind.STARTUP, bypass_rate_limit=True
                )
            except Exception:  # noqa: BLE001 - one bad guild must not stop boot
                log.exception("guild bootstrap failed", extra={"guild_id": guild.id})

    async def on_guild_join(self, guild: discord.Guild) -> None:
        log.info("joined guild", extra={"guild_id": guild.id, "name": guild.name})
        METRICS.gauge("guilds", len(self.guilds))
        try:
            async with self.db.begin() as session:
                uow = UnitOfWork(session)
                await uow.guilds.ensure(
                    guild.id,
                    guild_name=guild.name,
                    owner_id=guild.owner_id,
                    default_mode=self.shield_config.default_mode,
                )
            await self.snapshots.capture(guild, kind=SnapshotKind.STARTUP, bypass_rate_limit=True)
        except Exception:  # noqa: BLE001
            log.exception("could not initialise new guild", extra={"guild_id": guild.id})

        owner = guild.owner
        if owner is not None:
            try:
                await owner.send(
                    "**NFPD Shield** has been added to "
                    f"**{guild.name}**.\n\n"
                    "Protection starts **disabled** and in **alert-only** mode: Shield "
                    "will observe and report, but will not act until you explicitly "
                    "enable it.\n\n"
                    "Next steps:\n"
                    "1. `/shield logs set` - choose an incident log channel\n"
                    "2. `/shield health` - check intents, permissions and role hierarchy\n"
                    "3. `/shield enable mode:alert_only` - watch for a few days\n"
                    "4. `/shield thresholds view` - tune anything noisy\n"
                    "5. `/shield enable mode:enforce dry_run:false` - only once validated\n\n"
                    "Only you, the guild owner, can change the protection state."
                )
            except Exception:  # noqa: BLE001 - DMs closed
                pass

    async def on_guild_remove(self, guild: discord.Guild) -> None:
        log.info("left guild", extra={"guild_id": guild.id})
        METRICS.gauge("guilds", len(self.guilds))
        self.pipeline.forget_guild(guild.id)

    async def close(self) -> None:
        log.info("shield shutting down")
        if self._maintenance_task is not None:
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        await self.snapshot_scheduler.stop()
        try:
            await self.health.stop()
        except Exception:  # noqa: BLE001 - shutdown must never raise
            log.warning("error stopping the health server", exc_info=True)
        await super().close()
        await self.db.dispose()

    # -- background maintenance ---------------------------------------
    async def _maintenance_loop(self) -> None:
        await self.wait_until_ready()
        while not self.is_closed():
            try:
                await self.maintenance_tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("maintenance tick failed")
            await asyncio.sleep(MAINTENANCE_INTERVAL)

    async def maintenance_tick(self) -> dict[str, int]:
        """One maintenance pass. Returns a small report (used by tests)."""
        report = {
            "windows_swept": self.pipeline.sweep(),
            "cooldowns_purged": 0,
            "raid_modes_expired": 0,
            "trust_expired": 0,
            "events_pruned": 0,
            "incidents_pruned": 0,
        }
        try:
            async with self.db.begin() as session:
                uow = UnitOfWork(session)
                report["cooldowns_purged"] = await uow.cooldowns.purge_expired()
                report["trust_expired"] = await uow.trust.purge_expired()
                guilds = await uow.guilds.list_all()
                expiring = [
                    g.guild_id
                    for g in guilds
                    if g.raid_mode_active
                    and g.raid_mode_until is not None
                    and g.raid_mode_until <= datetime.now(tz=timezone.utc)
                ]
                states = {
                    g.guild_id: dict(g.raid_mode_state or {}) for g in guilds if g.guild_id in expiring
                }
        except Exception:  # noqa: BLE001
            log.warning("maintenance database pass failed; retrying next tick")
            return report

        for guild_id in expiring:
            guild = self.get_guild(guild_id)
            if guild is None:
                continue
            try:
                await self.lockdown.disable_raid_mode(guild, states.get(guild_id, {}))
                async with self.db.begin() as session:
                    uow = UnitOfWork(session)
                    await uow.guilds.update(
                        guild_id,
                        raid_mode_active=False,
                        raid_mode_until=None,
                        raid_mode_state=None,
                        protective_mode=None,
                    )
                self.pipeline.state_cache.invalidate(guild_id)
                report["raid_modes_expired"] += 1
                await self.notifier.send_text(
                    guild,
                    (self.pipeline.state_cache.peek(guild_id).log_channel_id
                     if self.pipeline.state_cache.peek(guild_id)
                     else None),
                    "Raid mode has expired; verification level and slowmode were restored.",
                )
            except Exception:  # noqa: BLE001
                log.exception("could not lift raid mode", extra={"guild_id": guild_id})

        # Retention pruning, once per maintenance pass; cheap because indexed.
        try:
            async with self.db.begin() as session:
                uow = UnitOfWork(session)
                report["events_pruned"] = await uow.events.prune(
                    self.shield_config.retention_event_days
                )
                report["incidents_pruned"] = await uow.incidents.prune(
                    self.shield_config.retention_incident_days
                )
        except Exception:  # noqa: BLE001
            log.warning("retention pruning failed; retrying next tick")

        METRICS.gauge("detection_windows", self.pipeline.windows.size())
        METRICS.gauge("guilds", len(self.guilds))
        return report

    # -- error handling ------------------------------------------------
    async def on_error(self, event_method: str, *args: object, **kwargs: object) -> None:
        METRICS.incr("gateway_handler_errors_total")
        log.exception("unhandled error in gateway handler", extra={"event": event_method})
