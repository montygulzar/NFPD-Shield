"""HTTP health endpoints for container orchestration and monitoring.

Two endpoints, with the distinction Docker cares about:

``/health`` (liveness)
    The process is up and its event loop is scheduling work. Answering at all
    is the signal. It stays 200 while dependencies are down, because restarting
    the container would not fix a PostgreSQL outage.

``/ready`` (readiness)
    Shield is logged into Discord *and* PostgreSQL is reachable. Returns 503
    otherwise, so a degraded container is visible in ``docker ps`` and to
    whatever watches the monitoring network.

The server is deliberately not published to the host in the compose file, so it
is reachable only from inside the Docker network. Both routes are read-only and
expose no guild data, no configuration values and no secrets - only aggregate
counts and connection states - so they need no authentication.

This mirrors the endpoint contract used by the other NFPD services, so one
monitoring configuration covers all of them.
"""

from __future__ import annotations

import time
from typing import Any

from aiohttp import web

from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS

log = get_logger("health")

#: Readiness tolerates a brief gateway drop: discord.py resumes sessions on its
#: own within seconds, and flapping the container's health state during a normal
#: resume would be noise rather than signal.
DISCORD_GRACE_SECONDS = 90.0

#: Readiness caps how long it waits on the database, so a wedged server makes the
#: probe fail fast instead of hanging until the orchestrator's own timeout.
DB_PROBE_TIMEOUT = 3.0


class HealthServer:
    """Small aiohttp server exposing liveness and readiness."""

    def __init__(self, bot) -> None:  # noqa: ANN001 - ShieldBot
        self._bot = bot
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._disconnected_since: float | None = None

    # -- gateway state tracking ---------------------------------------
    def note_disconnected(self) -> None:
        if self._disconnected_since is None:
            self._disconnected_since = time.monotonic()

    def note_connected(self) -> None:
        self._disconnected_since = None

    def _discord_state(self) -> tuple[bool, str]:
        bot = self._bot
        if bot.is_closed():
            return False, "client closed"
        if not bot.is_ready():
            return False, "connecting"
        if self._disconnected_since is not None:
            outage = time.monotonic() - self._disconnected_since
            if outage > DISCORD_GRACE_SECONDS:
                return False, f"disconnected for {outage:.0f}s"
            return True, f"reconnecting ({outage:.0f}s)"
        return True, "connected"

    async def _database_state(self) -> tuple[bool, str]:
        ok, error = await self._bot.db.ping(timeout=DB_PROBE_TIMEOUT)
        if ok:
            return True, "connected"
        # The error text is deliberately reduced to its exception class: a DSN
        # with credentials can appear in the full message.
        return False, (error or "unreachable").split(":")[0]

    # -- routes --------------------------------------------------------
    async def _liveness(self, _request: web.Request) -> web.Response:
        config = self._bot.shield_config
        return web.json_response(
            {
                "status": "ok",
                "service": "nfpd-shield",
                "instance": config.instance_id,
                "version": config.app_version,
                "commit": config.git_commit,
                "uptime_seconds": round(METRICS.uptime_seconds(), 1),
            }
        )

    async def _readiness(self, _request: web.Request) -> web.Response:
        discord_ok, discord_detail = self._discord_state()
        database_ok, database_detail = await self._database_state()
        ready = discord_ok and database_ok
        payload: dict[str, Any] = {
            "status": "ready" if ready else "not_ready",
            "service": "nfpd-shield",
            "instance": self._bot.shield_config.instance_id,
            "version": self._bot.shield_config.app_version,
            "discord": {"ok": discord_ok, "detail": discord_detail},
            "database": {"ok": database_ok, "detail": database_detail},
            "guilds": len(getattr(self._bot, "guilds", ())),
            "uptime_seconds": round(METRICS.uptime_seconds(), 1),
        }
        return web.json_response(payload, status=200 if ready else 503)

    # -- lifecycle -----------------------------------------------------
    async def start(self) -> None:
        config = self._bot.shield_config
        if not config.health_server_enabled:
            log.info("health server disabled by configuration")
            return
        app = web.Application()
        app.router.add_get("/health", self._liveness)
        app.router.add_get("/ready", self._readiness)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, config.health_host, config.health_port)
        try:
            await self._site.start()
        except OSError as exc:
            # A busy port must not stop the bot from protecting guilds.
            log.error(
                "could not bind the health server; continuing without it",
                extra={
                    "host": config.health_host,
                    "port": config.health_port,
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )
            await self.stop()
            return
        log.info(
            "health server listening",
            extra={"host": config.health_host, "port": config.health_port},
        )

    async def stop(self) -> None:
        if self._runner is not None:
            try:
                await self._runner.cleanup()
            except Exception:  # noqa: BLE001 - shutdown must never raise
                log.warning("error while stopping the health server", exc_info=True)
        self._runner = None
        self._site = None
