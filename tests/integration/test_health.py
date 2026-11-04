"""Health and readiness endpoints.

The contract matters beyond Shield itself: the compose HEALTHCHECK and the
monitoring network on the NFPD host both consume it, and it is the same shape
the other NFPD services expose.
"""

from __future__ import annotations

import contextlib

import pytest
from aiohttp import web

from shield.health import DISCORD_GRACE_SECONDS, HealthServer
from tests.conftest import GUILD_A, OWNER_A, build_guild


class StubBot:
    """The slice of ShieldBot the health server reads."""

    def __init__(self, config, db, *, ready: bool = True, closed: bool = False) -> None:  # noqa: ANN001
        self.shield_config = config
        self.db = db
        self.guilds = [build_guild(GUILD_A, OWNER_A)]
        self._ready = ready
        self._closed = closed

    def is_ready(self) -> bool:
        return self._ready

    def is_closed(self) -> bool:
        return self._closed


async def call(server: HealthServer, route: str) -> tuple[int, dict]:
    """Invoke a route handler directly, without binding a socket."""
    handler = server._liveness if route == "/health" else server._readiness
    request = _FakeRequest()
    response = await handler(request)
    import json

    return response.status, json.loads(response.body)


class _FakeRequest:
    """aiohttp passes the request in; neither handler reads anything from it."""


@pytest.fixture
def server(db, shield_config):  # noqa: ANN001, ANN201
    return HealthServer(StubBot(shield_config, db))


async def test_liveness_is_ok_even_when_dependencies_are_down(server, monkeypatch):  # noqa: ANN001
    """Restarting the container would not fix a database outage, so liveness stays 200."""

    async def broken_ping(timeout: float = 5.0):  # noqa: ANN202
        return False, "ConnectionRefusedError: refused"

    monkeypatch.setattr(server._bot.db, "ping", broken_ping)
    status, body = await call(server, "/health")
    assert status == 200
    assert body["status"] == "ok"
    assert body["service"] == "nfpd-shield"
    assert "uptime_seconds" in body


async def test_liveness_reports_the_running_build(server):  # noqa: ANN001
    _, body = await call(server, "/health")
    assert body["version"] == "dev" and body["commit"] == "unknown"


async def test_readiness_is_200_when_discord_and_database_are_up(server):  # noqa: ANN001
    status, body = await call(server, "/ready")
    assert status == 200
    assert body["status"] == "ready"
    assert body["discord"] == {"ok": True, "detail": "connected"}
    assert body["database"]["ok"] is True
    assert body["guilds"] == 1


async def test_readiness_is_503_when_the_database_is_unreachable(server, monkeypatch):  # noqa: ANN001
    async def broken_ping(timeout: float = 5.0):  # noqa: ANN202
        return False, "ConnectionRefusedError: connection refused to host db"

    monkeypatch.setattr(server._bot.db, "ping", broken_ping)
    status, body = await call(server, "/ready")
    assert status == 503
    assert body["status"] == "not_ready"
    assert body["database"]["ok"] is False
    # Only the exception class is exposed: the full text can contain a DSN.
    assert body["database"]["detail"] == "ConnectionRefusedError"
    assert "host db" not in str(body)


async def test_readiness_is_503_while_still_connecting(db, shield_config):  # noqa: ANN001
    server = HealthServer(StubBot(shield_config, db, ready=False))
    status, body = await call(server, "/ready")
    assert status == 503
    assert body["discord"] == {"ok": False, "detail": "connecting"}


async def test_readiness_is_503_when_the_client_is_closed(db, shield_config):  # noqa: ANN001
    server = HealthServer(StubBot(shield_config, db, closed=True))
    status, body = await call(server, "/ready")
    assert status == 503
    assert body["discord"]["detail"] == "client closed"


async def test_a_brief_gateway_drop_is_tolerated(server, monkeypatch):  # noqa: ANN001
    """discord.py resumes on its own; flapping the container state would be noise."""
    clock = {"now": 1000.0}
    monkeypatch.setattr("shield.health.time.monotonic", lambda: clock["now"])

    server.note_disconnected()
    clock["now"] += 5
    status, body = await call(server, "/ready")
    assert status == 200
    assert "reconnecting" in body["discord"]["detail"]

    clock["now"] += DISCORD_GRACE_SECONDS + 1
    status, body = await call(server, "/ready")
    assert status == 503
    assert "disconnected for" in body["discord"]["detail"]

    server.note_connected()
    status, _ = await call(server, "/ready")
    assert status == 200


async def test_server_binds_and_serves_both_routes(db, shield_config, unused_tcp_port):  # noqa: ANN001
    import dataclasses

    import aiohttp

    config = dataclasses.replace(shield_config, health_port=unused_tcp_port)
    server = HealthServer(StubBot(config, db))
    await server.start()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{unused_tcp_port}/health") as response:
                assert response.status == 200
                assert (await response.json())["status"] == "ok"
            async with session.get(f"http://127.0.0.1:{unused_tcp_port}/ready") as response:
                assert response.status == 200
            async with session.get(f"http://127.0.0.1:{unused_tcp_port}/nope") as response:
                assert response.status == 404
    finally:
        await server.stop()


async def test_disabled_server_binds_nothing(db, shield_config, unused_tcp_port):  # noqa: ANN001
    import dataclasses

    import aiohttp

    config = dataclasses.replace(
        shield_config, health_server_enabled=False, health_port=unused_tcp_port
    )
    server = HealthServer(StubBot(config, db))
    await server.start()
    try:
        async with aiohttp.ClientSession() as session:
            with pytest.raises(aiohttp.ClientConnectorError):
                await session.get(
                    f"http://127.0.0.1:{unused_tcp_port}/health", timeout=aiohttp.ClientTimeout(total=2)
                )
    finally:
        await server.stop()


async def test_a_busy_port_does_not_stop_the_bot(db, shield_config, unused_tcp_port):  # noqa: ANN001
    """Protecting guilds matters more than serving a probe."""
    import dataclasses

    blocker = web.Application()
    runner = web.AppRunner(blocker)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", unused_tcp_port)
    await site.start()
    try:
        config = dataclasses.replace(
            shield_config, health_host="127.0.0.1", health_port=unused_tcp_port
        )
        server = HealthServer(StubBot(config, db))
        await server.start()  # must not raise
        await server.stop()
    finally:
        with contextlib.suppress(Exception):
            await runner.cleanup()


async def test_stop_is_safe_before_start(db, shield_config):  # noqa: ANN001
    await HealthServer(StubBot(shield_config, db)).stop()
