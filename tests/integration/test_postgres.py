"""PostgreSQL-specific paths.

Skipped unless ``SHIELD_TEST_PG_URL`` points at a disposable database, because
CI should not require a server. Run locally with, for example::

    SHIELD_TEST_PG_URL=postgresql+asyncpg://shield@127.0.0.1:5432/nfpd_shield_test \
        pytest tests/integration/test_postgres.py

These cover the three behaviours whose implementation differs from SQLite:

* ``INSERT ... ON CONFLICT DO NOTHING`` deduplication and claim semantics,
* ``pg_advisory_xact_lock`` per-guild coordination across concurrent tasks,
* the Alembic migration producing a schema the ORM can actually use.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

import pytest

from shield.config import DatabaseConfig
from shield.constants import ActionKey, EventSource
from shield.db.repositories import UnitOfWork
from shield.db.session import Database

PG_URL = os.environ.get("SHIELD_TEST_PG_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SHIELD_TEST_PG_URL to run the PostgreSQL integration tests"
)

GUILD = 100000000000000777


def pg_config() -> DatabaseConfig:
    return DatabaseConfig(
        url=PG_URL or "",
        pool_size=5,
        max_overflow=5,
        pool_timeout=10,
        command_timeout=10,
        requires_tls=False,
        tls_configured=False,
    )


@pytest.fixture
async def pg():  # noqa: ANN201
    database = Database(pg_config())
    ok, error = await database.ping()
    if not ok:
        pytest.skip(f"PostgreSQL unreachable: {error}")
    # The schema is expected to come from `alembic upgrade head`.
    import sqlalchemy as sa

    async with database.engine.begin() as conn:
        exists = await conn.scalar(
            sa.text(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema='public' AND table_name='guild_settings'"
            )
        )
    if not exists:
        await database.dispose()
        pytest.skip("run `alembic upgrade head` against SHIELD_TEST_PG_URL first")

    async with database.begin() as session:
        uow = UnitOfWork(session)
        await uow.guilds.ensure(GUILD, guild_name="pg-test", owner_id=1)
    yield database
    # Clean up this test guild only.
    import sqlalchemy as sa

    from shield.db.models import (
        CommandAudit,
        CooldownRecord,
        EnforcementRecord,
        EventRecord,
        GuildSettings,
        Incident,
        RestoreJob,
        Snapshot,
    )

    async with database.begin() as session:
        for model in (
            EnforcementRecord,
            Incident,
            EventRecord,
            RestoreJob,
            Snapshot,
            CooldownRecord,
            CommandAudit,
        ):
            await session.execute(sa.delete(model).where(model.guild_id == GUILD))
        await session.execute(
            sa.delete(GuildSettings).where(GuildSettings.guild_id == GUILD)
        )
    await database.dispose()


async def test_on_conflict_dedupe(pg):  # noqa: ANN001
    now = datetime.now(tz=timezone.utc)
    async with pg.begin() as session:
        uow = UnitOfWork(session)
        results = []
        for _ in range(3):
            _, inserted = await uow.events.record(
                guild_id=GUILD,
                correlation_id="pg",
                dedupe_key="pg-dedupe-key",
                action_key=ActionKey.CHANNEL_DELETE,
                source=EventSource.GATEWAY,
                occurred_at=now,
            )
            results.append(inserted)
    assert results == [True, False, False]


async def test_concurrent_enforcement_claims_are_exclusive(pg):  # noqa: ANN001
    outcomes: list[bool] = []

    async def claim() -> None:
        async with pg.begin() as session:
            uow = UnitOfWork(session)
            _, claimed = await uow.enforcement.claim(
                guild_id=GUILD,
                incident_id=None,
                idempotency_key="pg-race-key",
                action_type="strip_dangerous_roles",
            )
            outcomes.append(claimed)

    await asyncio.gather(*(claim() for _ in range(5)))
    assert outcomes.count(True) == 1, "exactly one task may own the step"


async def test_advisory_lock_serialises_per_guild(pg):  # noqa: ANN001
    order: list[str] = []

    async def worker(name: str) -> None:
        async with pg.guild_lock(GUILD, "incident"):
            order.append(f"in-{name}")
            await asyncio.sleep(0.05)
            order.append(f"out-{name}")

    await asyncio.gather(worker("a"), worker("b"))
    assert order in (
        ["in-a", "out-a", "in-b", "out-b"],
        ["in-b", "out-b", "in-a", "out-a"],
    ), f"advisory lock did not serialise: {order}"


async def test_advisory_locks_do_not_block_other_guilds(pg):  # noqa: ANN001
    started = asyncio.Event()

    async def holder() -> None:
        async with pg.guild_lock(GUILD, "incident"):
            started.set()
            await asyncio.sleep(0.2)

    async def other() -> bool:
        await started.wait()
        async with pg.guild_lock(GUILD + 1, "incident"):
            return True

    task = asyncio.create_task(holder())
    assert await asyncio.wait_for(other(), timeout=1.0) is True
    await task


async def test_try_lock_probe(pg):  # noqa: ANN001
    assert await pg.try_guild_lock(GUILD, "snapshot") is True
