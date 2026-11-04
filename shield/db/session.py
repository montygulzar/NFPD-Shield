"""Async engine / session management, health checks and advisory locks."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from shield.config import DatabaseConfig
from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS

log = get_logger("db")

#: Namespace constant mixed into advisory lock keys so Shield cannot collide
#: with another application sharing the database.
ADVISORY_NAMESPACE = 0x5348_4C44  # "SHLD"


class Database:
    """Owns the engine and session factory.

    ``healthy`` tracks the last observed connectivity state so that detection
    can degrade gracefully (alert-only, in-memory) during a database outage
    rather than crashing the event loop.
    """

    def __init__(self, cfg: DatabaseConfig) -> None:
        self._cfg = cfg
        kwargs: dict[str, object] = {
            "echo": False,
            "pool_pre_ping": True,
            "future": True,
        }
        if cfg.is_sqlite:
            # SQLite (tests) does not support pool sizing options.
            # ``timeout`` is SQLite's busy timeout: concurrent sessions wait
            # for the write lock instead of failing immediately.
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        else:
            kwargs.update(
                pool_size=cfg.pool_size,
                max_overflow=cfg.max_overflow,
                pool_timeout=cfg.pool_timeout,
                pool_recycle=1800,
                connect_args={
                    "command_timeout": cfg.command_timeout,
                    "server_settings": {"application_name": "nfpd-shield"},
                },
            )
        self._engine: AsyncEngine = create_async_engine(cfg.url, **kwargs)
        self._sessionmaker = async_sessionmaker(
            self._engine, expire_on_commit=False, class_=AsyncSession
        )
        self.healthy: bool = False
        self.last_error: str | None = None

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @property
    def config(self) -> DatabaseConfig:
        return self._cfg

    def session(self) -> AsyncSession:
        return self._sessionmaker()

    @contextlib.asynccontextmanager
    async def begin(self) -> AsyncIterator[AsyncSession]:
        """Transactional scope; commits on success, rolls back on error."""
        session = self._sessionmaker()
        try:
            async with session.begin():
                yield session
            self.healthy = True
            self.last_error = None
        except Exception as exc:
            self.healthy = False
            self.last_error = f"{type(exc).__name__}: {exc}"
            METRICS.incr("db_errors_total")
            raise
        finally:
            await session.close()

    async def ping(self, timeout: float = 5.0) -> tuple[bool, str | None]:
        try:
            async with asyncio.timeout(timeout):
                async with self._engine.connect() as conn:
                    await conn.execute(sa.text("SELECT 1"))
            self.healthy = True
            self.last_error = None
            return True, None
        except Exception as exc:
            self.healthy = False
            self.last_error = f"{type(exc).__name__}: {exc}"
            METRICS.incr("db_errors_total")
            return False, self.last_error

    async def dispose(self) -> None:
        await self._engine.dispose()

    # -- per-guild coordination ---------------------------------------
    @contextlib.asynccontextmanager
    async def guild_lock(self, guild_id: int, purpose: str = "incident") -> AsyncIterator[bool]:
        """Serialise work for one guild across processes and shards.

        On PostgreSQL this is a transaction-scoped advisory lock, so multiple
        Shield instances never create duplicate incidents or race a restore.
        On SQLite (tests) it degrades to a process-local asyncio lock, which is
        why multi-process deployments require PostgreSQL.

        Yields ``True`` when the lock was obtained.
        """
        if self._cfg.is_sqlite:
            key = (guild_id, purpose)
            lock = _LOCAL_LOCKS.setdefault(key, asyncio.Lock())
            async with lock:
                yield True
            return

        key2 = _purpose_key(purpose)
        async with self._engine.begin() as conn:
            await conn.execute(
                sa.text("SELECT pg_advisory_xact_lock(:a, :b)"),
                {"a": _signed32(guild_id ^ ADVISORY_NAMESPACE), "b": key2},
            )
            yield True

    async def try_guild_lock(self, guild_id: int, purpose: str = "incident") -> bool:
        """Non-blocking advisory lock probe (session scoped, PostgreSQL only)."""
        if self._cfg.is_sqlite:
            key = (guild_id, purpose)
            lock = _LOCAL_LOCKS.setdefault(key, asyncio.Lock())
            if lock.locked():
                return False
            return True
        async with self._engine.connect() as conn:
            result = await conn.execute(
                sa.text("SELECT pg_try_advisory_lock(:a, :b)"),
                {"a": _signed32(guild_id ^ ADVISORY_NAMESPACE), "b": _purpose_key(purpose)},
            )
            got = bool(result.scalar())
            if got:
                await conn.execute(
                    sa.text("SELECT pg_advisory_unlock(:a, :b)"),
                    {"a": _signed32(guild_id ^ ADVISORY_NAMESPACE), "b": _purpose_key(purpose)},
                )
            return got


_LOCAL_LOCKS: dict[tuple[int, str], asyncio.Lock] = {}

_PURPOSES = ("incident", "restore", "snapshot", "lockdown", "bootstrap")


def _purpose_key(purpose: str) -> int:
    try:
        return _PURPOSES.index(purpose)
    except ValueError:
        return abs(hash(purpose)) % 10_000 + 100


def _signed32(value: int) -> int:
    """Fold an arbitrary integer into the signed 32-bit range PostgreSQL wants."""
    folded = value % (2**32)
    return folded - 2**32 if folded >= 2**31 else folded
