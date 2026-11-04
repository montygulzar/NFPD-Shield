"""Snapshot service: capture, validate, store, retain, schedule.

Snapshots are taken:

* at startup for every guild Shield can see,
* on a per-guild schedule (``snapshot_interval_minutes``),
* on demand via ``/shield backup create``,
* immediately before a restore (``PRE_RESTORE``) so a bad restore is itself
  reversible,
* before a known authorised structural change, when a command triggers one.

Retention is enforced per guild (``snapshot_retention``), and snapshots that
fail structural validation are stored but flagged so they can never be selected
as a restore source.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from shield.backup import serializer
from shield.constants import SnapshotKind
from shield.db.repositories import UnitOfWork
from shield.enforcement.ratelimit import RateLimiter, call_with_retry
from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS

log = get_logger("backup")


@dataclass(slots=True)
class SnapshotResult:
    ok: bool
    snapshot_id: int | None
    version: int | None
    summary: dict[str, Any]
    validation_errors: list[str]
    message: str
    encrypted: bool = False


class SnapshotService:
    def __init__(
        self,
        *,
        db,  # noqa: ANN001
        limiter: RateLimiter,
        encryption_key: str | None = None,
        include_webhooks_default: bool = True,
    ) -> None:
        self.db = db
        self.limiter = limiter
        self.encryption_key = encryption_key
        self.include_webhooks_default = include_webhooks_default

    async def capture(
        self,
        guild,  # noqa: ANN001
        *,
        kind: SnapshotKind,
        taken_by: int | None = None,
        include_webhooks: bool | None = None,
        bypass_rate_limit: bool = False,
    ) -> SnapshotResult:
        """Serialise and persist one snapshot of ``guild``."""
        if not bypass_rate_limit and not self.limiter.allow("snapshot", guild.id):
            return SnapshotResult(
                False,
                None,
                None,
                {},
                [],
                "snapshot rate limit reached for this guild; try again shortly",
            )

        want_webhooks = (
            self.include_webhooks_default if include_webhooks is None else include_webhooks
        )
        webhooks: list[Any] = []
        webhook_note = ""
        if want_webhooks:
            perms = getattr(getattr(guild, "me", None), "guild_permissions", None)
            if getattr(perms, "manage_webhooks", False) or getattr(perms, "administrator", False):
                try:
                    webhooks = list(
                        await call_with_retry(
                            lambda: guild.webhooks(), attempts=2, description="list webhooks"
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    webhook_note = f" webhook metadata unavailable ({type(exc).__name__})."
            else:
                webhook_note = " webhook metadata skipped (missing Manage Webhooks)."

        payload = serializer.build_snapshot(
            guild, include_webhooks=want_webhooks, webhooks=webhooks
        )
        errors = serializer.validate(payload)
        digest = serializer.checksum(payload)
        summary = serializer.summarize(payload)

        encrypted = bool(self.encryption_key)
        stored_payload: dict[str, Any] | None = None
        ciphertext: bytes | None = None
        if encrypted:
            try:
                ciphertext = serializer.encrypt_payload(payload, self.encryption_key or "")
            except serializer.SnapshotEncryptionError as exc:
                log.error("snapshot encryption failed", extra={"guild_id": guild.id})
                return SnapshotResult(False, None, None, summary, errors, str(exc))
        else:
            stored_payload = payload

        async with self.db.begin() as session:
            uow = UnitOfWork(session)
            settings = await uow.guilds.get(guild.id)
            retention = int(getattr(settings, "snapshot_retention", 12) or 12)
            row = await uow.snapshots.create(
                guild_id=guild.id,
                kind=kind,
                checksum=digest,
                summary=summary,
                payload=stored_payload,
                payload_ciphertext=ciphertext,
                encrypted=encrypted,
                taken_by=taken_by,
                validated=not errors,
                validation_errors=errors or None,
                schema_version=serializer.SNAPSHOT_SCHEMA_VERSION,
            )
            pruned = await uow.snapshots.enforce_retention(guild.id, retention)
            snapshot_id, version = row.id, row.version

        METRICS.incr("snapshots_total", kind=kind.value)
        message = (
            f"snapshot v{version} stored ({summary['roles']} roles, "
            f"{summary['categories']} categories, {summary['channels']} channels"
            f", {summary['webhooks']} webhooks)."
            + (f" Pruned {pruned} old snapshot(s)." if pruned else "")
            + webhook_note
        )
        if errors:
            message += " WARNING: snapshot failed validation and will not be offered for restore."
        log.info(
            "snapshot captured",
            extra={
                "guild_id": guild.id,
                "version": version,
                "kind": kind.value,
                "encrypted": encrypted,
                "validation_errors": errors,
            },
        )
        return SnapshotResult(
            not errors, snapshot_id, version, summary, errors, message, encrypted
        )

    async def load(self, guild_id: int, snapshot_id: int) -> tuple[Any, dict[str, Any]] | None:
        """Fetch a snapshot row and its decrypted payload (guild-scoped)."""
        async with self.db.begin() as session:
            uow = UnitOfWork(session)
            row = await uow.snapshots.get(guild_id, snapshot_id)
            if row is None:
                return None
            payload = serializer.load_snapshot_payload(row, self.encryption_key)
            detached = {
                "id": row.id,
                "version": row.version,
                "kind": row.kind.value,
                "taken_at": row.taken_at,
                "checksum": row.checksum,
                "encrypted": row.encrypted,
                "summary": dict(row.summary or {}),
                "validated": row.validated,
                "validation_errors": list(row.validation_errors or []),
            }
        return detached, payload

    async def latest_valid(self, guild_id: int) -> tuple[Any, dict[str, Any]] | None:
        async with self.db.begin() as session:
            uow = UnitOfWork(session)
            row = await uow.snapshots.latest(guild_id, validated_only=True)
            if row is None:
                return None
            snapshot_id = row.id
        return await self.load(guild_id, snapshot_id)

    async def verify_integrity(self, guild_id: int, snapshot_id: int) -> tuple[bool, str]:
        """Recompute the checksum to detect tampering or storage corruption."""
        loaded = await self.load(guild_id, snapshot_id)
        if loaded is None:
            return False, "snapshot not found for this guild"
        meta, payload = loaded
        recomputed = serializer.checksum(payload)
        if recomputed != meta["checksum"]:
            return False, (
                "checksum mismatch: stored "
                f"{meta['checksum'][:12]}... vs recomputed {recomputed[:12]}..."
            )
        return True, f"checksum verified ({recomputed[:12]}...)"


class SnapshotScheduler:
    """Background loop driving scheduled snapshots.

    Runs one pass per minute, which is cheap, and only captures a guild whose
    own interval has elapsed. Failures for one guild never stop the loop.
    """

    def __init__(self, *, bot, service: SnapshotService, db) -> None:  # noqa: ANN001
        self.bot = bot
        self.service = service
        self.db = db
        self._task: asyncio.Task | None = None
        self._last_run: dict[int, datetime] = {}
        self._stopping = asyncio.Event()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stopping.clear()
            self._task = asyncio.create_task(self._run(), name="shield-snapshot-scheduler")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _run(self) -> None:
        await self.bot.wait_until_ready()
        while not self._stopping.is_set():
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("snapshot scheduler tick failed")
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=60)
            except TimeoutError:
                continue

    async def tick(self, now: datetime | None = None) -> int:
        """One scheduler pass. Returns how many snapshots were taken."""
        moment = now or datetime.now(tz=timezone.utc)
        taken = 0
        async with self.db.begin() as session:
            uow = UnitOfWork(session)
            rows = await uow.guilds.list_all()
            plan = [
                (r.guild_id, int(r.snapshot_interval_minutes or 360), bool(r.snapshot_include_webhooks))
                for r in rows
            ]
        for guild_id, interval, include_webhooks in plan:
            guild = self.bot.get_guild(guild_id)
            if guild is None:
                continue
            last = self._last_run.get(guild_id)
            if last is not None and moment - last < timedelta(minutes=max(5, interval)):
                continue
            result = await self.service.capture(
                guild, kind=SnapshotKind.SCHEDULED, include_webhooks=include_webhooks
            )
            self._last_run[guild_id] = moment
            if result.snapshot_id is not None:
                taken += 1
        return taken
