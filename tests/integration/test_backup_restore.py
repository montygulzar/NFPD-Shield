"""Snapshot capture, integrity, planning and (partial) restoration."""

from __future__ import annotations

import discord
import pytest

from shield.backup import serializer
from shield.backup.snapshot import SnapshotScheduler, SnapshotService
from shield.constants import SnapshotKind
from shield.db.repositories import UnitOfWork
from shield.enforcement.ratelimit import RateLimiter
from shield.restore.applier import RestoreApplier
from shield.restore.planner import (
    UNSUPPORTED_CHANNEL_TYPES,
    build_plan,
    live_state_from_guild,
)
from tests.conftest import (
    GUILD_A,
    OWNER_A,
    FakeCategory,
    FakeChannel,
    FakeRole,
    build_guild,
    enable_guild,
    make_http_error,
    perms,
)


def populated_guild():  # noqa: ANN201
    """A guild with a category, two channels, overwrites and a managed role."""
    guild = build_guild()
    category = FakeCategory(id=GUILD_A + 200, name="Community", guild=guild, position=0)
    chat = FakeChannel(
        id=GUILD_A + 201, name="chat", guild=guild, category=category, topic="hello", position=0
    )
    voice = FakeChannel(id=GUILD_A + 202, name="Lounge", guild=guild, kind="voice", position=1)
    thread = FakeChannel(id=GUILD_A + 203, name="side-talk", guild=guild, kind="public_thread")
    managed = FakeRole(
        id=GUILD_A + 300,
        name="MusicBot",
        position=7,
        permissions=perms(manage_webhooks=True),
        managed=True,
        guild=guild,
    )
    guild.roles.append(managed)
    mod_role = next(r for r in guild.roles if r.name == "Admin")
    chat.overwrites = {
        mod_role: discord.PermissionOverwrite(send_messages=True, manage_messages=True)
    }
    guild.channels.extend([category, chat, voice, thread])
    return guild


def service(db, key: str | None = None) -> SnapshotService:  # noqa: ANN001
    return SnapshotService(
        db=db, limiter=RateLimiter(enforce_burst=99, notify_burst=99), encryption_key=key
    )


async def test_capture_records_structure_but_no_secrets(db):  # noqa: ANN001
    guild = populated_guild()
    await enable_guild(db, guild)
    result = await service(db).capture(guild, kind=SnapshotKind.MANUAL, taken_by=OWNER_A)

    assert result.ok and result.snapshot_id is not None and result.version == 1
    loaded = await service(db).load(guild.id, result.snapshot_id)
    assert loaded is not None
    meta, payload = loaded
    names = {c["name"] for c in payload["channels"]}
    assert {"chat", "Lounge", "side-talk"} <= names
    assert {c["name"] for c in payload["categories"]} == {"Community"}
    assert payload["guild"]["verification_level"] == "low"
    for webhook in payload["webhooks"]:
        assert set(webhook) <= {"id", "name", "channel_id", "type", "user_id", "created_at"}
        assert "token" not in webhook
    assert payload["not_captured"], "unrecoverable resources must be documented"
    assert any("webhook tokens" in n for n in payload["not_captured"])
    # overwrites are captured as allow/deny bitfields
    chat = next(c for c in payload["channels"] if c["name"] == "chat")
    assert chat["overwrites"] and chat["overwrites"][0]["allow"] > 0


async def test_capture_encrypts_when_a_key_is_configured(db):  # noqa: ANN001
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    guild = populated_guild()
    await enable_guild(db, guild)
    svc = service(db, key)
    result = await svc.capture(guild, kind=SnapshotKind.MANUAL)
    assert result.encrypted

    async with db.begin() as session:
        uow = UnitOfWork(session)
        row = await uow.snapshots.get(guild.id, result.snapshot_id)
        assert row.payload is None
        assert row.payload_ciphertext and b"Community" not in row.payload_ciphertext

    _, payload = await svc.load(guild.id, result.snapshot_id)
    assert payload["guild"]["name"] == guild.name

    # A different key cannot read it.
    other = service(db, Fernet.generate_key().decode())
    with pytest.raises(serializer.SnapshotEncryptionError):
        await other.load(guild.id, result.snapshot_id)

    # No key at all is an explicit, actionable failure.
    plain = service(db, None)
    with pytest.raises(serializer.SnapshotEncryptionError):
        await plain.load(guild.id, result.snapshot_id)


async def test_integrity_verification_detects_tampering(db):  # noqa: ANN001
    guild = populated_guild()
    await enable_guild(db, guild)
    svc = service(db)
    result = await svc.capture(guild, kind=SnapshotKind.MANUAL)
    ok, message = await svc.verify_integrity(guild.id, result.snapshot_id)
    assert ok and "verified" in message

    async with db.begin() as session:
        uow = UnitOfWork(session)
        row = await uow.snapshots.get(guild.id, result.snapshot_id)
        payload = dict(row.payload)
        payload["roles"] = []
        row.payload = payload
    ok, message = await svc.verify_integrity(guild.id, result.snapshot_id)
    assert not ok and "mismatch" in message


async def test_webhook_metadata_is_skipped_without_permission(db):  # noqa: ANN001
    guild = build_guild(
        bot_permissions=perms(view_audit_log=True, manage_roles=True, send_messages=True)
    )
    await enable_guild(db, guild)
    result = await service(db).capture(guild, kind=SnapshotKind.MANUAL, include_webhooks=True)
    assert "Manage Webhooks" in result.message


async def test_retention_is_enforced_per_guild(db):  # noqa: ANN001
    guild = populated_guild()
    await enable_guild(db, guild)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.guilds.update(guild.id, snapshot_retention=2)
    svc = service(db)
    for _ in range(4):
        await svc.capture(guild, kind=SnapshotKind.SCHEDULED, bypass_rate_limit=True)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        rows = await uow.snapshots.list_for_guild(guild.id)
    assert [r.version for r in rows] == [4, 3]


async def test_snapshot_rate_limit_protects_the_api(db):  # noqa: ANN001
    guild = populated_guild()
    await enable_guild(db, guild)
    svc = SnapshotService(db=db, limiter=RateLimiter(enforce_burst=1, notify_burst=1))
    outcomes = [await svc.capture(guild, kind=SnapshotKind.MANUAL) for _ in range(5)]
    assert any("rate limit" in o.message for o in outcomes)
    assert any(o.ok for o in outcomes)


async def test_scheduler_respects_each_guilds_interval(db, shield_config):  # noqa: ANN001
    from datetime import datetime, timedelta, timezone

    from tests.conftest import FakeBot

    guild = populated_guild()
    await enable_guild(db, guild)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.guilds.update(guild.id, snapshot_interval_minutes=60)
    bot = FakeBot(shield_config, db)
    bot.guilds.append(guild)
    scheduler = SnapshotScheduler(bot=bot, service=service(db), db=db)

    start = datetime.now(tz=timezone.utc)
    assert await scheduler.tick(now=start) == 1
    assert await scheduler.tick(now=start + timedelta(minutes=5)) == 0
    assert await scheduler.tick(now=start + timedelta(minutes=61)) == 1


# -- restore -----------------------------------------------------------
async def snapshot_then_wipe(db):  # noqa: ANN001, ANN201
    """Snapshot a populated guild, then simulate a nuke that deletes everything."""
    guild = populated_guild()
    await enable_guild(db, guild)
    svc = service(db)
    result = await svc.capture(guild, kind=SnapshotKind.MANUAL)
    _, payload = await svc.load(guild.id, result.snapshot_id)

    # The attacker deletes the category, both real channels and the Admin role.
    guild.channels = [c for c in guild.channels if c.name in {"general", "shield-log"}]
    guild.roles = [r for r in guild.roles if r.name not in {"Admin"}]
    return guild, payload, result


async def test_restore_plan_is_additive_and_honest(db):  # noqa: ANN001
    guild, payload, result = await snapshot_then_wipe(db)
    # Something legitimate was created after the snapshot.
    guild.channels.append(FakeChannel(id=GUILD_A + 999, name="new-project", guild=guild))

    roles, channels = live_state_from_guild(guild)
    plan = build_plan(
        guild_id=guild.id, snapshot_version=result.version, payload=payload,
        live_roles=roles, live_channels=channels,
    )
    ops = plan.counts()
    assert ops.get("create_role") == 1, "only the deleted Admin role"
    assert ops.get("create_category") == 1
    assert ops.get("create_channel") == 2, "chat + Lounge, never the thread"
    assert any("MusicBot" in s for s in plan.skipped), "managed roles are not recreated"
    assert any(
        UNSUPPORTED_CHANNEL_TYPES["public_thread"] in s for s in plan.skipped
    )
    assert any("new-project" in u for u in plan.untouched), "later edits are preserved"
    assert any("webhook" in u.lower() for u in plan.unrecoverable)
    assert "NOT recoverable" in plan.render()


async def test_restore_apply_recreates_structure_and_maps_ids(db, harness):  # noqa: ANN001
    guild, payload, result = await snapshot_then_wipe(db)
    roles, channels = live_state_from_guild(guild)
    plan = build_plan(
        guild_id=guild.id, snapshot_version=result.version, payload=payload,
        live_roles=roles, live_channels=channels,
    )
    applier = RestoreApplier(selfguard=harness.selfguard)
    outcome = await applier.apply(guild, plan)

    assert outcome.status_label == "completed"
    assert outcome.id_map, "old -> new IDs must be recorded"
    names = {c.name for c in guild.channels}
    assert {"Community", "chat", "Lounge"} <= names
    assert any(r.name == "Admin" for r in guild.roles)
    # The recreated channel sits under the recreated category.
    recreated_chat = next(c for c in guild.channels if c.name == "chat" and c.id > GUILD_A + 900)
    assert recreated_chat.category is not None
    assert recreated_chat.category.name == "Community"
    # New IDs, not the old ones.
    assert str(GUILD_A + 201) in outcome.id_map
    assert outcome.id_map[str(GUILD_A + 201)] != GUILD_A + 201


async def test_restore_registers_self_actions_so_it_cannot_trigger_itself(db, harness):  # noqa: ANN001
    guild, payload, result = await snapshot_then_wipe(db)
    roles, channels = live_state_from_guild(guild)
    plan = build_plan(
        guild_id=guild.id, snapshot_version=result.version, payload=payload,
        live_roles=roles, live_channels=channels,
    )
    applier = RestoreApplier(selfguard=harness.selfguard)
    await applier.apply(guild, plan)
    assert harness.selfguard.pending(guild.id) > 0
    assert harness.selfguard.is_self(guild.id, "channel_create", 123456)


async def test_partial_restoration_is_reported_truthfully(db, harness):  # noqa: ANN001
    """When Discord rejects some writes, the result says exactly what failed."""
    guild, payload, result = await snapshot_then_wipe(db)
    guild.fail_create_channel = make_http_error(403)
    roles, channels = live_state_from_guild(guild)
    plan = build_plan(
        guild_id=guild.id, snapshot_version=result.version, payload=payload,
        live_roles=roles, live_channels=channels,
    )
    outcome = await RestoreApplier(selfguard=harness.selfguard).apply(guild, plan)

    assert outcome.status_label == "partial"
    assert any("Admin" in r for r in outcome.restored), "the role still came back"
    assert len(outcome.failed) >= 2, "both channels and the category failed"
    assert all("Forbidden" in f for f in outcome.failed)
    rendered = outcome.render()
    assert "FAILED" in rendered and "partial" in rendered


async def test_restore_write_cap_defers_rather_than_dropping(db, harness):  # noqa: ANN001
    guild, payload, result = await snapshot_then_wipe(db)
    roles, channels = live_state_from_guild(guild)
    plan = build_plan(
        guild_id=guild.id, snapshot_version=result.version, payload=payload,
        live_roles=roles, live_channels=channels,
    )
    outcome = await RestoreApplier(selfguard=harness.selfguard).apply(guild, plan, max_writes=1)
    assert outcome.writes == 1
    assert any("write cap" in s for s in outcome.skipped)


async def test_restore_of_an_unchanged_guild_is_a_noop(db, harness):  # noqa: ANN001
    guild = populated_guild()
    await enable_guild(db, guild)
    svc = service(db)
    result = await svc.capture(guild, kind=SnapshotKind.MANUAL)
    _, payload = await svc.load(guild.id, result.snapshot_id)
    roles, channels = live_state_from_guild(guild)
    plan = build_plan(
        guild_id=guild.id, snapshot_version=result.version, payload=payload,
        live_roles=roles, live_channels=channels, scope={"roles", "categories", "channels"},
    )
    assert plan.write_count == 0
    assert "already matches" in plan.render()


async def test_guild_settings_restore_is_bounded_to_known_fields(db, harness):  # noqa: ANN001
    guild = populated_guild()
    await enable_guild(db, guild)
    svc = service(db)
    result = await svc.capture(guild, kind=SnapshotKind.MANUAL)
    _, payload = await svc.load(guild.id, result.snapshot_id)

    guild.verification_level = discord.VerificationLevel.none
    guild.name = "Hacked Guild"
    roles, channels = live_state_from_guild(guild)
    plan = build_plan(
        guild_id=guild.id, snapshot_version=result.version, payload=payload,
        live_roles=roles, live_channels=channels, scope={"settings"},
    )
    outcome = await RestoreApplier(selfguard=harness.selfguard).apply(guild, plan)
    assert guild.verification_level is discord.VerificationLevel.low
    assert guild.name == "Test Guild"
    assert len(outcome.restored) == 2


async def test_invalid_snapshot_is_never_the_restore_source(db):  # noqa: ANN001
    guild = populated_guild()
    await enable_guild(db, guild)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.snapshots.create(
            guild_id=guild.id,
            kind=SnapshotKind.SCHEDULED,
            checksum="x",
            summary={},
            payload={"schema_version": 1},
            validated=False,
            validation_errors=["no @everyone role present"],
        )
    assert await service(db).latest_valid(guild.id) is None
