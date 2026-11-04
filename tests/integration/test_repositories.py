"""Repository behaviour: multi-guild isolation, dedupe, idempotency, retention."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from shield.constants import (
    ActionKey,
    Confidence,
    EnforcementStatus,
    EventSource,
    IncidentStatus,
    ResponseAction,
    RestoreMode,
    RestoreStatus,
    Severity,
    ShieldMode,
    SnapshotKind,
    TrustScope,
)
from shield.db.repositories import UnitOfWork
from shield.policies.defaults import DEFAULT_POLICIES
from tests.conftest import GUILD_A, GUILD_B, OWNER_A, OWNER_B

NOW = datetime.now(tz=timezone.utc)


async def seed(db, guild_id: int, owner_id: int):  # noqa: ANN001, ANN201
    async with db.begin() as session:
        uow = UnitOfWork(session)
        return await uow.guilds.ensure(guild_id, guild_name=f"g{guild_id}", owner_id=owner_id)


async def test_new_guild_starts_disabled_dry_run_alert_only(db):  # noqa: ANN001
    settings = await seed(db, GUILD_A, OWNER_A)
    assert settings.enabled is False
    assert settings.dry_run is True
    assert settings.mode is ShieldMode.ALERT_ONLY


async def test_default_policies_are_seeded_once(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        first = await uow.policies.list_for_guild(GUILD_A)
        inserted_again = await uow.guilds.seed_policies(GUILD_A)
        second = await uow.policies.list_for_guild(GUILD_A)
    assert len(first) == len(DEFAULT_POLICIES)
    assert inserted_again == 0
    assert len(second) == len(DEFAULT_POLICIES)


async def test_default_thresholds_match_the_documented_policy(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    expected = {
        ActionKey.MASS_BAN: (2, 15),
        ActionKey.MASS_KICK: (2, 15),
        ActionKey.CHANNEL_DELETE: (1, 15),
        ActionKey.CHANNEL_CREATE_FLOOD: (4, 20),
        ActionKey.ROLE_DELETE: (1, 15),
        ActionKey.ROLE_CREATE_FLOOD: (4, 20),
        ActionKey.MASS_MENTION: (5, 10),
        ActionKey.MESSAGE_SPAM: (6, 8),
        ActionKey.DUPLICATE_SPAM: (4, 15),
        ActionKey.JOIN_FLOOD: (8, 20),
    }
    async with db.begin() as session:
        uow = UnitOfWork(session)
        for action, (threshold, window) in expected.items():
            policy = await uow.policies.get(GUILD_A, action)
            assert (policy.threshold_count, policy.window_seconds) == (threshold, window), action


async def test_policies_are_isolated_between_guilds(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    await seed(db, GUILD_B, OWNER_B)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.policies.set_values(
            GUILD_A, ActionKey.MASS_BAN, updated_by=1, threshold_count=99
        )
        a = await uow.policies.get(GUILD_A, ActionKey.MASS_BAN)
        b = await uow.policies.get(GUILD_B, ActionKey.MASS_BAN)
    assert a.threshold_count == 99
    assert b.threshold_count == 2, "guild B must keep the default"


async def test_policy_validation_rejects_nonsense(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        with pytest.raises(ValueError):
            await uow.policies.set_values(
                GUILD_A, ActionKey.MASS_BAN, updated_by=1, threshold_count=0
            )
        with pytest.raises(ValueError):
            await uow.policies.set_values(
                GUILD_A, ActionKey.MASS_BAN, updated_by=1, window_seconds=99999
            )


async def test_trust_entries_are_isolated_and_scoped(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    await seed(db, GUILD_B, OWNER_B)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.trust.add(
            GUILD_A,
            entity_type="user",
            entity_id=777,
            scopes=[TrustScope.WEBHOOKS],
            added_by=OWNER_A,
        )
        a = await uow.trust.list_for_guild(GUILD_A)
        b = await uow.trust.list_for_guild(GUILD_B)
    assert len(a) == 1 and a[0].scopes == ["webhooks"]
    assert b == []


async def test_trust_add_is_an_upsert(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.trust.add(
            GUILD_A, entity_type="user", entity_id=1, scopes=[TrustScope.ALL], added_by=OWNER_A
        )
        await uow.trust.add(
            GUILD_A, entity_type="user", entity_id=1, scopes=[TrustScope.MESSAGES], added_by=OWNER_A
        )
        rows = await uow.trust.list_for_guild(GUILD_A)
    assert len(rows) == 1 and rows[0].scopes == ["messages"]


async def test_expired_trust_entries_are_purged(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.trust.add(
            GUILD_A,
            entity_type="user",
            entity_id=1,
            scopes=[TrustScope.ALL],
            added_by=OWNER_A,
            expires_at=NOW - timedelta(hours=1),
        )
        assert await uow.trust.list_for_guild(GUILD_A) == []
        assert len(await uow.trust.list_for_guild(GUILD_A, include_expired=True)) == 1
        assert await uow.trust.purge_expired() == 1


async def test_duplicate_events_are_collapsed(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        inserts = []
        for _ in range(3):
            _, inserted = await uow.events.record(
                guild_id=GUILD_A,
                correlation_id="corr",
                dedupe_key="same-key",
                action_key=ActionKey.CHANNEL_DELETE,
                source=EventSource.GATEWAY,
                occurred_at=NOW,
            )
            inserts.append(inserted)
        count = await uow.events.count_in_window(
            GUILD_A, ActionKey.CHANNEL_DELETE, since=NOW - timedelta(minutes=1)
        )
    assert inserts == [True, False, False]
    assert count == 1


async def test_events_are_isolated_per_guild(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    await seed(db, GUILD_B, OWNER_B)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        for guild_id in (GUILD_A, GUILD_B):
            await uow.events.record(
                guild_id=guild_id,
                correlation_id="c",
                dedupe_key=f"k-{guild_id}",
                action_key=ActionKey.MASS_BAN,
                source=EventSource.GATEWAY,
                occurred_at=NOW,
            )
        a = await uow.events.count_in_window(
            GUILD_A, ActionKey.MASS_BAN, since=NOW - timedelta(minutes=1)
        )
    assert a == 1


async def make_incident(db, guild_id: int, **overrides):  # noqa: ANN001, ANN201
    async with db.begin() as session:
        uow = UnitOfWork(session)
        values = dict(
            guild_id=guild_id,
            correlation_id="corr",
            action_key=ActionKey.CHANNEL_DELETE,
            actor_id=4242,
            actor_confidence=Confidence.CONFIRMED,
            severity=Severity.CRITICAL,
            mode_at_detection=ShieldMode.ENFORCE,
            dry_run=False,
            detected_at=NOW,
            window_start=NOW,
            event_count=1,
            threshold_count=1,
            window_seconds=15,
            policy_version=1,
            response=ResponseAction.STRIP_DANGEROUS_ROLES,
            reason="test incident",
        )
        values.update(overrides)
        return await uow.incidents.create(**values)


async def test_incident_lookup_is_guild_scoped_idor_defence(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    await seed(db, GUILD_B, OWNER_B)
    incident = await make_incident(db, GUILD_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        assert await uow.incidents.get(GUILD_A, incident.id) is not None
        assert await uow.incidents.get(GUILD_B, incident.id) is None
        assert await uow.incidents.list_recent(GUILD_B) == []


async def test_acknowledge_and_false_positive_rate(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    first = await make_incident(db, GUILD_A)
    await make_incident(db, GUILD_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.incidents.acknowledge(
            GUILD_A, first.id, user_id=OWNER_A, note="legit restructure", false_positive=True
        )
        rate = await uow.incidents.false_positive_rate(GUILD_A, NOW - timedelta(days=1))
        counts = await uow.incidents.counts_by_status(GUILD_A, NOW - timedelta(days=1))
        refetched = await uow.incidents.get(GUILD_A, first.id)
    assert refetched.status is IncidentStatus.FALSE_POSITIVE
    assert refetched.acknowledgement_note == "legit restructure"
    assert rate == 0.5
    assert counts["false_positive"] == 1 and counts["open"] == 1


async def test_acknowledge_rejects_foreign_incident(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    await seed(db, GUILD_B, OWNER_B)
    incident = await make_incident(db, GUILD_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        assert await uow.incidents.acknowledge(GUILD_B, incident.id, user_id=OWNER_B) is None


async def test_enforcement_claim_is_idempotent(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    incident = await make_incident(db, GUILD_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        first, claimed_first = await uow.enforcement.claim(
            guild_id=GUILD_A,
            incident_id=incident.id,
            idempotency_key="key-1",
            action_type="strip_dangerous_roles",
            target_id=4242,
        )
        second, claimed_second = await uow.enforcement.claim(
            guild_id=GUILD_A,
            incident_id=incident.id,
            idempotency_key="key-1",
            action_type="strip_dangerous_roles",
            target_id=4242,
        )
        await uow.enforcement.finish(
            first.id,
            guild_id=GUILD_A,
            status=EnforcementStatus.SUCCEEDED,
            after_state={"removed": [1]},
            detail="ok",
        )
        rows = await uow.enforcement.list_for_incident(GUILD_A, incident.id)
    assert claimed_first is True and claimed_second is False
    assert first.id == second.id
    assert len(rows) == 1 and rows[0].status is EnforcementStatus.SUCCEEDED


async def test_concurrent_claims_only_one_wins(db):  # noqa: ANN001
    """Two tasks racing on the same step must not both execute it."""
    await seed(db, GUILD_A, OWNER_A)
    incident = await make_incident(db, GUILD_A)
    results: list[bool] = []

    async def claim() -> None:
        async with db.begin() as session:
            uow = UnitOfWork(session)
            _, claimed = await uow.enforcement.claim(
                guild_id=GUILD_A,
                incident_id=incident.id,
                idempotency_key="race",
                action_type="timeout",
            )
            results.append(claimed)

    await claim()
    await claim()
    assert results.count(True) == 1


async def test_cooldown_blocks_then_escalates(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        first_allowed, first_level = await uow.cooldowns.check_and_set(GUILD_A, "scope", 60)
        blocked, blocked_level = await uow.cooldowns.check_and_set(GUILD_A, "scope", 60)
        # A zero-second cooldown expires immediately -> escalation advances.
        await uow.cooldowns.clear(GUILD_A, "scope")
        await uow.cooldowns.check_and_set(GUILD_A, "scope", 0)
        allowed_again, level_again = await uow.cooldowns.check_and_set(GUILD_A, "scope", 0)
    assert (first_allowed, first_level) == (True, 0)
    assert blocked is False and blocked_level == 0
    assert allowed_again is True and level_again == 1


async def test_cooldowns_are_per_guild(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    await seed(db, GUILD_B, OWNER_B)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        assert (await uow.cooldowns.check_and_set(GUILD_A, "same", 60))[0] is True
        assert (await uow.cooldowns.check_and_set(GUILD_B, "same", 60))[0] is True


async def test_snapshot_versions_and_retention(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        for index in range(5):
            await uow.snapshots.create(
                guild_id=GUILD_A,
                kind=SnapshotKind.SCHEDULED,
                checksum=f"c{index}",
                summary={"roles": index},
                payload={"roles": []},
            )
        versions = [s.version for s in await uow.snapshots.list_for_guild(GUILD_A)]
        pruned = await uow.snapshots.enforce_retention(GUILD_A, keep=2)
        remaining = [s.version for s in await uow.snapshots.list_for_guild(GUILD_A)]
        latest = await uow.snapshots.latest(GUILD_A)
    assert versions == [5, 4, 3, 2, 1]
    assert pruned == 3 and remaining == [5, 4]
    assert latest.version == 5


async def test_invalid_snapshots_are_not_offered_for_restore(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.snapshots.create(
            guild_id=GUILD_A,
            kind=SnapshotKind.SCHEDULED,
            checksum="ok",
            summary={},
            payload={"roles": []},
        )
        await uow.snapshots.create(
            guild_id=GUILD_A,
            kind=SnapshotKind.SCHEDULED,
            checksum="bad",
            summary={},
            payload={"roles": []},
            validated=False,
            validation_errors=["truncated"],
        )
        latest_any = await uow.snapshots.latest(GUILD_A, validated_only=False)
        latest_valid = await uow.snapshots.latest(GUILD_A, validated_only=True)
    assert latest_any.version == 2
    assert latest_valid.version == 1


async def test_snapshots_are_isolated_between_guilds(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    await seed(db, GUILD_B, OWNER_B)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        snap = await uow.snapshots.create(
            guild_id=GUILD_A, kind=SnapshotKind.MANUAL, checksum="c", summary={}, payload={}
        )
        assert await uow.snapshots.get(GUILD_B, snap.id) is None
        assert await uow.snapshots.list_for_guild(GUILD_B) == []


async def test_restore_token_is_guild_scoped_and_expires(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    await seed(db, GUILD_B, OWNER_B)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        snap = await uow.snapshots.create(
            guild_id=GUILD_A, kind=SnapshotKind.MANUAL, checksum="c", summary={}, payload={}
        )
        job = await uow.restores.create(
            guild_id=GUILD_A,
            snapshot_id=snap.id,
            mode=RestoreMode.PREVIEW,
            status=RestoreStatus.PREVIEWED,
            requested_by=OWNER_A,
        )
        token = job.approval_token
        assert await uow.restores.find_pending_token(GUILD_A, token) is not None
        assert await uow.restores.find_pending_token(GUILD_A, token.lower()) is not None
        assert await uow.restores.find_pending_token(GUILD_B, token) is None
        assert await uow.restores.find_pending_token(GUILD_A, "NOPE12") is None

        expired = await uow.restores.create(
            guild_id=GUILD_A,
            snapshot_id=snap.id,
            mode=RestoreMode.PREVIEW,
            status=RestoreStatus.PREVIEWED,
            requested_by=OWNER_A,
            token_ttl_seconds=-1,
        )
        assert await uow.restores.find_pending_token(GUILD_A, expired.approval_token) is None
        refetched = await uow.restores.get(GUILD_A, expired.id)
        assert refetched.status is RestoreStatus.EXPIRED


async def test_retention_pruning(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    old = NOW - timedelta(days=400)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.events.record(
            guild_id=GUILD_A,
            correlation_id="c",
            dedupe_key="old",
            action_key=ActionKey.MASS_BAN,
            source=EventSource.GATEWAY,
            occurred_at=old,
        )
        await uow.events.record(
            guild_id=GUILD_A,
            correlation_id="c",
            dedupe_key="new",
            action_key=ActionKey.MASS_BAN,
            source=EventSource.GATEWAY,
            occurred_at=NOW,
        )
    await make_incident(db, GUILD_A, detected_at=old)
    await make_incident(db, GUILD_A, detected_at=NOW)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        assert await uow.events.prune(30) == 1
        assert await uow.incidents.prune(180) == 1
        assert await uow.events.prune(0) == 0, "retention 0 disables pruning"
        assert len(await uow.incidents.list_recent(GUILD_A, limit=10)) == 1


async def test_command_audit_records_denials(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        await uow.command_audit.record(
            user_id=999,
            command="shield enable",
            allowed=False,
            guild_id=GUILD_A,
            authority="none",
            reason="not the owner",
            parameters={"mode": "enforce"},
        )
        rows = await uow.command_audit.recent(GUILD_A)
        other = await uow.command_audit.recent(GUILD_B)
    assert len(rows) == 1 and rows[0].allowed is False
    assert other == []


async def test_incident_export_contains_no_message_content(db):  # noqa: ANN001
    await seed(db, GUILD_A, OWNER_A)
    await make_incident(db, GUILD_A)
    async with db.begin() as session:
        uow = UnitOfWork(session)
        rows = await uow.incidents.export(GUILD_A, NOW - timedelta(days=1))
    assert rows and set(rows[0]) >= {"id", "action", "actor_id", "confidence", "outcome"}
    assert "content" not in str(rows).lower()


async def test_guild_lock_serialises_work(db):  # noqa: ANN001
    """On SQLite this is a process-local lock; on PostgreSQL it is an advisory lock."""
    order: list[str] = []

    async def worker(name: str) -> None:
        async with db.guild_lock(GUILD_A, "incident"):
            order.append(f"in-{name}")
            await asyncio.sleep(0.01)
            order.append(f"out-{name}")

    await asyncio.gather(worker("a"), worker("b"))
    assert order in (
        ["in-a", "out-a", "in-b", "out-b"],
        ["in-b", "out-b", "in-a", "out-a"],
    )
