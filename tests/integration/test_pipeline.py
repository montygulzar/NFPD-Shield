"""End-to-end pipeline behaviour against Discord fakes.

These tests drive the real pipeline: normalise -> dedupe -> attribute ->
evaluate -> incident -> enforce -> notify, with only the Discord API faked.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import discord

from shield.constants import (
    ActionKey,
    Confidence,
    EnforcementStatus,
    EventSource,
    ResponseAction,
)
from shield.db.repositories import UnitOfWork
from shield.events.normalize import NormalizedEvent, hash_content
from tests.conftest import (
    ATTACKER,
    GUILD_A,
    GUILD_B,
    MOD,
    OWNER_A,
    OWNER_B,
    FakeRole,
    audit_entry,
    build_guild,
    enable_guild,
    perms,
    set_policy,
)


def channel_delete_event(guild, channel_id: int) -> NormalizedEvent:  # noqa: ANN001
    return NormalizedEvent(
        guild_id=guild.id,
        action_key=ActionKey.CHANNEL_DELETE,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        target_type="channel",
        target_id=channel_id,
        payload={"target_name": f"chan-{channel_id}"},
    )


def ban_event(guild, user_id: int) -> NormalizedEvent:  # noqa: ANN001
    return NormalizedEvent(
        guild_id=guild.id,
        action_key=ActionKey.MASS_BAN,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        target_type="user",
        target_id=user_id,
    )


def spam_event(guild, author_id: int, message_id: int, channel_id: int) -> NormalizedEvent:  # noqa: ANN001
    return NormalizedEvent(
        guild_id=guild.id,
        action_key=ActionKey.MESSAGE_SPAM,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        actor_id=author_id,
        actor_confidence=Confidence.CONFIRMED,
        target_type="message",
        target_id=message_id,
        channel_id=channel_id,
    )


def add_delete_audit(guild, entry_id: int, channel_id: int, actor_id: int = ATTACKER) -> None:  # noqa: ANN001
    guild.audit_entries.append(
        audit_entry(
            entry_id=entry_id,
            actor_id=actor_id,
            target_id=channel_id,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=0.2,
        )
    )


async def latest_incident(db, guild_id: int):  # noqa: ANN001, ANN201
    async with db.begin() as session:
        uow = UnitOfWork(session)
        rows = await uow.incidents.list_recent(guild_id, limit=1)
    return rows[0] if rows else None


# ---------------------------------------------------------------------
async def test_confirmed_nuke_strips_only_dangerous_roles(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    add_delete_audit(guild, 1, 555)

    result = await harness.pipeline.handle(channel_delete_event(guild, 555), guild)

    assert result.code == "enforce"
    assert result.enforcement["status"] in {
        EnforcementStatus.SUCCEEDED.value,
        EnforcementStatus.PARTIAL.value,
    }
    attacker = guild.members[ATTACKER]
    # Admin was removed; the colour role and @everyone were preserved.
    assert attacker.removed_roles, "dangerous role should have been removed"
    remaining = {r.name for r in attacker.roles}
    assert "Admin" not in remaining
    assert {"@everyone", "Blue"} <= remaining

    incident = await latest_incident(harness.db, guild.id)
    assert incident.actor_id == ATTACKER
    assert incident.actor_confidence is Confidence.CONFIRMED
    assert incident.outcome in {EnforcementStatus.SUCCEEDED, EnforcementStatus.PARTIAL}
    log_channel = guild.get_channel(guild.id + 101)
    assert log_channel.sent, "an incident report must be posted"


async def test_guild_owner_is_never_sanctioned(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    add_delete_audit(guild, 2, 556, actor_id=OWNER_A)

    result = await harness.pipeline.handle(channel_delete_event(guild, 556), guild)

    assert result.code == "owner_alert_only"
    assert result.enforcement is None
    assert guild.members[OWNER_A].removed_roles == []
    incident = await latest_incident(harness.db, guild.id)
    assert incident.actor_id == OWNER_A
    assert incident.response is ResponseAction.ALERT_ONLY
    assert guild.get_channel(guild.id + 101).sent


async def test_missing_audit_permission_degrades_to_alert(harness):  # noqa: ANN001
    guild = harness.register_guild(
        build_guild(bot_permissions=perms(manage_roles=True, send_messages=True, embed_links=True))
    )
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    add_delete_audit(guild, 3, 557)

    result = await harness.pipeline.handle(channel_delete_event(guild, 557), guild)

    assert result.code == "unconfirmed_actor"
    assert guild.members[ATTACKER].removed_roles == []
    incident = await latest_incident(harness.db, guild.id)
    assert incident.actor_confidence is Confidence.UNKNOWN
    assert "could not be confirmed" in incident.reason


async def test_stale_audit_entry_never_sanctions(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    guild.audit_entries.append(
        audit_entry(
            entry_id=4,
            actor_id=ATTACKER,
            target_id=558,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=3600,
        )
    )
    result = await harness.pipeline.handle(channel_delete_event(guild, 558), guild)
    assert result.code == "unconfirmed_actor"
    assert guild.members[ATTACKER].removed_roles == []


async def test_duplicate_gateway_delivery_is_collapsed(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    add_delete_audit(guild, 5, 559)

    first = await harness.pipeline.handle(channel_delete_event(guild, 559), guild)
    second = await harness.pipeline.handle(channel_delete_event(guild, 559), guild)

    assert first.code == "enforce"
    assert second.duplicate is True and second.code == "duplicate"
    assert len(guild.members[ATTACKER].removed_roles) == 1, "no double enforcement"


async def test_dry_run_changes_nothing(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, dry_run=True)
    add_delete_audit(guild, 6, 560)

    result = await harness.pipeline.handle(channel_delete_event(guild, 560), guild)

    assert result.code == "dry_run"
    assert guild.members[ATTACKER].removed_roles == []
    incident = await latest_incident(harness.db, guild.id)
    assert incident.dry_run is True
    assert incident.outcome is EnforcementStatus.DRY_RUN
    assert incident.details["would_have_done"] == "strip_dangerous_roles"


async def test_alert_only_guild_records_but_does_not_act(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, mode="alert_only", dry_run=False)
    add_delete_audit(guild, 7, 561)

    result = await harness.pipeline.handle(channel_delete_event(guild, 561), guild)

    assert result.code == "alert_only_mode"
    assert guild.members[ATTACKER].removed_roles == []


async def test_guild_not_enabled_is_alert_only(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    add_delete_audit(guild, 8, 562)
    result = await harness.pipeline.handle(channel_delete_event(guild, 562), guild)
    assert result.code == "alert_only_mode"
    assert "not enabled" in result.decision.reason


async def test_role_above_the_bot_reports_failed_containment(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    # Give the attacker a dangerous role above Shield's own role.
    super_role = FakeRole(
        id=guild.id + 900,
        name="SuperAdmin",
        position=99,
        permissions=perms(administrator=True),
        guild=guild,
    )
    guild.roles.append(super_role)
    attacker = guild.members[ATTACKER]
    attacker.roles = [guild.roles[0], super_role]
    add_delete_audit(guild, 9, 563)

    result = await harness.pipeline.handle(channel_delete_event(guild, 563), guild)

    assert result.code == "enforcement_blocked"
    assert attacker.removed_roles == []
    incident = await latest_incident(harness.db, guild.id)
    assert incident.severity.value == "critical"
    assert "out of Shield's reach" in incident.reason or "above Shield" in incident.reason


async def test_missing_manage_roles_is_reported_not_claimed(harness):  # noqa: ANN001
    guild = harness.register_guild(
        build_guild(
            bot_permissions=perms(view_audit_log=True, send_messages=True, embed_links=True)
        )
    )
    await enable_guild(harness.db, guild)
    add_delete_audit(guild, 10, 564)

    result = await harness.pipeline.handle(channel_delete_event(guild, 564), guild)

    assert result.code == "enforcement_blocked"
    assert "Manage Roles" in result.decision.reason


async def test_allowlisted_actor_is_ignored(harness):  # noqa: ANN001
    from shield.constants import TrustScope

    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        await uow.trust.add(
            guild.id,
            entity_type="user",
            entity_id=ATTACKER,
            scopes=[TrustScope.DESTRUCTIVE],
            added_by=OWNER_A,
        )
    harness.pipeline.state_cache.invalidate(guild.id)
    add_delete_audit(guild, 11, 565)

    result = await harness.pipeline.handle(channel_delete_event(guild, 565), guild)

    assert result.code == "trusted"
    assert guild.members[ATTACKER].removed_roles == []


async def test_shields_own_actions_do_not_trigger_itself(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    # Shield announces a repair burst, as the restore applier does.
    harness.selfguard.register(guild.id, "channel_create", None, count=5)

    results = []
    for index in range(5):
        event = NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.CHANNEL_CREATE_FLOOD,
            source=EventSource.GATEWAY,
            occurred_at=datetime.now(tz=timezone.utc),
            target_type="channel",
            target_id=700 + index,
        )
        results.append(await harness.pipeline.handle(event, guild))
    assert all(r.code == "self_inflicted" for r in results)
    assert guild.members[ATTACKER].removed_roles == []


async def test_cooldown_prevents_a_response_loop(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    add_delete_audit(guild, 12, 566)
    add_delete_audit(guild, 13, 567)

    first = await harness.pipeline.handle(channel_delete_event(guild, 566), guild)
    second = await harness.pipeline.handle(channel_delete_event(guild, 567), guild)

    assert first.code == "enforce"
    assert second.code == "cooldown"
    assert len(guild.members[ATTACKER].removed_roles) == 1


async def test_threshold_must_be_met_for_multi_event_policies(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    guild.audit_entries.append(
        audit_entry(
            entry_id=20,
            actor_id=ATTACKER,
            target_id=801,
            action=discord.AuditLogAction.ban,
            age_seconds=0.2,
        )
    )
    first = await harness.pipeline.handle(ban_event(guild, 801), guild)
    assert first.code == "below_threshold", "mass_ban needs 2 events in 15s"

    guild.audit_entries.append(
        audit_entry(
            entry_id=21,
            actor_id=ATTACKER,
            target_id=802,
            action=discord.AuditLogAction.ban,
            age_seconds=0.2,
        )
    )
    second = await harness.pipeline.handle(ban_event(guild, 802), guild)
    assert second.code == "enforce"


async def test_two_guilds_are_fully_isolated(harness):  # noqa: ANN001
    guild_a = harness.register_guild(build_guild(GUILD_A, OWNER_A))
    guild_b = harness.register_guild(build_guild(GUILD_B, OWNER_B))
    await enable_guild(harness.db, guild_a)
    await enable_guild(harness.db, guild_b, mode="alert_only")

    add_delete_audit(guild_a, 30, 900)
    add_delete_audit(guild_b, 31, 901)

    result_a, result_b = await asyncio.gather(
        harness.pipeline.handle(channel_delete_event(guild_a, 900), guild_a),
        harness.pipeline.handle(channel_delete_event(guild_b, 901), guild_b),
    )

    assert result_a.code == "enforce"
    assert result_b.code == "alert_only_mode"
    assert guild_a.members[ATTACKER].removed_roles
    assert guild_b.members[ATTACKER].removed_roles == []

    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        a_incidents = await uow.incidents.list_recent(GUILD_A, limit=10)
        b_incidents = await uow.incidents.list_recent(GUILD_B, limit=10)
    assert len(a_incidents) == 1 and len(b_incidents) == 1
    assert a_incidents[0].guild_id == GUILD_A and b_incidents[0].guild_id == GUILD_B


async def test_simultaneous_incidents_in_one_guild_are_serialised(harness):  # noqa: ANN001
    """Concurrent destructive events must not double-enforce or crash."""
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    for index in range(4):
        add_delete_audit(guild, 40 + index, 1000 + index)

    results = await asyncio.gather(
        *(harness.pipeline.handle(channel_delete_event(guild, 1000 + i), guild) for i in range(4))
    )
    enforced = [r for r in results if r.code == "enforce"]
    assert len(enforced) == 1, "the cooldown must collapse the burst into one response"
    assert len(guild.members[ATTACKER].removed_roles) == 1
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        events = await uow.events.recent(
            guild.id, since=datetime.now(tz=timezone.utc) - timedelta(minutes=1)
        )
    assert len(events) == 4, "every event is still recorded for the audit trail"


async def test_message_spam_times_out_and_purges(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)
    channel.purge_result = [object()] * 7

    results = []
    for index in range(6):
        results.append(
            await harness.pipeline.handle(
                spam_event(guild, MOD, 2000 + index, channel.id), guild
            )
        )
    assert [r.code for r in results[:5]] == ["below_threshold"] * 5
    assert results[-1].code == "enforce"
    member = guild.members[MOD]
    assert member.timeouts, "spam response is a timeout, not a role strip"
    assert member.roles, "spam must not strip roles"
    assert channel.purged, "bounded cleanup should run"
    assert channel.purged[0]["limit"] <= 25


async def test_duplicate_message_spam_uses_content_hash(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)
    digest = hash_content("buy my crypto")

    codes = []
    for index in range(4):
        event = NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.DUPLICATE_SPAM,
            source=EventSource.GATEWAY,
            occurred_at=datetime.now(tz=timezone.utc),
            actor_id=MOD,
            actor_confidence=Confidence.CONFIRMED,
            target_id=3000 + index,
            channel_id=channel.id,
            content_hash=digest,
        )
        codes.append((await harness.pipeline.handle(event, guild)).code)
    assert codes[-1] == "enforce"
    assert guild.members[MOD].timeouts


async def test_mass_mention_everyone_is_immediate(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)
    event = NormalizedEvent(
        guild_id=guild.id,
        action_key=ActionKey.MASS_MENTION,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        actor_id=MOD,
        actor_confidence=Confidence.CONFIRMED,
        target_id=4000,
        channel_id=channel.id,
        mentions_everyone=True,
    )
    result = await harness.pipeline.handle(event, guild)
    assert result.code == "enforce"
    assert guild.members[MOD].timeouts


async def test_mass_mention_counts_unique_targets(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    channel = guild.get_channel(guild.id + 100)

    repeated = NormalizedEvent(
        guild_id=guild.id,
        action_key=ActionKey.MASS_MENTION,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        actor_id=MOD,
        actor_confidence=Confidence.CONFIRMED,
        target_id=4001,
        channel_id=channel.id,
        mention_ids=(1, 1, 1, 1, 1),
    )
    assert (await harness.pipeline.handle(repeated, guild)).code == "below_threshold"

    many = NormalizedEvent(
        guild_id=guild.id,
        action_key=ActionKey.MASS_MENTION,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        actor_id=MOD,
        actor_confidence=Confidence.CONFIRMED,
        target_id=4002,
        channel_id=channel.id,
        mention_ids=(1, 2, 3, 4, 5),
    )
    assert (await harness.pipeline.handle(many, guild)).code == "enforce"


async def test_join_flood_enables_raid_mode_and_bans_nobody(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    guild.features.append("SUPPORTS_INVITE_TOGGLE")
    await enable_guild(harness.db, guild)

    codes = []
    for index in range(8):
        event = NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.JOIN_FLOOD,
            source=EventSource.GATEWAY,
            occurred_at=datetime.now(tz=timezone.utc),
            target_type="member",
            target_id=5000 + index,
            payload={"account_age_hours": 500},
        )
        codes.append((await harness.pipeline.handle(event, guild)).code)

    assert codes[-1] == "enforce"
    assert any("verification_level" in edit for edit in guild.edits)
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        settings = await uow.guilds.get(guild.id)
    assert settings.raid_mode_active is True
    assert settings.raid_mode_until is not None
    # Nobody was banned or kicked.
    assert all(not m.removed_roles for m in guild.members.values())


async def test_new_accounts_are_weighted_in_join_flood(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    codes = []
    for index in range(4):
        event = NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.JOIN_FLOOD,
            source=EventSource.GATEWAY,
            occurred_at=datetime.now(tz=timezone.utc),
            target_id=6000 + index,
            payload={"account_age_hours": 1},
        )
        codes.append((await harness.pipeline.handle(event, guild)).code)
    assert codes[-1] == "enforce", "4 brand-new accounts weigh as 8 joins"


async def test_enforcement_rate_limit_stops_runaway_responses(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    await set_policy(harness.db, guild.id, ActionKey.CHANNEL_DELETE, cooldown_seconds=0)
    harness.pipeline.state_cache.invalidate(guild.id)
    # Exhaust the enforcement budget (the fixture's limiter refills quickly, so
    # deny the purpose outright - that is exactly what an exhausted bucket does).
    real_allow = harness.limiter.allow
    harness.limiter.allow = lambda purpose, gid, *extra: (
        False if purpose == "enforce" else real_allow(purpose, gid, *extra)
    )

    add_delete_audit(guild, 60, 7000)
    result = await harness.pipeline.handle(channel_delete_event(guild, 7000), guild)
    assert result.enforcement["status"] == EnforcementStatus.SKIPPED.value
    assert result.enforcement["residual_risk"] is True
    assert guild.members[ATTACKER].removed_roles == []


async def test_notification_rate_limit_is_separate(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    real_allow = harness.limiter.allow
    harness.limiter.allow = lambda purpose, gid, *extra: (
        False if purpose == "notify" else real_allow(purpose, gid, *extra)
    )
    add_delete_audit(guild, 61, 7001)
    result = await harness.pipeline.handle(channel_delete_event(guild, 7001), guild)
    assert result.notified is False
    assert guild.get_channel(guild.id + 101).sent == []
    assert result.incident_id is not None, "the incident is still recorded"


async def test_database_outage_degrades_without_crashing(harness, monkeypatch):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    add_delete_audit(guild, 70, 8000)
    # Warm the cache, then break the database.
    await harness.pipeline.state_cache.get(guild.id)

    import contextlib

    @contextlib.asynccontextmanager
    async def broken():  # noqa: ANN202
        raise RuntimeError("connection refused")
        yield  # pragma: no cover

    monkeypatch.setattr(harness.db, "begin", broken)

    result = await harness.pipeline.handle(channel_delete_event(guild, 8000), guild)

    assert result.handled is True
    assert harness.pipeline.degraded_db is True
    assert result.code == "enforcement_blocked", "no idempotency guarantee -> no enforcement"
    assert guild.members[ATTACKER].removed_roles == []
    assert guild.get_channel(guild.id + 101).sent, "operators are still alerted"


async def test_missing_guild_state_and_no_cache_drops_the_event(harness, monkeypatch):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    import contextlib

    @contextlib.asynccontextmanager
    async def broken():  # noqa: ANN202
        raise RuntimeError("down")
        yield  # pragma: no cover

    monkeypatch.setattr(harness.db, "begin", broken)
    result = await harness.pipeline.handle(channel_delete_event(guild, 8001), guild)
    assert result.handled is False and result.code == "no_guild_state"


async def test_restart_recovery_rehydrates_windows(harness):  # noqa: ANN001
    """Events persisted before a restart still count toward the threshold."""
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    now = datetime.now(tz=timezone.utc)
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        await uow.events.record(
            guild_id=guild.id,
            correlation_id="pre-restart",
            dedupe_key="pre-1",
            action_key=ActionKey.MASS_BAN,
            source=EventSource.GATEWAY,
            occurred_at=now - timedelta(seconds=2),
            actor_id=ATTACKER,
            actor_confidence=Confidence.CONFIRMED,
        )
    restored = await harness.pipeline.rehydrate_windows(guild.id)
    assert restored >= 1

    guild.audit_entries.append(
        audit_entry(
            entry_id=80,
            actor_id=ATTACKER,
            target_id=9000,
            action=discord.AuditLogAction.ban,
            age_seconds=0.2,
        )
    )
    result = await harness.pipeline.handle(ban_event(guild, 9000), guild)
    assert result.code == "enforce", "the pre-restart ban must still count"


async def test_paused_guild_does_nothing_at_all(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild, log_channel_id=guild.id + 101)
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        await uow.guilds.update(guild.id, paused=True, pause_reason="maintenance")
    harness.pipeline.state_cache.invalidate(guild.id)
    add_delete_audit(guild, 90, 9100)

    result = await harness.pipeline.handle(channel_delete_event(guild, 9100), guild)

    assert result.code == "paused"
    assert guild.get_channel(guild.id + 101).sent == []
    assert guild.members[ATTACKER].removed_roles == []
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        events = await uow.events.recent(
            guild.id, since=datetime.now(tz=timezone.utc) - timedelta(minutes=1)
        )
    assert len(events) == 1, "events are still recorded while paused"


async def test_actor_who_left_the_guild_is_reported_not_crashed(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    gone = 999999999999999999
    guild.audit_entries.append(
        audit_entry(
            entry_id=100,
            actor_id=gone,
            target_id=9200,
            action=discord.AuditLogAction.channel_delete,
            age_seconds=0.2,
        )
    )
    result = await harness.pipeline.handle(channel_delete_event(guild, 9200), guild)
    assert result.enforcement["status"] == EnforcementStatus.SKIPPED.value
    assert "no longer a member" in result.enforcement["summary"]


async def test_discord_rejection_is_recorded_as_failed(harness):  # noqa: ANN001
    from tests.conftest import make_http_error

    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    guild.members[ATTACKER].fail_remove_roles = make_http_error(403)
    add_delete_audit(guild, 110, 9300)

    result = await harness.pipeline.handle(channel_delete_event(guild, 9300), guild)

    assert result.enforcement["status"] == EnforcementStatus.FAILED.value
    assert result.enforcement["residual_risk"] is True
    incident = await latest_incident(harness.db, guild.id)
    assert incident.outcome is EnforcementStatus.FAILED
    async with harness.db.begin() as session:
        uow = UnitOfWork(session)
        steps = await uow.enforcement.list_for_incident(guild.id, incident.id)
    assert steps and steps[0].error


async def test_policy_change_takes_effect_after_cache_invalidation(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    await set_policy(harness.db, guild.id, ActionKey.CHANNEL_DELETE, enabled=False)
    harness.pipeline.state_cache.invalidate(guild.id)
    add_delete_audit(guild, 120, 9400)
    result = await harness.pipeline.handle(channel_delete_event(guild, 9400), guild)
    assert result.code == "policy_disabled"


async def test_forget_guild_clears_all_state(harness):  # noqa: ANN001
    guild = harness.register_guild(build_guild())
    await enable_guild(harness.db, guild)
    add_delete_audit(guild, 130, 9500)
    await harness.pipeline.handle(channel_delete_event(guild, 9500), guild)
    assert harness.pipeline.windows.guild_bucket_count(guild.id) > 0
    harness.pipeline.forget_guild(guild.id)
    assert harness.pipeline.windows.guild_bucket_count(guild.id) == 0
    assert harness.pipeline.state_cache.peek(guild.id) is None
