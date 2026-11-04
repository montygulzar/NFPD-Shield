"""Trust evaluation and policy decisions - the false-positive guards."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from shield.constants import (
    ActionKey,
    Confidence,
    EventSource,
    ResponseAction,
    Severity,
    ShieldMode,
    TrustScope,
)
from shield.detection.windows import WindowHit
from shield.events.normalize import NormalizedEvent
from shield.policies.engine import Decision, GuildView, PolicyEngine, PolicyView
from shield.policies.trust import TrustDecision, TrustEntry, evaluate_trust

OWNER = 11
BOT = 22
ATTACKER = 33
DELEGATE = 44
ROLE = 55


def event(
    action: ActionKey = ActionKey.CHANNEL_DELETE,
    *,
    actor_id: int | None = ATTACKER,
    confidence: Confidence = Confidence.CONFIRMED,
    self_inflicted: bool = False,
) -> NormalizedEvent:
    return NormalizedEvent(
        guild_id=1,
        action_key=action,
        source=EventSource.GATEWAY,
        occurred_at=datetime.now(tz=timezone.utc),
        actor_id=actor_id,
        actor_confidence=confidence,
        target_id=999,
        self_inflicted=self_inflicted,
    )


def policy(**overrides) -> PolicyView:  # noqa: ANN003
    base = dict(
        action_key=ActionKey.CHANNEL_DELETE,
        enabled=True,
        threshold_count=1,
        window_seconds=15,
        cooldown_seconds=60,
        response=ResponseAction.STRIP_DANGEROUS_ROLES,
        severity=Severity.CRITICAL,
        requires_confirmed_actor=True,
        dry_run=None,
        options={},
    )
    base.update(overrides)
    return PolicyView(**base)


def guild(**overrides) -> GuildView:  # noqa: ANN003
    base = dict(
        guild_id=1,
        enabled=True,
        mode=ShieldMode.ENFORCE,
        dry_run=False,
        paused=False,
        owner_id=OWNER,
        policy_version=1,
    )
    base.update(overrides)
    return GuildView(**base)


def hit(count: int = 1, threshold: int = 1, triggered: bool = True) -> WindowHit:
    return WindowHit(
        key=(1, "channel_delete", ATTACKER),
        count=count,
        threshold=threshold,
        window_seconds=15,
        first_seen_monotonic=0.0,
        last_seen_monotonic=1.0,
        triggered=triggered,
    )


def untrusted() -> TrustDecision:
    return TrustDecision(False, "none")


# -- trust -------------------------------------------------------------
def test_guild_owner_is_trusted_but_still_alerted():
    decision = evaluate_trust(
        action_key=ActionKey.CHANNEL_DELETE,
        actor_id=OWNER,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert decision.trusted and decision.is_guild_owner and decision.alert_anyway


def test_bot_itself_is_exempt():
    decision = evaluate_trust(
        action_key=ActionKey.CHANNEL_DELETE,
        actor_id=BOT,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert decision.trusted and decision.basis == "bot_self"


def test_administrator_is_not_implicitly_trusted():
    """The core of the compromised-admin threat model."""
    decision = evaluate_trust(
        action_key=ActionKey.CHANNEL_DELETE,
        actor_id=ATTACKER,
        actor_role_ids=[ROLE],
        guild_owner_id=OWNER,
        bot_user_id=BOT,
        entries=(),
    )
    assert not decision.trusted


def test_allowlisted_user_scope_is_respected():
    entries = (TrustEntry("user", DELEGATE, (TrustScope.WEBHOOKS.value,)),)
    webhook = evaluate_trust(
        action_key=ActionKey.WEBHOOK_CREATE,
        actor_id=DELEGATE,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
        entries=entries,
    )
    destructive = evaluate_trust(
        action_key=ActionKey.CHANNEL_DELETE,
        actor_id=DELEGATE,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
        entries=entries,
    )
    assert webhook.trusted and not destructive.trusted


def test_allowlisted_role_applies_to_holders():
    entries = (TrustEntry("role", ROLE, (TrustScope.ALL.value,)),)
    decision = evaluate_trust(
        action_key=ActionKey.CHANNEL_DELETE,
        actor_id=ATTACKER,
        actor_role_ids=[ROLE],
        guild_owner_id=OWNER,
        bot_user_id=BOT,
        entries=entries,
    )
    assert decision.trusted and decision.basis == "allowlist_role"


def test_expired_allowlist_entry_is_ignored():
    past = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    entries = (TrustEntry("user", DELEGATE, (TrustScope.ALL.value,), expires_at=past),)
    decision = evaluate_trust(
        action_key=ActionKey.CHANNEL_DELETE,
        actor_id=DELEGATE,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
        entries=entries,
    )
    assert not decision.trusted


def test_manage_shield_scope_grants_no_detection_exemption():
    entries = (TrustEntry("user", DELEGATE, (TrustScope.MANAGE_SHIELD.value,)),)
    for action in (ActionKey.CHANNEL_DELETE, ActionKey.MASS_BAN, ActionKey.MESSAGE_SPAM):
        decision = evaluate_trust(
            action_key=action,
            actor_id=DELEGATE,
            guild_owner_id=OWNER,
            bot_user_id=BOT,
            entries=entries,
        )
        assert not decision.trusted, f"{action} must still be policed"


def test_unattributed_actor_is_never_trusted():
    decision = evaluate_trust(
        action_key=ActionKey.CHANNEL_DELETE,
        actor_id=None,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert not decision.trusted


# -- policy engine -----------------------------------------------------
@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


def test_enforce_on_confirmed_untrusted_actor(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(), policy=policy(), guild=guild(), trust=untrusted(), hit=hit()
    )
    assert decision.enforce and decision.code == "enforce"
    assert decision.response is ResponseAction.STRIP_DANGEROUS_ROLES


def test_below_threshold_is_a_noop(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(),
        policy=policy(threshold_count=2),
        guild=guild(),
        trust=untrusted(),
        hit=hit(count=1, threshold=2, triggered=False),
    )
    assert decision.is_noop and decision.code == "below_threshold"


def test_unconfirmed_actor_alerts_but_never_punishes(engine: PolicyEngine):
    for confidence in (Confidence.LIKELY, Confidence.UNKNOWN):
        decision = engine.evaluate(
            event=event(confidence=confidence),
            policy=policy(),
            guild=guild(),
            trust=untrusted(),
            hit=hit(),
        )
        assert decision.create_incident and decision.notify
        assert not decision.enforce
        assert decision.code == "unconfirmed_actor"


def test_unattributed_event_alerts_only(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(actor_id=None, confidence=Confidence.UNKNOWN),
        policy=policy(),
        guild=guild(),
        trust=untrusted(),
        hit=hit(),
    )
    assert not decision.enforce and decision.details["unattributed"] is True


def test_owner_is_alerted_never_sanctioned(engine: PolicyEngine):
    owner_trust = TrustDecision(True, "owner", alert_anyway=True)
    decision = engine.evaluate(
        event=event(actor_id=OWNER),
        policy=policy(),
        guild=guild(),
        trust=owner_trust,
        hit=hit(),
    )
    assert decision.create_incident and decision.notify
    assert not decision.enforce
    assert decision.code == "owner_alert_only"
    assert decision.response is ResponseAction.ALERT_ONLY


def test_trusted_actor_is_a_noop(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(),
        policy=policy(),
        guild=guild(),
        trust=TrustDecision(True, "allowlist_user", detail="allowlisted"),
        hit=hit(),
    )
    assert decision.is_noop and decision.code == "trusted"


def test_self_inflicted_events_are_ignored(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(self_inflicted=True),
        policy=policy(),
        guild=guild(),
        trust=untrusted(),
        hit=hit(),
    )
    assert decision.is_noop and decision.code == "self_inflicted"


def test_paused_guild_takes_no_action_at_all(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(), policy=policy(), guild=guild(paused=True), trust=untrusted(), hit=hit()
    )
    assert decision.code == "paused"
    assert not (decision.enforce or decision.notify or decision.create_incident)


def test_disabled_guild_is_alert_only(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(), policy=policy(), guild=guild(enabled=False), trust=untrusted(), hit=hit()
    )
    assert decision.code == "alert_only_mode"
    assert decision.create_incident and not decision.enforce
    assert decision.details["would_have_done"] == "strip_dangerous_roles"


def test_alert_only_mode_reports_intended_action(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(),
        policy=policy(),
        guild=guild(mode=ShieldMode.ALERT_ONLY),
        trust=untrusted(),
        hit=hit(),
    )
    assert decision.code == "alert_only_mode" and not decision.enforce


def test_guild_dry_run_simulates(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(), policy=policy(), guild=guild(dry_run=True), trust=untrusted(), hit=hit()
    )
    assert decision.code == "dry_run" and decision.dry_run and not decision.enforce


def test_policy_dry_run_overrides_guild(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(),
        policy=policy(dry_run=True),
        guild=guild(dry_run=False),
        trust=untrusted(),
        hit=hit(),
    )
    assert decision.code == "dry_run"


def test_global_dry_run_can_never_enforce():
    decision = PolicyEngine(global_dry_run=True).evaluate(
        event=event(), policy=policy(), guild=guild(), trust=untrusted(), hit=hit()
    )
    assert not decision.enforce and decision.code == "dry_run"


def test_cooldown_suppresses_repeat_incidents(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(),
        policy=policy(),
        guild=guild(),
        trust=untrusted(),
        hit=hit(),
        cooldown_allows=False,
    )
    assert decision.code == "cooldown" and decision.is_noop


def test_disabled_policy_is_ignored(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(), policy=policy(enabled=False), guild=guild(), trust=untrusted(), hit=hit()
    )
    assert decision.code == "policy_disabled"


def test_blocked_enforcement_is_reported_honestly(engine: PolicyEngine):
    decision = engine.evaluate(
        event=event(),
        policy=policy(),
        guild=guild(),
        trust=untrusted(),
        hit=hit(),
        can_enforce=False,
        enforcement_blocked_reason="role above the bot",
    )
    assert decision.code == "enforcement_blocked"
    assert not decision.enforce
    assert decision.severity is Severity.CRITICAL
    assert "role above the bot" in decision.reason
    assert decision.details["intended_response"] == "strip_dangerous_roles"


def test_escalation_promotes_alert_only_then_lockdown(engine: PolicyEngine):
    alert_policy = policy(response=ResponseAction.ALERT_ONLY, severity=Severity.MEDIUM)
    level_one = engine.evaluate(
        event=event(), policy=alert_policy, guild=guild(), trust=untrusted(), hit=hit(),
        escalation_level=1,
    )
    level_two = engine.evaluate(
        event=event(), policy=alert_policy, guild=guild(), trust=untrusted(), hit=hit(),
        escalation_level=2,
    )
    assert level_one.response is ResponseAction.ALERT_ONLY
    assert level_two.response is ResponseAction.STRIP_DANGEROUS_ROLES
    assert level_two.severity is Severity.CRITICAL

    strip = engine.evaluate(
        event=event(), policy=policy(), guild=guild(), trust=untrusted(), hit=hit(),
        escalation_level=2,
    )
    assert strip.response is ResponseAction.LOCKDOWN


def test_message_policies_do_not_require_audit_attribution(engine: PolicyEngine):
    spam_policy = policy(
        action_key=ActionKey.MESSAGE_SPAM,
        response=ResponseAction.TIMEOUT,
        requires_confirmed_actor=False,
        threshold_count=6,
    )
    decision = engine.evaluate(
        event=event(action=ActionKey.MESSAGE_SPAM, confidence=Confidence.CONFIRMED),
        policy=spam_policy,
        guild=guild(),
        trust=untrusted(),
        hit=hit(count=6, threshold=6),
    )
    assert decision.enforce and decision.response is ResponseAction.TIMEOUT


def test_decision_is_immutable():
    decision = Decision(
        create_incident=True,
        enforce=False,
        notify=True,
        response=ResponseAction.ALERT_ONLY,
        severity=Severity.LOW,
        reason="x",
        dry_run=True,
        code="c",
    )
    with pytest.raises((AttributeError, TypeError)):
        decision.enforce = True  # type: ignore[misc]
