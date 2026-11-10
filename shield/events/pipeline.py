"""The unified event pipeline.

    ingest -> normalize -> deduplicate -> audit attribution -> policy
    evaluation -> incident creation -> response -> snapshot/restore -> notify

Each stage is explicit and independently testable. Notable behaviours:

* **Deduplication is durable.** The ``event_records.dedupe_key`` unique index is
  the authority, so two Shield processes (or two shards) observing the same
  guild collapse the same event once.
* **Attribution precedes windowing** for administrative actions, because the
  rate window is keyed by actor. An unattributable action still gets a window
  under the ``unattributed`` key so a burst is still reported.
* **Per-guild coordination** uses a PostgreSQL advisory lock around incident
  creation, so concurrent events cannot create duplicate incidents for the same
  actor/action.
* **Database outage** degrades to in-memory detection plus alerting. Nothing
  crashes, enforcement is downgraded to alert-only (because idempotency cannot
  be guaranteed without the claim table), and the condition is reported by
  ``/shield health``.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from shield.audit.correlator import AuditCorrelator
from shield.audit.proxy import parse_moderator_id, proxy_bot_ids
from shield.constants import (
    AUDIT_CORRELATED_ACTIONS,
    ActionKey,
    Confidence,
    EnforcementStatus,
    ResponseAction,
)
from shield.db.repositories import UnitOfWork
from shield.detection.windows import SlidingWindowRegistry, WindowHit, window_key
from shield.enforcement.executor import ResponseExecutor
from shield.enforcement.ratelimit import RateLimiter
from shield.enforcement.selfguard import SelfActionGuard
from shield.events.normalize import NormalizedEvent
from shield.events.notifier import Notifier
from shield.observability.correlation import correlation_scope
from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS
from shield.policies.engine import Decision, GuildView, PolicyEngine, PolicyView
from shield.policies.trust import TrustDecision, entries_from_rows, evaluate_trust

log = get_logger("pipeline")

#: Per-message detectors. Every chat message produces these events, so they are
#: deduplicated in memory and only written to PostgreSQL when they lead
#: somewhere (an incident or alert). Their windows are seconds long, so nothing
#: is lost across a restart, and a quiet guild costs the database nothing.
HIGH_VOLUME_ACTIONS: frozenset[ActionKey] = frozenset(
    {ActionKey.MESSAGE_SPAM, ActionKey.DUPLICATE_SPAM, ActionKey.MASS_MENTION}
)

#: Size of the in-memory dedupe ring for high-volume events.
RECENT_KEYS_CAPACITY = 8192

#: How long a cached guild configuration stays valid. Short enough that a
#: ``/shield thresholds set`` takes effect quickly, long enough that message
#: traffic does not hammer PostgreSQL.
CACHE_TTL_SECONDS = 30.0


@dataclass(slots=True)
class GuildState:
    guild: GuildView
    policies: dict[ActionKey, PolicyView]
    trust_entries: tuple[Any, ...]
    fetched_at: float
    log_channel_id: int | None
    alert_channel_id: int | None

    def fresh(self, now: float, ttl: float = CACHE_TTL_SECONDS) -> bool:
        return (now - self.fetched_at) < ttl


@dataclass(slots=True)
class PipelineResult:
    handled: bool
    code: str
    decision: Decision | None = None
    incident_id: int | None = None
    duplicate: bool = False
    enforcement: dict[str, Any] | None = None
    notified: bool = False
    detail: str = ""
    extras: dict[str, Any] = field(default_factory=dict)


class GuildStateCache:
    """TTL cache of guild settings, policies and allowlist entries."""

    def __init__(self, db, *, default_mode, snapshot_defaults: dict[str, Any]) -> None:  # noqa: ANN001
        self.db = db
        self.default_mode = default_mode
        self.snapshot_defaults = snapshot_defaults
        self._cache: dict[int, GuildState] = {}
        self._locks: dict[int, asyncio.Lock] = {}

    def invalidate(self, guild_id: int) -> None:
        self._cache.pop(guild_id, None)

    def invalidate_all(self) -> None:
        self._cache.clear()

    def peek(self, guild_id: int) -> GuildState | None:
        return self._cache.get(guild_id)

    async def get(
        self, guild_id: int, *, guild_name: str | None = None, owner_id: int | None = None
    ) -> GuildState | None:
        now = time.monotonic()
        cached = self._cache.get(guild_id)
        if cached is not None and cached.fresh(now):
            return cached
        lock = self._locks.setdefault(guild_id, asyncio.Lock())
        async with lock:
            cached = self._cache.get(guild_id)
            if cached is not None and cached.fresh(time.monotonic()):
                return cached
            try:
                async with self.db.begin() as session:
                    uow = UnitOfWork(session)
                    settings = await uow.guilds.ensure(
                        guild_id,
                        guild_name=guild_name,
                        owner_id=owner_id,
                        default_mode=self.default_mode,
                        snapshot_interval_minutes=self.snapshot_defaults.get("interval", 360),
                        snapshot_retention=self.snapshot_defaults.get("retention", 12),
                        snapshot_include_webhooks=self.snapshot_defaults.get("webhooks", True),
                    )
                    policies = {
                        row.action_key: PolicyView.from_row(row)
                        for row in await uow.policies.list_for_guild(guild_id)
                    }
                    trust_rows = tuple(await uow.trust.list_for_guild(guild_id))
                    state = GuildState(
                        guild=GuildView.from_row(settings),
                        policies=policies,
                        trust_entries=trust_rows,
                        fetched_at=time.monotonic(),
                        log_channel_id=settings.log_channel_id,
                        alert_channel_id=settings.alert_channel_id,
                    )
            except Exception:  # noqa: BLE001 - database outage
                METRICS.incr("guild_state_load_errors_total")
                log.exception("could not load guild state", extra={"guild_id": guild_id})
                return cached  # may be stale, may be None
            self._cache[guild_id] = state
            return state


class EventPipeline:
    """Single entry point for every security-relevant event."""

    def __init__(
        self,
        *,
        bot,  # noqa: ANN001
        db,  # noqa: ANN001
        config,  # noqa: ANN001 - shield.config.ShieldConfig
        correlator: AuditCorrelator,
        engine: PolicyEngine,
        executor: ResponseExecutor,
        notifier: Notifier,
        selfguard: SelfActionGuard,
        limiter: RateLimiter,
        windows: SlidingWindowRegistry | None = None,
        state_cache: GuildStateCache | None = None,
    ) -> None:
        self.bot = bot
        self.db = db
        self.config = config
        self.correlator = correlator
        self.engine = engine
        self.executor = executor
        self.notifier = notifier
        self.selfguard = selfguard
        self.limiter = limiter
        self.windows = windows or SlidingWindowRegistry()
        self.state_cache = state_cache or GuildStateCache(
            db,
            default_mode=config.default_mode,
            snapshot_defaults={
                "interval": config.snapshot_interval_minutes,
                "retention": config.snapshot_retention,
                "webhooks": config.snapshot_include_webhooks,
            },
        )
        self.degraded_db = False
        self._recent_keys: OrderedDict[str, None] = OrderedDict()

    # -- public --------------------------------------------------------
    async def handle(self, event: NormalizedEvent, guild) -> PipelineResult:  # noqa: ANN001
        """Run one event through the whole pipeline."""
        with correlation_scope(event.correlation_id):
            try:
                return await self._handle(event, guild)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the gateway loop must survive
                METRICS.incr("pipeline_errors_total", action=event.action_key.value)
                log.exception("pipeline failure", extra=event.as_log_context())
                return PipelineResult(False, "pipeline_error")

    async def _handle(self, event: NormalizedEvent, guild) -> PipelineResult:  # noqa: ANN001
        if not self.config.guild_approved(event.guild_id):
            return PipelineResult(False, "guild_not_approved")
        METRICS.incr("events_ingested_total", action=event.action_key.value)

        # --- stage 1: self-action suppression -------------------------
        if self._is_self_action(event):
            event.self_inflicted = True

        # --- stage 2: guild state -------------------------------------
        state = await self.state_cache.get(
            event.guild_id,
            guild_name=str(getattr(guild, "name", "") or "") or None,
            owner_id=getattr(guild, "owner_id", None),
        )
        if state is None:
            self.degraded_db = True
            return PipelineResult(
                False,
                "no_guild_state",
                detail="guild configuration unavailable (database outage); event dropped",
            )

        policy = state.policies.get(event.action_key)
        if policy is None:
            return PipelineResult(False, "no_policy", detail="no policy row for this action")

        high_volume = event.action_key in HIGH_VOLUME_ACTIONS
        if high_volume:
            if not policy.enabled or state.guild.paused:
                return PipelineResult(True, "policy_disabled" if not policy.enabled else "paused")
            exempt = (policy.options or {}).get("exempt_channel_ids") or ()
            if event.channel_id is not None and int(event.channel_id) in {int(c) for c in exempt}:
                return PipelineResult(True, "exempt_channel")

        # --- stage 3: dedupe (+ persistence) --------------------------
        # Deduplication happens BEFORE attribution so that a redelivered event
        # is dropped without spending an audit-log read, and so the dedupe key
        # cannot shift because attribution differed between deliveries.
        event_row_id: int | None = None
        if high_volume:
            if self._seen_recently(event.dedupe_key):
                METRICS.incr("events_deduplicated_total", action=event.action_key.value)
                return PipelineResult(True, "duplicate", duplicate=True)
        else:
            event_row_id, inserted = await self._persist_event(event)
            if inserted is False:
                METRICS.incr("events_deduplicated_total", action=event.action_key.value)
                return PipelineResult(True, "duplicate", duplicate=True)

        # --- stage 4: audit attribution -------------------------------
        if (
            event.action_key in AUDIT_CORRELATED_ACTIONS
            and event.actor_confidence is not Confidence.CONFIRMED
            and policy.enabled
            and not event.self_inflicted
        ):
            attribution = await self.correlator.attribute(
                guild,
                action_key=event.action_key,
                target_id=event.target_id,
                occurred_at=event.occurred_at,
            )
            event.actor_id = attribution.actor_id or event.actor_id
            event.actor_confidence = attribution.confidence
            event.audit_entry_id = attribution.audit_entry_id
            if attribution.changes:
                event.payload.setdefault("audit_changes", attribution.changes)
            event.payload["attribution_reason"] = attribution.reason
            if attribution.degraded:
                event.payload["audit_degraded"] = True
            if attribution.actor_id and self.selfguard.bot_user_id == attribution.actor_id:
                event.self_inflicted = True
            self._resolve_proxy(event, guild, state)
            if event_row_id is not None:
                await self._safe_db(
                    lambda s: UnitOfWork(s).events.attach_attribution(
                        event_row_id,
                        guild_id=event.guild_id,
                        actor_id=event.actor_id,
                        confidence=event.actor_confidence,
                        audit_entry_id=event.audit_entry_id,
                    )
                )

        elif event.action_key in AUDIT_CORRELATED_ACTIONS and not event.self_inflicted:
            # Arrived already attributed (kicks, webhooks): still see through a
            # proxy bot, and record the result.
            if self._resolve_proxy(event, guild, state) and event_row_id is not None:
                await self._safe_db(
                    lambda s: UnitOfWork(s).events.attach_attribution(
                        event_row_id,
                        guild_id=event.guild_id,
                        actor_id=event.actor_id,
                        confidence=event.actor_confidence,
                        audit_entry_id=event.audit_entry_id,
                    )
                )

        # --- stage 5: trust -------------------------------------------
        actor = await self._resolve_member(guild, event.actor_id)
        trust = self._evaluate_trust(event, guild, state, actor)

        # --- stage 6: detection window --------------------------------
        hit = self._window_add(event, policy)

        # --- stage 7: cooldown ----------------------------------------
        cooldown_allows, escalation = True, 0
        if hit.triggered and not trust.trusted and not event.self_inflicted:
            cooldown_allows, escalation = await self._cooldown(event, policy, state)

        # --- stage 8: enforceability preflight ------------------------
        can_enforce, blocked_reason = self._preflight_enforcement(event, guild, policy, actor)

        # --- stage 9: policy evaluation -------------------------------
        decision = self.engine.evaluate(
            event=event,
            policy=policy,
            guild=state.guild,
            trust=trust,
            hit=hit,
            escalation_level=escalation,
            cooldown_allows=cooldown_allows,
            can_enforce=can_enforce,
            enforcement_blocked_reason=blocked_reason,
        )
        # Routine no-ops (every ordinary chat message is one) stay at DEBUG.
        log.log(
            10 if decision.is_noop else 20,
            "policy decision",
            extra=event.as_log_context()
            | {
                "decision": decision.code,
                "response": decision.response.value,
                "enforce": decision.enforce,
                "dry_run": decision.dry_run,
            },
        )
        if decision.is_noop:
            return PipelineResult(True, decision.code, decision=decision, detail=decision.reason)
        if high_volume:
            # It led somewhere, so it now belongs in the durable audit trail.
            await self._persist_event(event)

        # --- stage 10: incident creation (guild-locked) ---------------
        incident_id = None
        if decision.create_incident:
            incident_id = await self._create_incident(event, policy, state, decision, hit)

        # --- stage 11: response ---------------------------------------
        enforcement_payload: dict[str, Any] | None = None
        if decision.enforce:
            report = await self.executor.execute(
                guild=guild,
                event=event,
                decision=decision,
                policy=policy,
                incident_id=incident_id,
            )
            enforcement_payload = report.as_dict()
            await self._record_outcome(event.guild_id, incident_id, report.status)
            if report.recommend_lockdown and decision.response is not ResponseAction.LOCKDOWN:
                enforcement_payload["escalation_hint"] = (
                    "containment incomplete; consider /shield lockdown enable"
                )
        elif incident_id is not None:
            await self._record_outcome(
                event.guild_id,
                incident_id,
                EnforcementStatus.DRY_RUN if decision.dry_run else EnforcementStatus.SKIPPED,
            )

        # --- stage 12: notification -----------------------------------
        notified = False
        if decision.notify:
            notified = await self.notifier.send_incident(
                guild,
                incident_id=incident_id,
                action=event.action_key.value,
                severity=decision.severity,
                reason=decision.reason,
                decision_code=decision.code,
                response=decision.response,
                dry_run=decision.dry_run,
                actor_id=event.actor_id,
                confidence=event.actor_confidence.value,
                target_label=self._target_label(event),
                correlation_id=event.correlation_id,
                evidence=decision.details,
                enforcement=enforcement_payload,
                log_channel_id=state.log_channel_id,
                alert_channel_id=state.alert_channel_id,
            )
            if notified and incident_id is not None:
                await self._safe_db(
                    lambda s: UnitOfWork(s).incidents.mark_notified(event.guild_id, incident_id)
                )

        METRICS.incr("incidents_total", action=event.action_key.value, code=decision.code)
        return PipelineResult(
            True,
            decision.code,
            decision=decision,
            incident_id=incident_id,
            enforcement=enforcement_payload,
            notified=notified,
            detail=decision.reason,
        )

    # -- stages --------------------------------------------------------
    def _is_self_action(self, event: NormalizedEvent) -> bool:
        kind_map = {
            ActionKey.CHANNEL_CREATE_FLOOD: "channel_create",
            ActionKey.CHANNEL_DELETE: "channel_delete",
            ActionKey.ROLE_CREATE_FLOOD: "role_create",
            ActionKey.ROLE_DELETE: "role_delete",
            ActionKey.DANGEROUS_ROLE_GRANT: "member_role_update",
            ActionKey.DANGEROUS_PERMISSION_CHANGE: "role_update",
            ActionKey.GUILD_SETTINGS_CHANGE: "guild_update",
            ActionKey.VANITY_URL_CHANGE: "guild_update",
        }
        kind = kind_map.get(event.action_key)
        if kind is None:
            return False
        return self.selfguard.is_self(event.guild_id, kind, event.target_id)

    def _resolve_proxy(self, event: NormalizedEvent, guild, state: GuildState) -> bool:  # noqa: ANN001
        """Replace a moderation-proxy bot with the moderator who used it.

        Returns True when the event's attribution changed. See
        :mod:`shield.audit.proxy` for why the audit reason is trusted here.
        """
        bot_id = event.actor_id
        if bot_id is None or event.actor_confidence is not Confidence.CONFIRMED:
            return False
        if bot_id not in proxy_bot_ids(state.trust_entries):
            return False
        member = guild.get_member(int(bot_id)) if hasattr(guild, "get_member") else None
        if member is not None and not getattr(member, "bot", False):
            # Only a bot's reason text is machine-written. Never trust a human's.
            return False

        reason = (event.payload.get("audit_changes") or {}).get("reason")
        moderator_id = parse_moderator_id(reason)
        event.payload["via_proxy_bot"] = bot_id
        if moderator_id is None or moderator_id == bot_id:
            # The bot acted with no moderator named (e.g. an automatic action).
            # Nobody can be held responsible, so this may alert but never sanction.
            event.actor_confidence = Confidence.LIKELY
            event.payload["proxy_unresolved"] = True
            event.payload["attribution_reason"] = (
                "performed by a moderation proxy bot with no moderator named in the "
                "audit reason; nobody is sanctioned"
            )
            return True
        event.actor_id = moderator_id
        event.payload["attribution_reason"] = (
            f"moderator {moderator_id} acting through proxy bot {bot_id} "
            "(read from the bot's audit reason)"
        )
        METRICS.incr("proxy_resolved_total", action=event.action_key.value)
        return True

    def _seen_recently(self, key: str) -> bool:
        """Bounded in-memory dedupe for high-volume events."""
        if key in self._recent_keys:
            return True
        self._recent_keys[key] = None
        if len(self._recent_keys) > RECENT_KEYS_CAPACITY:
            self._recent_keys.popitem(last=False)
        return False

    async def _resolve_member(self, guild, user_id: int | None):  # noqa: ANN001, ANN202
        """The actor as a member: from cache, else fetched from Discord.

        The fetch matters. Shield does not chunk guilds at startup, so
        ``get_member`` misses for anyone not yet seen on the gateway. Trust
        evaluation on a miss would see no roles, a role-scoped allowlist entry
        would silently not apply, and an allowlisted moderator would be
        sanctioned. Returns ``None`` only when the user really is not a member
        (or Discord refuses the lookup).
        """
        if user_id is None:
            return None
        member = guild.get_member(int(user_id)) if hasattr(guild, "get_member") else None
        if member is not None:
            return member
        fetch = getattr(guild, "fetch_member", None)
        if fetch is None:
            return None
        try:
            return await fetch(int(user_id))
        except Exception:  # noqa: BLE001 - left the guild, or lookup refused
            return None

    def _evaluate_trust(
        self, event: NormalizedEvent, guild, state: GuildState, member=None  # noqa: ANN001
    ) -> TrustDecision:
        role_ids = [int(r.id) for r in getattr(member, "roles", ()) or ()]
        return evaluate_trust(
            action_key=event.action_key,
            actor_id=event.actor_id,
            actor_role_ids=role_ids,
            guild_owner_id=getattr(guild, "owner_id", None) or state.guild.owner_id,
            bot_user_id=self.selfguard.bot_user_id,
            entries=entries_from_rows(state.trust_entries),
        )

    def _window_add(self, event: NormalizedEvent, policy: PolicyView) -> WindowHit:
        """Key the rate window appropriately for each detector family."""
        guild_id = event.guild_id
        action = event.action_key
        options = policy.options or {}

        if action is ActionKey.JOIN_FLOOD:
            # Guild-wide window; newly created accounts can be weighted.
            weight = 1
            if options.get("new_account_hours") and event.payload.get("account_age_hours") is not None:
                if float(event.payload["account_age_hours"]) <= float(
                    options["new_account_hours"]
                ):
                    weight = int(options.get("new_account_weight", 1) or 1)
            hit = self.windows.add(
                window_key(guild_id, action.value),
                threshold=policy.threshold_count,
                window_seconds=policy.window_seconds,
                now=event.monotonic,
            )
            for _ in range(max(0, weight - 1)):
                hit = self.windows.add(
                    window_key(guild_id, action.value),
                    threshold=policy.threshold_count,
                    window_seconds=policy.window_seconds,
                    now=event.monotonic,
                )
            return hit

        if action is ActionKey.MASS_MENTION:
            if event.mentions_everyone and options.get("everyone_is_violation", True):
                # @everyone/@here from a non-allowlisted member is a violation on
                # its own; synthesise a triggered hit without polluting the window.
                self.windows.add(
                    window_key(guild_id, action.value, event.actor_id),
                    threshold=policy.threshold_count,
                    window_seconds=policy.window_seconds,
                    now=event.monotonic,
                )
                return WindowHit(
                    key=window_key(guild_id, action.value, event.actor_id),
                    count=1,
                    threshold=1,
                    window_seconds=policy.window_seconds,
                    first_seen_monotonic=event.monotonic,
                    last_seen_monotonic=event.monotonic,
                    triggered=True,
                    distinct=len(event.mention_ids),
                )
            key = window_key(guild_id, action.value, event.actor_id)
            last: WindowHit | None = None
            for mention_id in event.mention_ids or (event.target_id,):
                last = self.windows.add(
                    key,
                    threshold=policy.threshold_count,
                    window_seconds=policy.window_seconds,
                    value=mention_id,
                    distinct_threshold=policy.threshold_count,
                    now=event.monotonic,
                )
            if last is None:
                last = self.windows.add(
                    key,
                    threshold=policy.threshold_count,
                    window_seconds=policy.window_seconds,
                    distinct_threshold=policy.threshold_count,
                    now=event.monotonic,
                )
            return last

        if action is ActionKey.DUPLICATE_SPAM:
            return self.windows.add(
                window_key(guild_id, action.value, event.actor_id, event.content_hash),
                threshold=policy.threshold_count,
                window_seconds=policy.window_seconds,
                now=event.monotonic,
            )

        # Everything else is actor scoped - but only CONFIRMED attribution may
        # count against an actor. A LIKELY guess landing in someone's window
        # could push them over a threshold on evidence that was never theirs.
        return self.windows.add(
            window_key(guild_id, action.value, _actor_key(event.actor_id, event.actor_confidence)),
            threshold=policy.threshold_count,
            window_seconds=policy.window_seconds,
            now=event.monotonic,
        )

    async def _cooldown(
        self, event: NormalizedEvent, policy: PolicyView, state: GuildState
    ) -> tuple[bool, int]:
        cooldown = policy.cooldown_seconds or state.guild.incident_cooldown_seconds
        scope = event.scope_key()
        try:
            async with self.db.begin() as session:
                uow = UnitOfWork(session)
                return await uow.cooldowns.check_and_set(event.guild_id, scope, cooldown)
        except Exception:  # noqa: BLE001
            self.degraded_db = True
            log.warning(
                "cooldown check failed; allowing the incident but enforcement will be "
                "downgraded because idempotency cannot be guaranteed",
                extra={"guild_id": event.guild_id},
            )
            return True, 0

    def _preflight_enforcement(
        self, event: NormalizedEvent, guild, policy: PolicyView, member=None  # noqa: ANN001
    ) -> tuple[bool, str | None]:
        """Cheap, synchronous feasibility check before promising enforcement."""
        from shield.enforcement.safety import (
            check_enforceability,
            permissions_set,
            role_views_from_member,
        )

        if policy.response is ResponseAction.ALERT_ONLY:
            return True, None
        if self.degraded_db:
            return False, (
                "the database is unavailable, so Shield cannot guarantee idempotent "
                "enforcement; downgrading to alert-only"
            )
        if policy.response in {ResponseAction.LOCKDOWN, ResponseAction.RAID_MODE}:
            perms = permissions_set(
                getattr(getattr(guild, "me", None), "guild_permissions", None)
            )
            if "administrator" in perms or "manage_guild" in perms or "manage_channels" in perms:
                return True, None
            return False, "Shield lacks Manage Guild / Manage Channels for protective mode"

        if member is None:
            # Not a member (any more); the executor reports that honestly.
            return True, None

        required = (
            "moderate_members"
            if policy.response is ResponseAction.TIMEOUT
            else "manage_messages"
            if policy.response is ResponseAction.DELETE_MESSAGES
            else "manage_roles"
        )
        verdict = check_enforceability(
            actor=role_views_from_member(member, guild.id),
            bot_top_position=int(
                getattr(getattr(getattr(guild, "me", None), "top_role", None), "position", 0) or 0
            ),
            bot_permissions=permissions_set(
                getattr(getattr(guild, "me", None), "guild_permissions", None)
            ),
            guild_owner_id=getattr(guild, "owner_id", None),
            bot_user_id=self.selfguard.bot_user_id,
            required_permission=required,
            guild_id=guild.id,
        )
        if policy.response in {ResponseAction.TIMEOUT, ResponseAction.DELETE_MESSAGES}:
            # Role-strip feasibility is irrelevant for message policies; only the
            # permission and owner checks matter.
            perms = permissions_set(
                getattr(getattr(guild, "me", None), "guild_permissions", None)
            )
            if int(getattr(member, "id", 0)) == int(getattr(guild, "owner_id", 0) or 0):
                return False, "actor is the guild owner; Shield never sanctions the owner"
            if "administrator" not in perms and required not in perms:
                return False, f"Shield lacks the {required} permission"
            return True, None
        return verdict.possible, None if verdict.possible else verdict.reason

    async def _persist_event(self, event: NormalizedEvent) -> tuple[int | None, bool | None]:
        """Persist and deduplicate one event.

        Returns ``(row_id, inserted)`` where ``inserted`` is True for a new
        event, False for a duplicate delivery and None when the database is
        unavailable (detection continues in memory).
        """
        try:
            async with self.db.begin() as session:
                uow = UnitOfWork(session)
                row, inserted = await uow.events.record(
                    guild_id=event.guild_id,
                    correlation_id=event.correlation_id,
                    dedupe_key=event.dedupe_key,
                    action_key=event.action_key,
                    source=event.source,
                    occurred_at=event.occurred_at,
                    actor_id=event.actor_id,
                    actor_confidence=event.actor_confidence,
                    target_type=event.target_type,
                    target_id=event.target_id,
                    channel_id=event.channel_id,
                    audit_entry_id=event.audit_entry_id,
                    payload=_jsonable(event.payload),
                    instance_id=self.config.instance_id,
                )
                self.degraded_db = False
                return (row.id if row is not None else None), inserted
        except Exception:  # noqa: BLE001
            self.degraded_db = True
            METRICS.incr("event_persist_errors_total")
            log.warning(
                "could not persist event; continuing with in-memory detection only",
                extra=event.as_log_context(),
            )
            return None, None

    async def _create_incident(
        self,
        event: NormalizedEvent,
        policy: PolicyView,
        state: GuildState,
        decision: Decision,
        hit: WindowHit,
    ) -> int | None:
        window_start = event.occurred_at - timedelta(seconds=hit.span_seconds)
        try:
            async with self.db.guild_lock(event.guild_id, "incident") as session:
                uow = UnitOfWork(session)
                incident = await uow.incidents.create(
                    guild_id=event.guild_id,
                    correlation_id=event.correlation_id,
                    action_key=event.action_key,
                    actor_id=event.actor_id,
                    actor_confidence=event.actor_confidence,
                    severity=decision.severity,
                    mode_at_detection=state.guild.mode,
                    dry_run=decision.dry_run,
                    detected_at=event.occurred_at,
                    window_start=window_start,
                    event_count=hit.count,
                    threshold_count=policy.threshold_count,
                    window_seconds=policy.window_seconds,
                    policy_version=state.guild.policy_version,
                    response=decision.response,
                    reason=decision.reason,
                    target_type=event.target_type,
                    target_id=event.target_id,
                    details=_jsonable(
                        decision.details
                        | {
                            "payload": event.payload,
                            "dedupe_key": event.dedupe_key,
                            "decision_code": decision.code,
                            "instance_id": self.config.instance_id,
                        }
                    ),
                )
                return incident.id
        except Exception:  # noqa: BLE001
            self.degraded_db = True
            METRICS.incr("incident_persist_errors_total")
            log.exception(
                "could not persist incident; alerting without a durable record",
                extra=event.as_log_context(),
            )
            return None

    async def _record_outcome(
        self, guild_id: int, incident_id: int | None, status: EnforcementStatus
    ) -> None:
        if incident_id is None:
            return
        await self._safe_db(
            lambda s: UnitOfWork(s).incidents.set_outcome(guild_id, incident_id, status)
        )

    async def _safe_db(self, fn) -> bool:  # noqa: ANN001
        try:
            async with self.db.begin() as session:
                await fn(session)
            return True
        except Exception:  # noqa: BLE001
            self.degraded_db = True
            return False

    @staticmethod
    def _target_label(event: NormalizedEvent) -> str | None:
        name = event.payload.get("target_name")
        if event.target_id and name:
            return f"{name} (`{event.target_id}`)"
        if event.target_id:
            return f"`{event.target_id}`"
        return name

    # -- maintenance ---------------------------------------------------
    async def rehydrate_windows(self, guild_id: int) -> int:
        """Replay persisted events into the in-memory windows after a restart."""
        longest = 0
        state = await self.state_cache.get(guild_id)
        if state is None:
            return 0
        for policy in state.policies.values():
            longest = max(longest, policy.window_seconds)
        if longest <= 0:
            return 0
        since = datetime.now(tz=timezone.utc) - timedelta(seconds=longest)
        try:
            async with self.db.begin() as session:
                uow = UnitOfWork(session)
                rows = await uow.events.recent(guild_id, since=since, limit=2000)
        except Exception:  # noqa: BLE001
            return 0
        grouped: dict[tuple[Any, ...], list[datetime]] = {}
        for row in rows:
            policy = state.policies.get(row.action_key)
            if policy is None:
                continue
            if row.action_key in HIGH_VOLUME_ACTIONS:
                continue  # seconds-long windows; never rehydrated
            if row.action_key is ActionKey.JOIN_FLOOD:
                key = window_key(guild_id, row.action_key.value)
            else:
                key = window_key(
                    guild_id,
                    row.action_key.value,
                    _actor_key(row.actor_id, row.actor_confidence),
                )
            grouped.setdefault(key, []).append(row.occurred_at)
        restored = 0
        for key, stamps in grouped.items():
            action_value = key[1]
            policy = next(
                (p for p in state.policies.values() if p.action_key.value == action_value), None
            )
            if policy is None:
                continue
            restored += self.windows.rehydrate(
                key, sorted(stamps), window_seconds=policy.window_seconds
            )
        if restored:
            log.info(
                "rehydrated detection windows after restart",
                extra={"guild_id": guild_id, "samples": restored},
            )
        return restored

    def forget_guild(self, guild_id: int) -> None:
        self.windows.drop_guild(guild_id)
        self.state_cache.invalidate(guild_id)
        self.limiter.drop_guild(guild_id)
        self.correlator.forget_guild(guild_id)
        self.selfguard.clear_guild(guild_id)

    def sweep(self) -> int:
        """Maintenance pass over the in-memory detection state.

        Drops buckets nothing has touched recently and then enforces the
        per-guild bucket cap, so an attacker cycling thousands of distinct
        target IDs cannot grow the process heap without bound.
        """
        removed = self.windows.sweep()
        for guild_id in self.windows.guild_ids():
            removed += self.windows.enforce_guild_cap(guild_id)
        return removed


def _actor_key(actor_id: int | None, confidence: Confidence) -> int | str:
    """Window scope for an administrative event's actor."""
    if actor_id is not None and confidence is Confidence.CONFIRMED:
        return actor_id
    return "unattributed"


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "value"):
        return _jsonable(value.value)
    return str(value)
