# Architecture

## 1. Design constraints

Five facts about the Discord API shape everything else:

1. **The gateway does not name the actor** for destructive administrative
   events. `on_guild_channel_delete` hands you the channel, not the person.
2. **The audit log is eventually consistent.** The matching entry usually
   appears within a second, sometimes several, occasionally not at all.
3. **Reading the audit log requires `View Audit Log`**, and a guild can take it
   away at any time.
4. **Role hierarchy beats permissions.** A bot cannot touch a role at or above
   its own highest role, nor the guild owner, whatever permissions it holds.
5. **Almost nothing is restorable.** No message history, no IDs, no webhook
   tokens, no integrations.

So Shield is built to be *useful while uncertain*: it separates detection from
attribution, treats attribution confidence as a gate on enforcement, and
reports what it could not do rather than claiming success.

## 2. Package layout

```
shield/
  constants.py          enums, dangerous permission sets, hard caps (no deps)
  config.py             environment contract + fail-fast validation
  bot.py                ShieldBot: wiring, lifecycle, maintenance loop
  __main__.py           entry point, signal handling, exit codes
  observability/
    logging.py          JSON logging, secret redaction, rotation
    correlation.py      correlation IDs (contextvar)
    metrics.py          in-process counters/gauges/histograms
  db/
    models.py           SQLAlchemy 2.x ORM, portable types, constraints
    session.py          async engine, health, per-guild advisory locks
    repositories.py     guild-scoped data access (the isolation boundary)
  events/
    normalize.py        NormalizedEvent + dedupe-key derivation
    pipeline.py         the 12-stage pipeline
    notifier.py         Discord incident reports
    member_events.py    joins, departures, bans, role grants
    message_events.py   spam, duplicates, mentions, webhook messages
    admin_events.py     channels, roles, webhooks, guild settings
  detection/
    windows.py          monotonic sliding windows, rehydration, memory caps
  audit/
    mapping.py          ActionKey <-> AuditLogAction + limitation notes
    correlator.py       delayed, retried, single-use audit attribution
  policies/
    defaults.py         the strict default policy set
    trust.py            allowlist / owner / self evaluation (pure)
    engine.py           policy decisions (pure)
  enforcement/
    safety.py           hierarchy + collateral-damage rules (pure)
    selfguard.py        self-action suppression
    ratelimit.py        token buckets + bounded backoff
    executor.py         idempotent response execution
    lockdown.py         reversible lockdown / raid mode
  backup/
    serializer.py       snapshot schema, checksum, encryption
    snapshot.py         capture, retention, scheduler
  restore/
    planner.py          additive preflight diff
    applier.py          ordered, bounded, ID-mapping application
  commands/
    authz.py            server-side authority + command auditing
    core.py             /shield status|enable|disable|mode|pause|health|...
    thresholds.py whitelist.py incidents.py backup_cmds.py
    restore_cmds.py lockdown_cmds.py
```

The `policies/`, `enforcement/safety.py` and `detection/` modules are pure
functions over plain dataclasses. That is why the safety-critical rules (what
may be stripped, when enforcement is allowed, when a threshold is met) are
directly unit-testable without a Discord connection.

## 3. The event pipeline

```
ingest → normalize → deduplicate → audit attribution → policy evaluation
       → incident creation → response → snapshot/restore → notify
```

`EventPipeline._handle` implements this as twelve explicit stages:

| # | Stage | Behaviour |
|---|---|---|
| 1 | self-action suppression | A write Shield is about to make is pre-registered in `SelfActionGuard`; a matching event is flagged `self_inflicted` and ignored by the engine (but still logged). |
| 2 | guild state | TTL-cached (30s) settings, policies and allowlist. On a database outage the stale cache is reused; if there is none, the event is dropped with `no_guild_state`. |
| 3 | dedupe + persist | `event_records.dedupe_key` is globally unique. A duplicate returns immediately — **before** any audit-log read. Per-message events (spam, duplicates, mentions) are deduplicated in memory instead and persisted only if they lead to an incident, so chat volume never reaches PostgreSQL; exempt channels and disabled policies exit here. |
| 4 | audit attribution | Only for audit-correlated actions whose actor is not already confirmed. Result is attached to the stored row. |
| 5 | trust | Owner / bot-self / scoped allowlist. |
| 6 | window | Monotonic sliding window, keyed per detector family. |
| 7 | cooldown | Durable `cooldowns` row; also advances the escalation level. |
| 8 | enforceability preflight | Cheap, synchronous feasibility check (hierarchy, permissions, database health). |
| 9 | policy evaluation | Pure `PolicyEngine.evaluate` → `Decision`. |
| 10 | incident | Created under a per-guild advisory lock. |
| 11 | response | `ResponseExecutor`, idempotent and budgeted. |
| 12 | notify | Rate-limited embed to the log/alert channel. |

### Why dedupe precedes attribution

Attribution consumes an audit entry at most once per guild, so a replayed
gateway event would attribute differently from the original. If the dedupe key
included the actor, the replay would therefore produce a *different* key and be
counted twice. Deduplicating first makes the key depend only on facts that are
stable across deliveries, and saves an API call on every duplicate.

### Dedupe key derivation

| Case | Key |
|---|---|
| Audit entry known | `{guild}:{action}:audit:{entry_id}` — exact |
| Target can only be acted on once (channel/role deletion, a message) | `{guild}:{action}:tgt:{target_id}` — unique forever |
| Target can recur (user banned twice, guild edited twice) | `{guild}:{action}:tgt:{target_id}:b{bucket}` |
| No target | `{guild}:{action}:h:{sha256(channel, content_hash, bucket)}` |

`bucket = floor(occurred_at / 10s)`. The trade-off is stated in the code: two
genuinely distinct actions on the same target inside 10 seconds collapse into
one, and a redelivery straddling a bucket boundary counts twice. Both are
preferable to an evasion, and the audit-entry path (used for most
administrative actions) is exact.

### Window keying per detector family

| Detector | Window key | Notes |
|---|---|---|
| administrative actions | `(guild, action, actor_or_"unattributed")` | the actor key is used only for `CONFIRMED` attribution; `LIKELY`/`UNKNOWN` share the unattributed window, so a guess never counts against a person |
| `message_spam` | `(guild, action, author)` | |
| `duplicate_spam` | `(guild, action, author, content_hash)` | content is hashed, never stored |
| `mass_mention` | `(guild, action, author)` with distinct mention IDs | repeated mentions of one user count once; `@everyone` triggers immediately |
| `join_flood` | `(guild, action)` | guild-wide; accounts younger than `new_account_hours` are weighted |

Windows are driven by `time.monotonic()`, so an NTP step cannot widen or
collapse one. Buckets are trimmed on access, capped at 512 samples each and
20 000 buckets per guild, and swept every maintenance tick.

### Restart recovery

`EventPipeline.rehydrate_windows` replays `event_records` from the last
`max(window_seconds)` back into monotonic space at startup, so a restart during
an attack does not hand the attacker a fresh counter. Covered by
`tests/simulation/test_attack_scenarios.py::test_restart_during_an_attack_keeps_counting`.

## 4. Audit-log correlation strategy

`AuditCorrelator.attribute` runs:

1. Refuse immediately for gateway-only actions (spam, mentions, joins).
2. Check `View Audit Log`; if absent, return `UNKNOWN` + `degraded=True` and
   record the guild in `degraded_guilds` (surfaced by `/shield health`).
3. Sleep `AUDIT_CORRELATION_DELAY` (default 1.5s) to let Discord catch up.
4. Fetch the newest 10 entries for each mapped audit action.
5. Accept an entry only if it is unconsumed, has an actor, is newer than
   `AUDIT_CORRELATION_WINDOW` (default 20s), is not clock-skewed into the
   future, and its target matches → **`CONFIRMED`**.
6. A fresh entry of the right type whose target does not match →
   **`LIKELY`** (never authorises a sanction).
7. Otherwise retry with bounded exponential backoff up to
   `AUDIT_MAX_ATTEMPTS`, then **`UNKNOWN`**.

`Forbidden` is never retried. Each accepted entry ID is remembered in a bounded
per-guild LRU so one audit entry cannot be used to blame an actor for two
separate gateway events.

Guild-level events (`guild_update`) have no discrete target, so a fresh
guild-level entry is accepted as `CONFIRMED` on recency alone — which is why
`guild_settings_change` and `vanity_url_change` default to alert-only.

## 5. Data model

| Table | Purpose | Load-bearing constraints |
|---|---|---|
| `guild_settings` | tenancy root: mode, dry-run, pause, lockdown/raid state, log channels, snapshot policy, policy version | PK `guild_id` |
| `guild_policies` | per-detector threshold, window, cooldown, response, severity, options | `UNIQUE(guild_id, action_key)` |
| `trusted_entities` | explicit scoped allowlist | `UNIQUE(guild_id, entity_type, entity_id)` |
| `event_records` | normalised event log | `UNIQUE(dedupe_key)` ← deduplication |
| `incidents` | threshold crossings with evidence, mode, policy version, outcome | indexed by `(guild_id, detected_at)` and `(guild_id, status)` |
| `enforcement_actions` | one row per response step, before/after state | `UNIQUE(idempotency_key)` ← idempotency |
| `snapshots` | versioned structural backups | `UNIQUE(guild_id, version)` |
| `restore_jobs` | preview/apply runs, plan, result, ID map, approval token | indexed by `(guild_id, approval_token)` |
| `command_audit` | every privileged invocation, allowed or denied | indexed by guild and user |
| `cooldowns` | durable cooldown + escalation level | PK `(guild_id, scope_key)` |

Portability: enums are `VARCHAR` + `CHECK` (`native_enum=False`), JSON is
`JSONB` on PostgreSQL and `JSON` elsewhere, autoincrement PKs are `BIGSERIAL`
on PostgreSQL and `INTEGER` on SQLite, and `UTCDateTime` normalises every
timestamp to timezone-aware UTC in Python regardless of dialect. That is what
lets the integration suite run on SQLite while production runs on PostgreSQL.

Migrations are Alembic; `migrations/env.py` reads `DATABASE_URL` from the
environment (never from `alembic.ini`) and converts the async driver to its
sync equivalent for DDL, so one variable serves both.

## 6. Concurrency and multi-process operation

- **Per-guild advisory locks.** `Database.guild_lock` yields the session that
  holds the lock (the guarded work runs on that same connection, so a burst of
  waiters cannot starve the holder of a pool slot). It wraps
  `pg_advisory_xact_lock(guild_id ^ namespace, purpose)`. Incident creation,
  restores and snapshots take it, so two processes observing the same guild
  cannot create duplicate incidents or race a restore. On SQLite it degrades to
  a process-local `asyncio.Lock`, which is why **multi-process deployment
  requires PostgreSQL**.
- **Idempotent writes.** `EnforcementRepository.claim` inserts a unique
  `idempotency_key` (`ON CONFLICT DO NOTHING` on PostgreSQL) and returns
  `claimed=False` to the loser, which then performs no Discord call.
- **Durable cooldowns.** `cooldowns` rows survive restarts and are shared
  between processes, so a response loop cannot restart by moving shards.
- **Sharding.** `SHARD_COUNT`/`SHARD_IDS` are passed to discord.py; omit them
  for autosharding. `INSTANCE_ID` is recorded on every event and incident.
- **Budgets.** Token buckets per guild per purpose (`enforce`, `notify`,
  `snapshot`, `restore`) plus hard caps (`MAX_ENFORCEMENT_WRITES`,
  `MAX_RESTORE_WRITES`, `MAX_SPAM_DELETE`) bound the worst case even if a
  policy is misconfigured.

## 7. Degradation behaviour

| Failure | Behaviour |
|---|---|
| PostgreSQL unreachable at boot | refuse to start with an actionable message |
| PostgreSQL fails at runtime | stale guild state is reused; events and incidents are logged but may not persist; enforcement is **downgraded to alert-only** because idempotency cannot be guaranteed; `/shield health` reports it |
| `View Audit Log` revoked | detection continues, attribution returns `UNKNOWN`, nothing is sanctioned, the guild appears in `degraded_guilds` |
| Message Content disabled | `duplicate_spam` unavailable, `message_spam` falls back to rate only |
| Guild Members disabled | `join_flood` and `dangerous_role_grant` inert; `enforce` mode is refused at boot |
| Discord 429 | bounded exponential backoff honouring `Retry-After` |
| Discord 403/404 | never retried; recorded as a permanent failure with the reason |
| Shield's role moved below an attacker's | incident marked `enforcement_blocked`, severity critical, operator pointed at lockdown |

## 8. Phased implementation plan

Phase 1 is complete and shipped in this repository; the later phases are
explicitly out of scope and listed so the roadmap is honest.

| Phase | Scope | Status |
|---|---|---|
| **1. Foundation** | config validation, logging/redaction, ORM + migrations, repositories, guild bootstrap, policy seeding | **done** |
| **2. Detection** | normalisation, dedupe, monotonic windows, audit correlation, policy engine, incidents, alert-only end to end | **done** |
| **3. Response** | hierarchy-safe role stripping, timeouts, bounded deletion, lockdown/raid, idempotency, budgets, escalation | **done** |
| **4. Backup/restore** | snapshots, encryption, retention, additive planner, approval-gated applier, ID mapping | **done** |
| **5. Operations** | full slash surface, server-side authz, command auditing, health, metrics, systemd, runbooks | **done** |
| **6. Validation** | 250+ unit/integration/simulation tests, PostgreSQL-specific tests, staging plan | **done** |
| 7. Fleet scale-out | shared Redis window state for >1 process per guild, Prometheus exporter, per-shard health endpoint | not implemented |
| 8. Review workflow | in-Discord false-positive review queue with suggested threshold changes | not implemented (manual via `/shield incidents acknowledge`) |
| 9. Cross-guild intelligence | opt-in shared attacker reputation | not implemented (deliberately: it leaks guild data) |
