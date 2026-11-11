# Completion matrix

Status legend:

- **Implemented** — code is present and complete; no stubs or placeholders.
- **Tested** — automated coverage exists (`A`), staging-plan coverage only
  (`S`), or both (`A+S`).
- **Unsupported / partial** — stated plainly, with the reason.

Nothing in this repository is a stub. Where a capability is impossible through
the Discord API, it is listed as unsupported rather than silently omitted.

## 1. Detection

| Capability | Implemented | Tested | Notes / limits |
|---|---|---|---|
| Mass bans | yes | A+S | gateway `on_member_ban` + audit attribution |
| Mass kicks | yes | A+S | audit-only: a kick is indistinguishable from a voluntary leave on the gateway, so a leave emits nothing |
| Channel deletes | yes | A+S | single-event default; high false-positive risk, documented |
| Channel creation floods | yes | A+S | |
| Role deletes | yes | A+S | single-event default |
| Role creation floods | yes | A | |
| Dangerous role permission edits | yes | A+S | `on_guild_role_update` diff against `CRITICAL_PERMISSIONS` |
| Dangerous channel overwrite edits | yes | A+S | reported only when the diff *grants* a dangerous permission |
| Dangerous role grants to a member | yes | A+S | sanctions the granter, not the beneficiary |
| Bot additions | yes | A+S | **alert-only by default** — an authorised install is indistinguishable from a malicious one |
| Webhook create / delete / update | yes | A+S | classified from the audit log; without `View Audit Log` only "webhooks changed in #channel" |
| Suspicious webhook messages | partial | A | observable only in channels Shield can read; webhook executions are **not** audited, so there is no actor and no sanction |
| Mass mentions | yes | A+S | ≥5 unique mentions or any `@everyone`/`@here`; unique-target counting |
| Join floods | yes | A+S | guild-wide window; new accounts weighted; never bans a joiner |
| Message spam (rate) | yes | A+S | works without Message Content |
| Duplicate-content spam | yes | A+S | **requires the Message Content intent**; content is hashed, never stored |
| Guild name / icon / verification / security changes | yes | A+S | alert-only: `guild_update` audit coverage is coarse. Icon *content* is not captured, only its URL |
| Vanity URL changes | yes | A+S | only on guilds with the `VANITY_URL` feature, and only when the audit log exposes it |
| Member leaves (as distinct from kicks) | yes | A | deliberately produces no event |
| Presence / status abuse | **unsupported** | — | would need the Presence intent, which Shield never requests |
| Voice-channel raiding | **unsupported** | — | out of scope; no voice-state detector |
| Invite-creation abuse | **unsupported** | — | `on_invite_create` exists but the signal is too noisy to police without a per-guild allowlist; invites are pausable via lockdown instead |
| Nickname-mass-change raids | **unsupported** | — | detectable via `on_member_update`, not implemented |
| Emoji / sticker deletion | **unsupported** | — | not implemented; emoji are not snapshotted either |
| Scheduled-event abuse | **unsupported** | — | not implemented |
| Automod rule tampering | **unsupported** | — | audit actions exist in newer API versions; not implemented |

## 2. Attribution

| Capability | Implemented | Tested | Notes |
|---|---|---|---|
| Delayed audit-log correlation with retries | yes | A | configurable delay, window and attempt count, bounded exponential backoff |
| Target matching → `CONFIRMED` | yes | A | the only state that authorises a sanction |
| Unmatched fresh entry → `LIKELY` | yes | A | never sanctions |
| Stale / absent / forbidden → `UNKNOWN` | yes | A | alert only |
| Moderation-bot pass-through (`moderation_proxy`): the moderator behind a bot's ban/kick is the actor | yes | A | reads the ID the bot writes into its audit reason; bots only; unparseable reasons sanction nobody |
| Single-use audit entries per guild | yes | A | bounded LRU; one entry cannot blame two events |
| Clock-skew rejection | yes | A | future-dated entries are ignored |
| Missing-permission degradation reporting | yes | A | surfaced by `/shield health` |
| Guild-level (targetless) attribution | yes | A | accepted on recency alone, hence alert-only defaults |
| Cross-shard attribution | **partial** | — | each process reads the audit log independently; the single-use cache is per process, so two processes could both attribute the same entry. Avoided by partitioning shards per guild |

## 3. Response

| Capability | Implemented | Tested | Notes |
|---|---|---|---|
| Strip only dangerous, reachable, unmanaged roles | yes | A+S | safe roles preserved; before/after recorded |
| Hierarchy enforcement (strictly below the bot) | yes | A+S | equal position is also refused |
| `@everyone` and managed roles never removed | yes | A | |
| Guild owner never sanctioned | yes | A+S | checked in trust, planner and executor |
| Shield never sanctions itself | yes | A | |
| Timeouts for message abuse | yes | A+S | Discord's 28-day cap respected |
| Bounded message deletion | yes | A+S | hard cap of 25 |
| Reversible lockdown | yes | A+S | verification level, invite pause, slowmode; previous state recorded and restored |
| Reversible raid mode with expiry | yes | A+S | lifted by the maintenance loop |
| Escalation on repeat offences | yes | A | alert → strip → lockdown; severity escalates too |
| Idempotent execution | yes | A | unique `idempotency_key` claimed before every Discord call |
| Per-guild enforcement budget | yes | A | exhaustion reports `residual_risk` and alerts |
| Honest partial/failed containment reporting | yes | A+S | embed title `CONTAINMENT FAILED` |
| Self-action suppression | yes | A+S | 30s TTL, wildcard credits for repair bursts |
| Owner emergency pause/resume | yes | A | |
| Global dry-run kill switch | yes | A | no decision can carry `enforce=True` |
| Automatic unban after a false-positive ban | **unsupported** | — | deliberate: bulk unbanning is itself destructive and Shield never bans in the first place |
| Quarantine role (move the actor to a no-permission role) | **unsupported** | — | considered and rejected: it requires creating and managing a role, and role stripping achieves containment with less state |
| Reverting individual deleted messages | **unsupported** | — | no Discord API exists |

## 4. Backup and restore

| Capability | Implemented | Tested | Notes |
|---|---|---|---|
| Roles (name, permissions, colour, hoist, mentionable, position) | yes | A | |
| Categories and channels (type, name, position, parent, topic, slowmode, NSFW, voice settings) | yes | A | |
| Permission overwrites | yes | A | role/member classification is type-safe; targets that no longer exist are reported, not dropped silently |
| Guild settings (name, verification level, content filter, notifications, system channels) | yes | A | |
| Webhook metadata (opt-in) | yes | A | id, name, channel, type only — **never tokens** |
| Snapshots at startup / scheduled / manual / pre-restore | yes | A | |
| Versioning, per-guild retention | yes | A | |
| Checksum integrity verification | yes | A | detects tampering or corruption |
| Optional Fernet encryption at rest | yes | A | wrong or missing key fails loudly |
| Structural validation; invalid snapshots excluded from restore | yes | A | |
| Additive restore plan (never deletes, never renames) | yes | A | post-snapshot changes are reported as "left untouched" |
| Preview with explicit unrecoverable list | yes | A+S | |
| Approval token: guild-scoped, single-use, expiring | yes | A+S | constant-time comparison |
| Owner-only apply with explicit confirmation | yes | A+S | |
| Pre-restore safety snapshot | yes | A | a restore is itself reversible |
| Re-plan against current state at apply time | yes | A | avoids clobbering concurrent edits |
| Old → new ID mapping recorded | yes | A | |
| Per-item failure isolation; partial results reported | yes | A | |
| Write cap with deferral | yes | A | |
| Message history | **unsupported** | — | no API |
| Original snowflake IDs | **unsupported** | — | impossible; new objects get new IDs |
| Threads and forum posts | **unsupported** | — | cannot be recreated meaningfully |
| Invites (including vanity) | **unsupported** | — | not captured |
| Integrations, app commands, bot configuration | **unsupported** | — | not captured |
| Webhook tokens / URLs | **unsupported** | — | deliberate: they are bearer credentials |
| Member role assignments | **unsupported** | — | deliberate: re-granting dangerous roles to a list of members is an attacker's goal |
| Emoji, stickers, soundboard | **unsupported** | — | not captured |
| Guild icon / banner / splash images | **partial** | — | only the URL is recorded, so they cannot be re-uploaded |
| Automatic restore on detection | **unsupported** | — | deliberate: restoration is high-impact and requires human approval |

## 5. Configuration, data and operations

| Capability | Implemented | Tested | Notes |
|---|---|---|---|
| Environment-only secrets, `OWNERID` alias support | yes | A | |
| Exhaustive fail-fast validation with actionable messages | yes | A | exits 78 |
| Snowflake, URL, TLS, boolean, range and contradiction checks | yes | A | |
| systemd `EnvironmentFile` compatibility | yes | S | documented differences from python-dotenv |
| Per-guild settings in PostgreSQL | yes | A | env values are bootstrap defaults only |
| Per-channel exemptions for message detectors | yes | A | `/shield thresholds set ... exempt_channel:` |
| Approved-guild restriction (`APPROVED_GUILD_IDS`, optional auto-leave) | yes | A | events ignored and commands refused elsewhere |
| Alembic migrations, up and down | yes | A+S | round-trip verified |
| Default policy seeding, idempotent | yes | A | |
| Connection pooling, pre-ping, recycling | yes | — | |
| Guild-scoped repositories (IDOR defence) | yes | A | |
| PostgreSQL advisory locks per guild | yes | A (PG suite) | SQLite degrades to process-local, documented |
| `ON CONFLICT` dedupe and claim semantics | yes | A (PG suite) | |
| Durable cooldowns and escalation | yes | A | |
| Retention pruning | yes | A | |
| Structured JSON logging with correlation IDs | yes | A | |
| Secret redaction across all loggers | yes | A | |
| Rotating file sink (optional) | yes | — | journal-only by default |
| In-process metrics | yes | A | no Prometheus exporter (roadmap) |
| Slash-command surface (31 commands) | yes | A | guild-only, ephemeral |
| `/health` + `/ready` HTTP endpoints | yes | A | read-only, not published to the host, no state-changing route exists |
| Docker image + compose service | yes | A (CI builds it) | multi-stage, tini, non-root uid 10002, read-only rootfs, caps dropped |
| Container entrypoint: wait for PostgreSQL, migrate, exec | yes | A (shell) + S | distinct exit codes for invalid config (78) and connectivity timeout (1) |
| Driverless `postgresql://` DSN and discrete `POSTGRES_*` form | yes | A | one DSN spelling shared with the rest of the NFPD stack |
| TLS required for routable hosts only, with `DB_REQUIRE_TLS` override | yes | A | a single-label container name is not treated as remote |
| Server-side authority ladder | yes | A | owner > delegate > operator > none |
| `OPERATOR_FULL_AUTHORITY`: operator runs owner-only commands in every guild | yes | A | off by default; command authority only, never detection exemption; for a single-owner self-hosted bot |
| Command auditing of allowed and denied attempts | yes | A | |
| Health check (intents, permissions, hierarchy, database, audit log) | yes | A | |
| Incident export | yes | A | metadata only |
| Graceful shutdown on SIGTERM | yes | — | pool disposed, gateway closed |
| Maintenance loop (sweep, purge, raid expiry, retention) | yes | A | |
| systemd unit with hardening | yes | S | |
| Installer, rollback and backup scripts | yes | S | idempotent; syntax-checked in CI |
| Multi-process / sharded operation | yes | A (locks) | caveat: per-process detection windows |
| Web dashboard | **unsupported** | — | out of scope by requirement: slash commands only |
| Prometheus / OpenTelemetry export | **unsupported** | — | roadmap phase 7; `/health` and `/ready` cover orchestration today |
| Bot-to-bot HTTP API (as the mod bot's `POST /internal/unban`) | **unsupported** | — | deliberate: Shield exposes no state-changing HTTP route. Everything that changes behaviour goes through a slash command with server-side authorization |
| In-Discord false-positive review queue | **unsupported** | — | manual via `/shield incidents acknowledge` |
| Cross-guild attacker reputation sharing | **unsupported** | — | deliberate: it would leak guild-specific data |

## 6. Test suite

| Layer | Count | Scope |
|---|---|---|
| `tests/unit` | 163 | config validation, windows, trust, policy engine, hierarchy safety, audit correlation, rate limits, self-guard, redaction, dedupe keys, snapshot serialisation |
| `tests/integration` | 141 | repositories and isolation, the wired pipeline, backup/restore, slash commands and authorization, PostgreSQL-specific paths (8, skipped without a server) |
| `tests/simulation` | 28 | end-to-end attack scenarios through the real gateway cogs, mapped to the threat matrix |
| **Total** | **332** (324 run anywhere + 8 PostgreSQL-conditional) | the Discord API is always faked; no destructive action is ever taken against a real guild |
