# Testing

Three layers, all offline. **No test ever performs a destructive action against
a real guild**, and the automated suite never talks to Discord at all.

```bash
pip install -r requirements-dev.txt
pytest                       # everything (301 tests, a few seconds)
pytest tests/unit -q         # pure logic, no I/O
pytest tests/integration -q  # database + wired pipeline over fakes
pytest tests/simulation -q   # attack scenarios through the real cogs
```

## 1. Automated coverage

| Required scenario | Where |
|---|---|
| Thresholds (met, not met, window expiry, monotonic clock) | `tests/unit/test_windows.py`, `tests/integration/test_pipeline.py::test_threshold_must_be_met_for_multi_event_policies` |
| False positives (trusted actor, allowlist scope, expiry, legitimate restructuring, alert-only rollout) | `tests/unit/test_trust_and_policy.py`, `tests/simulation/test_attack_scenarios.py::test_t10_*` |
| Simultaneous incidents (same guild, two guilds) | `test_pipeline.py::test_simultaneous_incidents_in_one_guild_are_serialised`, `::test_two_guilds_are_fully_isolated`, `test_attack_scenarios.py::test_simultaneous_attacks_on_two_guilds_stay_isolated` |
| Actor attribution (confirmed, likely, unknown, guild-level, entry reuse) | `tests/unit/test_audit_correlator.py` |
| Stale audit logs | `test_audit_correlator.py::test_stale_entry_is_refused`, `test_pipeline.py::test_stale_audit_entry_never_sanctions` |
| Missing permissions (audit log, Manage Roles, Moderate Members, Manage Messages, Manage Webhooks) | `test_audit_correlator.py`, `test_pipeline.py::test_missing_*`, `test_backup_restore.py::test_webhook_metadata_is_skipped_without_permission` |
| Role hierarchy (above, equal, managed, `@everyone`, partial containment) | `tests/unit/test_safety.py`, `test_pipeline.py::test_role_above_the_bot_reports_failed_containment` |
| Owner exemption | `test_trust_and_policy.py::test_owner_is_alerted_never_sanctioned`, `test_pipeline.py::test_guild_owner_is_never_sanctioned`, `test_attack_scenarios.py::test_t9_owner_nuke_alerts_without_sanction` |
| Duplicate gateway events | `tests/unit/test_misc_units.py` (key derivation), `test_repositories.py::test_duplicate_events_are_collapsed`, `test_pipeline.py::test_duplicate_gateway_delivery_is_collapsed` |
| Partial restoration | `test_backup_restore.py::test_partial_restoration_is_reported_truthfully`, `::test_restore_write_cap_defers_rather_than_dropping` |
| Rate limits (Shield's budgets, Discord 429/403, backoff, `Retry-After`) | `test_misc_units.py`, `test_pipeline.py::test_enforcement_rate_limit_stops_runaway_responses`, `::test_notification_rate_limit_is_separate` |
| Database outage | `test_pipeline.py::test_database_outage_degrades_without_crashing`, `::test_missing_guild_state_and_no_cache_drops_the_event` |
| Restart recovery | `test_pipeline.py::test_restart_recovery_rehydrates_windows`, `test_attack_scenarios.py::test_restart_during_an_attack_keeps_counting` |
| Multi-guild isolation (policies, trust, events, incidents, snapshots, restore tokens, command audit) | `tests/integration/test_repositories.py`, `test_commands.py::test_incident_show_cannot_read_another_guild` |
| Idempotency (claim races, replayed decisions) | `test_repositories.py::test_enforcement_claim_is_idempotent`, `::test_concurrent_claims_only_one_wins` |
| Config validation / boot failure | `tests/unit/test_config.py` |
| Secret redaction | `tests/unit/test_misc_units.py` |
| Database URL handling (driverless upgrade, sync mapping for Alembic, TLS rules, credential encoding) | `tests/unit/test_db_urls.py`, `tests/unit/test_config.py` |
| Health / readiness endpoints (dependency outage, gateway grace, busy port, disabled) | `tests/integration/test_health.py` |
| Authorization (owner / delegate / operator / nobody, cross-guild) | `tests/integration/test_commands.py` |
| Self-action suppression | `test_pipeline.py::test_shields_own_actions_do_not_trigger_itself`, `test_attack_scenarios.py::test_restoration_burst_does_not_trigger_self_protection` |

## 2. The Discord fakes

`tests/conftest.py` provides `FakeGuild`, `FakeMember`, `FakeRole`,
`FakeChannel`, `FakeMessage`, `FakeWebhook`, `FakeAuditEntry` and
`FakeInteraction`. They implement exactly the surface Shield touches — including
the `audit_logs()` async iterator and `permissions_for()` — and record every
mutation (`removed_roles`, `timeouts`, `purged`, `edits`, `created_channels`,
`sent`) so a test can assert on side effects rather than on log text.

Real `discord.Permissions`, `discord.PermissionOverwrite`,
`discord.AuditLogAction` and `discord.VerificationLevel` are used, so
permission arithmetic and enum handling are exercised for real.

`make_http_error(403 | 404 | 429 | 500)` produces genuine `discord.Forbidden` /
`NotFound` / `HTTPException` instances for retry-path tests.

## 3. PostgreSQL-specific tests

The portable ORM lets the main suite run on SQLite. Three behaviours differ on
PostgreSQL and have their own suite:

```bash
createdb nfpd_shield_test
DATABASE_URL=postgresql+asyncpg://user@127.0.0.1:5432/nfpd_shield_test alembic upgrade head
SHIELD_TEST_PG_URL=postgresql+asyncpg://user@127.0.0.1:5432/nfpd_shield_test \
  pytest tests/integration/test_postgres.py -q
```

It covers `INSERT ... ON CONFLICT DO NOTHING` deduplication and claim
exclusivity under concurrency, `pg_advisory_xact_lock` serialising work for one
guild while leaving other guilds unblocked, and the Alembic migration producing
a schema the ORM can use. Skipped automatically when the variable is unset.

Also verify the migration round-trips:

```bash
alembic upgrade head && alembic downgrade base && alembic upgrade head
```

## 4. Staging-guild test plan

Do this before enabling enforcement anywhere that matters. You need a throwaway
guild you own, with Shield invited and its role placed **above** a test "Admin"
role.

### Setup

| Step | Command / action | Expected |
|---|---|---|
| S1 | `/shield health` | all permissions present; audit log OK; no out-of-reach dangerous roles |
| S2 | `/shield logs set channel:#shield-log` | confirmation; `/shield logs test` posts a message |
| S3 | `/shield enable mode:alert_only` (dry run on) | "Protection enabled"; warnings listed |
| S4 | Create a second account ("Attacker"), give it the test Admin role | — |
| S5 | `/shield backup create` | snapshot v1, counts match the guild |

### Detection, in alert-only (nothing should ever change)

| # | Action as Attacker | Expected incident | Must NOT happen |
|---|---|---|---|
| D1 | Delete one test channel | `channel_delete`, actor = Attacker, confidence `confirmed`, title `ALERT ONLY` | no role removed |
| D2 | Delete 5 channels quickly | exactly one incident (cooldown collapses the burst); 5 rows in `event_records` | no role removed |
| D3 | Create 5 channels in 20s | `channel_create_flood` | — |
| D4 | Delete a test role | `role_delete` | — |
| D5 | Ban two throwaway accounts within 15s | `mass_ban` on the second | no incident on the first |
| D6 | Kick a throwaway account | `mass_kick` only after the second kick | nothing at all when a member *leaves* voluntarily |
| D7 | Give a test role Administrator | `dangerous_permission_change`, `granted: ["administrator"]` | — |
| D8 | Grant the Admin role to a third account | `dangerous_role_grant`, actor = Attacker | — |
| D9 | Create a webhook | `webhook_create`, response `alert_only` | no sanction |
| D10 | Invite any bot | `bot_add`, actor = the inviter, response `alert_only` | no sanction |
| D11 | Post 6 messages in 8s | `message_spam` | no role strip |
| D12 | Post the same message 4 times in 15s | `duplicate_spam` | — |
| D13 | Mention 5 different users in one message | `mass_mention` | — |
| D14 | Post `@everyone` | `mass_mention` immediately | — |
| D15 | Rename the guild and lower the verification level | `guild_settings_change` listing both fields | — |

### Attribution and safety

| # | Action | Expected |
|---|---|---|
| A1 | Remove `View Audit Log` from Shield, delete a channel | incident titled `UNATTRIBUTED`, confidence `unknown`, reason mentions the missing permission. Restore the permission afterwards. |
| A2 | As the **guild owner**, delete a channel | incident titled `OWNER ACTION`, no sanction, ever |
| A3 | Move Shield's role **below** the Admin role, then delete a channel as Attacker | incident titled `CONTAINMENT FAILED`, severity critical, lists the out-of-reach role. Move Shield back up. |
| A4 | Allowlist Attacker (`scope:destructive`), delete 3 channels | no incident at all |
| A5 | Remove the allowlist entry, repeat | incidents resume |
| A6 | `/shield pause`, delete a channel | nothing posted; the event is still in `event_records`. `/shield resume` afterwards. |

### Enforcement (only once the above all behave)

| # | Action | Expected |
|---|---|---|
| E1 | `/shield enable mode:enforce dry_run:false`, delete a channel as Attacker | the Admin role is removed from Attacker; colour/member roles are kept; incident outcome `succeeded` |
| E2 | Repeat within 60s | second action suppressed by the cooldown; no duplicate role removal |
| E3 | Spam 6 messages as Attacker | timeout applied, up to 25 recent messages deleted, **no** role removed |
| E4 | 8 joins in 20s (or `/shield lockdown raid enable:true`) | raid mode on: verification level raised, slowmode applied, **nobody banned or kicked**; it lifts itself after the configured minutes and restores the previous values |
| E5 | `/shield lockdown enable` then `disable` | verification level and every channel's slowmode return to their prior values |

### Restore

| # | Action | Expected |
|---|---|---|
| R1 | `/shield backup create`, then delete a category, two channels and a role | snapshot exists from before the damage |
| R2 | Create one new channel by hand | it must survive the restore |
| R3 | `/shield restore preview` | plan lists exactly the missing objects; the hand-made channel is under "left untouched"; threads and managed roles under "skipped"; webhooks under "NOT recoverable"; a token is issued |
| R4 | Apply as a **delegate** | refused — owner only |
| R5 | `/shield restore apply token:<token> confirm:true` as the owner | objects recreated with **new** IDs; overwrites reapplied; pre-restore snapshot taken; result lists what was and was not restored |
| R6 | Re-use the same token | rejected (single use) |
| R7 | `/shield restore apply` with a token from a *different* guild | rejected (guild-scoped) |

### Authorization

| # | Action | Expected |
|---|---|---|
| Z1 | `/shield enable` as a non-owner Administrator | refused, with the explanation that Administrator grants no Shield authority |
| Z2 | `/shield thresholds view` as an ordinary member | refused, points at the `manage_shield` scope |
| Z3 | Allowlist a user with `scope:manage_shield`, retry Z2 | allowed; but that user still trips detectors (verify with D1) |
| Z4 | `/shield incidents show <id-from-another-guild>` | "No incident ... in this guild" |
| Z5 | `/shield health` as the global `OWNERID` operator | allowed |
| Z6 | `/shield enable` as the global operator | refused — diagnostics scope only |
| Z7 | `sudo -u postgres psql -d nfpd_shield -c "SELECT command, allowed, authority FROM command_audit ORDER BY created_at DESC LIMIT 20"` | every attempt above is recorded, allowed and denied alike |

### Resilience

| # | Action | Expected |
|---|---|---|
| X1 | `sudo systemctl stop postgresql`, delete a channel | Shield logs the degradation, alerts without an incident ID, does **not** enforce, does not crash. Start PostgreSQL again. |
| X2 | `sudo systemctl restart nfpd-shield` mid-burst | windows rehydrate from `event_records`; a pre-restart event still counts toward the threshold |
| X3 | Trip a detector ~20 times in a minute | enforcement budget exhausts; further responses are `skipped` with `residual_risk`, and Shield keeps alerting instead of hammering the API |

### Teardown

```
/shield disable
/shield lockdown disable          # if it is still on
```

Delete the staging guild, or leave it in place as a permanent canary that you
upgrade first.

## 5. What is deliberately not tested automatically

| Area | Why | How it is validated |
|---|---|---|
| Real Discord API semantics (exact audit timing, rate-limit buckets, `invites_disabled` availability) | cannot be faithfully faked | staging plan above |
| Privileged intent approval | a Discord process | manual |
| systemd hardening | needs a host | `systemd-analyze verify`, then staging deploy |
| Container runtime behaviour (restart policy, healthcheck interval, read-only rootfs) | needs a Docker daemon | CI builds the image and asserts the uid, entrypoint failure modes and probe; the rest is verified on the staging host |
| Multi-process window sharing | a documented limitation, not a feature | documented in `docs/DEPLOYMENT.md` §13 |
| Icon/banner restoration | not restorable from a URL | documented as unsupported |
