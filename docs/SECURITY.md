# Security review and deployment checklist

## 1. Security posture summary

| Property | How it is achieved |
|---|---|
| No secrets in the repository | every secret and ID comes from the process environment; `.env.example` contains only placeholders; `.gitignore` excludes `.env` |
| No secrets in logs | a `logging.Filter` on the root logger scrubs bot tokens, webhook URLs, DSN passwords and sensitive field names from every record — including records emitted by discord.py, SQLAlchemy and asyncpg |
| Secrets on disk | the environment file is 0600 root-owned; systemd reads it as root before dropping to the service user |
| Least-privilege process | dedicated system user, no login shell, no home directory, all capabilities dropped, read-only filesystem, restricted syscalls, no new privileges, W^X memory, memory and task caps |
| Least-privilege database | a non-superuser role that cannot create databases or roles; `PUBLIC` revoked; TLS mandatory for remote hosts |
| Least-privilege Discord | explicit permission list, never Administrator; only the two privileged intents actually used |
| SQL injection | all queries are SQLAlchemy Core/ORM constructs with bound parameters; no string interpolation of user input anywhere |
| Cross-guild isolation (IDOR) | every repository method requires `guild_id` and no query omits it; a foreign ID returns "not found", indistinguishable from a non-existent one |
| Server-side authorization | authority is resolved and enforced in `shield/commands/authz.py` on every invocation, independent of Discord's editable command-permission UI |
| Audit trail | `command_audit` records every privileged invocation, allowed or denied, with caller, parameters, authority and reason |
| Confused-deputy resistance | Administrator, Manage Guild, "is a bot" and "has a high role" grant **no** trust and **no** command authority |
| Data minimisation | no message content, no webhook tokens, no invite codes, no member lists are ever persisted; duplicate detection uses an in-memory truncated hash |
| Encryption at rest | snapshots are gzipped and Fernet-encrypted (AES-128-CBC + HMAC-SHA256) before insert when `SNAPSHOT_ENCRYPTION_KEY` is set |
| Integrity | every snapshot carries a SHA-256 checksum over its canonical JSON, verifiable with `/shield backup inspect` |
| Replay resistance | restore approval tokens are random 48-bit hex, guild-scoped, single-use, short-lived, and compared with `secrets.compare_digest` |
| Idempotency | every automated response claims a unique `idempotency_key` row before any Discord call |
| Abuse resistance | per-guild token buckets, durable cooldowns, escalation instead of repetition, hard write caps, bounded message deletion |
| Fail-safe defaults | a new guild is created disabled, `alert_only`, `dry_run=true`; enforcement responses require confirmed attribution |
| Fail-loud configuration | boot lists every invalid variable and exits 78 without connecting |

## 2. Threat-specific review notes

**Compromised admin / rogue moderator.** This is the primary threat and it
drives the trust model: nothing is implicitly trusted except the guild owner
(never sanctioned, always alerted) and Shield itself (so its repairs do not
trigger it). Administrator does not grant exemption, and it does not grant
command authority either, so a compromised admin cannot raise thresholds or
allowlist themselves to clear the way.

**Malicious bot.** Bots are not trusted. A bot that nukes channels is treated
exactly like a member. A bot *addition* is alert-only because Shield genuinely
cannot distinguish an authorised install from a malicious one.

**Privilege escalation through Shield.** Shield exposes no command that grants
a user any Discord permission. The only state-changing commands are protection
settings, and the destructive ones (`enable`, `disable`, `mode`, `pause`,
`restore apply`, `lockdown`, `whitelist add/remove`, `thresholds reset`) are
guild-owner-only. The global operator is explicitly downgraded: `authorize()`
refuses an operator for anything above operator level.

**Denial of service through Shield.** Three layers: Shield's own token buckets
(so it cannot be weaponised against the Discord API), durable cooldowns (so a
repeated trigger does not produce repeated responses), and hard caps
(`MAX_ENFORCEMENT_WRITES`, `MAX_RESTORE_WRITES`, `MAX_SPAM_DELETE`,
`MAX_CHANNELS_TOUCHED`). Detection memory is bounded by per-bucket sample caps,
a per-guild bucket cap and a periodic sweep.

**Destructive automation.** Shield never deletes a channel, role or message it
did not create, except for a bounded spam cleanup capped at 25 messages. It
never mass-bans. Restoration is additive and never removes anything.

**Information disclosure.** All command replies are ephemeral. Incident
details, allowlists and thresholds are security-sensitive — publishing them in
a channel would help an attacker map the defences. Snapshot payloads live only
in PostgreSQL and are encrypted when a key is configured.

**Supply chain.** Dependencies are pinned to compatible minors in
`requirements.txt` and installed into a dedicated virtualenv. For a locked
deployment, generate a hash-pinned lockfile (`pip-compile --generate-hashes`)
and install with `--require-hashes`.

## 3. Known weaknesses (accepted, documented)

| Weakness | Impact | Mitigation / why accepted |
|---|---|---|
| An actor above Shield in the role hierarchy cannot be contained | an attacker with a founder-level role can nuke freely | a Discord rule, not a bug. Shield reports `CONTAINMENT FAILED` instead of pretending, and `/shield health` warns in advance. Keep Shield's role high. |
| The guild owner cannot be sanctioned | an owner-account takeover is unstoppable by any bot | Discord forbids modifying the owner. Alerting only; mitigate with 2FA and ownership discipline. |
| Attribution requires `View Audit Log` | without it, nothing is ever sanctioned | detection and alerting still work; refusing to guess is the safer failure. |
| Audit-log eventual consistency | a very slow audit entry yields `LIKELY`/`UNKNOWN`, so a real attacker may escape sanction | tunable delay/window/retries; alert-only fallback. The alternative — blaming whoever appears nearby — is worse. |
| 10-second dedupe bucket for repeatable targets | two genuinely distinct actions on one target inside 10s can collapse; a redelivery across a bucket boundary can double-count | the audit-entry path (most administrative actions) is exact; the trade-off is documented in `shield/events/normalize.py`. |
| In-memory detection windows are per process | with overlapping shards across processes, a threshold can take longer to trip | partition shards so one guild maps to one process, or run a single instance. Documented in `docs/DEPLOYMENT.md` §13. |
| An allowlisted principal bypasses detection entirely | a compromised allowlisted account can nuke silently | scopes are narrow, expiries are supported, adding an entry is owner-only and audited, and `/shield whitelist add` says so explicitly. |
| Single-event policies have a high false-positive rate | legitimate restructuring trips them | those policies default to alert-only where attribution is weak; the rollout procedure requires alert-only validation first. |
| Snapshots are unencrypted without a key | a database dump reveals guild structure | `SNAPSHOT_ENCRYPTION_KEY` is prominently recommended; `/shield backup create` warns when it is unset. |
| Losing the snapshot key loses the snapshots | restore becomes impossible | the failure is explicit and actionable, never silent. Back the key up separately from the database. |
| `RUN_MIGRATIONS_ON_BOOT=true` with several instances can race | duplicate DDL attempts | defaults to false in the shipped environment file; migrate from the deploy step. |
| No Prometheus endpoint | metrics are only visible through `/shield metrics` and logs | counters are JSON-serialisable; wiring an exporter is a small addition (roadmap phase 7). |

## 4. Pre-deployment checklist

### Discord application
- [ ] Application created; bot user added.
- [ ] **Public Bot** disabled unless you intend multi-tenant use.
- [ ] Server Members intent enabled.
- [ ] Message Content intent enabled (or `ENABLE_MESSAGE_CONTENT=false` accepted).
- [ ] Invite uses the explicit permission list, **not** Administrator.
- [ ] Token freshly generated and never pasted into a shared channel, issue or log.

### Host
- [ ] Python 3.12+.
- [ ] Dedicated non-root system user, no login shell.
- [ ] Code root-owned, not writable by the service user.
- [ ] `/etc/nfpd-shield/shield.env` is `600 root:root` (`stat -c '%a %U:%G'`).
- [ ] systemd unit installed from `deploy/`; `systemd-analyze verify` is clean.
- [ ] Journal retention configured (`journalctl --vacuum-time=30d` or `SystemMaxUse`).
- [ ] Firewall allows outbound 443 only; nothing inbound is required.
- [ ] Unattended security upgrades enabled.

### Database
- [ ] Non-superuser role, cannot create databases or roles.
- [ ] `PUBLIC` revoked on the database.
- [ ] `pg_hba.conf` restricts the role to the expected source address with `scram-sha-256`.
- [ ] TLS configured if the database is remote; `?ssl=require` in the DSN.
- [ ] `alembic current` matches `head`.
- [ ] Automated, rotated, 0600 backups (`deploy/backup-db.sh` + cron/timer).
- [ ] Backups tested by restoring into a scratch database.

### Configuration
- [ ] `OWNERID` set to the real operator account.
- [ ] `DEFAULT_MODE=alert_only`.
- [ ] `SNAPSHOT_ENCRYPTION_KEY` set and backed up **separately** from the database.
- [ ] `RUN_MIGRATIONS_ON_BOOT=false` (migrate from the deploy step).
- [ ] `INSTANCE_ID` unique per process.
- [ ] Retention values reviewed against your policy.
- [ ] `grep -c CHANGE_ME /etc/nfpd-shield/shield.env` returns 0.

### Per guild
- [ ] Shield's role positioned **above** every role it must be able to strip.
- [ ] `/shield health` clean: no missing permissions, no out-of-reach dangerous roles, audit log OK, database OK.
- [ ] `/shield logs set` configured and `/shield logs test` delivered.
- [ ] Legitimate automation allowlisted with the narrowest scope that works.
- [ ] `/shield enable mode:alert_only` and validated for several days.
- [ ] 7-day false-positive rate at or near zero before enforcing.
- [ ] Guild owner knows `/shield pause` exists and what it does.

### Verification
- [ ] `pytest` green.
- [ ] Staging-guild plan in `docs/TESTING.md` executed end to end.
- [ ] Rollback rehearsed once: `deploy/rollback.sh <previous-ref>`.
- [ ] Token-rotation runbook rehearsed once.
- [ ] No secret appears in the journal (see `docs/DEPLOYMENT.md` §8).

## 5. Reporting a vulnerability

Do not open a public issue. Contact the repository owner privately with a
description, reproduction steps and the affected version. Please allow time for
a fix before any disclosure.
