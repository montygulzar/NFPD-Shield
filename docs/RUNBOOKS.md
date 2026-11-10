# Operational runbooks

Each runbook is written to be followed under pressure: do the steps in order,
and prefer the reversible option.

Throughout: `SVC=nfpd-shield`, `ENV=/etc/nfpd-shield/shield.env`,
`APP=/opt/nfpd-shield`.

---

## 1. Active raid or nuke in progress

**Symptoms.** A burst of incident embeds in the log channel; channels or roles
disappearing; a flood of joins.

1. **Read the newest incident embed.** It states the actor, the attribution
   confidence and whether containment succeeded. If the title says
   `CONTAINMENT FAILED`, Shield could not stop the actor — go to step 3.
2. **If containment succeeded**, the actor's dangerous roles are already gone.
   Confirm with `/shield incidents show <id>` and check the `Steps` field.
3. **Lock the guild down** (owner): `/shield lockdown enable reason:"active raid"`.
   This raises the verification level, pauses invites and applies slowmode, and
   is fully reversible. It does not ban or kick anyone.
4. **Deal with the actor manually.** If they are above Shield in the hierarchy
   or are the guild owner, only a human with sufficient Discord permissions can
   act: remove their roles in the client, or transfer ownership.
5. **Assess the damage**: `/shield backup list` to find the newest snapshot
   from before the attack, then `/shield restore preview snapshot_id:<id>`.
   Read the preview — including the "NOT recoverable" section — before anything
   else.
6. **Restore** (owner only): `/shield restore apply token:<token> confirm:true`.
   A pre-restore snapshot is taken automatically.
7. **Reconfigure what the restore cannot fix**: webhooks (tokens were never
   stored), integrations, invites, and anything referencing old channel/role
   IDs. The old → new ID map is on the restore job.
8. **Lift lockdown**: `/shield lockdown disable`. The previous verification
   level and per-channel slowmode are restored from the recorded state.
9. **Post-incident**: `/shield incidents export days:1`, rotate any credential
   the attacker may have seen, and review `/shield whitelist list` for entries
   you did not add.

## 2. False positive

**Symptoms.** A legitimate moderator lost roles, or a normal user was timed out.

1. **Stop the bleeding** if it is ongoing (owner): `/shield pause reason:"false positives"`.
   Shield keeps recording events but takes no action and sends no notifications.
2. **Undo the action.** Shield records before/after state:
   `/shield incidents show <id>` lists the removed roles by name and ID. Re-add
   them in the Discord client. For a timeout, remove it in the client.
3. **Mark it**: `/shield incidents acknowledge <id> false_positive:true note:"planned restructure"`.
   This also clears the actor/action cooldown so a corrected policy can fire
   again, and feeds the 7-day false-positive rate in `/shield status`.
4. **Fix the cause.** Pick the least drastic that works:
   - Raise the threshold or widen the window:
     `/shield thresholds set action:channel_delete threshold:3 window:30`
   - Make the detector report only:
     `/shield thresholds set action:channel_delete response:alert_only`
   - Simulate it while you watch:
     `/shield thresholds set action:channel_delete dry_run:true`
   - Exempt the principal with the narrowest scope that works, and an expiry:
     `/shield whitelist add user:@Mod scope:destructive expires_in_hours:8`
   - Exempt a busy channel from a message detector:
     `/shield thresholds set action:message_spam exempt_channel:#bots`
5. **Resume**: `/shield resume`.
6. **Planned maintenance in future**: pause or allowlist *before* the work, not
   after. A time-boxed allowlist entry is the cleanest option.

## 3. Missing audit-log permission

**Symptoms.** Incidents titled `UNATTRIBUTED`; `/shield health` says
`MISSING View Audit Log`; nothing is ever sanctioned.

1. Confirm: `/shield health` → "Audit log access".
2. Grant `View Audit Log` to Shield's role in Server Settings → Roles. Do not
   grant Administrator instead.
3. Re-check `/shield health`. Attribution recovers on the next event; no
   restart is needed.
4. While it is missing, Shield is a detection-and-alerting system only. That is
   intentional: without the audit log there is no way to know who acted, and
   sanctioning a guess is worse than not sanctioning.

Related: if `/shield health` lists dangerous roles "at or above Shield", drag
Shield's role **above** them in Server Settings → Roles. Discord forbids a bot
from touching a role at or above its own highest role.

## 4. Database outage

**Symptoms.** `/shield health` shows `Database: FAILED`; logs contain
`could not persist event` or `db_errors_total` rising; incidents stop being
recorded.

What Shield does on its own: stale guild configuration is reused from cache,
detection continues in memory, and **enforcement is downgraded to alert-only**
because idempotency cannot be guaranteed without the claim table. Nothing
crashes.

1. Check PostgreSQL: `sudo systemctl status postgresql`,
   `sudo journalctl -u postgresql -n 100 --no-pager`.
2. Check disk: `df -h` — a full data volume is the usual cause.
3. Check connectivity from the host:
   ```bash
   sudo -E bash -c 'set -a; . /etc/nfpd-shield/shield.env; set +a; \
     psql "$(echo "$DATABASE_URL" | sed "s|postgresql+asyncpg|postgresql|")" -c "select 1"'
   ```
4. Check the pool: `SELECT count(*) FROM pg_stat_activity WHERE application_name='nfpd-shield';`
   If it is pinned at `DB_POOL_SIZE + DB_MAX_OVERFLOW`, raise them or find the
   long-running query.
5. Restart PostgreSQL, then Shield: `sudo systemctl restart nfpd-shield`.
   On startup Shield re-pings the database, refuses to run if it is still down,
   and rehydrates detection windows from `event_records`.
6. After recovery, expect a gap in `event_records` for the outage window. Any
   incident that was alerted but not persisted appears in the log channel with
   "Incident: not persisted (database unavailable)".

## 5. Emergency disable

Pick the smallest hammer that solves your problem.

| Need | Action | Effect |
|---|---|---|
| Stop all responses in one guild, right now | `/shield pause reason:"..."` (owner) | Events still recorded; no enforcement, no notifications |
| Stop enforcement but keep visibility | `/shield mode alert_only` (owner) | Incidents and reports continue; nothing is changed |
| Turn one detector off | `/shield thresholds set action:<key> enabled:false` | That detector stops entirely |
| Simulate everything globally | set `GLOBAL_DRY_RUN=true` in `$ENV`, restart | No Discord write can ever be made, in any guild |
| Stop the process | `sudo systemctl stop nfpd-shield` | No detection at all; snapshots stop too |
| Remove Shield's power without stopping it | revoke Manage Roles in Discord | Shield reports `enforcement_blocked` honestly |

```bash
sudo sed -i 's/^GLOBAL_DRY_RUN=.*/GLOBAL_DRY_RUN=true/' /etc/nfpd-shield/shield.env
sudo systemctl restart nfpd-shield
sudo journalctl -u nfpd-shield -n 20 --no-pager | grep global_dry_run
```

## 6. Restore preview and approval

1. `/shield backup list` — choose the newest **valid** snapshot taken *before*
   the damage. A snapshot marked `INVALID` can never be used.
2. `/shield backup inspect <snapshot_id>` — verify the checksum and read what
   it contains.
3. `/shield restore preview snapshot_id:<id>` — optionally narrow with
   `scope:` (roles only / channels only / guild settings only). Nothing is
   written. You get a short-lived, single-use, guild-scoped token.
4. **Read the preview properly.** Check the planned operation list, what will
   be left untouched (changes made after the snapshot), what is skipped
   (managed roles, threads), and the "NOT recoverable" list.
5. The **guild owner** runs `/shield restore apply token:<token> confirm:true`.
   A delegate cannot. A pre-restore snapshot is taken first and the plan is
   recomputed against current state, so a concurrent legitimate edit is not
   clobbered.
6. Read the result: it lists exactly what was restored, what failed and why.
   If the status is `partial`, fix the cause (usually a permission or hierarchy
   problem) and run preview/apply again — the restore is additive and safe to
   repeat.
7. `/shield restore history` shows past jobs and their ID maps.

## 7. Compromised bot token rotation

Assume full compromise: anyone with the token can act as Shield.

1. **Rotate immediately.** Developer Portal → your application → Bot → Reset
   Token. The old token dies the moment you reset it.
2. **Update the environment file and restart:**
   ```bash
   sudoedit /etc/nfpd-shield/shield.env     # replace DISCORD_TOKEN
   sudo systemctl restart nfpd-shield
   sudo journalctl -u nfpd-shield -n 30 --no-pager
   ```
3. **Audit what was done with it.** Discord's own audit log is the authority
   (filter by the Shield bot user). Cross-check Shield's records:
   ```sql
   SELECT created_at, guild_id, action_type, status, target_id, detail
     FROM enforcement_actions ORDER BY created_at DESC LIMIT 100;
   SELECT created_at, guild_id, user_id, command, allowed, authority
     FROM command_audit ORDER BY created_at DESC LIMIT 100;
   SELECT created_at, guild_id, mode, status, requested_by, approved_by
     FROM restore_jobs ORDER BY created_at DESC LIMIT 50;
   ```
   Anything in Discord's audit log attributed to Shield that has **no**
   corresponding `enforcement_actions` or `restore_jobs` row was done with the
   stolen token, not by Shield.
4. **Rotate adjacent secrets** if the host itself may be compromised: the
   database password, and `SNAPSHOT_ENCRYPTION_KEY`. Rotating the snapshot key
   makes existing encrypted snapshots unreadable — take a fresh snapshot per
   guild immediately afterwards (`/shield backup create`), and keep the old key
   archived offline until you no longer need the old snapshots.
5. **Review allowlists** in every guild: `/shield whitelist list`.
6. If the host was compromised, rebuild it. Reinstall from a known-good ref and
   restore the database from a backup predating the compromise.

## 8. Incident export and data retention

**Export** (guild owner): `/shield incidents export days:30` returns a JSON
attachment. It contains incident metadata only — no message content and no
secrets.

Bulk export for a compliance request:

```bash
sudo -u postgres psql -d nfpd_shield -At -c \
  "SELECT row_to_json(i) FROM incidents i WHERE guild_id = 123456789012345678" \
  > incidents-123456789012345678.ndjson
```

**Retention** is enforced by the maintenance loop every 60 seconds:

| Data | Variable | Default | Notes |
|---|---|---|---|
| raw events | `RETENTION_EVENT_DAYS` | 30 | must not exceed incident retention; `0` disables |
| incidents (and their enforcement rows, via cascade) | `RETENTION_INCIDENT_DAYS` | 180 | `0` disables |
| snapshots | per-guild `snapshot_retention` | 12 versions | `/shield backup settings` |
| cooldowns | automatic | on expiry | |
| allowlist entries | automatic | on expiry | |

Shield stores no message content anywhere, and no webhook tokens. Duplicate
detection uses a truncated SHA-256 of the normalised text, held in memory only.

Deleting a guild's data entirely:

```sql
-- Cascades to guild_policies and trusted_entities.
DELETE FROM guild_settings WHERE guild_id = 123456789012345678;
-- Tables without a FK to guild_settings:
DELETE FROM incidents          WHERE guild_id = 123456789012345678;
DELETE FROM event_records      WHERE guild_id = 123456789012345678;
DELETE FROM enforcement_actions WHERE guild_id = 123456789012345678;
DELETE FROM snapshots          WHERE guild_id = 123456789012345678;
DELETE FROM restore_jobs       WHERE guild_id = 123456789012345678;
DELETE FROM cooldowns          WHERE guild_id = 123456789012345678;
DELETE FROM command_audit      WHERE guild_id = 123456789012345678;
```

## 9. High false-positive rate after rollout

1. `/shield status` → read the 7-day false-positive rate.
2. `/shield incidents list hours:168` and look for one detector dominating.
3. Put that detector in dry run rather than disabling it, so you keep the data:
   `/shield thresholds set action:<key> dry_run:true`.
4. Compare `window_count` against `threshold` on a few incidents
   (`/shield incidents show <id>` → Evidence) and raise the threshold to just
   above normal traffic.
5. Re-enable and watch for another 48 hours.
6. If a single principal causes most of the noise, allowlist it narrowly rather
   than weakening the policy for everyone.

## 10. Shield is noisy in the log channel

Notifications are rate limited per guild (`NOTIFY_BURST` / `NOTIFY_REFILL_SECONDS`),
and suppressed notifications are logged rather than queued. If it is still too
much:

- Route high-severity alerts separately: `/shield logs set channel:#shield-log alert_channel:#shield-critical`.
- Raise cooldowns so repeats collapse: `/shield thresholds set action:<key> cooldown:300`.
- Lower the per-guild budget in `$ENV` (`NOTIFY_BURST`) and restart.

## 11. Service will not start

```bash
sudo systemctl status nfpd-shield
sudo journalctl -u nfpd-shield -n 100 --no-pager
```

| Log line | Cause | Fix |
|---|---|---|
| `configuration is invalid; refusing to start` + a list | bad environment file | fix each listed variable; exit code is 78 |
| `Cannot reach PostgreSQL at ...` | database down, wrong DSN, missing TLS | see runbook 4 |
| `Discord rejected the bot token` | wrong or rotated token | see runbook 7 |
| `Discord rejected the requested privileged intents` | intents not enabled in the Developer Portal | enable Server Members / Message Content, or set `ENABLE_*` to false |
| `alembic.ini not found; skipping automatic migrations` | partial install | re-run `deploy/install.sh` |
| exits immediately, no log | unit misconfiguration | `systemd-analyze verify /etc/systemd/system/nfpd-shield.service` |
