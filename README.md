# NFPD Shield

Multi-guild anti-raid and anti-nuke protection for Discord, built on Python
3.12+ and **discord.py 2.x** with PostgreSQL for durable state.

> **Language note.** The original brief mentioned discord.js. That is a
> JavaScript library and cannot run in a Python process, so this project is
> implemented in Python with discord.py 2.x. Everything below is Python.

NFPD Shield is designed around one principle: **never claim a containment it
did not achieve, and never punish a user it cannot prove acted.** Discord does
not tell a bot who deleted a channel; that information lives in the audit log
and arrives late or not at all. Shield therefore treats attribution as a
first-class, fallible input, and a detector that cannot confirm an actor alerts
instead of guessing.

---

## Table of contents

- [What it detects](#what-it-detects)
- [What it does in response](#what-it-does-in-response)
- [Honest limitations](#honest-limitations)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Discord permissions and intents](#discord-permissions-and-intents)
- [Configuration](#configuration)
- [Commands](#commands)
- [Safe rollout procedure](#safe-rollout-procedure)
- [Backup and restoration](#backup-and-restoration)
- [Operations](#operations)
- [Tests](#tests)
- [Further documentation](#further-documentation)

---

## What it detects

| Detector (`action_key`) | Default threshold | Signal source | Default response |
|---|---|---|---|
| `mass_ban` | 2 / 15s per actor | gateway + audit | strip dangerous roles |
| `mass_kick` | 2 / 15s per actor | audit (a kick is indistinguishable from a leave on the gateway) | strip dangerous roles |
| `channel_delete` | 1 / 15s per actor | gateway + audit | strip dangerous roles |
| `channel_create_flood` | 4 / 20s per actor | gateway + audit | strip dangerous roles |
| `role_delete` | 1 / 15s per actor | gateway + audit | strip dangerous roles |
| `role_create_flood` | 4 / 20s per actor | gateway + audit | strip dangerous roles |
| `dangerous_permission_change` | 1 event | role/overwrite diff + audit | strip dangerous roles |
| `dangerous_role_grant` | 1 event | member role diff + audit | strip dangerous roles |
| `bot_add` | 1 event | gateway + audit | **alert only** |
| `webhook_create` / `webhook_delete` / `webhook_update` | 1 event | `on_webhooks_update` + audit classification | **alert only** |
| `mass_mention` | 5 unique mentions / 10s, or any `@everyone`/`@here` | gateway | timeout + bounded delete |
| `join_flood` | 8 joins / 20s per guild | gateway | reversible raid mode |
| `message_spam` | 6 messages / 8s per user | gateway | timeout + bounded delete |
| `duplicate_spam` | 4 identical / 15s per user | gateway (needs Message Content) | timeout + bounded delete |
| `guild_settings_change` | 1 event | `on_guild_update` diff + audit | **alert only** |
| `vanity_url_change` | 1 event | `on_guild_update` diff + audit | **alert only** |

Every threshold is per guild and changeable with `/shield thresholds set`.
A threshold of 1 fires on a single event and is the highest false-positive
risk setting there is; the policies that ship that way either default to
alert-only or are called out in `/shield thresholds view`.

## What it does in response

The default anti-nuke sanction is **not** a ban or a kick. It is the minimum
change that removes the attacker's ability to keep destroying things:

1. Compute the set of the actor's roles that carry a dangerous permission
   **and** sit strictly below Shield's own highest role **and** are not
   integration-managed.
2. Remove exactly those, recording the before/after state.
3. Preserve every safe role (colour roles, ping roles, member roles).

If a dangerous role is out of reach, or the actor is the guild owner, or
Shield lacks Manage Roles, then the incident is recorded and reported as
**containment failed / partial**, with the exact reason, and the operator is
pointed at `/shield lockdown enable`. Shield does not pretend.

Message-level abuse gets a timeout plus a bounded message cleanup (never a role
strip). A join flood enables a **reversible** raid mode (verification level,
invite pause, slowmode) and never bans or kicks a joiner — a flood of joins is
not proof that any individual joiner is malicious.

Guild owners are never sanctioned. They are always alerted on.

## Honest limitations

These are properties of the Discord API, not bugs, and they are repeated in
`/shield health`:

- **No actor on the gateway.** Channel/role deletions, webhook changes and
  guild edits arrive with no actor. Attribution needs `View Audit Log` and is
  eventually consistent. Without that permission Shield can detect but never
  sanction.
- **A kick looks like a leave.** `on_member_remove` cannot distinguish them.
  Shield consults the audit log and emits nothing for a voluntary leave.
- **Webhook executions are not audited.** Shield can see a suspicious webhook
  *message* only in channels it can read, and there is no member to attribute,
  so it alerts only. Webhook tokens are never visible to a bot.
- **`guild_update` is coarse.** Discord emits one audit action for many fields;
  per-field attribution depends on `entry.changes` being populated. Vanity URL
  changes are only visible on guilds with the `VANITY_URL` feature.
- **Nothing restores message history.** No bot API exists. Deleted messages,
  attachments, threads, invites, integrations and webhook tokens are gone.
- **IDs cannot be recovered.** A recreated channel or role gets a new
  snowflake; anything referencing the old ID must be reconfigured.
- **Message Content is privileged.** Without it, duplicate-content detection is
  unavailable and Shield falls back to message *rate* only.
- **Member role assignments are not restored.** Recreated roles come back
  empty, deliberately: re-granting a dangerous role to a list of members is
  exactly what an attacker would want.

See [`docs/COMPLETION_MATRIX.md`](docs/COMPLETION_MATRIX.md) for a
feature-by-feature implemented / tested / unsupported breakdown.

## Architecture

```
Discord gateway                                    PostgreSQL
      │                                                 ▲
      ▼                                                 │
┌──────────────┐   NormalizedEvent   ┌───────────────────┴────────────┐
│ events/      │────────────────────▶│ 1. dedupe (unique dedupe_key)  │
│  member      │                     │ 2. audit attribution           │
│  message     │                     │ 3. trust evaluation            │
│  admin       │                     │ 4. sliding window (monotonic)  │
└──────────────┘                     │ 5. cooldown + escalation       │
                                     │ 6. policy engine (pure)        │
                                     │ 7. incident (advisory-locked)  │
                                     │ 8. enforcement (idempotent)    │
                                     │ 9. notify (rate limited)       │
                                     └────────────────────────────────┘
                                                      │
            ┌─────────────────────────────────────────┼──────────────────┐
            ▼                        ▼                ▼                  ▼
      enforcement/            backup/snapshot   restore/planner    commands/
      (roles, timeouts,       (versioned,       (+applier:         (slash only,
       lockdown, raid)         encrypted)        additive,          owner-gated)
                                                 previewed)
```

Full detail, including the audit-correlation strategy and the data model, is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Key invariants:

- **Deduplication precedes attribution.** A redelivered gateway event is
  dropped before Shield spends an audit-log read, and the dedupe key never
  depends on attribution (which differs between a first delivery and a replay).
- **Only `CONFIRMED` attribution authorises a sanction.** `LIKELY` and
  `UNKNOWN` alert.
- **Every automated response is idempotent.** Each step claims a unique
  `idempotency_key` row before touching Discord, so a retry, a duplicate event
  or a process restart cannot double-act.
- **Per-guild coordination uses PostgreSQL advisory locks**, so running several
  processes or shards is safe.
- **Multi-guild isolation is structural.** Every repository method takes a
  `guild_id` and no query omits it, which also closes cross-guild IDOR from
  slash commands.
- **Shield's own writes cannot trigger Shield.** Every write registers with a
  self-action guard first, so a 40-channel restore is not read as a creation
  flood.
- **Only confirmed attribution counts against an actor.** A `LIKELY` guess is
  windowed as unattributed, so it can never push someone over a threshold.
- **Chat traffic costs the database nothing.** Per-message events are
  deduplicated in memory and written only when they lead to an incident.
- **Windows use `time.monotonic()`**; persistence uses UTC. An NTP correction
  cannot widen or collapse a rate window.

## Quick start

Two supported deployments, one environment contract.

**Docker**, alongside the other NFPD bots on a shared `nfpd-postgres` container:

```bash
git clone https://github.com/montygulzar/NFPD-Shield.git
cd NFPD-Shield
cp .env.example .env && chmod 600 .env
nano .env                          # DISCORD_TOKEN, APPLICATION_ID, OWNERID, DATABASE_URL
GIT_COMMIT="$(git rev-parse --short HEAD)" docker compose build
docker compose up -d && docker compose logs -f
```

Shield needs **its own database** on that PostgreSQL server (default
`nfpd_shield`), not the mod bot's — both define a `guild_settings` table with
different columns, and sharing one breaks both. The full rationale, the SQL to
create the role and database, and the side-by-side notes are in
[`docs/DOCKER.md`](docs/DOCKER.md).

**systemd**, on a standalone VPS:

```bash
sudo ./deploy/install.sh          # creates the user, venv, database and unit
sudoedit /etc/nfpd-shield/shield.env   # fill in DISCORD_TOKEN, APPLICATION_ID, OWNERID, DATABASE_URL
sudo ./deploy/install.sh --migrate-only
sudo systemctl status nfpd-shield
```

Step-by-step VPS commands, including the manual PostgreSQL path, are in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

For local development:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # then edit it; set SHIELD_LOAD_DOTENV=true
alembic upgrade head
python -m shield
```

## Discord permissions and intents

Create the application at <https://discord.com/developers/applications>.

**Privileged gateway intents** (Bot → Privileged Gateway Intents):

| Intent | Needed for | If disabled |
|---|---|---|
| **Server Members** | joins, member state, role-grant detection, member lookups | `join_flood` and `dangerous_role_grant` are inert; enforcement cannot resolve members. Shield refuses to boot in `enforce` mode without it. |
| **Message Content** | duplicate-message detection, reliable `@everyone` matching | `duplicate_spam` is unavailable; `message_spam` degrades to rate only. |

Both must be toggled on in the Developer Portal. Once a bot is in **100 or more
guilds**, Discord requires verification and explicit approval for each
privileged intent; apply before you cross that line, and expect to justify the
anti-raid use case. `Presence` is never requested.

**Bot permissions.** Grant only these; do *not* grant Administrator:

| Permission | Why |
|---|---|
| View Audit Log | actor attribution — without it nothing can be sanctioned |
| Manage Roles | remove dangerous roles from an attacker |
| Manage Channels | slowmode during lockdown, channel restoration |
| Manage Guild | verification level, invite pause, guild-setting restore |
| Moderate Members | timeouts for spam and mention floods |
| Manage Messages | bounded spam cleanup |
| Manage Webhooks | read webhook metadata for snapshots |
| View Channels, Send Messages, Embed Links, Read Message History | incident reports and cleanup |

Invite URL (permission integer `1100317027504`, scopes `bot applications.commands`):

```
https://discord.com/api/oauth2/authorize?client_id=<APPLICATION_ID>&permissions=1100317027504&scope=bot%20applications.commands
```

**Role position matters more than permissions.** Shield can only modify roles
*strictly below* its own highest role. Drag Shield's role above every role you
want it to be able to strip. `/shield health` lists every dangerous role that
is currently out of reach.

## Configuration

All secrets and deployment IDs come from the process environment; nothing is
hard coded and no ID is committed. `.env.example` is the full contract.

- `OWNERID` is the canonical global operator variable (`OWNER_ID`,
  `SHIELD_OWNER_ID` and the plural `OWNER_IDS` list are accepted). The operator gets **diagnostics
  scope only** — it is not exempt from any guild's protections and cannot
  change a guild's protection state.
- Per-guild settings (mode, thresholds, allowlist, log channel, snapshot
  cadence) live in PostgreSQL. Environment values are only bootstrap defaults
  applied the first time Shield sees a guild.
- `DATABASE_URL` takes a plain `postgresql://` URL (the driver is added
  automatically) or the discrete `POSTGRES_USER`/`PASSWORD`/`HOST`/`PORT`/`DB`
  form. TLS is required for routable hosts and not for loopback, a Unix socket
  or a single-label container name; `DB_REQUIRE_TLS` overrides that judgement.
- `APPROVED_GUILD_IDS` restricts Shield to the listed servers: anywhere else it
  ignores events and refuses commands, and with `LEAVE_UNAPPROVED_GUILDS=true`
  it leaves. Shield holds Manage Roles and Manage Guild; it should not sit armed
  in a server nobody approved.
- Boot validation lists **every** problem at once and exits `78` (`EX_CONFIG`)
  without starting. It rejects placeholder tokens, non-numeric snowflakes,
  synchronous database drivers, remote databases without TLS, and contradictory
  combinations such as `DEFAULT_MODE=enforce` with `ENABLE_GUILD_MEMBERS=false`.
- A systemd `EnvironmentFile` is **not** a shell script and **not** identical to
  python-dotenv: no `export`, no `$VAR` expansion, no inline comments. Keep
  values plain and unquoted.
- Secrets never reach the logs. A redaction filter scrubs bot tokens, webhook
  URLs, DSN passwords and sensitive field names from every record, including
  those emitted by discord.py and SQLAlchemy.

## Commands

Slash commands only; there is no dashboard. All replies are ephemeral, every
command is guild-only, and authority is re-checked **on the server** for every
invocation and written to `command_audit`.

Authority ladder: **owner** (the Discord guild owner — final authority) >
**delegate** (explicitly granted the `manage_shield` trust scope) >
**operator** (global `OWNERID`, diagnostics only) > nobody else.
Administrator and Manage Guild grant **no** Shield authority, because those are
exactly the permissions a compromised-admin attack abuses.

| Command | Authority | Purpose |
|---|---|---|
| `/shield status` | delegate | posture, recent incidents, snapshot age, false-positive rate |
| `/shield health` | operator | intents, permissions, role hierarchy, database, audit-log access |
| `/shield metrics` | operator | process counters |
| `/shield enable` | **owner** | turn protection on (defaults to `alert_only` + dry run) |
| `/shield disable` | **owner** | turn protection off (detection and snapshots continue) |
| `/shield mode` | **owner** | `alert_only` / `enforce` / `lockdown` |
| `/shield pause` / `/shield resume` | **owner** | emergency stop: record events, take no action, send nothing |
| `/shield thresholds view` / `set` | delegate | inspect and tune detection |
| `/shield thresholds reset` | **owner** | restore the strict defaults |
| `/shield whitelist add` / `remove` | **owner** | scoped allowlist entries |
| `/shield whitelist list` | delegate | show the allowlist |
| `/shield logs set` / `test` | delegate | incident log and alert channels |
| `/shield incidents list` / `show` / `acknowledge` | delegate | triage, mark false positives |
| `/shield incidents export` | **owner** | JSON export for retention or review |
| `/shield backup create` / `list` / `inspect` | delegate | snapshots and integrity checks |
| `/shield backup settings` | **owner** | cadence, retention, webhook metadata |
| `/shield restore preview` | delegate | diff against live state, returns an approval token |
| `/shield restore apply` | **owner** | apply a previewed plan (token + explicit confirm) |
| `/shield restore history` | delegate | past restore jobs |
| `/shield lockdown enable` / `disable` / `raid` | **owner** | protective modes |
| `/shield lockdown status` | delegate | current protective state |

Allowlist scopes are narrow on purpose: `all`, `destructive`, `webhooks`,
`messages`, `bots`, `guild_settings`, and `manage_shield` (command authority
only — a delegate is still policed by every detector).

## Safe rollout procedure

Shield's defaults are deliberately strict, and strict defaults produce false
positives. Do not skip this.

1. **Stage first.** Run against a throwaway guild. Follow the scripted
   scenarios in [`docs/TESTING.md`](docs/TESTING.md).
2. **`/shield logs set`** so you can actually see incidents.
3. **`/shield health`** and fix every warning — especially role position and
   `View Audit Log`.
4. **`/shield enable mode:alert_only`.** A new guild is created disabled, in
   `alert_only`, with `dry_run` on; Shield records and reports but never acts.
5. **Watch for at least several days of normal traffic.** Use
   `/shield incidents list` and mark noise with
   `/shield incidents acknowledge false_positive:true`.
6. **Tune.** Raise thresholds, widen windows, exempt busy channels
   (`/shield thresholds set action:message_spam exempt_channel:#bots`), allowlist your legitimate automation with the narrowest scope that
   works. Aim for a 7-day false-positive rate of zero before enforcing.
7. **Enforce one detector at a time:** set its response while leaving
   `dry_run: true` for the rest of the guild, then flip
   `/shield enable mode:enforce dry_run:false` only once you trust it.
8. **Keep `/shield pause` in reach.** It is the kill switch during planned
   restructuring or if Shield misbehaves.

## Backup and restoration

Snapshots are taken at startup, on a per-guild schedule, on demand, and
immediately before a restore. They capture roles (name, permissions, colour,
hoist, mentionable, position), categories and channels (type, name, position,
parent, topic, slowmode, NSFW, voice settings, permission overwrites), guild
settings, and — only when the guild opts in — webhook **metadata**.

They deliberately do **not** capture message content, webhook tokens, invite
codes or member lists. With `SNAPSHOT_ENCRYPTION_KEY` set, the payload is
gzipped and Fernet-encrypted before it reaches PostgreSQL, so a database dump
does not leak guild structure. Every snapshot is checksummed and can be
verified with `/shield backup inspect`; one that fails structural validation is
stored but can never be chosen as a restore source.

Restoration is **additive**: it recreates what is missing and never deletes or
renames what exists now, so a legitimate change made after the snapshot
survives. `/shield restore preview` shows the exact operation list, what will
be left untouched, what is skipped (managed roles, threads) and what is
unrecoverable, then issues a short-lived, single-use, guild-scoped approval
token. Only the guild owner can apply it, a pre-restore snapshot is taken
first, the plan is recomputed against current state, and the result records
old → new ID mapping plus precisely what was and was not restored.

## Health endpoints

Shield serves two read-only HTTP routes for container orchestration and
monitoring, matching the contract the other NFPD services expose:

| Route | Meaning | Codes |
|---|---|---|
| `GET /health` | Liveness: the process is up and its event loop is scheduling work. Stays 200 while dependencies are down, because a restart would not fix a database outage. | 200 |
| `GET /ready` | Readiness: logged into Discord **and** PostgreSQL reachable. Tolerates a 90s gateway drop, since discord.py resumes on its own. | 200 / 503 |

Neither is published to the host by the compose file, neither exposes guild
data, configuration or secrets, and Shield has no state-changing HTTP route at
all — everything that changes behaviour goes through a slash command with
server-side authorization. Disable with `HEALTH_SERVER_ENABLED=false`.

## Operations

```bash
docker compose ps && docker compose logs -f        # Docker deployment
systemctl status nfpd-shield
journalctl -u nfpd-shield -f                        # structured JSON, one object per line
journalctl -u nfpd-shield -p warning --since '1 hour ago'
journalctl -u nfpd-shield --since today | jq 'select(.correlation_id=="evt-...")'
sudo systemctl restart nfpd-shield
sudo /opt/nfpd-shield/deploy/rollback.sh <git-ref> [alembic-revision]
```

Every log line, incident, enforcement step and Discord report carries the same
`correlation_id`, so one string reconstructs a whole causal chain.

Runbooks for raid response, false positives, missing audit permissions,
database outage, emergency disable, restore approval, token rotation, incident
export and data retention are in [`docs/RUNBOOKS.md`](docs/RUNBOOKS.md).

## Tests

```bash
pip install -r requirements-dev.txt
pytest                                   # unit + integration + simulations
pytest tests/unit -q                     # pure logic, no I/O
pytest tests/simulation -q               # attack scenarios through the real cogs

# optional: exercise the PostgreSQL-specific paths
createdb nfpd_shield_test
DATABASE_URL=postgresql+asyncpg://user@127.0.0.1:5432/nfpd_shield_test alembic upgrade head
SHIELD_TEST_PG_URL=postgresql+asyncpg://user@127.0.0.1:5432/nfpd_shield_test \
  pytest tests/integration/test_postgres.py -q
```

The Discord API is always faked — no test ever performs a destructive action
against a real guild. Coverage includes thresholds, false positives,
simultaneous incidents, actor attribution, stale audit logs, missing
permissions, role hierarchy, owner exemption, duplicate gateway events, partial
restoration, rate limits, database outage and restart recovery.

## Further documentation

| Document | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | pipeline, data model, audit correlation, concurrency, phased plan |
| [`docs/THREAT_MATRIX.md`](docs/THREAT_MATRIX.md) | threats, detection, response, residual risk |
| [`docs/DOCKER.md`](docs/DOCKER.md) | Docker deployment beside the other NFPD bots, database separation, running both |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | exact VPS commands, systemd, rollback |
| [`docs/RUNBOOKS.md`](docs/RUNBOOKS.md) | incident runbooks |
| [`docs/SECURITY.md`](docs/SECURITY.md) | security review and deployment checklist |
| [`docs/TESTING.md`](docs/TESTING.md) | staging-guild test plan |
| [`docs/COMPLETION_MATRIX.md`](docs/COMPLETION_MATRIX.md) | implemented / tested / unsupported |

## Licence

MIT. See `pyproject.toml`.
