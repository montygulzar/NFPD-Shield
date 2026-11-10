# Docker deployment (alongside the other NFPD bots)

This is the deployment path for the NFPD host, where PostgreSQL already runs as
the `nfpd-postgres` container and the other bots attach to the
`nodey-monitoring` network. For a standalone VPS with systemd instead, see
[`DEPLOYMENT.md`](DEPLOYMENT.md) — both paths are supported and use the same
environment contract.

```
docker network: nodey-monitoring
├── nfpd-shield     this repo            → database: nfpd_shield
├── nfpd-mod-bot    moderation bot       → database: nfpd
└── nfpd-postgres   PostgreSQL 16, managed separately
```

`docker-compose.yml` defines **only the Shield service**, exactly as the mod
bot's does, so no compose command in this repository can touch the database
container or its volume.

---

## Shield must have its own database

Not a preference — sharing one would break both bots. Both projects define a
table called `guild_settings`, with different columns:

| | mod bot | Shield |
|---|---|---|
| created by | `CREATE TABLE IF NOT EXISTS` at start-up | Alembic migration |
| columns | log channels, lockdown role, raid/warn thresholds | enabled, mode, dry_run, paused, lockdown/raid state, policy version, snapshot policy |

Point both at one database and three things happen:

1. Whichever starts second finds the table already there. The mod bot's
   `CREATE TABLE IF NOT EXISTS` silently skips, then its
   `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` statements bolt its own columns
   onto Shield's table.
2. The mod bot reads settings with `SELECT *`, so reads do not error — they
   return Shield's columns, and the first access to `raid_min_account_age_hours`
   or `lockdown_role_id` raises `KeyError` inside its raid-protection and
   settings cogs.
3. The mod bot writes settings with
   `INSERT INTO guild_settings (guild_id, <column>) ... ON CONFLICT DO UPDATE`.
   Shield's table has ten `NOT NULL` columns with no server default, so that
   insert fails with `NotNullViolationError` for any guild Shield has not seen —
   and for a guild Shield *has* seen, the conflict path succeeds and `/log` in
   the mod bot silently redirects **Shield's** incident reports, because
   `log_channel_id` exists in both tables under the same name.

Separate databases on the same server cost nothing and remove the whole class of
problem. Their advisory locks do not collide, incidentally: the mod bot uses
PostgreSQL's single-key form and Shield the two-key form, which are separate
lock spaces.

## First-time setup

### 1. Create Shield's database and role

Run on the host. The role is deliberately minimal: it cannot create databases or
roles, and `PUBLIC` gets no rights.

```bash
DB_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"

docker exec -i nfpd-postgres psql -U postgres -v ON_ERROR_STOP=1 <<SQL
CREATE ROLE nfpd_shield LOGIN PASSWORD '${DB_PASSWORD}'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE DATABASE nfpd_shield OWNER nfpd_shield;
REVOKE ALL ON DATABASE nfpd_shield FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE nfpd_shield TO nfpd_shield;
SQL

docker exec -i nfpd-postgres psql -U postgres -d nfpd_shield -v ON_ERROR_STOP=1 <<'SQL'
GRANT ALL ON SCHEMA public TO nfpd_shield;
ALTER SCHEMA public OWNER TO nfpd_shield;
SQL

echo "put this in DATABASE_URL: ${DB_PASSWORD}"
```

Substitute the superuser name if `nfpd-postgres` does not use `postgres`.

### 2. Clone and configure

```bash
git clone https://github.com/montygulzar/NFPD-Shield.git
cd NFPD-Shield
cp .env.example .env
nano .env          # DISCORD_TOKEN, APPLICATION_ID, OWNERID, DATABASE_URL
chmod 600 .env     # holds the bot token and the database password
```

The DSN uses the **container name** as the host — containers on a user-defined
network resolve each other by name. `localhost` inside Shield's container points
at Shield:

```
DATABASE_URL=postgresql://nfpd_shield:<password>@nfpd-postgres:5432/nfpd_shield
```

TLS is not required for that hop and Shield does not demand it: a single-label
hostname is a private network name, not a routable host. Set
`DB_REQUIRE_TLS=true` if you want it enforced anyway.

Generate a snapshot encryption key and store it **outside** the database backups:

```bash
docker run --rm python:3.12-slim sh -c \
  'pip install -q cryptography && python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
# add to .env:  SNAPSHOT_ENCRYPTION_KEY=<value>
```

Losing that key makes existing encrypted snapshots unreadable, and
`/shield restore` will say so rather than failing quietly.

### 3. Confirm the network

```bash
docker network ls | grep nodey-monitoring \
  || docker network create nodey-monitoring

docker network inspect nodey-monitoring \
  --format '{{range .Containers}}{{.Name}} {{end}}'
# if nfpd-postgres is missing:
docker network connect nodey-monitoring nfpd-postgres
```

### 4. Build and start

```bash
GIT_COMMIT="$(git rev-parse --short HEAD)" docker compose build
docker compose up -d
docker compose logs -f
```

The entrypoint waits for PostgreSQL (up to `DB_WAIT_MAX_SECONDS`, default 300),
applies `alembic upgrade head`, and then starts the bot. Migrations run before
the gateway connects, so a failed migration never leaves a half-configured bot
online.

## Verifying a deployment

```bash
docker compose ps                       # State should be "running (healthy)"
docker inspect --format '{{.State.Health.Status}}' nfpd-shield

# Readiness from inside the network (the port is not published to the host):
docker exec nfpd-shield python -c \
  "import urllib.request,json;print(json.load(urllib.request.urlopen('http://127.0.0.1:8080/ready')))"

# Which build is live:
docker exec nfpd-shield python -c \
  "import urllib.request,json;print(json.load(urllib.request.urlopen('http://127.0.0.1:8080/health')))"

# Schema revision:
docker exec nfpd-shield alembic current

# No secret reached the logs:
docker compose logs --no-color | grep -c "$(grep '^DISCORD_TOKEN=' .env | cut -d= -f2-)"   # expect 0
```

Then in Discord: `/shield health`, `/shield logs set`, and
`/shield enable mode:alert_only`. The rollout procedure in the README still
applies — containerising Shield does not make its strict defaults any safer to
enable blind.

## Endpoints

| Route | Meaning | Codes |
|---|---|---|
| `GET /health` | Liveness: the process is up and its loop is scheduling work. Stays 200 while dependencies are down, because a restart would not fix a PostgreSQL outage. | 200 |
| `GET /ready` | Readiness: logged into Discord **and** PostgreSQL reachable. Tolerates a gateway drop for 90s, since discord.py resumes on its own. | 200 / 503 |

Neither route is published to the host, both are read-only, and neither exposes
guild data, configuration values or secrets — only aggregate counts and
connection states. Shield has no state-changing HTTP route at all; everything
that changes behaviour goes through a slash command with server-side
authorization. (The mod bot's `POST /internal/unban` has no equivalent here.)

## Routine deployment

```bash
cd ~/NFPD-Shield
git pull
GIT_COMMIT="$(git rev-parse --short HEAD)" docker compose build
docker compose up -d
docker compose logs -f --tail=50
```

Back up first — the schema is migrated automatically on start:

```bash
docker exec nfpd-postgres pg_dump -U nfpd_shield -d nfpd_shield | gzip > "shield-$(date +%F).sql.gz"
chmod 600 "shield-$(date +%F).sql.gz"
```

## Rollback

```bash
docker exec nfpd-postgres pg_dump -U nfpd_shield -d nfpd_shield | gzip > shield-pre-rollback.sql.gz
docker exec nfpd-shield alembic current          # note the revision
git checkout <previous-ref>
GIT_COMMIT="$(git rev-parse --short HEAD)" docker compose build
docker compose up -d
```

If the older code needs an older schema, downgrade explicitly before starting it:

```bash
docker compose run --rm --entrypoint alembic shield downgrade <revision>
```

Only downgrade to the revision the target code expects, never below what the
data requires.

## Operational behaviour

**PostgreSQL starts after Shield.** The entrypoint waits with exponential
backoff (1s → 15s) up to `DB_WAIT_MAX_SECONDS`, so there is no crash loop and no
Docker restart backoff.

**PostgreSQL restarts while Shield runs.** Shield degrades rather than dying:
cached guild configuration keeps serving, detection continues in memory, and
**enforcement is downgraded to alert-only** because idempotency cannot be
guaranteed without the claim table. `/ready` reports 503 and the container shows
unhealthy throughout.

**Wrong password or missing database.** Config validation and the entrypoint
probe fail loudly with the offending variable named, instead of retrying forever
and hiding it.

**Host reboots.** `restart: unless-stopped` brings the container back with the
Docker daemon. Ordering against `nfpd-postgres` does not matter because of the
wait above.

**`docker stop`.** `tini` forwards SIGTERM; Shield stops the snapshot scheduler
and maintenance loop, closes the health server, closes the gateway and disposes
the connection pool. `stop_grace_period: 45s` exceeds the internal timeouts, so
cleanup finishes before Docker escalates to SIGKILL.

**Container hardening.** Non-root uid 10002, read-only root filesystem with
tmpfs for `/tmp`, all capabilities dropped, `no-new-privileges`, 512 MB memory
ceiling, and Docker-side log rotation at 5 × 10 MB.

## Logs

```bash
docker compose logs -f
docker compose logs --since 1h
docker compose logs --no-color | jq 'select(.level=="WARNING")'      # LOG_FORMAT=json
docker compose logs --no-color | jq 'select(.correlation_id=="evt-...")'
```

Shield writes nothing to disk; rotation is the Docker daemon's job. `LOG_FORMAT`
accepts `json` (one object per line, for an aggregator) or `text`/`console`.

## Running both bots side by side

### Link the mod bot first

When a moderator bans or kicks through the mod bot, Discord's audit log names
**the bot**. Unlinked, Shield pools every moderator's actions into the bot's
rate window, blames the bot for a rogue moderator's mass ban, and cannot contain
anything (a bot's integration role is not removable). Link them once per guild:

```
/shield whitelist add user:@NFPD-Mod-Bot scope:moderation_proxy reason:"mod bot"
```

Shield then reads the moderator from the audit reason the mod bot already
writes (`Ban by name (id): reason`) and applies the normal thresholds to **that
moderator**. One moderator banning twice in 15 seconds trips `mass_ban`; two
moderators banning once each do not. The mod bot needs no change.

- The scope grants the bot **no exemption**; it only redirects attribution.
- It can only be given to a bot account. A person can type any audit reason, so
  a human proxy could frame someone.
- The mod bot's automatic actions (warn-threshold bans) name no moderator.
  Shield may alert on those but sanctions nobody.
- The guild owner and allowlisted moderators stay exempt when acting through
  the bot, exactly as when acting directly.

Two more things to settle before an incident, not during one:

**1. The mod bot's own structural work can still trip Shield.** The proxy link
covers moderator-issued actions; `/restorebackup` recreating roles and channels
crosses `role_create_flood` and `channel_create_flood`; its guild edits cross
`guild_settings_change`. Options, in increasing order of how much protection you
give up:

```
# Narrow: let it change guild settings, keep the flood detectors armed
/shield whitelist add user:@NFPD-Mod-Bot scope:guild_settings reason:"mod bot"

# Broad: also exempt it from destructive detectors (needed for /restorebackup)
/shield whitelist add user:@NFPD-Mod-Bot scope:guild_settings extra_scope:destructive
```

State the cost plainly: an allowlisted bot bypasses those detectors entirely, so
a stolen mod-bot token becomes an unmonitored path to a nuke — and "malicious
bot" is in Shield's threat model. The narrow entry plus
`/shield thresholds set action:role_create_flood response:alert_only` keeps a
real mass-create visible while silencing the routine false positive.

**2. Decide who owns backup and restore.** The mod bot's `/backupserver` writes
JSON to a Discord attachment (portable, offline, no database). Shield's
snapshots are richer — permission overwrites, checksums, optional encryption,
versioning, preview and an approval token. Running both is fine; restoring from
the weaker one during an incident is not. Pick the authoritative one now.

Related: Shield's raid mode records the current verification level and restores
it on expiry. If anything else changes that level inside the window, Shield
restores a stale value. The mod bot's raid protection is alert-only today, so
there is no enforcement conflict — but keep it that way deliberately rather than
by accident.
