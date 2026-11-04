# Deployment (Linux VPS)

Target: Debian 12 or Ubuntu 22.04/24.04 with systemd. Commands assume `sudo`.
`deploy/install.sh` automates all of this; the manual steps are here so you can
audit or adapt it.

Shield runs as a **non-root system user** with no login shell, reads its
secrets from a **0600 root-owned** environment file, and connects to a
**least-privilege** PostgreSQL role.

---

## 1. Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-dev build-essential \
                        postgresql postgresql-contrib libpq-dev git ca-certificates
python3 --version     # must be 3.12 or newer
```

If the distribution ships Python < 3.12, install a newer interpreter (deadsnakes
on Ubuntu, backports on Debian) and pass it to the installer:
`sudo PYTHON=python3.12 ./deploy/install.sh`.

## 2. Service account

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin nfpdshield
id nfpdshield
```

## 3. Application directory and virtualenv

```bash
sudo install -d -m 0755 -o root -g root /opt/nfpd-shield
sudo git clone https://github.com/montygulzar/NFPD-Shield.git /opt/nfpd-shield-src
sudo tar -C /opt/nfpd-shield-src --exclude='.git' -cf - . \
  | sudo tar -C /opt/nfpd-shield -xf -

sudo python3 -m venv /opt/nfpd-shield/.venv
sudo /opt/nfpd-shield/.venv/bin/pip install --upgrade pip wheel
sudo /opt/nfpd-shield/.venv/bin/pip install -r /opt/nfpd-shield/requirements.txt
# Alembic's DDL path is synchronous, so it needs a sync driver too:
sudo /opt/nfpd-shield/.venv/bin/pip install "psycopg2-binary>=2.9"

sudo chown -R root:root /opt/nfpd-shield
sudo chmod -R go-w /opt/nfpd-shield
```

The code is root-owned and world-readable but not writable by the service user:
a compromise of the bot process cannot rewrite its own code.

## 4. PostgreSQL: database and least-privilege role

```bash
sudo systemctl enable --now postgresql

# Generate a password without echoing it into your shell history.
DB_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"

sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
CREATE ROLE nfpd_shield LOGIN PASSWORD '${DB_PASSWORD}'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
SQL

sudo -u postgres createdb -O nfpd_shield nfpd_shield

sudo -u postgres psql -v ON_ERROR_STOP=1 -d nfpd_shield <<'SQL'
REVOKE ALL ON DATABASE nfpd_shield FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE nfpd_shield TO nfpd_shield;
GRANT ALL ON SCHEMA public TO nfpd_shield;
ALTER SCHEMA public OWNER TO nfpd_shield;
SQL

echo "put this password into DATABASE_URL: ${DB_PASSWORD}"
```

The role cannot create databases or roles and is not a superuser. `PUBLIC` has
no rights on the database.

**Local connections** go over loopback or the Unix socket and need no TLS.
**Remote databases MUST use TLS** — Shield refuses to start otherwise. Append
`?ssl=require` to the DSN (asyncpg spelling) and, if you pin a CA, configure it
in `postgresql.conf`/`pg_hba.conf` on the server side.

Recommended `pg_hba.conf` entry for a local deployment (reject everything else):

```
# TYPE  DATABASE      USER          ADDRESS        METHOD
host    nfpd_shield   nfpd_shield   127.0.0.1/32   scram-sha-256
```

```bash
sudo systemctl reload postgresql
```

## 5. Environment file (0600)

```bash
sudo install -d -m 0750 -o root -g root /etc/nfpd-shield
sudo install -m 0600 -o root -g root /dev/null /etc/nfpd-shield/shield.env
sudoedit /etc/nfpd-shield/shield.env
```

Minimum contents — **systemd `EnvironmentFile` syntax**: one `KEY=VALUE` per
line, no `export`, no quotes, no `$VAR` expansion, no inline comments.

```
DISCORD_TOKEN=your-bot-token
APPLICATION_ID=123456789012345678
OWNERID=123456789012345678
DATABASE_URL=postgresql+asyncpg://nfpd_shield:the-password@127.0.0.1:5432/nfpd_shield
ENABLE_MESSAGE_CONTENT=true
ENABLE_GUILD_MEMBERS=true
DEFAULT_MODE=alert_only
GLOBAL_DRY_RUN=false
LOG_LEVEL=INFO
LOG_FORMAT=json
SNAPSHOT_INTERVAL_MINUTES=360
SNAPSHOT_RETENTION=12
INSTANCE_ID=shield-1
RUN_MIGRATIONS_ON_BOOT=false
```

Generate and add a snapshot encryption key (strongly recommended — without it,
guild structure is readable in a database dump):

```bash
/opt/nfpd-shield/.venv/bin/python -c \
  "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# then add:  SNAPSHOT_ENCRYPTION_KEY=<that value>
```

**Keep that key somewhere safe and separate.** If you lose it, existing
encrypted snapshots become unreadable and `/shield restore` cannot use them.

Verify the permissions:

```bash
sudo stat -c '%a %U:%G %n' /etc/nfpd-shield/shield.env   # expect: 600 root:root
```

## 6. Migrations

```bash
cd /opt/nfpd-shield
sudo -E bash -c 'set -a; . /etc/nfpd-shield/shield.env; set +a; \
  /opt/nfpd-shield/.venv/bin/alembic upgrade head'
sudo -E bash -c 'set -a; . /etc/nfpd-shield/shield.env; set +a; \
  /opt/nfpd-shield/.venv/bin/alembic current'
```

Run migrations from the deploy step, not from the bot (`RUN_MIGRATIONS_ON_BOOT=false`),
so that several instances starting at once cannot race each other.

## 7. systemd unit

```bash
sudo install -m 0644 /opt/nfpd-shield/deploy/nfpd-shield.service \
  /etc/systemd/system/nfpd-shield.service
sudo systemctl daemon-reload
sudo systemctl enable --now nfpd-shield
sudo systemctl status nfpd-shield
```

The shipped unit runs as `nfpdshield`, drops every capability, mounts the system
read-only (`ProtectSystem=strict`), hides other processes, restricts syscalls to
`@system-service`, forbids new privileges and W^X memory, caps memory at 512 MB
and tasks at 256, and restarts always with a 5-restarts-in-5-minutes crash-loop
guard.

## 8. Verify the deployment

```bash
# Service is up and the gateway connected:
sudo systemctl is-active nfpd-shield
sudo journalctl -u nfpd-shield -n 50 --no-pager | tail -20

# Structured logs, one JSON object per line:
sudo journalctl -u nfpd-shield -n 200 -o cat | jq -r '.level + " " + .message' | tail

# No secret ever appears in the logs:
sudo journalctl -u nfpd-shield -o cat | grep -c "$(sudo grep '^DISCORD_TOKEN=' \
  /etc/nfpd-shield/shield.env | cut -d= -f2-)"    # expect: 0
```

Then, in Discord:

```
/shield health          → intents, permissions, hierarchy, database, audit log
/shield logs set        → choose an incident log channel
/shield enable mode:alert_only
```

## 9. Log inspection

```bash
sudo journalctl -u nfpd-shield -f                          # follow
sudo journalctl -u nfpd-shield -p warning --since '1 hour ago'
sudo journalctl -u nfpd-shield --since today -o cat | jq 'select(.context.guild_id==123456789012345678)'
sudo journalctl -u nfpd-shield -o cat | jq 'select(.correlation_id=="evt-0123456789abcdef")'
sudo journalctl --disk-usage
sudo journalctl --vacuum-time=30d
```

To write a rotating file sink as well, set `LOG_FILE=/var/log/nfpd-shield/shield.log`,
create the directory, and uncomment `ReadWritePaths=/var/log/nfpd-shield` in the
unit:

```bash
sudo install -d -m 0750 -o nfpdshield -g nfpdshield /var/log/nfpd-shield
```

## 10. Upgrades

```bash
cd /opt/nfpd-shield-src
sudo git fetch --all --tags
sudo git checkout v1.2.3
sudo /opt/nfpd-shield/deploy/install.sh     # idempotent: syncs code, deps, migrations, unit
```

Pre-upgrade checklist:

1. `sudo /opt/nfpd-shield/deploy/backup-db.sh`
2. Note the current revision: `alembic current`
3. Read the release notes for new required environment variables.
4. Upgrade. If the service does not come up within a minute, roll back.

## 11. Rollback

```bash
sudo /opt/nfpd-shield/deploy/rollback.sh v1.2.2            # code only
sudo /opt/nfpd-shield/deploy/rollback.sh v1.2.2 0001_initial   # code + schema
```

The script stops the service, takes a database backup **before** changing
anything, checks out the target ref, reinstalls dependencies, optionally
downgrades the schema, and restarts. Only downgrade the schema to the revision
the target code expects — never below what the data needs.

Manual rollback:

```bash
sudo systemctl stop nfpd-shield
sudo -u postgres pg_dump nfpd_shield | gzip > /var/backups/pre-rollback.sql.gz
cd /opt/nfpd-shield-src && sudo git checkout v1.2.2
sudo tar -C /opt/nfpd-shield-src --exclude='.git' -cf - . | sudo tar -C /opt/nfpd-shield -xf -
sudo /opt/nfpd-shield/.venv/bin/pip install -r /opt/nfpd-shield/requirements.txt
cd /opt/nfpd-shield && sudo -E bash -c 'set -a; . /etc/nfpd-shield/shield.env; set +a; \
  /opt/nfpd-shield/.venv/bin/alembic downgrade 0001_initial'
sudo systemctl start nfpd-shield
```

## 12. Backups

```bash
sudo /opt/nfpd-shield/deploy/backup-db.sh                 # ad hoc
sudo crontab -e
# 0 4 * * * /opt/nfpd-shield/deploy/backup-db.sh
```

Set `GPG_RECIPIENT=<key-id>` to encrypt each dump at rest; set `KEEP_DAYS` to
change the 14-day rotation. Backups contain guild structure, so they are
created 0600 and root-owned. Keep the snapshot encryption key **out** of the
database backup — otherwise an attacker with the dump has both halves.

## 13. Running more than one instance

Safe, because per-guild coordination uses PostgreSQL advisory locks and every
response claims a unique idempotency key. Requirements:

- PostgreSQL (not SQLite — its lock degrades to process-local).
- A distinct `INSTANCE_ID` per process.
- `RUN_MIGRATIONS_ON_BOOT=false` everywhere; migrate once from the deploy step.
- Either let discord.py autoshard, or give each process explicit
  `SHARD_COUNT`/`SHARD_IDS`.

Note the documented caveat: in-memory detection windows are **per process**. If
two processes both observe the same guild (overlapping shards), each sees only
its own share of events until the next rehydration, so thresholds can take
longer to trip. Partition shards so one guild is handled by one process, or
keep a single instance.
