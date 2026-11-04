#!/usr/bin/env bash
#
# Container entrypoint.
#
# There is no separate deploy step under `docker compose up`, so migrations run
# here: wait for PostgreSQL, apply `alembic upgrade head`, then exec Shield.
# Running them before the bot starts (rather than from inside it) keeps schema
# changes out of the event loop and means a failed migration never leaves a
# half-configured bot connected to Discord.
#
# One knob, RUN_MIGRATIONS_ON_BOOT, controls this (default true in the
# container). Once this script has migrated, it hands the bot the same variable
# set to false so the work is not repeated inside the event loop.
#
set -euo pipefail

log() { printf '%s shield-entrypoint %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

: "${RUN_MIGRATIONS_ON_BOOT:=true}"
: "${DB_WAIT_MAX_SECONDS:=300}"

if [[ "${RUN_MIGRATIONS_ON_BOOT,,}" =~ ^(1|true|yes|on|y|t)$ ]]; then
  # Wait for the database to accept work. PostgreSQL is a separate container
  # with its own lifecycle, so "not up yet" is normal, not an error. The probe
  # reuses Shield's own config parsing, so it honours DATABASE_URL and the
  # discrete POSTGRES_* form identically and never prints credentials.
  log "waiting for PostgreSQL (up to ${DB_WAIT_MAX_SECONDS}s)"
  probe_status=0
  python - "$DB_WAIT_MAX_SECONDS" <<'PY' || probe_status=$?
import asyncio
import sys

from shield.config import ConfigError, load_config
from shield.db.session import Database

async def main() -> int:
    deadline = float(sys.argv[1])
    try:
        config = load_config()
    except ConfigError as error:
        # Print the operator-facing report, not a traceback: this is what someone
        # reads in `docker logs` when the container will not start.
        print(str(error), file=sys.stderr)
        return 78
    database = Database(config.database)
    delay, waited = 1.0, 0.0
    try:
        while True:
            ok, error = await database.ping(timeout=5.0)
            if ok:
                print(f"database reachable at {config.database.safe_url()}", flush=True)
                return 0
            if waited >= deadline:
                print(f"database still unreachable after {waited:.0f}s: {error}", file=sys.stderr)
                return 1
            print(f"database not ready ({error}); retrying in {delay:.0f}s", flush=True)
            await asyncio.sleep(delay)
            waited += delay
            delay = min(delay * 2, 15.0)
    finally:
        await database.dispose()

raise SystemExit(asyncio.run(main()))
PY

  if [[ "$probe_status" -eq 78 ]]; then
    # Configuration, not connectivity. The report is already above; repeating
    # "could not reach PostgreSQL" here would point at the wrong thing.
    log "configuration is invalid; not starting"
    exit 78
  elif [[ "$probe_status" -ne 0 ]]; then
    log "giving up waiting for PostgreSQL"
    exit 1
  fi

  log "applying database migrations"
  alembic upgrade head
  alembic current

  # Already done; do not repeat it inside the bot's event loop.
  export RUN_MIGRATIONS_ON_BOOT=false
else
  log "RUN_MIGRATIONS_ON_BOOT is not true; skipping migrations"
fi

log "starting: $*"
exec "$@"
