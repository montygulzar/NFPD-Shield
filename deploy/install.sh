#!/usr/bin/env bash
#
# NFPD Shield installer for a Debian/Ubuntu VPS.
#
# Idempotent: safe to re-run for an upgrade. It does NOT write secrets - it
# creates the environment file with 0600 permissions and tells you which keys
# to fill in. No token or ID is ever echoed.
#
# Usage:
#   sudo ./deploy/install.sh                 # install or upgrade
#   sudo ./deploy/install.sh --migrate-only  # apply database migrations only
#
set -euo pipefail

APP_USER="${APP_USER:-nfpdshield}"
APP_DIR="${APP_DIR:-/opt/nfpd-shield}"
ENV_DIR="${ENV_DIR:-/etc/nfpd-shield}"
ENV_FILE="${ENV_FILE:-${ENV_DIR}/shield.env}"
SERVICE_NAME="nfpd-shield"
DB_NAME="${DB_NAME:-nfpd_shield}"
DB_USER="${DB_USER:-nfpd_shield}"
PYTHON="${PYTHON:-python3}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "run as root (sudo ./deploy/install.sh)"

MIGRATE_ONLY=0
[[ "${1:-}" == "--migrate-only" ]] && MIGRATE_ONLY=1

# ---------------------------------------------------------------------
# 1. Python version check (3.12+ required)
# ---------------------------------------------------------------------
log "checking Python"
command -v "${PYTHON}" >/dev/null || die "${PYTHON} not found"
"${PYTHON}" - <<'PY' || die "Python 3.12 or newer is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 12) else 1)
PY
log "using $("${PYTHON}" --version)"

if [[ ${MIGRATE_ONLY} -eq 0 ]]; then
  # -------------------------------------------------------------------
  # 2. System packages
  # -------------------------------------------------------------------
  log "installing system packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq \
    "${PYTHON}-venv" "${PYTHON}-dev" build-essential \
    postgresql postgresql-contrib libpq-dev ca-certificates

  # -------------------------------------------------------------------
  # 3. Service account (no login shell, no home directory writes)
  # -------------------------------------------------------------------
  if ! id -u "${APP_USER}" >/dev/null 2>&1; then
    log "creating system user ${APP_USER}"
    useradd --system --no-create-home --shell /usr/sbin/nologin "${APP_USER}"
  else
    log "user ${APP_USER} already exists"
  fi

  # -------------------------------------------------------------------
  # 4. Application directory
  # -------------------------------------------------------------------
  log "syncing application to ${APP_DIR}"
  install -d -m 0755 -o root -g root "${APP_DIR}"
  tar -C "${REPO_DIR}" \
      --exclude='.git' --exclude='.venv' --exclude='__pycache__' \
      --exclude='.pytest_cache' --exclude='.ruff_cache' --exclude='*.sqlite3' \
      -cf - . | tar -C "${APP_DIR}" -xf -
  chown -R root:root "${APP_DIR}"
  # The service user only needs to read the code.
  chmod -R go-w "${APP_DIR}"

  # -------------------------------------------------------------------
  # 5. Virtualenv
  # -------------------------------------------------------------------
  log "creating virtualenv"
  "${PYTHON}" -m venv "${APP_DIR}/.venv"
  "${APP_DIR}/.venv/bin/pip" install --quiet --upgrade pip wheel
  "${APP_DIR}/.venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"
  # psycopg2 is needed only by Alembic (its DDL path is synchronous).
  "${APP_DIR}/.venv/bin/pip" install --quiet "psycopg2-binary>=2.9"

  # -------------------------------------------------------------------
  # 6. PostgreSQL: database + least-privilege role
  # -------------------------------------------------------------------
  log "configuring PostgreSQL"
  systemctl enable --now postgresql

  if ! sudo -u postgres psql -tAc \
      "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1; then
    DB_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
    log "creating role ${DB_USER}"
    sudo -u postgres psql -v ON_ERROR_STOP=1 >/dev/null <<SQL
CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
SQL
    GENERATED_PASSWORD=1
  else
    log "role ${DB_USER} already exists (password left unchanged)"
    GENERATED_PASSWORD=0
  fi

  if ! sudo -u postgres psql -tAc \
      "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
    log "creating database ${DB_NAME}"
    sudo -u postgres createdb -O "${DB_USER}" "${DB_NAME}"
  else
    log "database ${DB_NAME} already exists"
  fi

  # Least privilege: the role owns its own schema and nothing else. It cannot
  # create databases or roles, and PUBLIC gets no rights on this database.
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d "${DB_NAME}" >/dev/null <<SQL
REVOKE ALL ON DATABASE ${DB_NAME} FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE ${DB_NAME} TO ${DB_USER};
GRANT ALL ON SCHEMA public TO ${DB_USER};
ALTER SCHEMA public OWNER TO ${DB_USER};
SQL

  # -------------------------------------------------------------------
  # 7. Environment file (0600, no secrets written by this script)
  # -------------------------------------------------------------------
  install -d -m 0750 -o root -g root "${ENV_DIR}"
  if [[ ! -f "${ENV_FILE}" ]]; then
    log "creating ${ENV_FILE} (mode 0600)"
    install -m 0600 -o root -g root /dev/null "${ENV_FILE}"
    cat > "${ENV_FILE}" <<ENVEOF
# NFPD Shield environment. systemd EnvironmentFile syntax:
# one KEY=VALUE per line, no export, no quotes, no \$VAR expansion,
# no inline comments. Keep this file at mode 0600.
DISCORD_TOKEN=CHANGE_ME
APPLICATION_ID=CHANGE_ME
OWNERID=CHANGE_ME
DATABASE_URL=postgresql+asyncpg://${DB_USER}:CHANGE_ME@127.0.0.1:5432/${DB_NAME}
ENABLE_MESSAGE_CONTENT=true
ENABLE_GUILD_MEMBERS=true
DEFAULT_MODE=alert_only
GLOBAL_DRY_RUN=false
LOG_LEVEL=INFO
LOG_FORMAT=json
SNAPSHOT_INTERVAL_MINUTES=360
SNAPSHOT_RETENTION=12
SNAPSHOT_ENCRYPTION_KEY=
INSTANCE_ID=shield-1
RUN_MIGRATIONS_ON_BOOT=false
ENVEOF
    chmod 0600 "${ENV_FILE}"
    if [[ "${GENERATED_PASSWORD:-0}" -eq 1 ]]; then
      warn "a database password was generated for ${DB_USER}."
      warn "Set it into DATABASE_URL now:"
      warn "  sudoedit ${ENV_FILE}"
      printf '%s\n' "${DB_PASSWORD}" > "${ENV_DIR}/.db-password"
      chmod 0600 "${ENV_DIR}/.db-password"
      warn "It is in ${ENV_DIR}/.db-password - copy it, then shred that file:"
      warn "  sudo shred -u ${ENV_DIR}/.db-password"
    fi
  else
    log "${ENV_FILE} already exists (left untouched)"
    chmod 0600 "${ENV_FILE}"
  fi
  chown root:root "${ENV_FILE}"
fi

# ---------------------------------------------------------------------
# 8. Migrations
# ---------------------------------------------------------------------
if grep -q 'CHANGE_ME' "${ENV_FILE}" 2>/dev/null; then
  warn "${ENV_FILE} still contains CHANGE_ME placeholders."
  warn "Fill them in, then run: sudo ${APP_DIR}/deploy/install.sh --migrate-only"
  warn "Skipping migrations and service start."
  exit 0
fi

log "applying database migrations"
set -a
# shellcheck disable=SC1090
. "${ENV_FILE}"
set +a
( cd "${APP_DIR}" && "${APP_DIR}/.venv/bin/alembic" upgrade head )

# ---------------------------------------------------------------------
# 9. systemd unit
# ---------------------------------------------------------------------
log "installing systemd unit"
install -m 0644 -o root -g root "${APP_DIR}/deploy/${SERVICE_NAME}.service" \
  "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

sleep 3
if systemctl is-active --quiet "${SERVICE_NAME}"; then
  log "${SERVICE_NAME} is running"
else
  warn "${SERVICE_NAME} is not running. Inspect it with:"
  warn "  journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
  exit 1
fi

cat <<'NEXT'

Installed. Next steps, in order:

  1. Invite the bot with only the permissions it needs (see README.md).
  2. In the guild:  /shield logs set   -> choose an incident log channel
  3.                /shield health     -> verify intents, permissions, hierarchy
  4.                /shield enable mode:alert_only
  5. Watch for several days, tune with /shield thresholds set.
  6. Only once validated: /shield enable mode:enforce dry_run:false

Operations:
  systemctl status nfpd-shield
  journalctl -u nfpd-shield -f
  journalctl -u nfpd-shield -p warning --since '1 hour ago'
NEXT
