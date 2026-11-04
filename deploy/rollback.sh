#!/usr/bin/env bash
#
# Roll NFPD Shield back to a previous release.
#
#   sudo ./deploy/rollback.sh <git-ref> [alembic-revision]
#
# Code is rolled back first, then (optionally) the schema. Always roll the
# schema back to the revision that the target code expects - never to an older
# revision than the data requires.
#
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/nfpd-shield}"
ENV_FILE="${ENV_FILE:-/etc/nfpd-shield/shield.env}"
SERVICE_NAME="nfpd-shield"
SRC_DIR="${SRC_DIR:-/opt/nfpd-shield-src}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "run as root"
TARGET_REF="${1:-}"
[[ -n "${TARGET_REF}" ]] || die "usage: $0 <git-ref> [alembic-revision]"
TARGET_REVISION="${2:-}"

log "stopping ${SERVICE_NAME}"
systemctl stop "${SERVICE_NAME}" || true

set -a
# shellcheck disable=SC1090
. "${ENV_FILE}"
set +a

log "backing up the database before any change"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="/var/backups/nfpd-shield-${STAMP}.sql.gz"
install -d -m 0700 /var/backups
sudo -u postgres pg_dump "${DB_NAME:-nfpd_shield}" | gzip > "${BACKUP}"
chmod 0600 "${BACKUP}"
log "database backed up to ${BACKUP}"

if [[ -d "${SRC_DIR}/.git" ]]; then
  log "checking out ${TARGET_REF}"
  git -C "${SRC_DIR}" fetch --all --tags --quiet
  git -C "${SRC_DIR}" checkout --quiet "${TARGET_REF}"
  tar -C "${SRC_DIR}" --exclude='.git' --exclude='.venv' -cf - . \
    | tar -C "${APP_DIR}" -xf -
  "${APP_DIR}/.venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"
else
  die "${SRC_DIR} is not a git checkout; clone the repository there first"
fi

if [[ -n "${TARGET_REVISION}" ]]; then
  log "downgrading the schema to ${TARGET_REVISION}"
  ( cd "${APP_DIR}" && "${APP_DIR}/.venv/bin/alembic" downgrade "${TARGET_REVISION}" )
else
  log "no alembic revision given; leaving the schema as it is"
  ( cd "${APP_DIR}" && "${APP_DIR}/.venv/bin/alembic" current )
fi

log "starting ${SERVICE_NAME}"
systemctl start "${SERVICE_NAME}"
sleep 3
systemctl is-active --quiet "${SERVICE_NAME}" \
  && log "rollback complete" \
  || die "service did not start: journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
