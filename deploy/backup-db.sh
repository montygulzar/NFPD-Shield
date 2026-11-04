#!/usr/bin/env bash
#
# Encrypted, rotated PostgreSQL backup for NFPD Shield.
# Install as a daily timer or cron job:
#   0 4 * * * /opt/nfpd-shield/deploy/backup-db.sh
#
# Snapshots contain guild structure, so treat backups as sensitive: 0600,
# root-owned, and encrypted if they leave the host.
set -euo pipefail

ENV_FILE="${ENV_FILE:-/etc/nfpd-shield/shield.env}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/nfpd-shield}"
KEEP_DAYS="${KEEP_DAYS:-14}"
DB_NAME="${DB_NAME:-nfpd_shield}"

[[ ${EUID} -eq 0 ]] || { echo "run as root" >&2; exit 1; }
install -d -m 0700 "${BACKUP_DIR}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${BACKUP_DIR}/${DB_NAME}-${STAMP}.sql.gz"
sudo -u postgres pg_dump --no-owner --no-privileges "${DB_NAME}" | gzip -9 > "${OUT}"
chmod 0600 "${OUT}"

# Optional at-rest encryption when a recipient key is configured.
if [[ -n "${GPG_RECIPIENT:-}" ]]; then
  gpg --batch --yes --encrypt --recipient "${GPG_RECIPIENT}" "${OUT}"
  shred -u "${OUT}"
  OUT="${OUT}.gpg"
  chmod 0600 "${OUT}"
fi

find "${BACKUP_DIR}" -type f -mtime "+${KEEP_DAYS}" -print -delete
echo "backup written: ${OUT}"
