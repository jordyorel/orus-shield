#!/bin/sh
# Daily dump of the database, run as postgres by orus-backup.service
# (installed as /usr/local/libexec/orus/backup.sh). Keeps 14 days.
#
# This copy stays on the server: it protects against a bad migration or a
# mistaken delete, not against losing the server. Copy /var/backups/orus
# elsewhere too (README: "Backups").
#
# ORUS_MFA_KEY and ORUS_CREDENTIALS_KEY are not in the dump, on purpose:
# keep them in a password manager. Without them a restored database cannot
# open TOTP secrets or customers' test accounts.
set -eu
dir=/var/backups/orus
file="$dir/orus-$(date -u +%Y%m%dT%H%MZ).dump"
pg_dump --format=custom --dbname=orus --file="$file.part"
mv "$file.part" "$file"
find "$dir" -name 'orus-*.dump' -mtime +14 -delete
