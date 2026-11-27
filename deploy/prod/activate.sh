#!/usr/bin/env bash
# Switches the server to a release that deploy.sh copied to
# /opt/orus/releases/VERSION, then restarts the services in order:
#
#   1. the worker, which applies pending migrations (one transaction: all or
#      none) and only then logs "worker started";
#   2. the API, which only checks that the schema is up to date (its role
#      cannot change it).
#
# If the worker does not start, nothing was migrated: the previous release
# is put back. Installed as /usr/local/libexec/orus/activate.sh by setup.sh.
set -euo pipefail

version=${1:?usage: activate.sh VERSION}
[[ $version =~ ^[0-9A-Za-z._-]+$ ]] || { echo "bad version $version" >&2; exit 1; }
rel=/opt/orus/releases/$version
for f in bin/api bin/worker bin/orusctl web/index.html; do
  [[ -f $rel/$f ]] || { echo "$rel/$f is missing" >&2; exit 1; }
done
chown -R root:root "$rel"
chmod -R u=rwX,go=rX "$rel"

switch() { # target
  ln -sfn "$1" /opt/orus/current.new
  mv -T /opt/orus/current.new /opt/orus/current
}
previous=$(readlink /opt/orus/current || true)
switch "$rel"
echo "current -> $rel"

since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart orus-worker
started=
for _ in $(seq 1 90); do
  if journalctl -u orus-worker --since "$since" -o cat | grep -q '"msg":"worker started"'; then
    started=1
    break
  fi
  sleep 1
done
if [[ -z $started ]]; then
  echo "the worker did not start; its log:" >&2
  journalctl -u orus-worker --since "$since" -o cat | tail -20 >&2
  if [[ -n $previous ]]; then
    switch "$previous"
    systemctl restart orus-worker
    echo "back to $previous" >&2
  fi
  exit 1
fi
echo "worker started (migrations applied)"

# The API checks the schema version at start: it may read that table only.
sudo -u postgres psql -q -d orus -c 'GRANT SELECT ON schema_migrations TO orus_api'

since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart orus-api
for _ in $(seq 1 30); do
  if curl -fs -o /dev/null http://127.0.0.1:8180/api/v1/plans; then
    echo "api answers"
    # Keep the five newest releases, and always the current one (after a
    # rollback it is an older one).
    # (grep finds nothing to remove most of the time: not an error.)
    # shellcheck disable=SC2012 # our own release names: [0-9A-Za-z._-]
    ls -1dt /opt/orus/releases/*/ | tail -n +6 | { grep -vxF "$rel/" || true; } | xargs -r rm -rf
    exit 0
  fi
  sleep 1
done
echo "the API does not answer; its log:" >&2
journalctl -u orus-api --since "$since" -o cat | tail -20 >&2
exit 1
