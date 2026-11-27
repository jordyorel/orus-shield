#!/usr/bin/env bash
# Deploys Orus Shield from your machine to the production server, over SSH.
#
#   deploy/prod/deploy.sh setup   HOST DOMAIN   # prepare the server (setup.sh)
#   deploy/prod/deploy.sh release HOST          # build, copy, switch, restart
#
# HOST is an SSH destination with root, such as root@203.0.113.10. Needs Go,
# npm, git and ssh locally; nothing is built on the server.
#
# release builds the committed code only (a dirty tree is refused: what
# runs in production must be in git), for the server's architecture, then
# copies it to /opt/orus/releases/<date>-<commit> and runs activate.sh
# there. Rolling back: deploy.sh rollback HOST VERSION switches to an older
# release still on the server (the last five are kept); it does not undo
# migrations, which only ever add.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
# macOS tar would add AppleDouble (._*) files for extended attributes.
export COPYFILE_DISABLE=1
usage() {
  sed -n '4,5p' "$0" | sed 's/^# //' >&2
  echo "  deploy/prod/deploy.sh rollback HOST VERSION" >&2
  exit 2
}
[[ $# -ge 2 ]] || usage
cmd=$1 host=$2
# Values put into the remote command line: checked here, so the remote
# shell can only ever see plain names.
safe() { # value pattern what
  [[ $1 =~ $2 ]] || { echo "bad $3: $1" >&2; exit 2; }
}

case $cmd in
setup)
  domain=${3:-}
  [[ -n $domain ]] || usage
  safe "$domain" '^[a-z0-9.-]+$' domain
  echo "==> copying deploy/ to $host:/opt/orus/deploy"
  tar --no-xattrs -C "$root" -czf - deploy | ssh "$host" \
    'rm -rf /opt/orus/deploy && mkdir -p /opt/orus && tar -xzf - -C /opt/orus'
  ssh -t "$host" "ORUS_DOMAIN='$domain' bash /opt/orus/deploy/prod/setup.sh"
  ;;

release)
  cd "$root"
  if [[ -n $(git status --porcelain) ]]; then
    echo "uncommitted changes: commit them first (production runs what is in git)" >&2
    exit 1
  fi
  case $(ssh "$host" uname -m) in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *) echo "unsupported server architecture" >&2; exit 1 ;;
  esac
  version="$(date -u +%Y%m%d%H%M%S)-$(git rev-parse --short=10 HEAD)"
  out=$(mktemp -d)
  trap 'rm -rf "$out"' EXIT

  echo "==> building $version (linux/$arch)"
  (cd engine && CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
    go build -trimpath -ldflags '-s -w' -o "$out/bin/" ./cmd/api ./cmd/worker ./cmd/orusctl)
  (cd web && npm ci --no-audit --no-fund && npm run build)
  cp -R web/dist "$out/web"

  echo "==> copying to $host:/opt/orus/releases/$version"
  # shellcheck disable=SC2029 # expanded here on purpose: a generated name
  tar --no-xattrs -C "$out" -czf - bin web | ssh "$host" \
    "mkdir -p /opt/orus/releases/$version && tar -xzf - -C /opt/orus/releases/$version"
  # shellcheck disable=SC2029 # as above
  ssh "$host" /usr/local/libexec/orus/activate.sh "$version"
  echo "==> $version is live"
  ;;

rollback)
  version=${3:-}
  [[ -n $version ]] || { ssh "$host" 'ls -1t /opt/orus/releases'; usage; }
  safe "$version" '^[0-9A-Za-z._-]+$' version
  # shellcheck disable=SC2029 # checked just above
  ssh "$host" /usr/local/libexec/orus/activate.sh "$version"
  ;;

*)
  usage
  ;;
esac
