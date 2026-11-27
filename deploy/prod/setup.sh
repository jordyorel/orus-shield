#!/usr/bin/env bash
# Prepares a fresh Ubuntu 24.04 server for Orus Shield: one machine for the
# site, the API, the worker, PostgreSQL, Unbound and the scanners (README.md
# explains the layout and each choice).
#
# Run from your machine, not by hand: deploy/prod/deploy.sh setup HOST DOMAIN
# copies deploy/ to the server and runs this as root with ORUS_DOMAIN set.
# It is idempotent: run it again after changing a file of deploy/prod, or to
# install newer pinned scanners. It never overwrites /etc/orus/*.env.
#
# It does not start the API or the worker: the first deploy.sh release does,
# once their binaries exist.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi
: "${ORUS_DOMAIN:?set ORUS_DOMAIN to the product domain, such as orus-shield.com}"
if [[ ! $ORUS_DOMAIN =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
  echo "ORUS_DOMAIN=$ORUS_DOMAIN: want a lowercase domain name" >&2
  exit 1
fi
# The lab domain is deliberately misconfigured (CLAUDE.md): never production.
if [[ $ORUS_DOMAIN == orushield.xyz || $ORUS_DOMAIN == *.orushield.xyz ]]; then
  echo "orushield.xyz is the test lab's domain, not the product's" >&2
  exit 1
fi
. /etc/os-release
if [[ $ID != ubuntu || $VERSION_ID != 24.04 ]]; then
  echo "written for Ubuntu 24.04, found $PRETTY_NAME" >&2
  exit 1
fi

here=$(cd "$(dirname "$0")" && pwd)   # deploy/prod
deploy=$(dirname "$here")             # deploy
export DEBIAN_FRONTEND=noninteractive

step() { echo; echo "==> $*"; }

step "SSH: keys only"
# Refuse to lock ourselves out: a key must already be installed.
if [[ ! -s /root/.ssh/authorized_keys ]]; then
  echo "/root/.ssh/authorized_keys is empty: add your SSH key before disabling passwords" >&2
  exit 1
fi
cat >/etc/ssh/sshd_config.d/60-orus.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
sshd -t
systemctl reload ssh

step "packages"
apt-get update -q
apt-get install -y -q ca-certificates curl gnupg unzip rsync nftables unbound bind9-dnsutils \
  docker.io postgresql-common unattended-upgrades
# PostgreSQL 18 (the schema uses its built-in uuidv7()); Ubuntu 24.04 ships 16.
# The PostgreSQL project's own repository, set up by its own script.
if [[ ! -f /etc/apt/sources.list.d/pgdg.list && ! -f /etc/apt/sources.list.d/pgdg.sources ]]; then
  /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
fi
# Caddy from its official repository (Ubuntu's package is years old).
if [[ ! -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg ]]; then
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key |
    gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    >/etc/apt/sources.list.d/caddy-stable.list
fi
apt-get update -q
apt-get install -y -q postgresql-18 caddy
# Security updates install themselves (Ubuntu's default, made explicit).
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

step "swap (2 GB)"
# ZAP may take 3 GB; swap keeps a peak from killing PostgreSQL.
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi

step "users and directories"
# orus-scan: the scanners' group, confined by the firewall.
getent group orus-scan >/dev/null || groupadd --system orus-scan
# orus: the worker (and orusctl). In the docker group for ZAP.
id orus >/dev/null 2>&1 || useradd --system --home-dir /var/lib/orus --shell /usr/sbin/nologin orus
usermod -aG docker orus
# orus-api: the API, a separate user outside the docker group.
id orus-api >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin orus-api
install -d -m 0755 /opt/orus /opt/orus/releases
install -d -m 0750 -o orus -g orus /var/lib/orus
# ZAP's runs: the module makes each run's directory writable by the
# container's user (uid 1000); docker mounts it, so it cannot live in the
# worker's private /tmp.
install -d -m 0711 -o orus -g orus /var/lib/orus/zap
install -d -m 0700 /etc/orus
install -d -m 0700 -o postgres -g postgres /var/backups/orus
install -d -m 0755 /usr/local/libexec/orus
scan_gid=$(getent group orus-scan | cut -d: -f3)

step "PostgreSQL"
systemctl enable --now postgresql
sudo -u postgres psql -q -v ON_ERROR_STOP=1 -f "$here/postgres-roles.sql"
# Peer authentication: the OS users orus and orus-api connect, over the
# Unix socket only, as the roles orus and orus_api. No password exists.
pgconf=/etc/postgresql/18/main
if ! grep -q '^orus ' "$pgconf/pg_ident.conf"; then
  cat >>"$pgconf/pg_ident.conf" <<'EOF'
orus  orus      orus
orus  orus-api  orus_api
EOF
fi
if ! grep -q 'map=orus' "$pgconf/pg_hba.conf"; then
  # First line wins: before Ubuntu's "local all all peer".
  sed -i '0,/^local/s//local   orus            orus,orus_api                           peer map=orus\n&/' "$pgconf/pg_hba.conf"
fi
systemctl reload postgresql
sudo -u orus psql -q "dbname=orus user=orus" -c 'SELECT 1' >/dev/null
sudo -u orus-api psql -q "dbname=orus user=orus_api" -c 'SELECT 1' >/dev/null

step "Unbound (127.0.0.1:5335)"
install -m 0644 "$here/unbound.conf" /etc/unbound/unbound.conf.d/orus.conf
unbound-checkconf >/dev/null
systemctl enable unbound
systemctl restart unbound
for _ in $(seq 1 10); do
  dig +short +time=2 @127.0.0.1 -p 5335 example.com A >/dev/null && break
  sleep 1
done
dig +short +time=2 @127.0.0.1 -p 5335 example.com A | grep -q . || { echo "Unbound does not answer" >&2; exit 1; }

step "firewall"
install -m 0600 "$here/firewall.nft" /etc/orus/firewall.nft
nft -c -f /etc/orus/firewall.nft
install -m 0644 "$here/systemd/orus-firewall.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable orus-firewall
systemctl restart orus-firewall

step "scanners"
# Nuclei and its templates, pinned and checksummed by deploy/nuclei. The
# binary is setgid orus-scan: whoever runs it, its connections carry that
# group, which the firewall allows to reach gateproxy and nothing else.
# Installed again only when deploy/nuclei/install.sh (its versions and
# hashes) changed: the download is large.
pin=$(sha256sum "$deploy/nuclei/install.sh" | cut -d' ' -f1)
if [[ $(cat /opt/orus/nuclei/.pin 2>/dev/null) != "$pin" ]]; then
  sh "$deploy/nuclei/install.sh" /opt/orus/nuclei >/dev/null
  echo "$pin" >/opt/orus/nuclei/.pin
fi
chown root:orus-scan /opt/orus/nuclei/nuclei
chmod 2755 /opt/orus/nuclei/nuclei
# ZAP's image, pinned by digest in deploy/zap/install.sh (read from there,
# so there is one place to update).
eval "$(grep -E '^(TAG|DIGEST)=' "$deploy/zap/install.sh")"
zap_image="zaproxy/zap-stable:${TAG}@${DIGEST}"
systemctl enable --now docker
docker pull -q "$zap_image" >/dev/null

step "configuration (/etc/orus)"
# Created once, never overwritten: they hold the generated keys and what
# you filled in by hand.
render() { # template destination
  if [[ -f $2 ]]; then
    echo "kept $2"
    return
  fi
  sed -e "s|@DOMAIN@|$ORUS_DOMAIN|g" \
    -e "s|@MFA_KEY@|$(openssl rand -base64 32)|" \
    -e "s|@CREDENTIALS_KEY@|$(openssl rand -base64 32)|" \
    -e "s|@SCAN_GID@|$scan_gid|" \
    -e "s|@ZAP_IMAGE@|$zap_image|" "$1" >"$2.new"
  chmod 0600 "$2.new"
  mv "$2.new" "$2"
  echo "created $2"
}
render "$here/env/shared.env" /etc/orus/shared.env
render "$here/env/api.env" /etc/orus/api.env
render "$here/env/worker.env" /etc/orus/worker.env
# A newer ZAP pin replaces the old one in an existing worker.env; the
# proxies' ports must match the firewall's.
sed -i "s|^ORUS_ZAP_IMAGE=.*|ORUS_ZAP_IMAGE=$zap_image|" /etc/orus/worker.env
if grep -q '^ORUS_GATEPROXY_PORTS=' /etc/orus/worker.env; then
  sed -i 's|^ORUS_GATEPROXY_PORTS=.*|ORUS_GATEPROXY_PORTS=61000-61999|' /etc/orus/worker.env
else
  echo 'ORUS_GATEPROXY_PORTS=61000-61999' >>/etc/orus/worker.env
fi

step "services"
install -m 0644 "$here/systemd/orus-api.service" "$here/systemd/orus-worker.service" \
  "$here/systemd/orus-backup.service" "$here/systemd/orus-backup.timer" /etc/systemd/system/
install -m 0755 "$here/backup.sh" /usr/local/libexec/orus/backup.sh
install -m 0755 "$here/activate.sh" /usr/local/libexec/orus/activate.sh
install -m 0755 "$here/orusctl" /usr/local/bin/orusctl
systemctl daemon-reload
systemctl enable orus-api orus-worker orus-backup.timer
systemctl start orus-backup.timer

step "Caddy"
# deploy/web/Caddyfile holds the site's security headers (CSP, HSTS...):
# it is used as is, with the domain, the API's port and the release's path.
{
  sed -e "s|app\.example\.com|$ORUS_DOMAIN|" \
    -e "s|127\.0\.0\.1:8080|127.0.0.1:8180|" \
    -e "s|/srv/orus/web/dist|/opt/orus/current/web|" "$deploy/web/Caddyfile"
  cat <<EOF

# www. leads to the site.
www.$ORUS_DOMAIN {
	redir https://$ORUS_DOMAIN{uri} permanent
}
EOF
} >/etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
systemctl enable caddy
systemctl reload caddy || systemctl restart caddy

echo
echo "Done. Next:"
echo "  1. Copy ORUS_MFA_KEY (/etc/orus/api.env) and ORUS_CREDENTIALS_KEY (/etc/orus/shared.env)"
echo "     into your password manager."
echo "  2. Fill in SMTP, Paddle and Microsoft values in /etc/orus/*.env."
echo "  3. Point $ORUS_DOMAIN and www.$ORUS_DOMAIN (A and AAAA) at this server."
echo "  4. From your machine: deploy/prod/deploy.sh release HOST"
