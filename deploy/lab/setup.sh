#!/usr/bin/env bash
# Orus Shield test lab: turns a fresh Ubuntu 24.04 server into a deliberately
# misconfigured target for the scanning modules (ports, TLS, later web headers).
#
# Run it ONLY on the lab server of orushield.xyz (never on a production host,
# never under the product domain):
#   scp deploy/lab/setup.sh root@<ip>:/root/ && ssh root@<ip> bash /root/setup.sh
#
# What it sets up, and what each part is for:
#   - nginx on 80 and 443: version shown in the Server header, no security
#     headers, self-signed certificate, TLS 1.0 and 1.1 accepted (TLS module).
#   - nginx on 8080 (fake admin page) and 8443 (self-signed HTTPS): alternate web
#     ports the ports module reports.
#   - lab-banners: a tiny service that listens on 3306 (MySQL) and 6379 (Redis),
#     sends a fixed banner and closes. Nothing real runs behind it, so nothing can
#     be exploited: the ports module sees an "exposed database" without the risk.
#   - SSH stays on 22, key-only (DigitalOcean default), so it is reported too.
#   - ufw: everything else is closed.
#
# Defects are configuration only. Never install a really vulnerable application
# here: an internet-facing server is probed by bots within hours.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

NAMES="orushield.xyz www.orushield.xyz lab.orushield.xyz"

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q nginx ufw openssl python3

echo "==> SSH: keys only"
# DigitalOcean droplets created with an SSH key already refuse passwords;
# make it explicit so the lab never accepts password guessing.
cat >/etc/ssh/sshd_config.d/60-lab.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl reload ssh

echo "==> self-signed certificate"
install -d -m 700 /etc/nginx/lab
if [[ ! -f /etc/nginx/lab/cert.pem ]]; then
  san=$(printf 'DNS:%s,' $NAMES)
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj "/CN=orushield.xyz" -addext "subjectAltName=${san%,}" \
    -keyout /etc/nginx/lab/key.pem -out /etc/nginx/lab/cert.pem 2>/dev/null
  chmod 600 /etc/nginx/lab/key.pem
fi

echo "==> web pages"
install -d /var/www/lab /var/www/lab-admin
cat >/var/www/lab/index.html <<'EOF'
<!doctype html><title>Orus Shield lab</title>
<p>Deliberately misconfigured test server of the Orus Shield project. Nothing to see here.</p>
EOF
cat >/var/www/lab-admin/index.html <<'EOF'
<!doctype html><title>Admin</title>
<p>Fake admin panel (static page) for the Orus Shield ports module tests.</p>
EOF

echo "==> nginx"
# server_tokens on: the Server header shows the nginx version (a finding for
# the future web module). No security headers on purpose.
cat >/etc/nginx/sites-available/lab <<'EOF'
server_tokens on;

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/lab;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    root /var/www/lab;

    ssl_certificate     /etc/nginx/lab/cert.pem;
    ssl_certificate_key /etc/nginx/lab/key.pem;
    # Obsolete versions on purpose. OpenSSL 3 refuses them at its default
    # security level, hence SECLEVEL=0.
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers   DEFAULT:@SECLEVEL=0;
}

server {
    listen 8080;
    listen [::]:8080;
    server_name _;
    root /var/www/lab-admin;
}

server {
    listen 8443 ssl;
    listen [::]:8443 ssl;
    server_name _;
    root /var/www/lab-admin;
    ssl_certificate     /etc/nginx/lab/cert.pem;
    ssl_certificate_key /etc/nginx/lab/key.pem;
}
EOF
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/lab /etc/nginx/sites-enabled/lab
nginx -t
systemctl restart nginx

echo "==> fake database banners"
cat >/usr/local/bin/lab-banners <<'EOF'
#!/usr/bin/env python3
"""Send a fixed banner on each port, then close. Reads nothing from clients."""
import socket
import threading

BANNERS = {
    3306: b"5.7.44-lab (fake MySQL banner, nothing behind it)\n",
    6379: b"-NOAUTH Authentication required. (fake Redis banner)\r\n",
}

def serve(port, banner):
    srv = socket.create_server(("", port), family=socket.AF_INET6, dualstack_ipv6=True)
    while True:
        conn, _ = srv.accept()
        try:
            conn.settimeout(2)
            conn.sendall(banner)
        except OSError:
            pass
        finally:
            conn.close()

threads = [threading.Thread(target=serve, args=pb, daemon=True) for pb in BANNERS.items()]
for t in threads:
    t.start()
for t in threads:
    t.join()
EOF
chmod 755 /usr/local/bin/lab-banners
cat >/etc/systemd/system/lab-banners.service <<'EOF'
[Unit]
Description=Orus Shield lab: fake service banners
After=network.target

[Service]
ExecStart=/usr/local/bin/lab-banners
DynamicUser=yes
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now lab-banners

echo "==> firewall"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
for port in 22 80 443 8080 8443 3306 6379; do
  ufw allow "${port}/tcp"
done
ufw --force enable

echo
echo "Lab ready. Open ports: 22 80 443 8080 8443 3306 6379"
ss -ltnp | awk 'NR==1 || /:(22|80|443|8080|8443|3306|6379) /'
