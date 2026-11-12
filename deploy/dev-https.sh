#!/bin/sh
# Local HTTPS for the dashboard (development only).
#
# Safari refuses the session cookie (Secure) on http://localhost; the other
# browsers accept it. This script makes a certificate for localhost signed
# by a local authority that mkcert adds to the system trust store, so
# https://localhost:5173 opens without a warning. Vite picks it up from
# web/.certs (git-ignored) at its next start.
#
# Requirements: mkcert (macOS: brew install mkcert). The first run of
# "mkcert -install" asks for your password: it adds the local authority to
# the keychain. Its private key never leaves this machine; never share
# the folder printed by "mkcert -CAROOT".
set -eu

command -v mkcert >/dev/null 2>&1 || { echo "mkcert is missing: brew install mkcert" >&2; exit 1; }

root=$(cd "$(dirname "$0")/.." && pwd)
dir="$root/web/.certs"
mkdir -p "$dir"
mkcert -install
mkcert -cert-file "$dir/localhost.pem" -key-file "$dir/localhost-key.pem" localhost 127.0.0.1 ::1
chmod 600 "$dir/localhost-key.pem"
echo "Done. Restart the dashboard (npm run dev): https://localhost:5173"
