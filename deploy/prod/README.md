# Production server

One Ubuntu 24.04 server runs everything: the site, the API, the worker,
PostgreSQL, Unbound and the scanners. That is enough for the first customers
(about 20 $/month at Hetzner, 8 GB of RAM: CX32 or CAX21). Workers are
stateless, so a second machine for scans can come later without code changes.

```
            internet
               |  22 (SSH, keys only), 80/443 (Caddy)
   +-----------+---------------------------------------------------+
   |  Caddy  -- TLS, security headers, static site (web/dist)      |
   |    | /api/*                                                   |
   |  api (user orus-api)  127.0.0.1:8180                          |
   |    |                                                          |
   |  PostgreSQL 18  Unix socket, peer auth, no password           |
   |    |                                                          |
   |  worker (user orus)  -- Unbound 127.0.0.1:5335                |
   |    +-- gateproxy 127.0.0.1:61000-61999 (one per scan)         |
   |          ^                                                    |
   |    Nuclei (setgid orus-scan), ZAP container (gid orus-scan)   |
   |    firewall: group orus-scan may reach 61000-61999, nothing   |
   |    else                                                       |
   +---------------------------------------------------------------+
```

## Files

| File | Installed as | Role |
|---|---|---|
| `deploy.sh` | (your machine) | `setup`, `release`, `rollback` over SSH |
| `setup.sh` | | prepares the server, idempotent |
| `activate.sh` | `/usr/local/libexec/orus/activate.sh` | switches to a release, restarts in order |
| `postgres-roles.sql` | | login and NOLOGIN roles, the database |
| `firewall.nft` | `/etc/orus/firewall.nft` | incoming filter, scanners' sandbox |
| `unbound.conf` | `/etc/unbound/unbound.conf.d/orus.conf` | our own resolver |
| `env/*.env` | `/etc/orus/*.env` (0600, created once) | configuration and keys |
| `systemd/*` | `/etc/systemd/system/` | services, firewall, daily backup |
| `backup.sh` | `/usr/local/libexec/orus/backup.sh` | `pg_dump`, 14 days kept |
| `orusctl` | `/usr/local/bin/orusctl` | orusctl as the worker's user |
| `../web/Caddyfile` | `/etc/caddy/Caddyfile` | used as is, with the domain filled in |

## Launch, step by step

1. **Domain.** Buy the product domain (never `orushield.xyz`, the lab).
2. **Server.** Create an Ubuntu 24.04 server with your SSH key. Name it after
   the domain, so its reverse DNS (PTR) is under it.
3. **Prepare it**, from the repository on your machine:
   ```
   deploy/prod/deploy.sh setup root@SERVER_IP example.com
   ```
   This installs PostgreSQL 18, Caddy, Unbound, Docker, the pinned Nuclei and
   ZAP, the firewall and the services, and writes `/etc/orus/*.env` with fresh
   `ORUS_MFA_KEY` and `ORUS_CREDENTIALS_KEY`.
4. **Save the two keys** in a password manager, never next to the backups.
   Without `ORUS_MFA_KEY` every two-factor enrolment is lost; without
   `ORUS_CREDENTIALS_KEY`, every stored test account and webhook secret.
5. **DNS.** A and AAAA records of `example.com` and `www.example.com` to the
   server. Caddy gets the certificates by itself once they resolve.
6. **Email.** An SMTP relay (Brevo, Mailjet...) on the domain: its SPF and DKIM
   records, a DMARC policy, then `ORUS_SMTP_*` in `/etc/orus/shared.env`.
   Port 587: Hetzner blocks 25 and 465 on new accounts.
7. **First release**, with the code committed:
   ```
   deploy/prod/deploy.sh release root@SERVER_IP
   ```
8. **First admin**, on the server:
   ```
   orusctl user add -role admin you@example.com
   ```
   then set the password on `https://example.com/setup-password` and enrol MFA.
9. **Paddle production.** Once Paddle has approved the site: the prices, API
   key, client token and webhook (`https://example.com/api/v1/billing/paddle`,
   events `subscription.*`) in `/etc/orus/api.env`, then
   `systemctl restart orus-api`. One real payment, refunded, checks it all.
10. **Signup.** `ORUS_SIGNUP=closed` (invitation only) until the legal pages
    are complete; remove the line and restart the API to open it.
11. **Monitoring.** A free uptime check (UptimeRobot, Better Stack) on
    `https://example.com/api/v1/plans`.

Microsoft 365 needs `ORUS_M365_*` in `shared.env` and
`https://example.com/api/v1/identities/m365/callback` as the app's redirect URI.

## Everyday

| Task | Command |
|---|---|
| deploy | `deploy/prod/deploy.sh release root@SERVER_IP` |
| roll back | `deploy/prod/deploy.sh rollback root@SERVER_IP` (lists), then with a version |
| logs | `journalctl -u orus-api -f`, `journalctl -u orus-worker -f` |
| change a setting | edit `/etc/orus/*.env`, `systemctl restart orus-api orus-worker` |
| change deploy/prod | commit, then `deploy.sh setup` again (keeps the env files) |
| newer Nuclei or ZAP | update the pins in `deploy/nuclei` or `deploy/zap`, `deploy.sh setup` |
| a backup now | `systemctl start orus-backup` |

A release is built on your machine from committed code only, for the
server's architecture, and lives in `/opt/orus/releases/<date>-<commit>`
(the five newest are kept); `/opt/orus/current` points to the running one.
`activate.sh` restarts the worker first: it applies the migrations (one
transaction, all or none) before it logs "worker started". If it does not
start, nothing was migrated and the previous release comes back. Then the API,
which cannot change the schema, only check it is up to date. A rollback does
not undo migrations; they only ever add.

## Choices, and why

**PostgreSQL roles** (`postgres-roles.sql`). Two login roles, named after the
system users and authenticated by the kernel (peer, Unix socket only): no
database password exists. `orus` owns the schema and has `BYPASSRLS` (the worker
handles every organization); it is not a superuser. `orus_api` owns nothing and
has no privilege of its own: each API transaction switches to `orus_app`,
`orus_auth`, `orus_billing`, `orus_public` or `orus_agent`, so a query that
forgot to switch fails rather than seeing every customer. Since the schema owner
cannot create roles, the NOLOGIN roles are created ahead; a migration adding a
role must add it to the file too (`TestProdRolesListEveryRole` checks it).

**Two system users.** The worker is in the `docker` group to run ZAP, which is
equivalent to root on this host. The API, which faces the internet, runs as
another user outside that group, and both units are hardened (read-only
system, no capabilities, private `/tmp`).

**The scanners' sandbox** (security rules 1 to 3, `firewall.nft`). Nuclei and
ZAP are told to use the scan's gateproxy, which applies the gate to every
request; the firewall makes sure they cannot do otherwise. Both run with the
group `orus-scan`: Nuclei because its binary is setgid `orus-scan`, ZAP because
its container runs as `1000:<gid of orus-scan>` (`ORUS_ZAP_USER`). The
firewall lets that group reach 127.0.0.1 on 61000-61999 only, the ports
gateproxy listens on (`ORUS_GATEPROXY_PORTS`). The range sits above the kernel's
ephemeral ports (32768-60999), so no other local service lands there by chance.
Everything else, DNS included, is refused.
Checked on a test server (2026-11-27): under the worker's unit, the real Nuclei
and ZAP pass their integration tests, the firewall refused 20 and 1,098 packets
they tried to send elsewhere, and a probe with that group reaches neither
PostgreSQL nor the internet.
The price: the worker's unit cannot set `NoNewPrivileges` (it would ignore the
setgid). A compromised Nuclei process could switch back to the worker's group
(its real gid); Nuclei runs HTTP templates only, no code templates. ZAP's
container cannot: it holds no capability.

**Our own resolver.** Unbound resolves from the root servers and validates
DNSSEC; negative answers are kept one minute at most. A network's resolver
once kept a stale NXDOMAIN for over an hour and made per-IP ownership refuse a
valid address.

**Ports.** The API listens on 8180, not 8080, which is ZAP's default and ZAP
shares the host's network. Only 22, 80 and 443 are open from outside.

## Backups

`orus-backup.timer` dumps the database every night to `/var/backups/orus`
(14 days). That copy protects against a bad migration or a mistaken delete,
not against losing the server: also copy the folder off the machine (Hetzner
Storage Box with `rsync`, or the provider's server backups, about 20 % of the
server's price). Test a restore once:
`pg_restore --create --dbname=postgres <dump>` on another machine.

## Not covered yet

- Off-site backup copies (above): to set up with the storage chosen.
- Alerts when the worker stops (the uptime check only sees the API).
- A second machine for scans, when they load the API.
