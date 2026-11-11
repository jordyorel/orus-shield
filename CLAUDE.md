# Orus Shield

Continuous security audit platform for small and mid-sized businesses. It discovers what a
company exposes on the internet, checks it, scores it, and turns each finding into a
prioritized, plain-language action plan. The market is international, with particular
attention to French-speaking Africa (local payment methods, French-first reports).

Status: roadmap steps 1 to 6 are done (finding schema, Module interface, gated DNS
resolver and dialer, email and TLS modules, PostgreSQL storage and queue, gate, worker,
orusctl, ownership verification, per-IP ownership and the ports module, tested for real on
the lab server on 2026-11-11). The passive `web` module (HTTPS redirect, security headers,
cookies, disclosed versions) is done too. Step 7 follows the order in
`docs/ui-adaptation.md`: organizations (multi-tenant scoping, `store.Org` + PostgreSQL
row-level security), the findings lifecycle (`fixed_at`, `finding_events` history) and the
asset inventory (`module.Result` with findings and assets, `assets` table) and the check
catalog with evaluated checks and posture score (`check_status`, `posture_snapshots`,
package `posture`) and CDN / WAF detection (passive `cdn` module, asset details) are done;
framework mappings (CIS Controls v8) wait for Jordy's review. The HTTP API with
invitation-only accounts, sessions and the screen 1 to 3 endpoints is done
(`engine/cmd/api`, `engine/internal/api`), with TOTP two-factor authentication, mandatory
for admins (packages `totp` and `seal`); the authentication flows live in package
`account`. `GET /orgs/{org}/overview` computes everything the overview screen shows
(score pooled across domains with `posture.Series`, daily trend, remediation time against
the previous period, new assets, rule-based priorities); `GET /orgs/{org}/findings` lists
every target's findings. The dashboard is a React + TypeScript app in `web/` that consumes
the API (an earlier server-rendered Go version was dropped on 2026-11-10 in favor of
React): sign-in, MFA, password setup, the overview, vulnerabilities, assets (add a domain, DNS
TXT verification, first scan), scans (modules, launch, per-domain rate and exclusions
through `PATCH /targets/{id}`, live history) and settings (profile: password change, MFA;
team: invite with a one-time setup code, roles, removal, at least one admin kept; migration
0009 lets the auth role do exactly that), attack surface, posture, prioritization and
governance (from `/orgs/{org}/assets`, `/checks`, `/trends`) screens are done: every menu
entry works, data without a source is shown as "Bientôt"; scheduling does not exist yet,
the other menu entries show "Bientôt disponible". Finding texts stay in the modules'
English (decided 2026-11-10); the dashboard's own wording is French.

## How to work on this repo

- The maintainer (Jordy) writes in French. Reply to him in French; write code, comments,
  commit messages and docs in English.
- Jordy is building this partly to master Go and security engineering. Explain non-obvious
  decisions, and prefer clear code over clever code.
- Work one module at a time: agree on the design, write the tests, implement, then stop for
  review. Small, focused commits.
- Never add a dependency without saying why the standard library is not enough.

## Architecture

```
web (dashboard)  ->  api  ->  queue  ->  engine workers  ->  modules  ->  findings (JSON)
                      |                                                     |
                      +------------------- database  <----------------------+
                                              |
                                        ai layer (explains, prioritizes)
```

- **engine/** (Go): stateless workers. They pull scan jobs from a queue, run the enabled
  modules against a target, and write findings to the database. Scaling means adding
  workers, never changing code. Workers keep nothing in memory between jobs.
- **modules**: each check (email, TLS, ports, web headers, leaks, ...) is an independent
  package implementing one shared interface. Adding a check means adding a module, never
  editing the engine.
- **findings**: one standard, versioned JSON schema shared by every module. The dashboard,
  reports, alerts and AI layer depend only on this schema, never on module internals.
- **api/**: HTTP API for the dashboard and customers (Go).
- **web/**: customer dashboard, React + TypeScript built with Vite. It talks only to the
  JSON API, on the same origin (Vite proxies `/api` in development). Screens reproduce the
  mockups in `docs/design/`; data that does not exist yet is shown as "Bientôt disponible",
  never as invented figures. Strict CSP: no inline script.
- **ai layer**: reads findings, explains them, ranks them for the customer's context and
  suggests fixes. It never creates or removes findings.

Planned layout (create folders only when they are needed):

```
engine/
  cmd/worker/        worker entrypoint
  cmd/orusctl/       admin and development CLI (orgs, users, targets, scans, findings, audit)
  cmd/api/           HTTP API entrypoint
  internal/account/  authentication flows of the API (login, MFA, sessions, org access)
  internal/api/      JSON handlers: auth, org-scoped reads and writes (handlers get a *store.Org)
  internal/password/ argon2id password hashing
  internal/totp/     TOTP codes (RFC 6238), stdlib only
  internal/seal/     AES-256-GCM sealing of TOTP secrets (key from ORUS_MFA_KEY)
  internal/module/   the Module interface and the registry
  internal/modules/  one package per check (email, tls, ports, cdn, web, ...)
  internal/finding/  finding schema and validation
  internal/asset/    asset schema (hostname, ip, service, certificate) and validation
  internal/dnsname/  DNS name normalization, shared by module and asset
  internal/posture/  posture score from check statuses (pure, deterministic)
  internal/resolver/ DNS lookups for modules, gated (exclusions + rate limit) per scan
  internal/dialer/   TCP connections for modules, to gate-approved IPs only
  internal/gate/     per-scan module.Gate: customer exclusions + rate limiter
  internal/ownership/ DNS TXT ownership verification and re-checks (rule 1)
  internal/store/    PostgreSQL: organizations, targets, scan queue, findings lifecycle,
                     audit log; org-scoped handle (store.Org) + row-level security
  internal/worker/   claims scans, runs modules, records results
  internal/modules/all/  the list of shipped modules
deploy/              local infrastructure files (PostgreSQL init; lab/setup.sh: the test lab server)
web/                 dashboard (React + TypeScript, Vite)
docs/
```

The API lives in the engine module, not in a top-level `api/` module: Go `internal/`
packages cannot be imported from another module, and the store must stay internal.

### Module contract (target shape, to be refined before the first module)

Every module:
- has a stable ID, a name, and declares whether it is **passive** (public data only: DNS,
  certificates, HTTP responses) or **active** (sends probes: port scans, app tests);
- declares its check catalog in `Info.Checks` (ID unique across modules, category,
  severity used as the score weight, title); every finding uses a declared check;
- receives a `context.Context` and must respect its cancellation and deadline;
- receives the target and its configuration; never reads global state;
- returns a `module.Result`: findings in the standard schema and the assets it observed
  (package `asset`: hostnames under the target, IPs, services, certificates), and the
  checks it actually evaluated (`Result.Evaluated`; a check never claimed is not
  applicable, never passed), or an error; it never prints or logs findings itself;
- goes through the shared rate limiter for every network call.

### Finding schema (fields to include)

ID, module ID, target, asset, severity (critical, high, medium, low, info), title,
description, evidence (raw technical proof), remediation steps, references (CVE, standards),
first seen, last seen, status (open, fixed, accepted risk).

## Security rules (non-negotiable)

These are the product. A breach of them is a bug, never a trade-off.

1. **No active scan without verified ownership.** A target must be verified (DNS TXT record
   `_orus-verify.<domain>` = `orus-verify=<token>`, see `internal/ownership`) before any
   active module runs on it. The record must stay published: it is re-checked before active
   scans when the last check is over 24 hours old, and verification is revoked if it is gone.
   Passive modules may run on unverified domains, but only public, read-only checks.
   **Per-IP ownership (closes the gap of DNS-only verification):** a TXT record proves
   control of the domain, not of the IPs it points to (shared hosting, CDN, a registrar's
   parking page such as Porkbun's for a fresh domain). Active modules therefore receive an
   `ownership.IPGate`: they may only connect to IPs with forward-confirmed reverse DNS (PTR
   under the verified domain, resolving back to the same IP). Only an IP's real holder can
   set its PTR. Refused IPs are skipped like exclusions and written to the audit log.
2. **Respect exclusions.** Customer exclusions (paths, IPs, ports) are checked before every
   request, not only at job start.
3. **Rate limiting is mandatory.** Every outbound request goes through the limiter, using the
   customer's configured rate.
4. **Audit log.** Every scan records who started it, which target, which modules, when.
5. **No secrets in code or in the repo.** Configuration comes from environment variables;
   `.env` files are git-ignored.
6. **Never scan real third-party systems in tests.** Tests use local fixtures, test servers
   (`httptest`, fake DNS resolvers) or targets the project owns.
7. **Treat everything a target returns as untrusted input**: bound sizes, set timeouts,
   never execute or eval it.
8. **The AI layer explains, it never invents.** Scanners produce facts; AI only interprets
   findings that exist.

## Go conventions

- Format with `gofmt`, check with `go vet` and `golangci-lint` (config in
  `engine/.golangci.yml`; from `engine/`:
  `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...`).
  A `//nolint` needs a comment explaining why.
- CI (`.github/workflows/ci.yml`) runs tidy check, vet, golangci-lint, `go test -race` with a
  PostgreSQL 18 service, and govulncheck on every push and pull request. Actions are pinned
  to commit SHAs.
- Prefer the standard library (`net`, `net/http`, `crypto/tls`, `log/slog`, `context`).
- Every network operation has a timeout via `context.Context`.
- Wrap errors with context: `fmt.Errorf("lookup dmarc for %s: %w", domain, err)`.
- Table-driven tests; `go test -race ./...` must pass before every commit.
- Structured logging with `log/slog`; never log secrets or full customer data.
- Keep packages small and internal (`internal/`) unless they are a deliberate public API.

## Local development

```
cp .env.example .env            # then set a password (never commit .env)
docker-compose up -d            # PostgreSQL 18 on 127.0.0.1:55432 (ORUS_PG_PORT)
set -a; . ./.env; set +a
cd engine && go test -race ./...    # integration tests run when ORUS_TEST_DATABASE_URL is set
go run ./cmd/worker                 # in one terminal
go run ./cmd/orusctl target add <domain> && go run ./cmd/orusctl scan <domain>
go run ./cmd/api                    # API on 127.0.0.1:8080 (needs ORUS_MFA_KEY in .env)
go run ./cmd/orusctl user add -role admin you@example.com   # prints a one-time setup token
cd web && npm ci && npm run dev     # dashboard on http://localhost:5173, /api relayed to :8080
npm test && npm run typecheck       # from web/
```

The dashboard sets a `Secure` session cookie: Brave, Chrome and Firefox accept it on
`http://localhost`, Safari does not (use another browser locally). Restart `go run ./cmd/api`
after changing Go code: it does not reload by itself. Vite reloads the dashboard live.

Accounts are invitation-only: an organization admin invites from Paramètres > Équipe
(the dashboard shows the setup code once), or `orusctl user add` creates the account and
prints a setup token; the user sets their password on the dashboard page `/setup-password` (or with
`POST /api/v1/auth/setup-password`). Session
cookies are `Secure`: browsers accept them on `localhost`, anywhere else the API must be
behind HTTPS.

Two-factor authentication (TOTP) is mandatory for admins: an admin session opened without
a second factor gets `403 {"code": "mfa_required"}` on every route of that organization,
reads included. Enrolment is `POST /auth/mfa/setup` (password) then `/auth/mfa/confirm`
(first code, returns 10 recovery codes); with MFA, `POST /auth/login` returns an
`mfa_token` that `POST /auth/login/mfa` exchanges with a code for the session. Wrong codes
count as failed logins. The API needs `ORUS_MFA_KEY` (`openssl rand -base64 32`), which
encrypts the secrets in the database: losing it invalidates every enrolment. A user who
lost their phone and recovery codes is reset with `orusctl user reset-mfa <email>`.

orusctl works in one organization at a time: `-org NAME|ID`, else `ORUS_ORG`, else
`Default` (created by migration 0003, which also holds every pre-existing target).
`orusctl org add <name>` creates another one.

Tenant isolation: API code must only receive a `*store.Org`, never the `*store.Store`
(cross-organization, worker only). Org transactions run as the `orus_app` role with
row-level security; the worker connects as the schema owner (a superuser in dev). In
production the worker needs a role with `BYPASSRLS` and the API a login role granted
`orus_app`: a role with neither sees no rows at all.

Only scan domains you own, even passively. The lab domain is `orushield.xyz` (verified;
the product domain will be a .io or .com). Its lab server is a DigitalOcean droplet named
`orushield.xyz` (so its PTR is under the domain), set up with `deploy/lab/setup.sh`:
configuration defects only, never a really vulnerable application. Run scans from a normal
network: a mobile hotspot may cache stale DNS answers and intercept ports (21 answered on
every IP through one), which skews ownership checks and port results. For TLS test cases,
badssl.com subdomains are built for that purpose. The test lab domain is deliberately misconfigured: never reuse the
product's own domain for it.

## Roadmap

1. Finding schema and Module interface, with tests. (done)
2. Email module: SPF, DKIM, DMARC (passive). (done)
3. TLS/certificate module (passive). (done)
4. Worker, queue and storage. (done)
5. Ownership verification (DNS TXT). (done)
6. Ports module (active, verified targets only). (done; tested on the lab VPS 2026-11-11)
7. API, then dashboard. Mockups are in `docs/design/` (see its README); how each screen
   maps to engine data, and the backend work it needs, is in `docs/ui-adaptation.md`.

## External tools: plan and status

Steps 1 to 3 need nothing beyond Go and its standard library. Do not introduce any of the
tools below before the roadmap step listed for it.

| Tool | Role | Decision | When |
|---|---|---|---|
| PostgreSQL | Main database: customers, assets, scans, findings (`JSONB`) | Adopted: PostgreSQL 18 (uuidv7), driver pgx v5 (MIT) | Step 4 |
| Docker / Compose | Local dev environment; isolation of heavy scanners | Adopted for local dev (`docker-compose.yml`) | Step 4 |
| Queue | Scan jobs for workers | Adopted: PostgreSQL (`SELECT ... FOR UPDATE SKIP LOCKED`), leases + fencing; no extra service | Step 4 |
| Fonts | Inter and Space Grotesk from `@fontsource-variable/*` (OFL-1.1, no dependencies, no install scripts), bundled and served from our origin: never Google Fonts, which would send visitors' addresses to a third party | Adopted 2026-11-10 | Step 7 |
| React + TypeScript (Vite) | Dashboard in `web/`. Exact versions, each at least two weeks old when added; `.npmrc` sets `save-exact` and `ignore-scripts`; CI runs `npm ci` and `npm audit`. Deps: react, react-dom (MIT); dev: typescript (Apache-2.0), vite, @vitejs/plugin-react, vitest, jsdom, @testing-library/react and /dom, @types/react(-dom) (MIT). No UI kit (styles come from the mockups), no router library | Adopted 2026-11-10 | Step 7 |
| golang.org/x/crypto | argon2id password hashing (stdlib only has PBKDF2, which is not memory-hard) | Adopted (BSD-3-Clause, maintained by the Go team) | Step 7.6 |
| Redis or Valkey | Shared rate limiting and cache across workers | Defer until several workers run; check Redis's current license first, prefer Valkey (BSD) if in doubt | After step 4 |
| Nuclei | Template-based vulnerability detection (Go, MIT) | Adopt as a library, wrapped in a module | After step 6 |
| OWASP ZAP | Deep web application testing ("Deep" scan profile) | Adopt later, run in Docker, driven through its API | After step 7 |
| naabu / native Go | Port discovery | Preferred for the ports module (native TCP connect scan, or naabu, MIT) | Step 6 |
| Nmap | Service fingerprinting | Do not integrate until its license (NPSL) has been reviewed for commercial SaaS use | Undecided |
| OpenVAS | Network vulnerability scanning | Not planned: heavy to operate, feed usage terms set by Greenbone; Nuclei and our modules cover the SME scope | Not planned |

Rules for every external tool:
- It runs only inside a module and obeys all security rules above: verified ownership for
  active scans, exclusions, the shared rate limiter, the audit log.
- Its output is converted to the standard finding schema; nothing downstream depends on the
  tool's own format.
- Verify its license before it ships in the paid product, and record the result here.
