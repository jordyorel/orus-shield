# Orus Shield

Continuous security audit platform for small and mid-sized businesses. It discovers what a
company exposes on the internet, checks it, scores it, and turns each finding into a
prioritized, plain-language action plan. The market is international, with particular
attention to French-speaking Africa (local payment methods, French-first reports).

Status: roadmap steps 1 to 5 are done (finding schema, Module interface, gated DNS
resolver and dialer, email and TLS modules, PostgreSQL storage and queue, gate, worker,
orusctl, ownership verification). Next: step 6, the ports module, which first requires
closing the rule 1 gap described below.

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
- **web/**: customer dashboard and public site.
- **ai layer**: reads findings, explains them, ranks them for the customer's context and
  suggests fixes. It never creates or removes findings.

Planned layout (create folders only when they are needed):

```
engine/
  cmd/worker/        worker entrypoint
  cmd/orusctl/       development CLI (targets, scans, findings, audit) until the API exists
  internal/module/   the Module interface and the registry
  internal/modules/  one package per check (email, tls, ports, ...)
  internal/finding/  finding schema and validation
  internal/resolver/ DNS lookups for modules, gated (exclusions + rate limit) per scan
  internal/dialer/   TCP connections for modules, to gate-approved IPs only
  internal/gate/     per-scan module.Gate: customer exclusions + rate limiter
  internal/ownership/ DNS TXT ownership verification and re-checks (rule 1)
  internal/store/    PostgreSQL: targets, scan queue, findings lifecycle, audit log
  internal/worker/   claims scans, runs modules, records results
  internal/modules/all/  the list of shipped modules
deploy/              local infrastructure files (PostgreSQL init)
api/
web/
docs/
```

### Module contract (target shape, to be refined before the first module)

Every module:
- has a stable ID, a name, and declares whether it is **passive** (public data only: DNS,
  certificates, HTTP responses) or **active** (sends probes: port scans, app tests);
- receives a `context.Context` and must respect its cancellation and deadline;
- receives the target and its configuration; never reads global state;
- returns findings in the standard schema, or an error; it never prints or logs findings
  itself;
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
   **Known gap, to solve before step 6:** a DNS TXT record proves control of the domain,
   not ownership of the IPs it points to. A customer on shared hosting, a parking page or
   behind a CDN (Cloudflare proxy, GitHub Pages...) passes verification, and an active scan
   would then hit the provider's infrastructure. Real case seen on the lab domain: a fresh
   Porkbun domain points to Porkbun's parking servers until those records are deleted.
   Active modules must not run against such IPs (for example: exclude known CDN/hosting
   ranges, or require server-level verification).
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
```

Only scan domains you own, even passively. The lab domain is `orushield.xyz` (verified;
the product domain will be a .io or .com). For TLS test cases, badssl.com subdomains are
built for that purpose. The test lab domain is deliberately misconfigured: never reuse the
product's own domain for it.

## Roadmap

1. Finding schema and Module interface, with tests. (done)
2. Email module: SPF, DKIM, DMARC (passive). (done)
3. TLS/certificate module (passive). (done)
4. Worker, queue and storage. (done)
5. Ownership verification (DNS TXT). (done)
6. Ports module (active, verified targets only).
7. API, then dashboard (design mockups exist on the project canvas).

## External tools: plan and status

Steps 1 to 3 need nothing beyond Go and its standard library. Do not introduce any of the
tools below before the roadmap step listed for it.

| Tool | Role | Decision | When |
|---|---|---|---|
| PostgreSQL | Main database: customers, assets, scans, findings (`JSONB`) | Adopted: PostgreSQL 18 (uuidv7), driver pgx v5 (MIT) | Step 4 |
| Docker / Compose | Local dev environment; isolation of heavy scanners | Adopted for local dev (`docker-compose.yml`) | Step 4 |
| Queue | Scan jobs for workers | Adopted: PostgreSQL (`SELECT ... FOR UPDATE SKIP LOCKED`), leases + fencing; no extra service | Step 4 |
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
