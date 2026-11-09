# Adapting the dashboard mockups to the real engine

This document tells Claude Code how to connect the four "advanced panel" mockups in
`docs/design/` (`Surface`, `Priorisation`, `Posture`, `Gouvernance`: attack surface,
prioritization, posture and compliance, governance) to what the engine actually produces. It is a plan, not a spec to implement in one go: follow
CLAUDE.md (one step at a time, design first, tests first, stop for review).

## What exists today (after roadmap step 6)

- `targets`: one row per registered domain, with ownership verification (`verified_at`,
  `verify_token`, `verify_checked_at`), exclusions and rate.
- `scans`: the queue, with `requested_by`, `modules`, status and timings.
- `findings`: one row per issue, deterministic ID, `severity`, `status`
  (open, fixed, accepted_risk), `first_seen`, `last_seen`, `fixed_at` (step 7.2), full JSON
  in `data`.
- `finding_events` (step 7.2): every status change (opened, fixed, reopened, risk
  accepted or withdrawn) with its time, actor and scan. Mean time to remediate and
  "opened vs fixed per month" are computed from it.
- `assets` (step 7.3): the inventory per target. Modules return a `module.Result` with
  findings and assets. Kinds: hostname (only the target domain and its subdomains), ip,
  service (`ip:port/tcp`), certificate (SHA-256). `sources` lists the modules that saw the
  asset in their last successful run; an asset no module sees any more gets `gone_at`.
  `tls` reports names, addresses, port 443 and certificates; `ports` reports scanned
  addresses and open ports; `email` reports none. There is no "discovered" state yet: it
  comes with the discovery module.
- Check catalog and posture (step 7.4): each module declares its checks (`Info.Checks`:
  ID, category, severity, title) and reports the ones it evaluated. `module.Evaluate`
  gives each check passed, failed or not_applicable; `check_status` keeps the latest
  status per target and check, `posture_snapshots` the score after each scan with its
  breakdown (package `posture`: weights critical 10, high 6, medium 3, low 1, info 0;
  score = passed weight / evaluated weight; no score when nothing was evaluated).
- `audit_log`: append-only record of actions.
- `organizations` (step 7.1): every target, scan, finding and audit entry has an `org_id`.
  API code works through `store.Org` (every query filtered by organization), backed by
  PostgreSQL row-level security (role `orus_app`, `app.org_id` set per transaction).
  A domain is unique per organization, not globally.
- Modules: `email` (SPF, DKIM, DMARC) and `tlscheck` (certificates, protocol versions),
  both passive; `ports` (exposed network services), active, which only reaches IPs whose
  ownership is proven by forward-confirmed reverse DNS (`ownership.IPGate`). Check IDs such as `dmarc-policy-none`, `tls-cert-expiring-soon`.
- `orusctl`: org add/list; target add/show/verify-token/verify, scan, status, findings,
  assets, audit, each in one organization (`-org`, `ORUS_ORG`, default `Default`).

What does not exist yet: users and authentication, a record of checks
that passed, a security score, CVE or exploit data, context factors,
an HTTP API, a web dashboard.

## Rules for every screen

1. **No invented numbers in the product.** The mockups use demo data. In the real product,
   every number comes from a query on stored data. When the data does not exist yet, show
   an empty state that says what is missing and how to get it ("Connect Microsoft 365 to
   see your identities"), never a placeholder figure.
2. **Hide what we cannot compute.** A panel whose data source is not built is either
   hidden or shown as "Coming soon". It is never filled with estimates.
3. **Risk and scores are computed by the engine, deterministically.** The AI layer may
   explain a score; it never produces one (security rule 8). Store the factors that led to
   each score so the UI can show "why".
4. **Compliance wording is honest.** External scans cover only part of any framework.
   Say "automated checks mapped to ISO 27001", never "ISO 27001 compliant".
5. **Multi-tenant from the first API endpoint.** Every query is scoped to the caller's
   organization.

## Screen 1: Attack surface (mockup inspired by Rapid7)

| Panel | Data source | Available now? |
|---|---|---|
| Header totals (assets, cloud/SaaS, identities, admins) | Asset inventory; identities need a Microsoft 365 / Google connector | Partly: count targets now; identities later |
| Priority actions | Queries: unverified targets, targets with no scan for N days, open critical findings | Yes, with these three actions. "Admins without MFA" waits for the identity connector |
| Coverage: scan modules | Module registry (`modules/all`) + last scan result per module + `CheckAllowed` (active module on unverified target = "Blocked") | Yes |
| Coverage: DNS, identities, cloud, alerts | Connectors | No: show "Coming soon" |
| External assets (domains, IPs, certificates, services) | Asset inventory (`assets`, step 7.3) | Yes |
| Recent changes | `audit_log`, findings opened or fixed, new assets | Partly: audit log and findings now |

Backend work needed:
- **Organizations** table and `targets.org_id` (every screen needs it).
- **Asset inventory**: an `assets` table (kind: domain, subdomain, ip, certificate,
  service; value; target; source module; first_seen; last_seen; monitored or discovered).
  Modules must be able to report observed assets, not only findings. This changes the
  Module contract: propose the design (for example a `Result` with `Findings` and
  `Assets`) before coding. The resolver already resolves IPs and `tlscheck` already sees
  certificates, so both can report assets.
- Later: a passive **discovery module** (subdomains from certificate transparency logs).
  Discovered assets are listed as "discovered", never scanned actively until the customer
  adds and verifies them.

## Screen 2: Prioritization by real risk (mockup inspired by Zafran)

| Column / panel | Data source | Available now? |
|---|---|---|
| Identifier | CVE ID when the finding references one, else `check_id` | Yes (check_id) |
| Asset, component | `finding.asset`, evidence | Yes |
| Exposure (days open) | `now - first_seen` | Yes |
| Running / Internet-facing | All current modules are external, so always "yes" | Show only once an internal agent or service detection exists |
| Threat (actively exploited, public exploit) | CISA KEV catalog (public JSON), matched on CVE IDs | No: useful only once modules emit CVEs (Nuclei, service versions) |
| Protections (WAF, CDN) | CDN and WAF detection | No: see below |
| Real risk score and the raw-vs-real funnel | Contextual risk function | No |

Backend work needed:
- A **contextual risk function** in the engine: input = severity, exposure age, internet
  facing, actively exploited, protections, asset criticality (set by the customer);
  output = score 0 to 10, level, and the list of factors applied. Store raw severity and
  real risk side by side. Deterministic and unit-tested.
- **CDN and hosting detection** (known IP ranges and response headers). It feeds the
  "Protections" column. (It is no longer needed for rule 1: per-IP reverse DNS
  verification already keeps active modules off shared hosting and CDNs.)
- **KEV ingestion**: a periodic job that downloads the CISA KEV catalog and stores it;
  findings with a matching CVE get the "actively exploited" factor.
- Until context factors exist: show the table sorted by severity, hide the funnel.

## Screen 3: Posture and compliance (mockup inspired by Datadog)

| Panel | Data source | Available now? |
|---|---|---|
| Threats | Open critical and high findings | Yes |
| Misconfigurations "31 / 212" | Failed checks / evaluated checks (`check_status`) | Yes |
| Posture score | Passed checks weighted by severity (`posture_snapshots`) | Yes |
| Coverage | Verified targets / targets; connected sources | Partly |
| Risk categories (Emails, Web, TLS, DNS, Identities, Network, Cloud, Leaks) | `module_id` to category mapping | Partly: Emails and TLS now, others "Coming soon" |
| Compliance reports (passed / failed per framework) | Check catalog with framework mappings | No: mappings not written yet (Jordy reviews them) |

Backend work needed:
- A **check catalog**: each module declares its checks (check_id, category, default
  severity, title keys for localization, framework mappings).
- **Evaluated checks per scan**: record passed, failed and not-applicable results, not
  only failures. Without this, "X / Y", the posture score and pass/fail counts cannot be
  computed honestly.
- **Framework mappings**: start with one framework (CIS Controls v8 is the most natural for
  external checks), then ISO 27001 Annex A. Each mapping is reviewed by Jordy.
- **Score snapshots**: store the score after each scan so trends (+16 points) are real.

## Screen 4: Governance and risks (mockup inspired by a GRC dashboard)

Most of this screen is business data that scanners do not produce: risk register,
likelihood and impact, owners, controls, policies, audit findings. It needs users and
editable entities, so it comes after the API, users and the first customers.

What can be computed earlier from engine data:
- Vulnerabilities over time (opened vs fixed per month) and by severity.
- **Mean time to remediate**: needs a `fixed_at` (or a status history table) on findings.
  Add it with the findings lifecycle; `last_seen` is not enough.
- Compliance by framework, reusing screen 3.
- Mean time to detect: postpone. It needs a definition we can measure honestly.

Later, a GRC module: `risks` (likelihood, impact, owner, status, due date, linked
findings), `controls`, `policies`. The heat map and risk register read from it.

## Suggested order

1. Organizations and `org_id` scoping. (done: `store.Org` + row-level security; users and
   authentication come with the API endpoints)
2. Findings lifecycle: `fixed_at` / status history. (done: `findings.fixed_at` and
   `finding_events`)
3. Asset inventory and the Module contract change for observed assets. (done:
   `module.Result`, package `asset`, `assets` table, `orusctl assets`)
4. Check catalog and evaluated checks; posture score and snapshots. (done, except
   framework mappings)
5. CDN and hosting detection (for the "Protections" column).
6. API endpoints for screens 1 to 3, scoped by organization, with tests.
7. Contextual risk function, then KEV ingestion once CVE-producing modules exist.
8. Discovery module and connectors.
9. Governance entities.

Steps 1 to 5 change the data model: propose each design to Jordy and wait for approval
before writing code.
