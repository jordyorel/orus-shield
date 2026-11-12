# Product features: the full list, for the dashboard design

This is the list of every feature the product will have once the work chosen on
2026-11-12 is done (gap items 1, 2, 3, 4, 5, 8 and 9), grouped by screen. It exists to
prepare the graphical interface: each entry says what the user sees and does, where the
data comes from, and its status.

Status: **done** (works today), **A** to **G** (the step that builds it, see the end),
**later** (planned, no date). Plan: the cheapest offer that includes it (Découverte,
PME, Pro, Entreprise; prices not validated yet). UI wording stays French; finding texts
stay in the modules' English (decided 2026-11-10).

## 1. Public pages (not signed in)

| Feature | What the user sees / does | Status |
|---|---|---|
| Landing page | What Orus Shield does, for whom, the scan types, trust points (ownership check, no intrusive test) | later |
| Pricing page | The 4 offers, monthly / yearly toggle, local currencies (EUR, XOF/XAF, USD), payment methods logos | F |
| Free external check | Enter a domain, get a short passive report (email, TLS, web headers) by email, to convert visitors | later |
| Sign up | Email + organization name, confirmation link | done |
| Sign in, MFA, password reset, setup password | | done |
| Legal pages | Terms, privacy, scanning authorization (customer confirms they own the assets) | F |

## 2. Onboarding (first sign-in)

| Feature | What the user sees / does | Status |
|---|---|---|
| Add a first domain | Domain field, then the TXT record to publish, "Vérifier" button | done |
| Guided first scan | Passive scan starts at once (no verification needed), active modules unlock after verification | done (to polish) |
| Choose an offer / start a trial | 14-day trial of PME, then card or Mobile Money | F |
| Checklist | Verify domain, invite a colleague, enable MFA, set a schedule, set alert recipients | later |

## 3. Overview (Vue d'ensemble)

| Feature | Data | Status |
|---|---|---|
| Posture score, trend, breakdown by category | check_status, posture_snapshots | done |
| Open findings by severity, remediation time | findings, finding_events | done |
| Rule-based priorities | overview endpoint | done |
| New assets since last period | assets | done |
| **Emerging threats banner**: "A new critical CVE affects your stack; rescan queued / done" | `GET /orgs/{org}/threats` (done) | C: data done, UI waits for a design |
| **Leaks summary**: exposed accounts found this month | leak module | G |
| Plan usage: domains used / allowed, next scheduled scan | plan limits | F |

## 4. Vulnerabilities (Vulnérabilités)

| Feature | Data | Status |
|---|---|---|
| List, filters (severity, status, module, domain), detail with evidence and remediation | findings | done |
| Accept a risk, history of a finding | finding_events | done |
| **CVE details**: CVE ID, CVSS score, EPSS (probability of exploitation), "known exploited" (CISA KEV) badge, affected version, fixed version | vulns module (Nuclei): CVE, CVSS, EPSS and KEV in evidence and references | done (engine); UI badges later |
| **Filter "known vulnerabilities" / "configuration"** | check category | A |
| **Source badge**: which scan found it (passive, active, deep web scan) | module ID | A |
| Export (CSV now, PDF with the report) | PDF: done (technical report); CSV later | E |
| Assign a finding to a member, due date, comment | | later |

## 5. Assets (Actifs) and attack surface (Surface)

| Feature | Data | Status |
|---|---|---|
| Domains: add, verify (TXT), remove | targets | done |
| Discovered subdomains (CT logs, common names), IPs, certificates, CDN / WAF | discovery, tls, cdn | done |
| **Open ports on 1000 common ports** (was ~30), with the service and **its version** ("OpenSSH 8.9p1", "nginx 1.18.0") | ports module, step B | B |
| **Technologies detected** per host (web server, CMS, frameworks, versions) | Nuclei tech templates, step A | A |
| **"Outdated" badge** when a detected version has known CVEs | A + B | A/B |
| Per-IP ownership status (verified / refused and why) | audit ip.not_verified | later (data exists) |

## 6. Scans

| Feature | Data | Status |
|---|---|---|
| Launch a scan, choose modules, history, live status | scans | done |
| Rate, exclusions (IPs, ports, paths, hosts) | targets | done |
| Schedule: daily, weekly, monthly | targets.schedule_* | done |
| **Scan profiles**: Passif, Standard (+ ports, known vulnerabilities), **Approfondi** (+ deep web application scan, ZAP) | profiles map to module lists | A (Standard), D (Approfondi) |
| **Deep scan settings**: start URL, pages to skip, optional test account for the app (login form), max duration | ZAP config per target | D |
| **Deep scan warning and consent**: "this scan sends test inputs to your forms; run it on a test environment if you can" | | D |
| Scan quota display: "3 scans approfondis restants ce mois" | plan limits | F |
| Rescans triggered by emerging threats, shown with a "Menace émergente" tag | scans.requested_by = threats | C: data done, tag in the UI later |
| Continuous mode ("Continue") | | later |

## 7. Reports (Rapports) — new screen

| Feature | What the user sees / does | Status |
|---|---|---|
| Report list per domain and period | | later (reports are generated on demand, not stored) |
| **PDF report in French and English**: cover, executive summary (score and trend, open problems by severity, top 5 actions, domains table), findings with evidence, remediation and references, accepted risks, asset inventory | `GET /orgs/{org}/report?kind=executive|technical&lang=fr|en`, engine data only | done |
| Two versions: "Direction" (no jargon) and "Technique" (full) | Paramètres > Rapports (version and language), overview link | done |
| Monthly report sent by email automatically to chosen recipients | notifications outbox | later (checkboxes shown, inactive) |
| Branding for resellers (logo, colors) | | later (Entreprise) |
| Compliance mapping annex (CIS v8, ISO 27001: "automated checks mapped to") | waits for Jordy's review | later |

## 8. Leaks (Fuites de données) — new screen

| Feature | What the user sees / does | Status |
|---|---|---|
| Accounts of the domain found in public breaches: email, breach name, date, data types (password, phone...) | breach data provider, verified domains only | G |
| Never show a password, even hashed; show only "a password was exposed" | | G |
| Actions: force password reset, enable MFA; mark as handled | | G |
| Alert when a new breach contains the domain's accounts | notifications | G |

## 9. Emerging threats (Menaces émergentes) — new screen

| Feature | What the user sees / does | Status |
|---|---|---|
| Feed of new critical CVEs relevant to the customer's detected technologies | `GET /orgs/{org}/threats`: CVE, name, severity, KEV, EPSS, domain, matched technologies | done (API); screen not in the mockups yet |
| For each: affected domain, rescan status (queued, running, done, failed) | threat_matches + scans | done (API) |
| Alert email: "N nouvelles failles pouvant concerner X, vérification en cours" | notifications `emerging_threat` | done |

## 10. Alerts and notifications

| Feature | What the user sees / does | Status |
|---|---|---|
| Email to admins on new critical / high findings | notifications | done |
| **Alert settings**: recipients (any member, external address), minimum severity, per-domain, weekly digest | | later (data model in C) |
| Other channels: WhatsApp, SMS, Slack, Teams, webhook | | later |

## 11. Settings (Paramètres)

| Feature | Status |
|---|---|
| Profile, password, MFA | done |
| Team: invite, roles admin / viewer, remove | done |
| Organization: name, country, time zone, language | later |
| **Subscription (Abonnement)**: current offer, usage against limits (domains, hosts, scans), change offer, cancel | F |
| **Billing (Facturation)**: payment method (card, PayPal, Mobile Money: Orange Money, MTN MoMo, Wave, Moov), invoices (PDF), billing details (company, tax ID) | F |
| API keys (Pro and up) | later |
| Audit log viewer | later (data exists) |

## 12. Plan limits (what the UI must show and enforce)

Enforced by the API and the worker, shown in the UI with a clear "upgrade" path, never a
silent failure. Numbers are a proposal (not validated):

| | Découverte (free) | PME | Pro | Entreprise |
|---|---|---|---|---|
| Domains | 1 | 3 | 15 | on quote |
| Hosts per scan | 5 | 25 | 25 | more |
| Modules | passive only | all except deep | all | all |
| Deep web scans (ZAP) | no | no | 4 / month | on quote |
| Schedule | monthly | weekly | daily | daily |
| Email alerts | no | yes | yes | yes |
| PDF reports | no | monthly | on demand | on demand + branding |
| Leaks | no | yes | yes | yes |
| Emerging threat rescans | no | yes | yes | yes |
| Members | 1 | 3 | 10 | unlimited |

## 13. Internal admin (back office, not customer-facing)

| Feature | Status |
|---|---|
| Organizations, subscriptions, payments, trials | F |
| Worker health, queue length, failed scans | later |
| Scanner versions (Nuclei, templates, ZAP) and their update date | A/C |

## Steps

| Step | Builds | Needs from Jordy |
|---|---|---|
| A | Nuclei behind our gating proxy: known CVEs, exposures, misconfigurations, technologies | nothing more (validated 2026-11-12) |
| B | Ports: top 1000, service and version identification (native Go) | nothing |
| C | Emerging threats: new templates and CISA KEV, rescan of affected customers, EPSS | nothing |
| D | ZAP deep web scan ("Approfondi") | nothing |
| E | French PDF reports | approve a PDF library |
| F | Payment, subscriptions, plan limits | company country, providers, prices |
| G | Leaks | a breach data provider (paid) |
