# Design mockups

Source files of the Orus Shield mockups, exported from the design canvas:
https://claude.ai/artifact/B5z3w95GnvqT6vmxN2Wr1t (private to the maintainer).

These are design references, not production code. Each `.dc.html` file is one screen in
the canvas editor's component format: plain HTML with inline styles, plus a small
`<script type="text/x-dc">` block holding demo data and interactions. They need the
canvas runtime to render, so open them on the canvas; read them here for layout, copy,
components and the data each screen expects.

All numbers in the mockups are demo data ("Microfinance Exemple SA"). The real product
shows only computed data: see `docs/ui-adaptation.md`.

| File | Screen | Notes |
|---|---|---|
| `Main.dc.html` | Public site | Free passive scan, features, pricing in USD with local payment methods |
| `Dashboard.dc.html` | Overview | Score, trend, severity breakdown, weekly priorities, compliance, exposed assets |
| `Issues.dc.html` | Vulnerabilities | Severity filters, finding detail: AI explanation, remediation steps, evidence |
| `Assets.dc.html` | Assets | Add target, DNS TXT ownership verification, discovered assets |
| `Scans.dc.html` | Scan configuration | Profiles, module toggles, schedule, rate, exclusions, history |
| `Settings.dc.html` | Settings | Alert rules, integrations, team, reports, API keys, billing |
| `Surface.dc.html` | Attack surface | Priority actions, coverage by source, external assets, recent changes |
| `Priorisation.dc.html` | Prioritization by real risk | Raw severity vs contextual risk, context columns |
| `Posture.dc.html` | Posture and compliance | Posture score, risk categories, pass/fail per framework |
| `Gouvernance.dc.html` | Governance and risks | Heat map, risk register, controls, remediation times, policies |
| `canvas.json` | Canvas layout | Position and order of the screens |

The canvas is the source of truth. When a mockup changes there, export it here again.
