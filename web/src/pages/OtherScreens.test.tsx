import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Check, Finding, Me, Overview, OrgAsset } from "../api/types";
import { App } from "../App";
import { AuthProvider } from "../auth";
import { mockApi, ok } from "../test/fetch";
import { protections } from "./PrioritizationPage";

const ORG = "0193a1c4-0000-7000-8000-000000000001";
const base = `/orgs/${ORG}`;
const me: Me = { user_id: "u1", email: "v@acme.example", mfa_enabled: false, mfa_session: false, orgs: [{ org_id: ORG, org_name: "Acme", role: "viewer" }] };
const ago = (d: number) => new Date(Date.now() - d * 86400_000).toISOString();

const asset = (kind: OrgAsset["kind"], value: string, details: Record<string, string> = {}): OrgAsset => ({
  target_id: "t1", domain: "acme.example", id: value, kind, value, details, sources: ["tls"], first_seen: ago(1), last_seen: ago(0), gone_at: null,
});
const assets = [
  asset("hostname", "acme.example", { cdn: "Cloudflare", waf: "Cloudflare" }),
  asset("ip", "192.0.2.10"),
  asset("certificate", "abc", { not_after: ago(-10) }),
  asset("service", "192.0.2.10:443/tcp"),
];
const finding = (id: string, severity: Finding["severity"], extra: Partial<Finding> = {}): Finding => ({
  target_id: "t1", schema_version: "1", id, module_id: "email", check_id: id, target: "acme.example", asset: "acme.example", severity,
  title: `Title ${id}`, description: "", evidence: "", remediation: null, references: null, first_seen: ago(5), last_seen: ago(0), status: "open", ...extra,
});
const findings = [finding("spf-pass-all", "critical"), finding("dmarc", "medium"), finding("old", "high", { status: "fixed", fixed_at: ago(2) })];
const check = (id: string, category: Check["category"], status: Check["status"]): Check => ({
  target_id: "t1", id, title: `Check ${id}`, module: "email", category, severity: "high", status, findings: status === "failed" ? 1 : 0, evaluated_at: ago(0),
});
const checks = [check("spf", "email", "failed"), check("dmarc", "email", "passed"), check("tls-version", "tls", "passed")];
const overview: Overview = {
  days: 30, targets: 1, verified_targets: 0, open_findings: { critical: 1, medium: 1 }, assets: 4, new_assets: 4, score: 66, score_change: 4,
  trend: [], remediation: { fixed: 1, mean_seconds: 3 * 86400, previous_fixed: 0, previous_mean_seconds: null }, priorities: [],
  per_target: [{ id: "t1", domain: "acme.example", verified: false, last_scan_at: ago(0), stale: false, open_findings: { critical: 1, medium: 1 }, posture_score: 66, current_assets: 4 }],
};

function start(section: string) {
  mockApi({
    "GET /auth/me": ok(me),
    [`GET ${base}/targets`]: ok({ items: [{ id: "t1", domain: "acme.example", verified: false, rate_per_sec: 5, exclusions: {} }] }),
    [`GET ${base}/assets`]: ok({ items: assets }),
    [`GET ${base}/modules`]: ok({ items: [{ id: "email", name: "", kind: "passive", checks: 1 }, { id: "ports", name: "", kind: "active", checks: 1 }] }),
    [`GET ${base}/members`]: ok({ items: [{ user_id: "u1", email: "v@acme.example", role: "viewer", activated: true, mfa_enabled: false }] }),
    [`GET ${base}/findings`]: ok({ items: findings }),
    [`GET ${base}/checks`]: ok({ items: checks }),
    [`GET ${base}/overview?days=30`]: ok(overview),
    [`GET ${base}/trends?months=6`]: ok({ items: [{ month: "2026-10", opened: 2, fixed: 0 }, { month: "2026-11", opened: 1, fixed: 1 }] }),
  });
  window.history.replaceState(null, "", `${base}/${section}`);
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
}

describe("remaining screens", () => {
  it("surface: counts the inventory and blocks active modules on unverified domains", async () => {
    start("surface");
    expect(await screen.findByText("Domaines")).toBeTruthy();
    expect(screen.getByText(/dont 1 expire dans moins de 30 jours/)).toBeTruthy();
    expect(screen.getByText("Bloqué")).toBeTruthy(); // ports, no verified domain
    expect([...document.querySelectorAll(".action-big")].map((e) => e.textContent)).toContain("1 compte sans double authentification");
    expect(screen.getAllByText("Nouvelle vulnérabilité").length).toBeGreaterThan(0);
    expect(screen.getByText("Corrigé")).toBeTruthy();
  });

  it("posture: misconfigurations from the checks, compliance as coming", async () => {
    start("posture");
    expect(await screen.findByText("Mauvaises configurations")).toBeTruthy();
    expect(screen.getByText(/1 RISQUE/)).toBeTruthy(); // emails: one failed check
    expect(screen.getByText("Check spf", { exact: false })).toBeTruthy();
    expect(screen.getAllByText("Correspondances en cours de rédaction")).toHaveLength(4);
  });

  it("prioritization: open findings by severity with their protections", async () => {
    start("priorisation");
    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2); // the fixed one is out
    expect(rows[0]?.textContent).toContain("SPF-PASS-ALL");
    expect(rows[0]?.textContent).toContain("Cloudflare");
    expect(protections("www.other.example:443", assets)).toBe("Aucune");
  });

  it("governance: controls in place and remediation time from real data", async () => {
    start("gouvernance");
    expect(await screen.findByText("Contrôles en place")).toBeTruthy();
    expect(screen.getAllByText("67 %").length).toBeGreaterThan(0); // 2 of 3 checks passed
    expect(screen.getByText("3,0 j")).toBeTruthy();
  });
});
