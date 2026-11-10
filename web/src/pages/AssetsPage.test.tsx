import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Me, Overview, OverviewTarget } from "../api/types";
import { App } from "../App";
import { AuthProvider } from "../auth";
import { fail, mockApi, ok, type Route } from "../test/fetch";

const ORG = "0193a1c4-0000-7000-8000-000000000001";
const base = `/orgs/${ORG}`;

const me = (role: "admin" | "viewer"): Me => ({
  user_id: "u1", email: `${role}@acme.example`, mfa_enabled: role === "admin", mfa_session: role === "admin",
  orgs: [{ org_id: ORG, org_name: "Acme", role }],
});

const target = (id: string, domain: string, verified: boolean, score: number | null = null): OverviewTarget => ({
  id, domain, verified, last_scan_at: null, stale: true, open_findings: { high: 1, info: 2 }, posture_score: score, current_assets: 0,
});

const overview = (per_target: OverviewTarget[]): Overview => ({
  days: 30, targets: per_target.length, verified_targets: 0, open_findings: {}, assets: 0, new_assets: 0, score: null, score_change: null,
  trend: [], remediation: { fixed: 0, mean_seconds: null, previous_fixed: 0, previous_mean_seconds: null }, priorities: [], per_target,
});

const instructions = {
  domain: "new.example", record_name: "_orus-verify.new.example", record_type: "TXT", record_value: "orus-verify=abc123",
  expires_at: new Date(Date.now() + 7 * 86400_000).toISOString(), verified: false,
};

function start(routes: Record<string, Route>) {
  const calls = mockApi(routes);
  window.history.replaceState(null, "", base + "/actifs");
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

describe("AssetsPage", () => {
  it("adds a domain, shows the DNS record and verifies it", async () => {
    let added = false;
    let verifyTries = 0;
    const calls = start({
      "GET /auth/me": ok(me("admin")),
      [`GET ${base}/overview?days=30`]: () => ({
        status: 200,
        json: overview([target("t1", "acme.example", true, 72), ...(added ? [target("t2", "new.example", verifyTries > 1)] : [])]),
      }),
      [`POST ${base}/targets`]: () => {
        added = true;
        return { status: 201, json: { id: "t2", domain: "new.example", verified: false } };
      },
      [`POST ${base}/targets/t2/verification`]: ok(instructions),
      [`POST ${base}/targets/t2/verify`]: () =>
        ++verifyTries === 1 ? { status: 422, json: { error: "verification record not found yet" } } : { status: 200, json: { id: "t2", verified: true } },
      [`POST ${base}/targets/t2/scans`]: () => ({ status: 202, json: { id: "s1", status: "queued" } }),
    });

    fireEvent.change(await screen.findByLabelText("Adresse"), { target: { value: "new.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Ajouter" }));
    expect(await screen.findByText("Vérifiez la propriété de new.example")).toBeTruthy();
    expect(document.querySelector(".record")?.textContent).toBe('_orus-verify.new.example  TXT  "orus-verify=abc123"');

    fireEvent.click(screen.getByRole("button", { name: "Vérifier maintenant" }));
    expect(await screen.findByText(/Enregistrement introuvable pour l’instant/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Vérifier maintenant" }));
    expect(await screen.findByText(/Propriété vérifiée pour new\.example\. Le premier scan complet démarre maintenant\./)).toBeTruthy();
    expect(calls.find((c) => c.key === `POST ${base}/targets`)?.body).toEqual({ domain: "new.example" });
    expect(calls.some((c) => c.key === `POST ${base}/targets/t2/scans`)).toBe(true);
  });

  it("explains a refused domain", async () => {
    start({
      "GET /auth/me": ok(me("admin")),
      [`GET ${base}/overview?days=30`]: ok(overview([target("t1", "acme.example", true)])),
      [`POST ${base}/targets`]: fail(409, "this domain is already a target of the organization"),
    });
    fireEvent.change(await screen.findByLabelText("Adresse"), { target: { value: "acme.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Ajouter" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Ce domaine est déjà surveillé.");
  });

  it("lists the monitored domains with ownership and score; viewers cannot add", async () => {
    start({
      "GET /auth/me": ok(me("viewer")),
      [`GET ${base}/overview?days=30`]: ok(overview([target("t2", "beta.example", false), target("t1", "acme.example", true, 86)])),
    });
    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows[0]?.textContent).toContain("acme.example");
    expect(rows[0]?.textContent).toContain("Vérifiée");
    expect(rows[0]?.textContent).toContain("86");
    expect(rows[1]?.textContent).toContain("À vérifier");
    expect(screen.getByText("2 actifs")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Ajouter" })).toBeNull();
    expect(screen.getByText(/réservé aux administrateurs/)).toBeTruthy();
    // Discovery is announced, never filled with invented items.
    expect(screen.getByText("Bientôt disponible")).toBeTruthy();
  });
});
