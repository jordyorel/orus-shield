import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Me, ModuleInfo, Scan, Target } from "../api/types";
import { App } from "../App";
import { AuthProvider } from "../auth";
import { mockApi, ok, type Route } from "../test/fetch";

const ORG = "0193a1c4-0000-7000-8000-000000000001";
const base = `/orgs/${ORG}`;

const me = (role: "admin" | "viewer"): Me => ({
  user_id: "u1", email: `${role}@acme.example`, mfa_enabled: role === "admin", mfa_session: role === "admin",
  orgs: [{ org_id: ORG, org_name: "Acme", role }],
});

const modules: ModuleInfo[] = [
  { id: "cdn", name: "CDN", kind: "passive", checks: 0 },
  { id: "email", name: "Email", kind: "passive", checks: 12 },
  { id: "ports", name: "Ports", kind: "active", checks: 4 },
  { id: "tls", name: "TLS", kind: "passive", checks: 6 },
];

const target = (id: string, domain: string, verified: boolean): Target => ({
  id, domain, verified, verified_at: null, verify_checked_at: null, rate_per_sec: 5, exclusions: { paths: ["/admin"], ports: [3389] }, created_at: "",
});

const scan = (id: string, status: Scan["status"], mods: string[], extra: Partial<Scan> = {}): Scan => ({
  id, target_id: "t1", domain: "acme.example", modules: mods, requested_by: "user:a", status, attempts: 1,
  created_at: new Date(2026, 10, 8, 22, 40).toISOString(), started_at: null, finished_at: null, ...extra,
});

function start(role: "admin" | "viewer", routes: Record<string, Route> = {}) {
  const calls = mockApi({
    "GET /auth/me": ok(me(role)),
    [`GET ${base}/modules`]: ok({ items: modules }),
    [`GET ${base}/targets`]: ok({ items: [target("t1", "acme.example", true), target("t2", "beta.example", false)] }),
    [`GET ${base}/scans?limit=20`]: ok({
      items: [
        scan("s2", "done", ["cdn", "email", "ports", "tls"], {
          started_at: new Date(2026, 10, 8, 6, 0).toISOString(), finished_at: new Date(2026, 10, 8, 6, 6).toISOString(), new_findings: 1,
        }),
        scan("s1", "done", ["cdn", "email", "tls"], { new_findings: 0 }),
      ],
    }),
    ...routes,
  });
  window.history.replaceState(null, "", base + "/scans");
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

describe("ScansPage", () => {
  it("shows the engine's modules, the profiles and the history", async () => {
    start("admin");
    expect(await screen.findByText("Sécurité des emails")).toBeTruthy();
    expect(screen.getByText("4 modules actifs")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Standard/ }).getAttribute("aria-pressed")).toBe("true");
    // Modules the engine lacks are listed as coming, and cannot be enabled.
    expect((screen.getByRole("button", { name: "Microsoft 365 : bientôt disponible" }) as HTMLButtonElement).disabled).toBe(true);

    const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1);
    expect(rows[0]?.textContent).toContain("Standard");
    expect(rows[0]?.textContent).toContain("6 min");
    expect(rows[1]?.textContent).toContain("Rapide");

    // The quick profile keeps the passive modules only.
    fireEvent.click(screen.getByRole("button", { name: /Rapide/ }));
    expect(screen.getByText("3 modules actifs")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Activer Ports et services" }).getAttribute("aria-pressed")).toBe("false");
  });

  it("launches a scan of every domain and warns about active checks on unverified ones", async () => {
    const calls = start("admin", {
      [`POST ${base}/targets/t1/scans`]: () => ({ status: 202, json: scan("s3", "queued", []) }),
      [`POST ${base}/targets/t2/scans`]: () => ({ status: 202, json: scan("s4", "queued", []) }),
    });
    await screen.findByText("Sécurité des emails");
    fireEvent.click(screen.getByRole("button", { name: "Lancer maintenant" }));
    expect(await screen.findByText(/2 scans lancés\. Les vérifications actives ne s’exécuteront pas sur beta\.example/)).toBeTruthy();
    expect(calls.find((c) => c.key === `POST ${base}/targets/t1/scans`)?.body).toEqual({ modules: ["cdn", "email", "ports", "tls"] });
  });

  it("saves a domain's intensity and exclusions", async () => {
    const calls = start("admin", {
      [`PATCH ${base}/targets/t1`]: (body) => ({ status: 200, json: { ...target("t1", "acme.example", true), ...(body as object) } }),
    });
    const excl = (await screen.findByLabelText("Exclusions")) as HTMLTextAreaElement;
    expect(excl.value).toBe("/admin\n3389");
    fireEvent.change(excl, { target: { value: "/admin\n3389\n192.0.2.10" } });
    fireEvent.change(screen.getByLabelText(/Requêtes par seconde/), { target: { value: "20" } });
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer" }));
    expect(await screen.findByText("Configuration enregistrée")).toBeTruthy();
    expect(calls.find((c) => c.key.startsWith("PATCH"))?.body).toEqual({
      rate_per_sec: 20,
      exclusions: { ips: ["192.0.2.10"], ports: [3389], paths: ["/admin"], hosts: [] },
    });
  });

  it("refuses unreadable exclusions before sending them", async () => {
    const calls = start("admin");
    fireEvent.change(await screen.findByLabelText("Exclusions"), { target: { value: "tout sauf la compta" } });
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer" }));
    expect(await screen.findByText(/Exclusions illisibles : tout sauf la compta/)).toBeTruthy();
    expect(calls.some((c) => c.key.startsWith("PATCH"))).toBe(false);
  });

  it("lets a viewer read only", async () => {
    start("viewer");
    expect(await screen.findByText(/réservés aux administrateurs/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Lancer maintenant" })).toBeNull();
    expect(((await screen.findByLabelText("Exclusions")) as HTMLTextAreaElement).disabled).toBe(true);
  });
});
