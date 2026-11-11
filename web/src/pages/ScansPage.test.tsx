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
  id, domain, verified, verified_at: null, verify_checked_at: null, rate_per_sec: 5, exclusions: { paths: ["/admin"], ports: [3389] }, created_at: "", schedule: null,
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
  it("reproduces the mockup: profiles, every module, planning, intensity, history", async () => {
    start("admin");
    expect(await screen.findByText("Sécurité des emails")).toBeTruthy();
    for (const name of ["Rapide", "Standard", "Approfondi"]) expect(screen.getByRole("button", { name: new RegExp(name) })).toBeTruthy();
    expect(screen.getByRole("button", { name: /Standard/ }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByText("4 modules actifs")).toBeTruthy();
    // The mockup's nine modules plus the engine's CDN module.
    expect(document.querySelectorAll(".module")).toHaveLength(10);
    expect((screen.getByRole("button", { name: "Microsoft 365 : bientôt disponible" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("Intrusif")).toBeTruthy();
    for (const label of ["Fréquence", "Jour", "Heure"]) expect((screen.getByLabelText(label) as HTMLSelectElement).disabled).toBe(false);
    expect(screen.getByLabelText("Requêtes par seconde, par actif")).toBeTruthy();

    const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1);
    expect(rows[0]?.textContent).toContain("Standard");
    expect(rows[0]?.textContent).toContain("6 min");
    expect(rows[1]?.textContent).toContain("Rapide");

    // Profiles are clickable and change the modules.
    fireEvent.click(screen.getByRole("button", { name: /Rapide/ }));
    expect(screen.getByText("3 modules actifs")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Activer Ports et services" }).getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(screen.getByRole("button", { name: /Approfondi/ }));
    expect(screen.getByText(/Approfondi lance les mêmes modules que Standard/)).toBeTruthy();
  });

  it("groups a launch's scans and shows its real progress", async () => {
    const at = new Date(2026, 10, 10, 9, 0).toISOString();
    start("admin", {
      [`GET ${base}/scans?limit=20`]: ok({
        items: [
          scan("a", "running", ["cdn", "email", "ports", "tls"], { created_at: at, domain: "acme.example" }),
          scan("b", "done", ["cdn", "email", "ports", "tls"], { created_at: at, domain: "beta.example" }),
        ],
      }),
    });
    const rows = within(await screen.findByRole("table")).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.textContent).toContain("En cours · 50 %");
    expect(within(rows[0]!).getAllByRole("cell")[2]?.textContent).toBe("2");
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

  it("saves intensity and exclusions for every domain", async () => {
    const calls = start("admin", {
      [`PATCH ${base}/targets/t1`]: (body) => ({ status: 200, json: { ...target("t1", "acme.example", true), ...(body as object) } }),
      [`PATCH ${base}/targets/t2`]: (body) => ({ status: 200, json: { ...target("t2", "beta.example", false), ...(body as object) } }),
    });
    const excl = (await screen.findByLabelText("Exclusions")) as HTMLTextAreaElement;
    expect(excl.value).toBe("/admin\n3389");
    fireEvent.change(excl, { target: { value: "/admin\n3389\n192.0.2.10" } });
    fireEvent.change(screen.getByLabelText("Requêtes par seconde, par actif"), { target: { value: "50" } });
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer" }));
    expect(await screen.findByText("Configuration enregistrée")).toBeTruthy();
    const patches = calls.filter((c) => c.key.startsWith("PATCH"));
    expect(patches.map((c) => c.key)).toEqual([`PATCH ${base}/targets/t1`, `PATCH ${base}/targets/t2`]);
    expect(patches[0]?.body).toEqual({
      rate_per_sec: 50,
      exclusions: { ips: ["192.0.2.10"], ports: [3389], paths: ["/admin"], hosts: [] },
      // The mockup's defaults: weekly, Sunday, 02:00, in the browser's zone,
      // with the selected modules.
      schedule: { frequency: "weekly", weekday: 0, hour: 2, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, modules: ["cdn", "email", "ports", "tls"] },
    });
  });

  it("shows the saved schedule and the next run, and saves a change", async () => {
    const next = new Date(2026, 10, 12, 6, 0).toISOString();
    const planned = { ...target("t1", "acme.example", true), schedule: { frequency: "daily" as const, weekday: 0, hour: 6, timezone: "Africa/Douala", modules: ["email", "tls"], next_scan_at: next } };
    const calls = start("admin", {
      [`GET ${base}/targets`]: ok({ items: [planned] }),
      [`PATCH ${base}/targets/t1`]: (body) => ({ status: 200, json: { ...planned, ...(body as object), schedule: { ...(body as { schedule: object }).schedule, next_scan_at: next } } }),
    });
    expect(await screen.findByText(/Prochain scan planifié : jeudi 12\/11 à 06:00/)).toBeTruthy();
    expect((screen.getByLabelText("Fréquence") as HTMLSelectElement).value).toBe("daily");
    expect((screen.getByLabelText("Jour") as HTMLSelectElement).disabled).toBe(true); // daily: no day
    expect((screen.getByLabelText("Heure") as HTMLSelectElement).value).toBe("6");
    expect(screen.getByText("2 modules actifs")).toBeTruthy(); // the schedule's modules

    fireEvent.change(screen.getByLabelText("Fréquence"), { target: { value: "monthly" } });
    fireEvent.change(screen.getByLabelText("Jour"), { target: { value: "1" } });
    expect(screen.getByText(/Le premier lundi de chaque mois/)).toBeTruthy();
    expect((screen.getByRole("option", { name: /Continue/ }) as HTMLOptionElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer" }));
    expect(await screen.findByText("Configuration enregistrée")).toBeTruthy();
    const body = calls.find((c) => c.key === `PATCH ${base}/targets/t1`)?.body as { schedule: object };
    expect(body.schedule).toMatchObject({ frequency: "monthly", weekday: 1, hour: 6, modules: ["email", "tls"] });
  });

  it("says when nothing is scheduled yet", async () => {
    start("admin");
    expect(await screen.findByText(/Aucun scan planifié : enregistrez la configuration/)).toBeTruthy();
  });

  it("refuses unreadable exclusions before sending them", async () => {
    const calls = start("admin");
    fireEvent.change(await screen.findByLabelText("Exclusions"), { target: { value: "tout sauf la compta" } });
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer" }));
    expect(await screen.findByText(/Exclusions illisibles : tout sauf la compta/)).toBeTruthy();
    expect(calls.some((c) => c.key.startsWith("PATCH"))).toBe(false);
  });

  it("shows a viewer the same screen, with the buttons inactive", async () => {
    start("viewer");
    await screen.findByText("Sécurité des emails");
    const launch = screen.getByRole("button", { name: "Lancer maintenant" }) as HTMLButtonElement;
    const save = screen.getByRole("button", { name: "Enregistrer" }) as HTMLButtonElement;
    expect(launch.disabled && save.disabled).toBe(true);
    expect(launch.title).toBe("Réservé aux administrateurs");
    // Options stay clickable: they only change what is shown.
    fireEvent.click(screen.getByRole("button", { name: /Rapide/ }));
    expect(screen.getByText("3 modules actifs")).toBeTruthy();
  });
});
