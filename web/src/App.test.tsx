import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Finding, Me, OrgSettings, Overview, Plan, Subscription } from "./api/types";
import { App } from "./App";
import { AuthProvider } from "./auth";
import { navigate } from "./router";
import { fail, mockApi, ok } from "./test/fetch";

const ORG = "o1";

const me: Me = {
  user_id: "u1",
  email: "jordy@example.cg",
  mfa_enabled: true,
  mfa_session: true,
  orgs: [{ org_id: ORG, org_name: "Microfinance Exemple SA", role: "admin" }],
  name: "Jordy Konda",
  password_changed_at: "2026-08-01T00:00:00Z",
  recovery_codes_left: 8,
};

const plans: Plan[] = [
  { id: "discovery", name: "Gratuit", domains: 1, hosts_per_scan: 5, members: 1, active_modules: false, max_frequency: "monthly", alerts: false, reports: false, threats: false, deep_scans: false, deep_scans_per_month: 0, api_scans: false, auth_scans: false, agents: false, usd_monthly: 0, usd_yearly: 0, xaf_monthly: 0, xaf_yearly: 0, on_quote: false },
  { id: "sme", name: "Essentiel", domains: 3, hosts_per_scan: 25, members: 3, active_modules: true, max_frequency: "weekly", alerts: true, reports: true, threats: true, deep_scans: false, deep_scans_per_month: 0, api_scans: false, auth_scans: false, agents: false, usd_monthly: 35, usd_yearly: 29, xaf_monthly: 20000, xaf_yearly: 16500, on_quote: false },
  { id: "pro", name: "Pro", domains: 15, hosts_per_scan: 25, members: 10, active_modules: true, max_frequency: "daily", alerts: true, reports: true, threats: true, deep_scans: true, deep_scans_per_month: 4, api_scans: true, auth_scans: true, agents: false, usd_monthly: 99, usd_yearly: 79, xaf_monthly: 57000, xaf_yearly: 45500, on_quote: false },
];

const overview: Overview = {
  days: 84,
  targets: 1,
  verified_targets: 1,
  open_findings: { high: 1 },
  assets: 2,
  new_assets: 0,
  score: 74,
  score_change: 2,
  trend: [
    { at: "2026-10-01T00:00:00Z", score: 60 },
    { at: new Date().toISOString(), score: 74 },
  ],
  remediation: { fixed: 0, mean_seconds: null, previous_fixed: 0, previous_mean_seconds: null },
  priorities: [],
  per_target: [],
};

const dmarc: Finding = {
  target_id: "t1",
  schema_version: "1",
  id: "f1",
  module_id: "email",
  check_id: "dmarc-missing",
  target: "example.cg",
  asset: "_dmarc.example.cg",
  severity: "high",
  title: "No DMARC record",
  description: "Anyone can send email as you.",
  evidence: "_dmarc.example.cg: no TXT record",
  remediation: ["Publish a DMARC record."],
  references: null,
  first_seen: "2026-11-01T00:00:00Z",
  last_seen: "2026-11-11T00:00:00Z",
  status: "open",
  category: "email",
  minutes: 15,
  gain: 9,
  emerging: false,
};

const settings: OrgSettings = { alert_level: "high", email_alerts: true, profile: "standard", disabled_modules: [], frequency: "weekly", weekday: 6, hour: 2, timezone: "UTC", rate_per_sec: 0, deep_consent_at: null };

const subscription: Subscription = { plan: plans[1]!, status: "trialing", until: "2026-11-26T00:00:00Z", in_grace: false, lapsed: false, usage: { domains: 1, members: 1, deep_scans: 0 }, plans };

function orgRoutes(extra: Record<string, ReturnType<typeof ok>> = {}, sub: Subscription = subscription) {
  const base = `/orgs/${ORG}`;
  return mockApi({
    "GET /auth/me": ok(me),
    [`GET ${base}/overview?days=84`]: ok(overview),
    [`GET ${base}/findings`]: ok({ items: [dmarc] }),
    [`GET ${base}/assets`]: ok({
      items: [{ target_id: "t1", domain: "example.cg", id: "a1", kind: "hostname", value: "example.cg", details: {}, sources: ["dns"], first_seen: "", last_seen: "", gone_at: null }],
    }),
    [`GET ${base}/checks`]: ok({ items: [] }),
    [`GET ${base}/targets`]: ok({ items: [{ id: "t1", domain: "example.cg", verified: true, verified_at: "", verify_checked_at: "", rate_per_sec: 0, exclusions: {}, created_at: "", schedule: null }] }),
    [`GET ${base}/subscription`]: ok(sub),
    [`GET ${base}/settings`]: ok(settings),
    [`GET ${base}/activity?days=7&limit=10`]: ok({
      items: [{ kind: "finding", at: new Date().toISOString(), target_id: "t1", domain: "example.cg", finding_id: "f1", title: "No DMARC record", asset: "_dmarc.example.cg", severity: "high", to: "open" }],
    }),
    [`GET ${base}/scans?limit=20`]: ok({ items: [] }),
    [`GET ${base}/targets/t1/apis`]: ok({ items: [] }),
    [`GET ${base}/agents`]: ok({ items: [] }),
    [`GET ${base}/targets/t1/credential`]: fail(404, "no test account"),
    ...extra,
  });
}

function renderAt(path: string) {
  window.history.replaceState(null, "", path);
  return render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
}

describe("public site", () => {
  it("shows real prices on Tarifs, greyed payment means", async () => {
    mockApi({ "GET /auth/me": fail(401), "GET /plans": ok({ items: plans }) });
    renderAt("/tarifs");
    expect(await screen.findByText("35 $")).toBeTruthy();
    expect(screen.getByText("99 $")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "FCFA" }));
    expect(screen.getByText(/20\s000 FCFA/)).toBeTruthy();
  });

  // signedIn: whether the browser keeps the session cookie (the second
  // GET /auth/me, after login).
  const loginRoutes = (cookieKept: boolean) => {
    let meCalls = 0;
    return mockApi({
      "GET /auth/me": () => (++meCalls > 1 && cookieKept ? { status: 200, json: me } : { status: 401, json: { error: "not logged in" } }),
      "POST /auth/login": ok({ mfa_required: true, mfa_token: "mt" }),
      "POST /auth/login/mfa": ok(me),
    });
  };
  const loginWithCode = async () => {
    renderAt("/connexion");
    fireEvent.change(await screen.findByLabelText("Adresse email"), { target: { value: "jordy@example.cg" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Se connecter" }));
    const first = await screen.findByLabelText("Chiffre 1");
    fireEvent.paste(first, { clipboardData: { getData: () => "123456" } });
  };

  it("shows the legal pages, marked as drafts", async () => {
    for (const [path, title] of [
      ["/conditions", "Conditions d’utilisation"],
      ["/confidentialite", "Politique de confidentialité"],
      ["/traitement-des-donnees", "Accord de traitement des données"],
    ] as const) {
      mockApi({ "GET /auth/me": fail(401) });
      const view = renderAt(path);
      expect(await screen.findByRole("heading", { level: 1, name: title })).toBeTruthy();
      expect(screen.getByText(/à faire valider par un juriste/)).toBeTruthy();
      expect(screen.getAllByRole("link", { name: "Confidentialité" })[0]?.getAttribute("href")).toBe("/confidentialite");
      view.unmount();
    }
  });

  it("starts a card payment through our API, for the chosen offer", async () => {
    const calls = mockApi({
      "GET /auth/me": ok(me),
      "GET /plans": ok({ items: plans }),
      [`POST /orgs/${ORG}/checkout`]: ok({ transaction_id: "txn_1", client_token: "test_tok", environment: "sandbox", email: me.email }),
    });
    renderAt(`/paiement?offre=pro&org=${ORG}`);
    fireEvent.click(await screen.findByRole("button", { name: "À l’année, jusqu’à 20 % de moins" }));
    fireEvent.click(screen.getByRole("button", { name: "Continuer vers le paiement sécurisé" }));
    await waitFor(() => expect(calls.some((c) => c.key === `POST /orgs/${ORG}/checkout`)).toBe(true));
    expect(calls.find((c) => c.key === `POST /orgs/${ORG}/checkout`)?.body).toEqual({ plan: "pro", period: "yearly" });
    // No card field of ours: Paddle's form goes in its frame.
    expect(screen.queryByLabelText("Numéro de carte")).toBeNull();
  });

  it("confirms the payment when Paddle sends the customer back", async () => {
    mockApi({ "GET /auth/me": ok(me), "GET /plans": ok({ items: plans }) });
    renderAt("/paiement?statut=ok");
    expect(await screen.findByText("Paiement reçu, merci.")).toBeTruthy();
  });

  it("logs in with a 6-digit code", async () => {
    const calls = loginRoutes(true);
    await loginWithCode();
    await waitFor(() => expect(window.location.pathname).toBe(`/orgs/${ORG}/aujourdhui`));
    expect(calls.find((c) => c.key === "POST /auth/login/mfa")?.body).toEqual({ mfa_token: "mt", code: "123456" });
    act(() => navigate("/"));
  });

  it("says so when the browser refuses the session cookie (Safari on http://localhost)", async () => {
    loginRoutes(false);
    await loginWithCode();
    expect(await screen.findByText(/refusé le cookie de session/)).toBeTruthy();
    expect(window.location.pathname).toBe("/connexion");
  });
});

describe("dashboard", () => {
  it("greets the user and lists the actions of the day", async () => {
    orgRoutes();
    renderAt(`/orgs/${ORG}/aujourdhui`);
    expect(await screen.findByText("Bonjour Jordy")).toBeTruthy();
    expect(screen.getByText("Plus qu’une action pour aujourd’hui.")).toBeTruthy();
    expect(screen.getAllByText("No DMARC record").length).toBeGreaterThan(0);
    expect(screen.getByText("+9 pts")).toBeTruthy();
    expect(screen.getByText("74")).toBeTruthy();
  });

  it("marks a problem fixed through the API", async () => {
    const calls = orgRoutes({ [`PUT /orgs/${ORG}/targets/t1/findings/f1/status`]: () => ({ status: 204 }) });
    renderAt(`/orgs/${ORG}/problemes`);
    const check = await screen.findByRole("button", { name: "Marquer « No DMARC record » comme corrigé" });
    await act(async () => {
      fireEvent.click(check);
    });
    expect(calls.find((c) => c.key.startsWith("PUT"))?.body).toEqual({ status: "fixed" });
    await waitFor(() => expect(screen.getByText("Marqué comme corrigé : +9 points")).toBeTruthy());
  });

  it("ticks an action of the day at once, keeps it in place, and undoes it if refused", async () => {
    let answer: (v: Response) => void = () => {};
    orgRoutes();
    const real = globalThis.fetch;
    globalThis.fetch = ((input: string, init?: RequestInit) =>
      init?.method === "PUT" ? new Promise<Response>((r) => (answer = r)) : real(input, init)) as typeof fetch;
    renderAt(`/orgs/${ORG}/aujourdhui`);
    const check = await screen.findByRole("button", { name: "Marquer « No DMARC record » comme fait" });
    fireEvent.click(check);
    // Green before the API answers, same row.
    expect(check.getAttribute("aria-pressed")).toBe("true");
    expect(check.closest("li")?.className).toBe("done");
    expect(screen.getByText("Tout est fait pour aujourd’hui.")).toBeTruthy();
    await act(async () => {
      answer(new Response(JSON.stringify({ error: "x" }), { status: 500, headers: { "Content-Type": "application/json" } }));
    });
    await waitFor(() => expect(check.getAttribute("aria-pressed")).toBe("false"));
  });

  it("goes back from a problem to its asset in the side sheet", async () => {
    orgRoutes();
    renderAt(`/orgs/${ORG}/aujourdhui`);
    // A dot of the radar opens its asset, with its open problems.
    fireEvent.click(await screen.findByRole("button", { name: /example\.cg : 1 problème/ }));
    const sheet = document.getElementById("sheet-title")!.closest("aside")!;
    await waitFor(() => expect(sheet.querySelector("#sheet-title")?.textContent).toBe("example.cg"));
    expect(sheet.querySelector(".back")).toBeNull();
    // A problem of the list replaces it, with a way back.
    fireEvent.click(sheet.querySelector(".rowmain")!);
    await waitFor(() => expect(sheet.querySelector("#sheet-title")?.textContent).toBe("No DMARC record"));
    fireEvent.click(sheet.querySelector(".back")!);
    await waitFor(() => expect(sheet.querySelector("#sheet-title")?.textContent).toBe("example.cg"));
    expect(sheet.querySelector(".back")).toBeNull();
  });

  it("opens a problem's sheet with its steps and proof", async () => {
    orgRoutes();
    renderAt(`/orgs/${ORG}/problemes`);
    const title = (await screen.findAllByText("No DMARC record")).find((el) => el.closest(".rowmain"));
    fireEvent.click(title!.closest(".rowmain")!);
    expect(await screen.findByText("Publish a DMARC record.")).toBeTruthy();
    expect(screen.getByText("_dmarc.example.cg: no TXT record")).toBeTruthy();
  });

  it("saves Réglages for the organization", async () => {
    const calls = orgRoutes({ [`PUT /orgs/${ORG}/settings`]: (b) => ({ status: 200, json: b }), [`GET /orgs/${ORG}/members`]: ok({ items: [] }) });
    renderAt(`/orgs/${ORG}/reglages`);
    fireEvent.click(await screen.findByRole("button", { name: "Critique seulement" }));
    await waitFor(() => expect(calls.some((c) => c.key === `PUT /orgs/${ORG}/settings`)).toBe(true));
    expect((calls.find((c) => c.key === `PUT /orgs/${ORG}/settings`)?.body as OrgSettings).alert_level).toBe("critical");
    expect(screen.getByText(/Offre Essentiel/)).toBeTruthy();
    expect(screen.getByText(/Essai gratuit jusqu’au/)).toBeTruthy();
  });

  it("asks for consent before the deep profile", async () => {
    const pro: Subscription = { ...subscription, plan: plans[2]!, status: "active", until: null };
    const calls = orgRoutes(
      {
        [`PUT /orgs/${ORG}/settings`]: (b) => ({ status: 200, json: { ...(b as OrgSettings), deep_consent_at: "2026-11-12T18:00:00Z" } }),
        [`GET /orgs/${ORG}/members`]: ok({ items: [] }),
      },
      pro,
    );
    renderAt(`/orgs/${ORG}/reglages`);
    fireEvent.click(await screen.findByRole("button", { name: /Approfondi/ }));
    const activate = await screen.findByRole("button", { name: "Activer le profil approfondi" });
    fireEvent.click(activate);
    expect(screen.getByText("Cochez la case pour confirmer votre autorisation.")).toBeTruthy();
    expect(calls.some((c) => c.key.startsWith("PUT"))).toBe(false);
    fireEvent.click(screen.getByLabelText(/Je confirme être autorisé/));
    fireEvent.click(activate);
    await waitFor(() => expect(calls.some((c) => c.key === `PUT /orgs/${ORG}/settings`)).toBe(true));
    const body = calls.find((c) => c.key === `PUT /orgs/${ORG}/settings`)?.body as OrgSettings;
    expect(body.profile).toBe("deep");
    expect(body.deep_consent).toBe(true);
  });

  it("declares an API on a domain", async () => {
    const pro: Subscription = { ...subscription, plan: plans[2]!, status: "active", until: null };
    const calls = orgRoutes(
      {
        [`GET /orgs/${ORG}/members`]: ok({ items: [] }),
        [`POST /orgs/${ORG}/targets/t1/apis`]: (b) => ({ status: 201, json: { ...(b as object), id: "a1", target_id: "t1", created_at: "", created_by: "x" } }),
      },
      pro,
    );
    renderAt(`/orgs/${ORG}/reglages`);
    fireEvent.click(await screen.findByRole("button", { name: "Ajouter une API" }));
    fireEvent.change(screen.getByLabelText("Nom"), { target: { value: "Clients" } });
    fireEvent.change(screen.getByLabelText("Adresse de base de l’API"), { target: { value: "https://api.example.cg/v1" } });
    fireEvent.change(screen.getByLabelText(/Adresse de la spécification OpenAPI/), { target: { value: "https://api.example.cg/openapi.json" } });
    fireEvent.click(screen.getByRole("button", { name: "Ajouter" }));
    await waitFor(() => expect(calls.some((c) => c.key === `POST /orgs/${ORG}/targets/t1/apis`)).toBe(true));
    expect(calls.find((c) => c.key === `POST /orgs/${ORG}/targets/t1/apis`)?.body).toEqual({
      name: "Clients",
      kind: "openapi",
      base_url: "https://api.example.cg/v1",
      spec_url: "https://api.example.cg/openapi.json",
    });
  });

  it("stores a test account with consent, and never shows its secret", async () => {
    const pro: Subscription = { ...subscription, plan: plans[2]!, status: "active", until: null };
    const calls = orgRoutes(
      {
        [`GET /orgs/${ORG}/members`]: ok({ items: [] }),
        [`PUT /orgs/${ORG}/targets/t1/credential`]: () => ({ status: 200, json: { kind: "header", header_name: "Authorization", created_at: "", created_by: "x" } }),
      },
      pro,
    );
    renderAt(`/orgs/${ORG}/reglages`);
    fireEvent.click(await screen.findByRole("button", { name: "Ajouter un compte de test" }));
    fireEvent.change(screen.getByLabelText(/Valeur \(par exemple/), { target: { value: "Bearer s3cret" } });
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer le compte de test" }));
    expect(screen.getByText("Cochez la case pour confirmer qu’il s’agit d’un compte de test.")).toBeTruthy();
    expect(calls.some((c) => c.key.startsWith("PUT"))).toBe(false);
    fireEvent.click(screen.getByLabelText(/Je confirme que c’est un compte de test/));
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer le compte de test" }));
    await waitFor(() => expect(calls.some((c) => c.key === `PUT /orgs/${ORG}/targets/t1/credential`)).toBe(true));
    expect(calls.find((c) => c.key.startsWith("PUT"))?.body).toEqual({ kind: "header", header_name: "Authorization", header_value: "Bearer s3cret", consent: true });
    await waitFor(() => expect(screen.getByText(/en-tête Authorization/)).toBeTruthy());
    expect(screen.queryByText(/s3cret/)).toBeNull();
  });

  it("creates an internal network and shows its one-time code", async () => {
    const quote: Subscription = { ...subscription, plan: { ...plans[2]!, id: "enterprise", name: "Sur devis", agents: true }, status: "active", until: null };
    const agent = { id: "ag1", target_id: "t9", name: "Siège", ranges: ["192.168.1.0/24"], enroll_expires_at: "", enrolled_at: null, last_seen_at: null, revoked_at: null, created_at: "", created_by: "x" };
    const calls = orgRoutes({ [`POST /orgs/${ORG}/agents`]: () => ({ status: 201, json: { agent, enrolment_code: "CODE-123" } }) }, quote);
    renderAt(`/orgs/${ORG}/actifs`);
    fireEvent.click(await screen.findByRole("button", { name: "Ajouter un réseau interne" }));
    fireEvent.change(screen.getByLabelText(/Nom \(le site/), { target: { value: "Siège" } });
    fireEvent.change(screen.getByLabelText(/Plages d’adresses privées/), { target: { value: "192.168.1.0/24, 10.0.0.0/24" } });
    fireEvent.click(screen.getByRole("button", { name: "Créer et obtenir le code" }));
    await waitFor(() => expect(calls.some((c) => c.key === `POST /orgs/${ORG}/agents`)).toBe(true));
    expect(calls.find((c) => c.key === `POST /orgs/${ORG}/agents`)?.body).toEqual({ name: "Siège", ranges: ["192.168.1.0/24", "10.0.0.0/24"] });
    expect(await screen.findByText("CODE-123")).toBeTruthy();
    expect(screen.getByText(/orus-agent enroll -api .* -code CODE-123/)).toBeTruthy();
  });

  it("sends an unknown screen back to Aujourd'hui", async () => {
    orgRoutes();
    renderAt(`/orgs/${ORG}/nope`);
    await waitFor(() => expect(window.location.pathname).toBe(`/orgs/${ORG}/aujourdhui`));
    act(() => navigate("/"));
  });
});
