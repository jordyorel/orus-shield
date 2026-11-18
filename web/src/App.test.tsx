import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding, Me, OrgSettings, Overview, Plan, Subscription } from "./api/types";
import { api } from "./api/client";
import { App } from "./App";
import { LangProvider, Relang, setLangForTests } from "./i18n";
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
  lang: "",
};

const plans: Plan[] = [
  { id: "discovery", name: "Gratuit", domains: 1, hosts_per_scan: 5, members: 1, active_modules: false, monitoring: false, max_frequency: "", alerts: false, reports: false, threats: false, deep_scans: false, deep_scans_per_month: 0, api_scans: false, auth_scans: false, agents: false, usd_monthly: 0, usd_yearly: 0, on_quote: false },
  { id: "sme", name: "Essentiel", domains: 3, hosts_per_scan: 25, members: 3, active_modules: true, monitoring: true, max_frequency: "weekly", alerts: true, reports: true, threats: true, deep_scans: false, deep_scans_per_month: 0, api_scans: false, auth_scans: false, agents: false, usd_monthly: 35, usd_yearly: 29, on_quote: false },
  { id: "pro", name: "Pro", domains: 15, hosts_per_scan: 25, members: 10, active_modules: true, monitoring: true, max_frequency: "daily", alerts: true, reports: true, threats: true, deep_scans: true, deep_scans_per_month: 4, api_scans: true, auth_scans: true, agents: false, usd_monthly: 99, usd_yearly: 79, on_quote: false },
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

const subscription: Subscription = { plan: plans[1]!, status: "trialing", until: "2026-11-26T00:00:00Z", in_grace: false, lapsed: false, usage: { domains: 1, members: 1, deep_scans: 0 }, trial_available: false, period: "", plans };

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
    <LangProvider>
      <AuthProvider>
        <Relang>
          <App />
        </Relang>
      </AuthProvider>
    </LangProvider>,
  );
}

describe("public site", () => {
  it("shows real prices on Tarifs, cards and PayPal only", async () => {
    mockApi({ "GET /auth/me": fail(401), "GET /plans": ok({ items: plans }) });
    renderAt("/tarifs");
    expect(await screen.findByText("35 $")).toBeTruthy();
    expect(screen.getByText("99 $")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "FCFA" })).toBeNull();
    expect(screen.queryByText(/Mobile Money/)).toBeNull();
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

  it("shows the authenticator key as a QR code, with the key beside it", async () => {
    const uri = "otpauth://totp/Orus%20Shield:jordy%40example.cg?secret=2N72MPVIUIADZTAL46RZJOLASC2CFP37&issuer=Orus%20Shield";
    mockApi({
      "GET /auth/me": ok({ ...me, mfa_enabled: false, mfa_session: false }),
      "POST /auth/mfa/setup": ok({ secret: "2N72MPVIUIADZTAL46RZJOLASC2CFP37", otpauth_uri: uri }),
    });
    renderAt("/mfa/setup?reason=admin");
    fireEvent.change(await screen.findByLabelText(/Mot de passe de/), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Continuer" }));
    const qr = await screen.findByRole("img", { name: /Code QR/ });
    expect(qr.querySelector("path")?.getAttribute("d")).toMatch(/^M\d/);
    expect(screen.getByText("2N72MPVIUIADZTAL46RZJOLASC2CFP37")).toBeTruthy();
    expect(screen.getByRole("link", { name: /ouvrir l’application/ }).getAttribute("href")).toBe(uri);
  });

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

  it("shows the trial in the summary only when the organization still has it", async () => {
    mockApi({ "GET /auth/me": ok(me), "GET /plans": ok({ items: plans }), [`GET /orgs/${ORG}/subscription`]: ok({ ...subscription, trial_available: true }) });
    const view = renderAt(`/paiement?offre=sme&org=${ORG}`);
    expect(await screen.findByText(/rien n’est prélevé avant le/)).toBeTruthy();
    view.unmount();
    mockApi({ "GET /auth/me": ok(me), "GET /plans": ok({ items: plans }), [`GET /orgs/${ORG}/subscription`]: ok(subscription) });
    renderAt(`/paiement?offre=sme&org=${ORG}`);
    expect(await screen.findByText(/Sans engagement : l’abonnement s’arrête/)).toBeTruthy();
    expect(screen.queryByText(/rien n’est prélevé/)).toBeNull();
  });

  it("opens the payment of the offer chosen before signing up", async () => {
    // This test environment has no localStorage: a small one in memory.
    const kept = new Map<string, string>([["orus.offer", "pro"]]);
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => kept.get(k) ?? null,
      setItem: (k: string, v: string) => void kept.set(k, v),
      removeItem: (k: string) => void kept.delete(k),
    });
    mockApi({ "GET /auth/me": ok(me), "GET /plans": ok({ items: plans }) });
    renderAt("/app");
    await waitFor(() => expect(window.location.pathname + window.location.search).toBe("/paiement?offre=pro"));
    expect(kept.has("orus.offer")).toBe(false); // once only
    vi.unstubAllGlobals();
    act(() => navigate("/"));
  });

  it("confirms the payment when Paddle sends the customer back", async () => {
    mockApi({ "GET /auth/me": ok(me), "GET /plans": ok({ items: plans }) });
    renderAt("/paiement?statut=ok");
    expect(await screen.findByText("Paiement reçu, merci.")).toBeTruthy();
  });

  it("takes a signed-in customer who picks an offer to its payment", async () => {
    mockApi({ "GET /auth/me": ok(me), "GET /plans": ok({ items: plans }) });
    renderAt("/inscription?offre=pro");
    await waitFor(() => expect(window.location.pathname + window.location.search).toBe("/paiement?offre=pro"));
    act(() => navigate("/"));
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

describe("language", () => {
  afterEach(() => setLangForTests("fr"));

  it("signs in in English when English is the language", async () => {
    setLangForTests("en");
    mockApi({ "GET /auth/me": fail(401) });
    renderAt("/connexion");
    expect(await screen.findByText("Welcome back.")).toBeTruthy();
    expect(screen.getByLabelText("Email address")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
  });

  it("switches the public site to English from the top of the page", async () => {
    const calls = mockApi({ "GET /auth/me": fail(401), "GET /plans": ok({ items: plans }) });
    renderAt("/tarifs");
    fireEvent.click(await screen.findByRole("button", { name: "English" }));
    expect(await screen.findByText("A simple price, paid the way you like.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "English" }).getAttribute("aria-pressed")).toBe("true");
    expect(calls.some((c) => c.key.startsWith("PATCH"))).toBe(false); // signed out: kept in this browser only
  });

  it("saves the language on the account when signed in", async () => {
    const calls = mockApi({ "GET /auth/me": ok(me), "GET /plans": ok({ items: plans }), "PATCH /auth/me": ok({ ...me, lang: "en" }) });
    renderAt("/tarifs");
    const en = await screen.findByRole("button", { name: "English" });
    await act(async () => {
      fireEvent.click(en);
    });
    expect(calls.find((c) => c.key === "PATCH /auth/me")?.body).toEqual({ lang: "en" });
    expect(await screen.findByText("My dashboard")).toBeTruthy();
    // Requests carry the language on screen: the API writes emails in it.
    expect(calls[0]?.lang).toBe("fr");
    await api.plans();
    expect(calls.at(-1)?.lang).toBe("en");
  });

  it("follows the language chosen in Profil once signed in", async () => {
    orgRoutes({ "GET /auth/me": ok({ ...me, lang: "en" }) });
    renderAt(`/orgs/${ORG}/aujourdhui`);
    expect((await screen.findAllByText("Problems")).length).toBeGreaterThan(0);
    expect(screen.queryByText("Problèmes")).toBeNull();
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
    await waitFor(() => expect(screen.getByText("Marqué comme corrigé : +9 points, vérification en cours")).toBeTruthy());
  });

  describe("problems, scans and verification", () => {
    const tlsAt = (id: string, asset: string): Finding => ({
      ...dmarc, id, module_id: "tls", check_id: "tls-cert-untrusted", asset, title: "Certificate is not trusted by browsers", severity: "high",
    });
    const two = { [`GET /orgs/${ORG}/findings`]: ok({ items: [tlsAt("c1", "example.cg:443"), tlsAt("c2", "www.example.cg:443")] }) };

    it("shows the same problem on two names as one line, fixed in one gesture", async () => {
      const calls = orgRoutes({
        ...two,
        [`PUT /orgs/${ORG}/targets/t1/findings/c1/status`]: () => ({ status: 204 }),
        [`PUT /orgs/${ORG}/targets/t1/findings/c2/status`]: () => ({ status: 204 }),
      });
      renderAt(`/orgs/${ORG}/problemes`);
      const checks = await screen.findAllByRole("button", { name: "Marquer « Certificate is not trusted by browsers » comme corrigé" });
      expect(checks).toHaveLength(1);
      expect(screen.getByText("example.cg, www.example.cg")).toBeTruthy();
      expect(screen.getByText(/nous relançons aussitôt un contrôle/)).toBeTruthy();
      await act(async () => {
        fireEvent.click(checks[0]!);
      });
      await waitFor(() => expect(calls.filter((c) => c.key.startsWith("PUT")).map((c) => c.key)).toHaveLength(2));
    });

    it("follows the verification and says when the problem is still there", async () => {
      let scans = 0;
      let after = false;
      orgRoutes({
        [`GET /orgs/${ORG}/findings`]: () => ({ status: 200, json: { items: [{ ...dmarc, status: after ? "open" : "open" }] } }),
        [`PUT /orgs/${ORG}/targets/t1/findings/f1/status`]: () => {
          after = true;
          return { status: 204 };
        },
        [`GET /orgs/${ORG}/scans?limit=20`]: () => {
          scans++;
          const running = after && scans < 3;
          return { status: 200, json: { items: running ? [{ id: "v1", target_id: "t1", domain: "example.cg", modules: ["email"], requested_by: "u", status: "running", attempts: 1, created_at: "", started_at: "", finished_at: null }] : [] } };
        },
      });
      vi.useFakeTimers({ shouldAdvanceTime: true });
      try {
        renderAt(`/orgs/${ORG}/problemes`);
        const check = await screen.findByRole("button", { name: "Marquer « No DMARC record » comme corrigé" });
        await act(async () => {
          fireEvent.click(check);
        });
        expect(await screen.findByText("Vérification en cours…")).toBeTruthy();
        await vi.advanceTimersByTimeAsync(12_000);
        expect(await screen.findByText(/Toujours présent au contrôle de/)).toBeTruthy();
      } finally {
        vi.useRealTimers();
      }
    });

    it("says when the domains were scanned, and scans now", async () => {
      const calls = orgRoutes({
        [`GET /orgs/${ORG}/scans?limit=20`]: ok({ items: [{ id: "s1", target_id: "t1", domain: "example.cg", modules: [], requested_by: "u", status: "done", attempts: 1, created_at: "", started_at: "", finished_at: new Date().toISOString() }] }),
        [`POST /orgs/${ORG}/targets/t1/scans`]: ok({ id: "s2", target_id: "t1", domain: "example.cg", modules: [], requested_by: "u", status: "queued", attempts: 0, created_at: "", started_at: null, finished_at: null }),
      });
      renderAt(`/orgs/${ORG}/aujourdhui`);
      expect(await screen.findByText(/Dernier scan : aujourd’hui à/)).toBeTruthy();
      expect(screen.getByText(/Aucun scan planifié/)).toBeTruthy();
      await act(async () => {
        fireEvent.click(screen.getByRole("button", { name: "Scanner maintenant" }));
      });
      expect(calls.some((c) => c.key === `POST /orgs/${ORG}/targets/t1/scans`)).toBe(true);
    });

    it("shows a problem in French when the finding carries its translation", async () => {
      const fr = {
        ...dmarc,
        translations: { fr: { title: "Aucun enregistrement DMARC", description: "Le domaine ne publie aucune politique DMARC.", remediation: ["Publiez un enregistrement DMARC."] } },
        remediation: ["Publish a DMARC record."],
      };
      orgRoutes({ [`GET /orgs/${ORG}/findings`]: ok({ items: [fr] }) });
      renderAt(`/orgs/${ORG}/problemes?id=f1`);
      expect(await screen.findByRole("heading", { name: "Aucun enregistrement DMARC" })).toBeTruthy();
      expect(screen.getByText("Le domaine ne publie aucune politique DMARC.")).toBeTruthy();
      expect(screen.getByText("Publiez un enregistrement DMARC.")).toBeTruthy();
      expect(screen.queryByText("No DMARC record")).toBeNull();
    });

    it("prepares the problem for the customer's provider, in the language chosen for it", async () => {
      const fr = {
        ...dmarc,
        translations: { fr: { title: "Aucun enregistrement DMARC", description: "Le domaine ne publie aucune politique DMARC.", remediation: ["Publiez un enregistrement DMARC."] } },
        remediation: ["Publish a DMARC record."],
      };
      orgRoutes({ [`GET /orgs/${ORG}/findings`]: ok({ items: [fr] }) });
      renderAt(`/orgs/${ORG}/problemes?id=f1`);
      expect(await screen.findByRole("heading", { name: "Envoyer à mon prestataire" })).toBeTruthy();
      const wa = () => new URL(screen.getByRole("link", { name: "WhatsApp" }).getAttribute("href") ?? "").searchParams.get("text") ?? "";
      expect(wa()).toContain("1. Publiez un enregistrement DMARC.");
      expect(screen.getByRole("link", { name: "Email" }).getAttribute("href")).toMatch(/^mailto:\?subject=/);
      fireEvent.click(screen.getByRole("button", { name: "English" }));
      expect(wa()).toContain("1. Publish a DMARC record.");
      expect(wa()).toContain("Thank you,\nJordy Konda");
      // The dashboard itself stays in French.
      expect(screen.getByRole("heading", { name: "Aucun enregistrement DMARC" })).toBeTruthy();
    });

    it("shows a sheet large on demand, and keeps it so", async () => {
      orgRoutes();
      renderAt(`/orgs/${ORG}/problemes?id=f1`);
      fireEvent.click(await screen.findByRole("button", { name: "Agrandir" }));
      expect(document.querySelector(".sheet.wide")).toBeTruthy();
      fireEvent.click(screen.getByRole("button", { name: "Réduire" }));
      expect(document.querySelector(".sheet.wide")).toBeNull();
    });

    it("shows the trial's days left, and opens a problem from an email link", async () => {
      orgRoutes();
      renderAt(`/orgs/${ORG}/problemes?id=f1`);
      expect(await screen.findByRole("link", { name: /Essai Essentiel : \d+ jours? restants?/ })).toBeTruthy();
      expect(await screen.findByRole("heading", { name: "No DMARC record" })).toBeTruthy();
    });
  });

  describe("after the free audit", () => {
    const free: Subscription = { ...subscription, plan: plans[0]!, status: "active", until: null, trial_available: true };

    it("offers the trial instead of marking a problem fixed, and says Gratuit is a single audit", async () => {
      const calls = orgRoutes({}, free);
      renderAt(`/orgs/${ORG}/aujourdhui`);
      expect(await screen.findByText(/Offre Gratuit : audit unique/)).toBeTruthy();
      fireEvent.click(await screen.findByRole("button", { name: "Marquer « No DMARC record » comme fait" }));
      expect(await screen.findByText("Faisons vérifier votre correction")).toBeTruthy();
      expect(calls.some((c) => c.key.startsWith("PUT"))).toBe(false);
    });

    it("shows the offer page with the audit's own figures and the trial", async () => {
      orgRoutes({}, free);
      renderAt(`/orgs/${ORG}/offre`);
      expect(await screen.findByText("Votre audit est prêt. Voici la suite.")).toBeTruthy();
      expect(screen.getByText("No DMARC record", { selector: "b" })).toBeTruthy();
      const trial = screen.getAllByRole("link", { name: "Essayer 14 jours" })[0]!;
      expect(trial.getAttribute("href")).toBe(`/paiement?offre=sme&org=${ORG}`);
    });

    it("leads from the first scan's closing screen to the offer", async () => {
      const kept = new Map<string, string>([[`orus.onboard.${ORG}`, "shown"]]);
      vi.stubGlobal("localStorage", {
        getItem: (k: string) => kept.get(k) ?? null,
        setItem: (k: string, v: string) => void kept.set(k, v),
        removeItem: (k: string) => void kept.delete(k),
      });
      orgRoutes({}, free);
      renderAt(`/orgs/${ORG}/aujourdhui`);
      fireEvent.click(await screen.findByRole("button", { name: "Voir mes résultats" }));
      expect(await screen.findByText("Votre audit est prêt. Voici la suite.")).toBeTruthy();
      expect(window.location.pathname).toBe(`/orgs/${ORG}/offre`);
    });

    it("turns a refused fix (audit used) into the offer", async () => {
      // The offer in the browser is stale (paid), the API knows better.
      const calls = orgRoutes({ [`PUT /orgs/${ORG}/targets/t1/findings/f1/status`]: fail(403, "single audit", "audit_used") });
      renderAt(`/orgs/${ORG}/problemes`);
      const check = await screen.findByRole("button", { name: "Marquer « No DMARC record » comme corrigé" });
      await act(async () => {
        fireEvent.click(check);
      });
      expect(await screen.findByText("Faisons vérifier votre correction")).toBeTruthy();
      expect(calls.some((c) => c.key.startsWith("PUT"))).toBe(true);
    });
  });

  it("records the subscription on the return from Paddle, without waiting for the webhook", async () => {
    let asks = 0;
    const calls = mockApi({
      "GET /auth/me": ok(me),
      "GET /plans": ok({ items: plans }),
      [`GET /orgs/${ORG}/subscription`]: ok(subscription),
      [`POST /orgs/${ORG}/billing/sync`]: () => ({ status: 200, json: { state: ++asks < 2 ? "pending" : "active" } }),
    });
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      renderAt(`/paiement?statut=ok&org=${ORG}&txn=txn_42`);
      expect(await screen.findByText("Activation de votre offre en cours…")).toBeTruthy();
      await vi.advanceTimersByTimeAsync(3000);
      expect(await screen.findByText("C’est activé, merci.")).toBeTruthy();
      expect(calls.find((c) => c.key === `POST /orgs/${ORG}/billing/sync`)?.body).toEqual({ transaction_id: "txn_42" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("unsubscribes from reminders with the link's token, after a click", async () => {
    const calls = mockApi({ "GET /auth/me": fail(401, "no session"), "POST /unsubscribe": () => ({ status: 204 }) });
    renderAt("/desinscription#token=tok-1");
    fireEvent.click(await screen.findByRole("button", { name: "Me désinscrire" }));
    expect(await screen.findByText("C’est fait.")).toBeTruthy();
    expect(calls.find((c) => c.key === "POST /unsubscribe")?.body).toEqual({ token: "tok-1" });
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

  describe("Premiers pas, before the first scan", () => {
    const base = `/orgs/${ORG}`;
    const empty = { [`GET ${base}/findings`]: ok({ items: [] }), [`GET ${base}/assets`]: ok({ items: [] }), [`GET ${base}/activity?days=7&limit=10`]: ok({ items: [] }) };
    const target = (verified: boolean) => ({ id: "t2", domain: "oruslabs.cg", verified, verified_at: null, verify_checked_at: null, rate_per_sec: 0, exclusions: {}, created_at: "", schedule: null });

    it("guides a new organization to its domain instead of an empty picture", async () => {
      orgRoutes({ ...empty, [`GET ${base}/targets`]: ok({ items: [] }) });
      renderAt(`${base}/aujourdhui`);
      expect(await screen.findByText("Premiers pas")).toBeTruthy();
      expect(screen.getByText(/Bienvenue/)).toBeTruthy();
      expect(screen.getByLabelText("Nom de domaine")).toBeTruthy();
      expect(screen.getByRole("img", { name: "1 étape faite sur 4" })).toBeTruthy();
      expect(screen.queryByText("À faire aujourd’hui")).toBeNull();
      expect(document.querySelector("#radar")).toBeNull();
    });

    it("opens the TXT record of a domain waiting for verification", async () => {
      orgRoutes({
        ...empty,
        [`GET ${base}/targets`]: ok({ items: [target(false)] }),
        [`POST ${base}/targets/t2/verification`]: ok({ domain: "oruslabs.cg", record_name: "_orus-verify.oruslabs.cg", record_type: "TXT", record_value: "orus-verify=abc", expires_at: null, verified: false }),
      });
      renderAt(`${base}/aujourdhui`);
      expect(await screen.findByText("orus-verify=abc")).toBeTruthy();
      expect(screen.getByText(/Plus qu’une étape/)).toBeTruthy();
      expect(screen.getByText("Il démarre dès que le domaine est vérifié.")).toBeTruthy();
    });

    it("checks the record again by itself until it appears, and names the Host field", async () => {
      let tries = 0;
      const calls = orgRoutes({
        ...empty,
        [`GET ${base}/targets`]: ok({ items: [target(false)] }),
        [`POST ${base}/targets/t2/verification`]: ok({ domain: "oruslabs.cg", record_name: "_orus-verify.oruslabs.cg", record_type: "TXT", record_value: "orus-verify=abc", expires_at: null, verified: false }),
        [`POST ${base}/targets/t2/verify`]: () => (++tries < 2 ? { status: 422, json: { error: "not found yet" } } : { status: 200, json: target(true) }),
      });
      vi.useFakeTimers({ shouldAdvanceTime: true });
      try {
        renderAt(`${base}/aujourdhui`);
        await screen.findByText("orus-verify=abc");
        expect(screen.getByText("_orus-verify", { selector: "b" })).toBeTruthy();
        fireEvent.click(screen.getByRole("button", { name: "Vérifier maintenant" }));
        expect(await screen.findByText(/réessayons automatiquement/)).toBeTruthy();
        await vi.advanceTimersByTimeAsync(30_000);
        expect(await screen.findByText("oruslabs.cg est vérifié")).toBeTruthy();
        expect(calls.filter((c) => c.key.endsWith("/verify"))).toHaveLength(2);
      } finally {
        vi.useRealTimers();
      }
    });

    it("ends with a closing screen for a customer who saw the card, then the results", async () => {
      // This test environment has no localStorage: a small one in memory.
      const kept = new Map<string, string>([[`orus.onboard.${ORG}`, "shown"]]);
      vi.stubGlobal("localStorage", {
        getItem: (k: string) => kept.get(k) ?? null,
        setItem: (k: string, v: string) => void kept.set(k, v),
        removeItem: (k: string) => void kept.delete(k),
      });
      orgRoutes({});
      renderAt(`${base}/aujourdhui`);
      expect(await screen.findByText("Votre premier scan est terminé.")).toBeTruthy();
      expect(screen.getByRole("img", { name: "4 étapes faites sur 4" })).toBeTruthy();
      fireEvent.click(screen.getByRole("button", { name: "Voir mes résultats" }));
      expect(await screen.findByText("À faire aujourd’hui")).toBeTruthy();
      expect(kept.get(`orus.onboard.${ORG}`)).toBe("closed");
    });

    it("waits for the first scan once the domain is verified", async () => {
      orgRoutes({
        ...empty,
        [`GET ${base}/targets`]: ok({ items: [target(true)] }),
        [`GET ${base}/scans?limit=20`]: ok({ items: [{ id: "s1", target_id: "t2", domain: "oruslabs.cg", modules: [], requested_by: "u1", status: "running", attempts: 1, created_at: "", started_at: "", finished_at: null }] }),
      });
      renderAt(`${base}/aujourdhui`);
      expect(await screen.findByText("Votre premier scan est lancé.")).toBeTruthy();
      expect(screen.getByText(/En cours/)).toBeTruthy();
      expect(screen.queryByLabelText("Nom de domaine")).toBeNull();
    });
  });

  it("shows a canceled subscription's end, never a next charge", async () => {
    const canceled: Subscription = { ...subscription, status: "canceled" };
    orgRoutes({ [`GET /orgs/${ORG}/members`]: ok({ items: [] }) }, canceled);
    renderAt(`/orgs/${ORG}/reglages`);
    expect(await screen.findByText(/Abonnement annulé : il se termine le/)).toBeTruthy();
    expect(screen.queryByText(/Prochaine échéance/)).toBeNull();
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
