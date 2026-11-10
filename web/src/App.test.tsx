import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Me, Overview } from "./api/types";
import { App } from "./App";
import { AuthProvider } from "./auth";
import { fail, mockApi, ok } from "./test/fetch";

const ORG = "0193a1c4-0000-7000-8000-000000000001";

const viewer: Me = {
  user_id: "u1", email: "viewer@acme.example", mfa_enabled: false, mfa_session: false,
  orgs: [{ org_id: ORG, org_name: "Acme", role: "viewer" }],
};
const adminNoMfa: Me = { ...viewer, email: "admin@acme.example", orgs: [{ org_id: ORG, org_name: "Acme", role: "admin" }] };

const daysAgo = (n: number) => new Date(Date.now() - n * 86400_000).toISOString();

function overview(days = 30): Overview {
  return {
    days, targets: 2, verified_targets: 0, open_findings: { critical: 1, info: 3 }, assets: 5, new_assets: 2,
    score: 60, score_change: 27,
    trend: Array.from({ length: days + 1 }, (_, i) => ({ at: daysAgo(days - i), score: i < days - 3 ? null : 60 })),
    remediation: { fixed: 1, mean_seconds: 2 * 86400, previous_fixed: 1, previous_mean_seconds: 3.8 * 86400 },
    priorities: [
      { kind: "finding", target_id: "b", domain: "beta.example", finding_id: "f1", severity: "critical", title: "SPF allows every server to send mail", asset: "beta.example", first_seen: daysAgo(2) },
      { kind: "verify_target", target_id: "a", domain: "acme.example" },
    ],
    per_target: [
      { id: "a", domain: "acme.example", verified: false, last_scan_at: daysAgo(1), stale: false, open_findings: {}, posture_score: 100, current_assets: 3 },
      { id: "b", domain: "beta.example", verified: true, last_scan_at: daysAgo(2), stale: false, open_findings: { critical: 1 }, posture_score: 38, current_assets: 2 },
    ],
  };
}

function start(path: string) {
  window.history.replaceState(null, "", path);
  return render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
}

describe("App", () => {
  it("sends a signed-out visitor to the login page", async () => {
    mockApi({ "GET /auth/me": fail(401) });
    start("/orgs/" + ORG);
    expect(await screen.findByRole("heading", { name: "Connexion" })).toBeTruthy();
    expect(window.location.pathname).toBe("/login");
  });

  it("logs in with a second factor", async () => {
    let codeTries = 0;
    const calls = mockApi({
      "GET /auth/me": fail(401),
      "POST /auth/login": ok({ mfa_required: true, mfa_token: "challenge-1" }),
      "POST /auth/login/mfa": () => (++codeTries === 1 ? { status: 401, json: { error: "invalid code" } } : { status: 200, json: viewer }),
      [`GET /orgs/${ORG}/overview?days=30`]: ok(overview()),
    });
    start("/login");
    fireEvent.change(await screen.findByLabelText("Adresse e-mail"), { target: { value: "viewer@acme.example" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "correct horse battery staple" } });
    fireEvent.click(screen.getByRole("button", { name: "Se connecter" }));

    fireEvent.change(await screen.findByLabelText("Code"), { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Vérifier" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("Code incorrect"));

    fireEvent.change(screen.getByLabelText("Code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Vérifier" }));
    expect(await screen.findByRole("heading", { name: "Vue d'ensemble" })).toBeTruthy();
    expect(window.location.pathname).toBe("/orgs/" + ORG);
    // The MFA token went in the request body, never in a URL.
    expect(calls.filter((c) => c.key === "POST /auth/login/mfa").at(-1)?.body).toEqual({ mfa_token: "challenge-1", code: "123456" });
  });

  it("goes back to the password when the MFA login expired", async () => {
    mockApi({
      "GET /auth/me": fail(401),
      "POST /auth/login": ok({ mfa_required: true, mfa_token: "old" }),
      "POST /auth/login/mfa": fail(401, "login expired, sign in again", "login_expired"),
    });
    start("/login");
    fireEvent.change(await screen.findByLabelText("Adresse e-mail"), { target: { value: "a@acme.example" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "correct horse battery staple" } });
    fireEvent.click(screen.getByRole("button", { name: "Se connecter" }));
    fireEvent.change(await screen.findByLabelText("Code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Vérifier" }));
    expect(await screen.findByText(/La vérification a expiré/)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Connexion" })).toBeTruthy();
  });

  it("shows one message for every bad credential", async () => {
    mockApi({ "GET /auth/me": fail(401), "POST /auth/login": fail(401, "invalid email or password") });
    start("/login");
    fireEvent.change(await screen.findByLabelText("Adresse e-mail"), { target: { value: "nobody@acme.example" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "wrong password!!" } });
    fireEvent.click(screen.getByRole("button", { name: "Se connecter" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Adresse e-mail ou mot de passe incorrect.");
  });

  it("says when the API cannot be reached", async () => {
    mockApi({ "GET /auth/me": fail(401), "POST /auth/login": fail(502) });
    start("/login");
    fireEvent.change(await screen.findByLabelText("Adresse e-mail"), { target: { value: "a@acme.example" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "correct horse battery staple" } });
    fireEvent.click(screen.getByRole("button", { name: "Se connecter" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/Le serveur ne répond pas/);
  });

  it("sends an admin without a second factor to enrolment", async () => {
    mockApi({ "GET /auth/me": ok(adminNoMfa) });
    start("/orgs/" + ORG);
    expect(await screen.findByRole("heading", { name: "Activer la double authentification" })).toBeTruthy();
    expect(screen.getByText(/exige la double authentification/)).toBeTruthy();
  });

  it("enrols a second factor and shows the recovery codes once", async () => {
    const codes = Array.from({ length: 10 }, (_, i) => `AAAA-BBBB-CCCC-DDD${i}`);
    mockApi({
      "GET /auth/me": ok(adminNoMfa),
      "POST /auth/mfa/setup": ({ password }: any) =>
        password === "right password!!" ? { status: 200, json: { secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Orus%20Shield:a?secret=X" } } : { status: 403, json: { error: "invalid email or password" } },
      "POST /auth/mfa/confirm": ok({ recovery_codes: codes }),
    });
    start("/mfa/setup");
    fireEvent.change(await screen.findByLabelText("Confirmez votre mot de passe"), { target: { value: "wrong" } });
    fireEvent.click(screen.getByRole("button", { name: "Continuer" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Mot de passe incorrect.");

    fireEvent.change(screen.getByLabelText("Confirmez votre mot de passe"), { target: { value: "right password!!" } });
    fireEvent.click(screen.getByRole("button", { name: "Continuer" }));
    expect((await screen.findByLabelText("Clé secrète")).textContent).toBe("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP");
    expect(screen.getByRole("link", { name: /Ouvrir directement/ }).getAttribute("href")).toMatch(/^otpauth:\/\//);

    fireEvent.change(screen.getByLabelText(/Code à 6 chiffres/), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Activer" }));
    const list = await screen.findByRole("list", { name: "Codes de secours" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(10);
  });

  it("renders the overview from computed figures only", async () => {
    const calls = mockApi({
      "GET /auth/me": ok(viewer),
      [`GET /orgs/${ORG}/overview?days=30`]: ok(overview(30)),
      [`GET /orgs/${ORG}/overview?days=7`]: ok(overview(7)),
    });
    start("/orgs/" + ORG);
    expect(await screen.findByText("+27 points")).toBeTruthy();
    expect(screen.getByText("60")).toBeTruthy();
    expect(screen.getByText("dont 1 critique")).toBeTruthy(); // info findings are not vulnerabilities
    expect(screen.getByText("2,0 j")).toBeTruthy();
    expect(screen.getByText("−1,8 j")).toBeTruthy(); // faster than the previous period
    expect(screen.getByText("2 nouveaux en 30 jours")).toBeTruthy();
    expect(screen.getByText("SPF allows every server to send mail")).toBeTruthy();
    expect(screen.getByText("Vérifier la propriété de acme.example")).toBeTruthy();
    expect(screen.getAllByText("Bientôt disponible")).toHaveLength(3); // compliance: no invented figures

    // Most exposed first: beta (38) before acme (100).
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]?.textContent).toContain("beta.example");
    expect(rows[1]?.textContent).toContain("acme.example");

    // Every entry of the mockup's menu is there.
    expect(within(screen.getByRole("navigation", { name: "Application" })).getAllByRole("link")).toHaveLength(9);

    fireEvent.click(screen.getByRole("button", { name: "7 j" }));
    await waitFor(() => expect(calls.some((c) => c.key.endsWith("days=7"))).toBe(true));
    expect(await screen.findByText("2 nouveaux en 7 jours")).toBeTruthy();
  });

  it("opens the screens not built yet as coming soon", async () => {
    mockApi({ "GET /auth/me": ok(viewer) });
    start(`/orgs/${ORG}/actifs`);
    expect(await screen.findByRole("heading", { name: "Actifs" })).toBeTruthy();
    expect(screen.getByText("Bientôt disponible")).toBeTruthy();
  });

  it("does not open another organization", async () => {
    mockApi({ "GET /auth/me": ok(viewer) });
    start("/orgs/0193a1c4-0000-7000-8000-00000000ffff");
    expect(await screen.findByRole("heading", { name: "Page introuvable" })).toBeTruthy();
  });
});
