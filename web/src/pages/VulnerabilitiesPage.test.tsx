import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding, Me } from "../api/types";
import { App } from "../App";
import { AuthProvider } from "../auth";
import { mockApi, ok, type Route } from "../test/fetch";

const ORG = "0193a1c4-0000-7000-8000-000000000001";
const base = `/orgs/${ORG}`;

const me = (role: "admin" | "viewer"): Me => ({
  user_id: "u1", email: `${role}@acme.example`, mfa_enabled: role === "admin", mfa_session: role === "admin",
  orgs: [{ org_id: ORG, org_name: "Acme", role }],
});

const daysAgo = (n: number) => new Date(Date.now() - n * 86400_000).toISOString();

function finding(id: string, severity: Finding["severity"], over: Partial<Finding> = {}): Finding {
  return {
    target_id: "t1", schema_version: "1", id, module_id: "email", check_id: id, target: "acme.example", asset: "acme.example",
    severity, title: `Title ${id}`, description: `Description ${id}`, evidence: `evidence ${id}`, remediation: [`Step one ${id}`, `Step two ${id}`],
    references: ["RFC 7489"], first_seen: daysAgo(2), last_seen: daysAgo(0), status: "open", ...over,
  };
}

const findings = [
  finding("dmarc", "medium", { first_seen: daysAgo(6) }),
  finding("spf-all", "critical", { first_seen: daysAgo(2) }),
  finding("tls-old", "high", { module_id: "tls", asset: "www.acme.example:443" }),
  finding("accepted", "low", { status: "accepted_risk" }),
  finding("gone", "critical", { status: "fixed" }),
  finding("cdn-info", "info", { module_id: "cdn" }),
];

function start(path: string, routes: Record<string, Route>) {
  const calls = mockApi(routes);
  window.history.replaceState(null, "", path);
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

const items = () => within(screen.getByRole("region", { name: "Liste des vulnérabilités" })).getAllByRole("button");

afterEach(() => vi.useRealTimers());

describe("VulnerabilitiesPage", () => {
  it("lists open findings by severity and shows the selected one", async () => {
    start(base + "/vulnerabilites", { "GET /auth/me": ok(me("viewer")), [`GET ${base}/findings`]: ok({ items: findings }) });
    await screen.findByRole("region", { name: "Liste des vulnérabilités" });
    // Fixed and info findings are not listed; accepted risks are, last by severity.
    expect(items().map((b) => b.querySelector(".list-title")?.textContent)).toEqual(["Title spf-all", "Title tls-old", "Title dmarc", "Title accepted"]);
    expect(screen.getByRole("button", { name: /Toutes 4/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: /Critiques 1/ })).toBeTruthy();

    const detail = screen.getByRole("region", { name: "Détail" });
    expect(within(detail).getByRole("heading", { name: "Title spf-all" })).toBeTruthy();
    expect(within(detail).getByText("Description spf-all")).toBeTruthy();
    expect(within(detail).getByText("Step two spf-all")).toBeTruthy();
    expect(within(detail).getByText("evidence spf-all")).toBeTruthy();
    // A viewer reads, does not act.
    expect(within(detail).queryByRole("button", { name: /revérifier/ })).toBeNull();
    expect(within(detail).getByText(/réservées aux administrateurs/)).toBeTruthy();

    fireEvent.click(items()[2]!);
    expect(within(screen.getByRole("region", { name: "Détail" })).getByRole("heading", { name: "Title dmarc" })).toBeTruthy();
    expect(new URLSearchParams(window.location.search).get("id")).toBe("dmarc");

    fireEvent.click(screen.getByRole("button", { name: /Élevées/ }));
    expect(items()).toHaveLength(1);
  });

  it("opens the finding named in the URL", async () => {
    start(base + "/vulnerabilites?id=tls-old", { "GET /auth/me": ok(me("viewer")), [`GET ${base}/findings`]: ok({ items: findings }) });
    const detail = await screen.findByRole("region", { name: "Détail" });
    expect(within(detail).getByRole("heading", { name: "Title tls-old" })).toBeTruthy();
    expect(within(detail).getByText(/TLS et certificats/)).toBeTruthy();
  });

  it("lets an admin accept a risk", async () => {
    let status: Finding["status"] = "open";
    const calls = start(base + "/vulnerabilites", {
      "GET /auth/me": ok(me("admin")),
      [`GET ${base}/findings`]: () => ({ status: 200, json: { items: [finding("spf-all", "critical", { status })] } }),
      [`PUT ${base}/targets/t1/findings/spf-all/status`]: (body) => {
        status = (body as { status: Finding["status"] }).status;
        return { status: 204 };
      },
    });
    fireEvent.click(await screen.findByRole("button", { name: "Accepter le risque" }));
    expect(await screen.findByRole("button", { name: "Retirer l’acceptation du risque" })).toBeTruthy();
    expect(calls.find((c) => c.key.startsWith("PUT"))?.body).toEqual({ status: "accepted_risk" });
  });

  it("re-checks with the finding's module and reports the scan's verdict", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let fixed = false;
    let polls = 0;
    const calls = start(base + "/vulnerabilites", {
      "GET /auth/me": ok(me("admin")),
      [`GET ${base}/findings`]: () => ({ status: 200, json: { items: [finding("spf-all", "critical", fixed ? { status: "fixed" } : {})] } }),
      [`POST ${base}/targets/t1/scans`]: ok({ id: "scan-1", status: "queued" }),
      [`GET ${base}/scans/scan-1`]: () => {
        if (++polls < 2) return { status: 200, json: { id: "scan-1", status: "running" } };
        fixed = true;
        return { status: 200, json: { id: "scan-1", status: "done" } };
      },
    });
    fireEvent.click(await screen.findByRole("button", { name: "J’ai corrigé, revérifier" }));
    expect(await screen.findByText(/Vérification en cours/)).toBeTruthy();
    await act(() => vi.advanceTimersByTimeAsync(7000));
    expect(await screen.findByText(/Corrigée : le scan ne détecte plus ce problème/)).toBeTruthy();
    // Only the finding's module is scanned again.
    expect(calls.find((c) => c.key.startsWith("POST"))?.body).toEqual({ modules: ["email"] });
  });

  it("says when nothing is open", async () => {
    start(base + "/vulnerabilites", { "GET /auth/me": ok(me("viewer")), [`GET ${base}/findings`]: ok({ items: [finding("gone", "high", { status: "fixed" })] }) });
    expect(await screen.findByRole("heading", { name: "Aucune vulnérabilité ouverte" })).toBeTruthy();
  });
});
