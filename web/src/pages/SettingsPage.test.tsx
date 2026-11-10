import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Me, Member } from "../api/types";
import { App } from "../App";
import { AuthProvider } from "../auth";
import { fail, mockApi, ok, type Route } from "../test/fetch";

const ORG = "0193a1c4-0000-7000-8000-000000000001";
const base = `/orgs/${ORG}`;

const me = (role: "admin" | "viewer"): Me => ({
  user_id: "u1", email: `${role}@acme.example`, mfa_enabled: role === "admin", mfa_session: role === "admin",
  orgs: [{ org_id: ORG, org_name: "Acme", role }],
});

const members: Member[] = [
  { user_id: "u1", email: "admin@acme.example", role: "admin", activated: true, mfa_enabled: true },
  { user_id: "u2", email: "it@acme.example", role: "viewer", activated: false, mfa_enabled: false },
];

function start(role: "admin" | "viewer", tab: string, routes: Record<string, Route> = {}) {
  const calls = mockApi({ "GET /auth/me": ok(me(role)), [`GET ${base}/members`]: ok({ items: members }), ...routes });
  window.history.replaceState(null, "", `${base}/parametres?onglet=${tab}`);
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

describe("SettingsPage", () => {
  it("changes the password from the profile", async () => {
    const calls = start("viewer", "profil", { "POST /auth/password": () => ({ status: 204 }) });
    expect(await screen.findByText("viewer@acme.example", { selector: "dd" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Mot de passe actuel"), { target: { value: "correct horse battery staple" } });
    fireEvent.change(screen.getByLabelText("Nouveau mot de passe"), { target: { value: "another long passphrase" } });
    fireEvent.change(screen.getByLabelText("Confirmez"), { target: { value: "another long passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: "Changer le mot de passe" }));
    expect(await screen.findByText(/Mot de passe changé/)).toBeTruthy();
    expect(calls.find((c) => c.key === "POST /auth/password")?.body).toEqual({
      current_password: "correct horse battery staple",
      new_password: "another long passphrase",
    });
    // MFA off: the profile offers to turn it on.
    expect(screen.getByRole("link", { name: "Activer la double authentification" })).toBeTruthy();
  });

  it("says when the current password is wrong", async () => {
    start("viewer", "profil", { "POST /auth/password": fail(403, "invalid email or password") });
    fireEvent.change(await screen.findByLabelText("Mot de passe actuel"), { target: { value: "wrong" } });
    fireEvent.change(screen.getByLabelText("Nouveau mot de passe"), { target: { value: "another long passphrase" } });
    fireEvent.change(screen.getByLabelText("Confirmez"), { target: { value: "another long passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: "Changer le mot de passe" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Mot de passe actuel incorrect.");
  });

  it("invites a member and shows the setup code once", async () => {
    const calls = start("admin", "equipe", {
      [`POST ${base}/members`]: ok({ member: { user_id: "u3", email: "dg@acme.example", role: "viewer", activated: false, mfa_enabled: false }, setup_token: "tok-123" }),
    });
    await screen.findByText("it@acme.example");
    expect(screen.getByText("Invitation en attente")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Inviter un membre" }));
    fireEvent.change(screen.getByLabelText("Adresse e-mail"), { target: { value: "dg@acme.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Inviter" }));
    expect(await screen.findByText("Code d’activation pour dg@acme.example")).toBeTruthy();
    expect(screen.getByText("tok-123")).toBeTruthy();
    expect(calls.find((c) => c.key === `POST ${base}/members`)?.body).toEqual({ email: "dg@acme.example", role: "viewer" });
  });

  it("explains that the last admin stays", async () => {
    start("admin", "equipe", { [`PUT ${base}/members/u1/role`]: fail(409, "keep an admin", "last_admin") });
    const select = await screen.findByLabelText("Rôle de admin@acme.example");
    fireEvent.change(select, { target: { value: "viewer" } });
    expect(await screen.findByText("L’organisation doit garder au moins un administrateur.")).toBeTruthy();
  });

  it("lets a viewer see the team without acting", async () => {
    start("viewer", "equipe");
    const table = await screen.findByRole("table");
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    expect(screen.queryByRole("button", { name: "Inviter un membre" })).toBeNull();
    expect(within(table).queryByRole("combobox")).toBeNull();
  });

  it("shows the mockup's other tabs as coming", async () => {
    start("viewer", "abonnement");
    expect(await screen.findByText("Bientôt disponible")).toBeTruthy();
    expect(screen.getAllByRole("tab")).toHaveLength(7);
  });
});
