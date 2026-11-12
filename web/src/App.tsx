import type { ReactNode } from "react";
import { needsMfa, useAuth } from "./auth";
import { match, Redirect, useLocation } from "./router";
import { appPath, AppShell } from "./ui/AppShell";
import { OrgProvider, useOrg } from "./ui/OrgData";
import { ActifsPage } from "./ui/pages/Actifs";
import { AujourdhuiPage } from "./ui/pages/Aujourdhui";
import { ConnexionPage, InscriptionPage, MfaSetupPage, SetPasswordPage } from "./ui/pages/auth";
import { ProblemesPage } from "./ui/pages/Problemes";
import { ProfilPage } from "./ui/pages/Profil";
import { ConditionsPage, ConfidentialitePage, TraitementPage } from "./ui/pages/legal";
import { AccueilPage, PaiementPage, TarifsPage } from "./ui/pages/public";
import { RapportsPage } from "./ui/pages/Rapports";
import { ReglagesPage } from "./ui/pages/Reglages";
import { UIProvider } from "./ui/ui";

const VIEWS: Record<string, () => ReactNode> = {
  aujourdhui: () => <AujourdhuiPage />,
  problemes: () => <ProblemesPage />,
  actifs: () => <ActifsPage />,
  rapports: () => <RapportsPage />,
  reglages: () => <ReglagesPage />,
  profil: () => <ProfilPage />,
};

/** Paths of the previous dashboard, still reachable from old emails and bookmarks. */
const MOVED: Record<string, string> = { "/login": "/connexion", "/signup": "/inscription", "/forgot-password": "/connexion" };

function OrgView({ view }: { view: string }) {
  const { data, error } = useOrg();
  const render = VIEWS[view];
  return (
    <AppShell view={view}>
      {error ? <p className="err">{error}</p> : data && render ? render() : null}
    </AppShell>
  );
}

function Page({ children }: { children: ReactNode }) {
  return <UIProvider>{children}</UIProvider>;
}

export function App() {
  const { state } = useAuth();
  const { path } = useLocation();

  if (state.status === "loading") return null;
  const moved = MOVED[path];
  if (moved) return <Redirect to={moved + window.location.search} />;

  // Pages open to everyone.
  if (path === "/") return <Page><AccueilPage /></Page>;
  if (path === "/tarifs") return <Page><TarifsPage /></Page>;
  if (path === "/conditions") return <Page><ConditionsPage /></Page>;
  if (path === "/confidentialite") return <Page><ConfidentialitePage /></Page>;
  if (path === "/traitement-des-donnees") return <Page><TraitementPage /></Page>;
  if (path === "/setup-password") return <Page><SetPasswordPage kind="setup" /></Page>;
  if (path === "/signup/complete") return <Page><SetPasswordPage kind="signup" /></Page>;
  if (path === "/connexion") return state.status === "signed-in" ? <Redirect to="/app" /> : <Page><ConnexionPage /></Page>;
  if (path === "/inscription") return state.status === "signed-in" ? <Redirect to="/app" /> : <Page><InscriptionPage /></Page>;
  if (path === "/paiement") return <Page><PaiementPage /></Page>;
  if (state.status === "signed-out") return <Redirect to="/connexion" />;

  const me = state.me;
  // An admin without a second factor can do nothing else (the API would
  // answer 403 mfa_required everywhere).
  if (path === "/mfa/setup") return me.mfa_enabled && me.mfa_session ? <Redirect to="/app" /> : <Page><MfaSetupPage /></Page>;
  if (needsMfa(me)) return <Redirect to="/mfa/setup?reason=admin" />;

  if (path === "/app") {
    const first = me.orgs[0];
    return first ? (
      <Redirect to={appPath(first.org_id, "aujourdhui")} />
    ) : (
      <Page>
        <main>
          <p className="err">Votre compte n’appartient à aucune organisation. Demandez une invitation à votre administrateur.</p>
        </main>
      </Page>
    );
  }

  const params = match("/orgs/:org/:view", path) ?? match("/orgs/:org", path);
  const org = params && me.orgs.find((o) => o.org_id === params.org);
  if (!params || !org) return <Redirect to="/app" />;
  const view = params.view ?? "aujourdhui";
  if (!VIEWS[view]) return <Redirect to={appPath(org.org_id, "aujourdhui")} />;
  return (
    <OrgProvider key={org.org_id} me={me} org={org}>
      <UIProvider>
        <OrgView view={view} />
      </UIProvider>
    </OrgProvider>
  );
}
