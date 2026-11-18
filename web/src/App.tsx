import { useEffect, type ReactNode } from "react";
import { tr, useLang } from "./i18n";
import { needsMfa, useAuth } from "./auth";
import { match, Redirect, useLocation } from "./router";
import { appPath, AppShell } from "./ui/AppShell";
import { OrgProvider, useOrg } from "./ui/OrgData";
import { ActifsPage } from "./ui/pages/Actifs";
import { AujourdhuiPage } from "./ui/pages/Aujourdhui";
import { TestPage } from "./ui/pages/quicktest";
import { ConnexionPage, InscriptionPage, MfaSetupPage, SetPasswordPage, takeOffer, UnsubscribePage } from "./ui/pages/auth";
import { OffrePage } from "./ui/pages/Offre";
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
  // Not a tab: the trial offer after the free audit.
  offre: () => <OffrePage />,
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
  const { lang, setLang } = useLang();
  // Signed in with a language chosen in Profil: the whole site speaks it.
  const chosen = state.status === "signed-in" ? state.me.lang : "";
  useEffect(() => {
    if (chosen && chosen !== lang) setLang(chosen);
  }, [chosen, lang, setLang]);

  if (state.status === "loading") return null;
  const moved = MOVED[path];
  if (moved) return <Redirect to={moved + window.location.search} />;

  // Pages open to everyone.
  if (path === "/") return <Page><AccueilPage /></Page>;
  if (path === "/tarifs") return <Page><TarifsPage /></Page>;
  // The public test is for visitors: a signed-in customer's domains are
  // tested in depth on their dashboard.
  if (path === "/test") return state.status === "signed-in" ? <Redirect to="/app" /> : <Page><TestPage /></Page>;
  if (path === "/conditions") return <Page><ConditionsPage /></Page>;
  if (path === "/confidentialite") return <Page><ConfidentialitePage /></Page>;
  if (path === "/traitement-des-donnees") return <Page><TraitementPage /></Page>;
  if (path === "/setup-password") return <Page><SetPasswordPage kind="setup" /></Page>;
  if (path === "/signup/complete") return <Page><SetPasswordPage kind="signup" /></Page>;
  if (path === "/connexion") return state.status === "signed-in" ? <Redirect to="/app" /> : <Page><ConnexionPage /></Page>;
  if (path === "/inscription") {
    // A signed-in customer who picks an offer on Tarifs ("Essayer 14 jours")
    // already has an account: take them to the payment of that offer.
    const offer = new URLSearchParams(window.location.search).get("offre");
    if (state.status === "signed-in") return <Redirect to={offer === "sme" || offer === "pro" ? `/paiement?offre=${offer}` : "/app"} />;
    return <Page><InscriptionPage /></Page>;
  }
  if (path === "/paiement") return <Page><PaiementPage /></Page>;
  if (path === "/desinscription") return <Page><UnsubscribePage /></Page>;
  if (state.status === "signed-out") return <Redirect to="/connexion" />;

  const me = state.me;
  // An admin without a second factor can do nothing else (the API would
  // answer 403 mfa_required everywhere).
  if (path === "/mfa/setup") return me.mfa_enabled && me.mfa_session ? <Redirect to="/app" /> : <Page><MfaSetupPage /></Page>;
  if (needsMfa(me)) return <Redirect to="/mfa/setup?reason=admin" />;

  if (path === "/app") {
    // An offer chosen on Tarifs before signing up: its payment (and trial)
    // comes first, for the organization's admin.
    const offer = me.orgs.some((o) => o.role === "admin") ? takeOffer() : "";
    if (offer) return <Redirect to={`/paiement?offre=${offer}`} />;
    const first = me.orgs[0];
    return first ? (
      <Redirect to={appPath(first.org_id, "aujourdhui")} />
    ) : (
      <Page>
        <main>
          <p className="err">
            {tr(
              "Votre compte n’appartient à aucune organisation. Demandez une invitation à votre administrateur.",
              "Your account belongs to no organization. Ask your administrator for an invitation.",
            )}
          </p>
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
