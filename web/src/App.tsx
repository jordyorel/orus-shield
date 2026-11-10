import { needsMfa, useAuth } from "./auth";
import { sections } from "./components/nav";
import { LoginPage } from "./pages/LoginPage";
import { MfaSetupPage } from "./pages/MfaSetupPage";
import { AssetsPage } from "./pages/AssetsPage";
import { ComingSoonPage, NoOrgPage, NotFoundPage } from "./pages/OtherPages";
import { OverviewPage } from "./pages/OverviewPage";
import { ScansPage } from "./pages/ScansPage";
import { SettingsPage } from "./pages/SettingsPage";
import { SetupPasswordPage } from "./pages/SetupPasswordPage";
import { VulnerabilitiesPage } from "./pages/VulnerabilitiesPage";
import { match, Redirect, useLocation } from "./router";

export function App() {
  const { state } = useAuth();
  const { path } = useLocation();

  if (state.status === "loading") return null;

  // Pages open to everyone.
  if (path === "/setup-password") return <SetupPasswordPage />;
  if (path === "/login") return state.status === "signed-in" ? <Redirect to="/" /> : <LoginPage />;
  if (state.status === "signed-out") return <Redirect to="/login" />;

  const me = state.me;
  // An admin without a second factor can do nothing else (the API would
  // answer 403 mfa_required everywhere).
  if (path === "/mfa/setup") return me.mfa_enabled ? <Redirect to="/" /> : <MfaSetupPage />;
  if (needsMfa(me)) return <Redirect to="/mfa/setup?reason=admin" />;

  if (path === "/") {
    const first = me.orgs[0];
    return first ? <Redirect to={"/orgs/" + encodeURIComponent(first.org_id)} /> : <NoOrgPage me={me} />;
  }

  const params = match("/orgs/:org", path) ?? match("/orgs/:org/:section", path);
  const org = params && me.orgs.find((o) => o.org_id === params.org);
  if (!params || !org) return <NotFoundPage />;
  const section = params.section ?? "";
  if (section === "") return <OverviewPage key={org.org_id} me={me} org={org} />;
  if (section === "parametres") return <SettingsPage key={org.org_id} me={me} org={org} />;
  if (section === "scans") return <ScansPage key={org.org_id} me={me} org={org} />;
  if (section === "actifs") return <AssetsPage key={org.org_id} me={me} org={org} />;
  if (section === "vulnerabilites") return <VulnerabilitiesPage key={org.org_id} me={me} org={org} />;
  if (sections.some((s) => s.path === section)) return <ComingSoonPage me={me} org={org} section={section} />;
  return <NotFoundPage />;
}
