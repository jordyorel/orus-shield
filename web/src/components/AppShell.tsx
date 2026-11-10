import type { ReactNode } from "react";
import type { Me, Membership } from "../api/types";
import { useAuth } from "../auth";
import { initial } from "../format";
import { Link, navigate } from "../router";
import { Logo } from "./Logo";
import { orgPath, sections } from "./nav";

interface AppShellProps {
  me: Me;
  org: Membership;
  /** Current section path ("" for the overview). */
  section: string;
  title: string;
  /** Controls on the right of the title (period selector, buttons). */
  actions?: ReactNode;
  children: ReactNode;
}

const roleLabel = (r: Membership["role"]) => (r === "admin" ? "Administrateur" : "Lecteur");

/** AppShell is the application layout of the mockups: sidebar, header, content. */
export function AppShell({ me, org, section, title, actions, children }: AppShellProps) {
  const { signOut } = useAuth();
  const logout = async () => {
    await signOut();
    navigate("/login?ok=logout", { replace: true });
  };
  return (
    <div className="app">
      <aside className="sidebar">
        <Link className="brand" to={orgPath(org.org_id)}>
          <Logo />
          <span className="brand-name">Orus Shield</span>
        </Link>
        <nav className="nav" aria-label="Application">
          {sections.map((s) => (
            <Link key={s.path} to={orgPath(org.org_id, s.path)} aria-current={s.path === section ? "page" : undefined}>
              {s.icon}
              {s.label}
            </Link>
          ))}
        </nav>
        {me.orgs.length > 1 && (
          <div className="side-section">
            <p className="side-title" id="orgs-title">
              Organisations
            </p>
            <nav className="nav" aria-labelledby="orgs-title">
              {me.orgs.map((o) => (
                <Link key={o.org_id} to={orgPath(o.org_id)} aria-current={o.org_id === org.org_id ? "page" : undefined}>
                  {o.org_name}
                </Link>
              ))}
            </nav>
          </div>
        )}
        <div className="side-card">
          <p className="title">{me.email}</p>
          <p className="sub">
            {roleLabel(org.role)} · {org.org_name}
          </p>
          <button type="button" className="link-button" onClick={logout}>
            Se déconnecter
          </button>
        </div>
      </aside>
      <main className="main">
        <div className="page-header">
          <div>
            <p className="org">{org.org_name}</p>
            <h1>{title}</h1>
          </div>
          <div className="header-actions">
            {actions}
            <span className="avatar" title={me.email} aria-hidden="true">
              {initial(me.email)}
            </span>
          </div>
        </div>
        <div className="content">{children}</div>
      </main>
    </div>
  );
}
