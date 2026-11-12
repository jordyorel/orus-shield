import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError, reportURL } from "../api/client";
import type { Me, Member, Membership, Role } from "../api/types";
import { useAuth } from "../auth";
import { AppShell } from "../components/AppShell";
import { Alert } from "../components/AuthLayout";
import { orgPath } from "../components/nav";
import { Link, navigate, useLocation } from "../router";
import { fallback, msg, PASSWORD_MIN_LENGTH } from "./messages";

// Settings (docs/design/Settings.dc.html) with a Profile tab first. Profile
// and Team work; the mockup's other tabs say what they will hold.

const TABS = [
  { id: "profil", label: "Profil" },
  { id: "notifications", label: "Notifications" },
  { id: "integrations", label: "Intégrations" },
  { id: "equipe", label: "Équipe" },
  { id: "rapports", label: "Rapports" },
  { id: "api", label: "API" },
  { id: "abonnement", label: "Abonnement" },
] as const;

const UPCOMING: Record<string, { title: string; text: string }> = {
  notifications: { title: "Règles d’alerte", text: "Choisissez quel canal reçoit quelles alertes (email, WhatsApp, Slack, SMS), avec des heures calmes sauf pour les alertes critiques." },
  integrations: { title: "Intégrations", text: "WhatsApp Business, email, Slack, Microsoft Teams, Jira et webhook pour recevoir les alertes et créer des tickets." },
  api: { title: "Clés d’API", text: "Pour intégrer les résultats dans vos propres outils." },
  abonnement: { title: "Abonnement", text: "Offre, actifs inclus et moyen de paiement : carte, PayPal ou Mobile Money (MTN, Airtel, Orange Money, M-Pesa, Wave)." },
};

const roleLabel = (r: Role) => (r === "admin" ? "Administrateur" : "Lecteur");

export function SettingsPage({ me, org }: { me: Me; org: Membership }) {
  const { search } = useLocation();
  const tab = TABS.find((t) => t.id === search.get("onglet"))?.id ?? "profil";
  const pick = (id: string) => navigate(`${orgPath(org.org_id, "parametres")}?onglet=${id}`, { replace: true });

  return (
    <AppShell me={me} org={org} section="parametres" title="Paramètres">
      <div className="pills tabs" role="tablist" aria-label="Sections">
        {TABS.map((t) => (
          <button key={t.id} type="button" role="tab" aria-selected={tab === t.id} aria-pressed={tab === t.id} onClick={() => pick(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      <div className="content">
        {tab === "profil" && <Profile me={me} org={org} />}
        {tab === "equipe" && <Team me={me} org={org} />}
        {tab === "rapports" && <Reports org={org} />}
        {UPCOMING[tab] && (
          <section className="card empty">
            <h2>{UPCOMING[tab].title}</h2>
            <p>{UPCOMING[tab].text}</p>
            <p className="card-note soon">Bientôt disponible</p>
          </section>
        )}
      </div>
    </AppShell>
  );
}

/** The mockup's automatic reports, not sent yet. */
const AUTOMATIC = [
  { name: "Rapport mensuel pour la direction", desc: "Score, évolution et priorités, sans jargon technique." },
  { name: "Rapport technique après chaque scan", desc: "Détails, preuves et étapes de correction." },
  { name: "Rapport de conformité trimestriel", desc: "Correspondance avec ISO 27001 et PCI-DSS, pour vos partenaires et auditeurs." },
];

/**
 * Reports tab (docs/design/Settings.dc.html). Generating works now, in
 * French or English; automatic sending and the logo come later.
 */
function Reports({ org }: { org: Membership }) {
  const [kind, setKind] = useState<"executive" | "technical">("executive");
  const [lang, setLang] = useState<"fr" | "en">("fr");
  return (
    <section className="card stack">
      <h2>Rapports automatiques</h2>
      {AUTOMATIC.map((r) => (
        <label key={r.name} className="check-row">
          <input type="checkbox" disabled />
          <span>
            <span className="strong">{r.name}</span> <span className="tag accepted">Bientôt</span>
            <br />
            <span className="small muted">{r.desc}</span>
          </span>
        </label>
      ))}
      <div className="report-actions">
        <div className="field">
          <label htmlFor="report-kind">Version</label>
          <select id="report-kind" value={kind} onChange={(e) => setKind(e.target.value as "executive" | "technical")}>
            <option value="executive">Direction</option>
            <option value="technical">Technique</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="report-lang">Langue</label>
          <select id="report-lang" value={lang} onChange={(e) => setLang(e.target.value as "fr" | "en")}>
            <option value="fr">Français</option>
            <option value="en">English</option>
          </select>
        </div>
        <a className="btn btn-primary" href={reportURL(org.org_id, kind, lang)} download>
          Générer le rapport maintenant
        </a>
        <button type="button" className="btn btn-secondary" disabled title="Bientôt disponible">
          Ajouter votre logo
        </button>
      </div>
    </section>
  );
}

function Profile({ me, org }: { me: Me; org: Membership }) {
  const { refresh } = useAuth();
  const [pwError, setPwError] = useState("");
  const [pwDone, setPwDone] = useState(false);
  const [mfaError, setMfaError] = useState("");
  const [busy, setBusy] = useState(false);

  const changePassword = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const data = new FormData(form);
    const next = String(data.get("new"));
    setPwDone(false);
    if (next !== String(data.get("confirm"))) return setPwError(msg.passwordMatch);
    if ([...next].length < PASSWORD_MIN_LENGTH) return setPwError(msg.passwordShort);
    setBusy(true);
    setPwError("");
    try {
      await api.changePassword(String(data.get("current")), next);
      form.reset();
      setPwDone(true);
    } catch (err) {
      setPwError(err instanceof ApiError && err.status === 403 ? "Mot de passe actuel incorrect." : fallback(err));
    } finally {
      setBusy(false);
    }
  };

  const disableMfa = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    setBusy(true);
    setMfaError("");
    try {
      await api.mfaDisable(String(data.get("password")), String(data.get("code")));
      await refresh();
    } catch (err) {
      setMfaError(err instanceof ApiError && err.status === 403 ? "Mot de passe ou code incorrect." : fallback(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <section className="card">
        <h2>Mon compte</h2>
        <dl className="facts">
          <dt>Adresse e-mail</dt>
          <dd>{me.email}</dd>
          <dt>Rôle dans {org.org_name}</dt>
          <dd>{roleLabel(org.role)}</dd>
          <dt>Organisations</dt>
          <dd>{me.orgs.map((o) => o.org_name).join(", ")}</dd>
        </dl>
      </section>

      <section className="card">
        <h2>Mot de passe</h2>
        <p className="card-sub">Vos autres sessions seront fermées.</p>
        {pwError && <Alert kind="error">{pwError}</Alert>}
        {pwDone && <Alert kind="notice">Mot de passe changé. Vos autres sessions ont été fermées.</Alert>}
        <form className="form-grid" onSubmit={(e) => void changePassword(e)}>
          <div className="field">
            <label htmlFor="current">Mot de passe actuel</label>
            <input id="current" name="current" type="password" autoComplete="current-password" required />
          </div>
          <div className="field">
            <label htmlFor="new">Nouveau mot de passe</label>
            <input id="new" name="new" type="password" autoComplete="new-password" minLength={PASSWORD_MIN_LENGTH} required />
          </div>
          <div className="field">
            <label htmlFor="confirm">Confirmez</label>
            <input id="confirm" name="confirm" type="password" autoComplete="new-password" minLength={PASSWORD_MIN_LENGTH} required />
          </div>
          <div>
            <button className="btn btn-primary" type="submit" disabled={busy}>
              Changer le mot de passe
            </button>
          </div>
        </form>
      </section>

      <section className="card">
        <h2>Double authentification</h2>
        {me.mfa_enabled ? (
          <>
            <p className="card-sub">
              <span className="tag ok">Activée</span> Un code de votre application est demandé à chaque connexion.
            </p>
            {me.orgs.some((o) => o.role === "admin") && (
              <Alert kind="warning">Vous êtes administrateur : sans double authentification, vous n’aurez plus accès à vos organisations jusqu’à la réactiver.</Alert>
            )}
            {mfaError && <Alert kind="error">{mfaError}</Alert>}
            <form className="form-grid" onSubmit={(e) => void disableMfa(e)}>
              <div className="field">
                <label htmlFor="mfa-password">Mot de passe</label>
                <input id="mfa-password" name="password" type="password" autoComplete="current-password" required />
              </div>
              <div className="field">
                <label htmlFor="mfa-code">Code ou code de secours</label>
                <input id="mfa-code" name="code" type="text" autoComplete="one-time-code" required />
              </div>
              <div>
                <button className="btn btn-secondary" type="submit" disabled={busy}>
                  Désactiver
                </button>
              </div>
            </form>
          </>
        ) : (
          <>
            <p className="card-sub">
              <span className="tag warn">Désactivée</span> Un mot de passe volé suffit pour accéder à votre compte.
            </p>
            <p className="card-note">
              <Link className="btn btn-primary" to="/mfa/setup">
                Activer la double authentification
              </Link>
            </p>
          </>
        )}
      </section>
    </div>
  );
}

function Team({ me, org }: { me: Me; org: Membership }) {
  const isAdmin = org.role === "admin";
  const [members, setMembers] = useState<Member[] | null>(null);
  const [error, setError] = useState("");
  const [inviting, setInviting] = useState(false);
  const [token, setToken] = useState<{ email: string; token: string; emailed: boolean } | null>(null);
  const [added, setAdded] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setMembers((await api.members(org.org_id)).items);
    } catch (err) {
      setError(fallback(err));
    }
  }, [org.org_id]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
      await load();
    } catch (err) {
      if (err instanceof ApiError && err.code === "last_admin") setError("L’organisation doit garder au moins un administrateur.");
      else if (err instanceof ApiError && err.status === 409) setError("Cette personne est déjà membre de l’organisation.");
      else if (err instanceof ApiError && err.status === 400) setError("Adresse e-mail invalide.");
      else setError(fallback(err));
    } finally {
      setBusy(false);
    }
  };

  const invite = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const email = String(data.get("email")).trim();
    void act(async () => {
      const inv = await api.invite(org.org_id, email, String(data.get("role")) as Role);
      setInviting(false);
      setToken(inv.setup_token ? { email: inv.member.email, token: inv.setup_token, emailed: inv.emailed } : null);
      setAdded(inv.setup_token ? "" : `${inv.member.email} a maintenant accès à ${org.org_name}${inv.emailed ? " ; un email l’en a informé" : ""}.`);
      if (!inv.setup_token) setError("");
    });
  };

  const setupUrl = `${window.location.origin}/setup-password`;

  return (
    <section className="card">
      <div className="card-head">
        <h2>Membres</h2>
        {isAdmin && (
          <button type="button" className="btn btn-secondary" onClick={() => setInviting((v) => !v)}>
            Inviter un membre
          </button>
        )}
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      {inviting && (
        <form className="add-form" onSubmit={invite}>
          <div className="field name">
            <label htmlFor="invite-email">Adresse e-mail</label>
            <input id="invite-email" name="email" type="email" required autoFocus />
          </div>
          <div className="field crit">
            <label htmlFor="invite-role">Rôle</label>
            <select id="invite-role" name="role" defaultValue="viewer">
              <option value="viewer">Lecteur</option>
              <option value="admin">Administrateur</option>
            </select>
          </div>
          <button className="btn btn-primary" type="submit" disabled={busy}>
            Inviter
          </button>
        </form>
      )}
      {added && <Alert kind="notice">{added}</Alert>}
      {token && (
        <div className="verify-box">
          <p className="strong">{token.emailed ? `Invitation envoyée à ${token.email}` : `Code d’activation pour ${token.email}`}</p>
          <p className="verify-text">
            {token.emailed
              ? "Un email avec le lien d’activation vient de lui être envoyé (valable 24 heures, une seule fois). S’il ne le reçoit pas, transmettez-lui ce code par un canal de confiance ; il ne sera plus affiché."
              : `Transmettez-le par un canal de confiance. La personne l’utilise sur ${setupUrl} pour choisir son mot de passe. Valable 24 heures, une seule fois ; il ne sera plus affiché.`}
          </p>
          <pre className="record">{token.token}</pre>
          <div className="button-row verify-actions">
            <button type="button" className="btn btn-secondary" onClick={() => void navigator.clipboard.writeText(`${setupUrl}#token=${token.token}`)}>
              Copier le lien d’activation
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => setToken(null)}>
              J’ai transmis le code
            </button>
          </div>
        </div>
      )}
      {members && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Nom</th>
                <th scope="col">Rôle</th>
                <th scope="col">Double authentification</th>
                {isAdmin && <th scope="col">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <tr key={m.user_id}>
                  <td className="name">
                    {m.email}
                    {m.email === me.email && <span className="muted"> (vous)</span>}
                    {!m.activated && <span className="badge warn">Invitation en attente</span>}
                  </td>
                  <td>
                    {isAdmin ? (
                      <select
                        aria-label={`Rôle de ${m.email}`}
                        value={m.role}
                        disabled={busy}
                        onChange={(e) => void act(() => api.setMemberRole(org.org_id, m.user_id, e.target.value as Role))}
                      >
                        <option value="admin">Administrateur</option>
                        <option value="viewer">Lecteur</option>
                      </select>
                    ) : (
                      roleLabel(m.role)
                    )}
                  </td>
                  <td>{m.mfa_enabled ? "Activée" : "Désactivée"}</td>
                  {isAdmin && (
                    <td className="row-actions">
                      {!m.activated && (
                        <button
                          type="button"
                          className="link-button"
                          disabled={busy}
                          onClick={() =>
                            void act(async () => {
                              const res = await api.newSetupToken(org.org_id, m.user_id);
                              setToken({ email: m.email, token: res.setup_token, emailed: res.emailed });
                            })
                          }
                        >
                          Nouveau code
                        </button>
                      )}
                      <button
                        type="button"
                        className="link-button danger"
                        disabled={busy}
                        onClick={() => {
                          if (window.confirm(`Retirer ${m.email} de ${org.org_name} ?`)) void act(() => api.removeMember(org.org_id, m.user_id));
                        }}
                      >
                        Retirer
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
