import { useEffect, useState } from "react";
import { api, ApiError } from "../../api/client";
import type { AuthActivity, DeviceSession } from "../../api/types";
import { useAuth } from "../../auth";
import { locale, tr, useLang, type Lang } from "../../i18n";
import { useChooseLang } from "../LangSwitch";
import { Link, navigate } from "../../router";
import { Device, Soon } from "../icons";
import { device, feedDay, initials, pwScore, sinceText, whenActive } from "../model";
import { useOrg } from "../OrgData";
import { useUI } from "../ui";

/** actionLabel: the CSS class and the label of an account event. */
function actionLabel(action: string): [string, string] {
  switch (action) {
    case "login.ok":
      return ["f-ok", tr("Connexion", "Sign-in")];
    case "login.failed":
      return ["f-crit", tr("Échec de connexion", "Failed sign-in")];
    case "logout":
      return ["", tr("Déconnexion", "Sign-out")];
    case "password.set":
      return ["", tr("Mot de passe modifié", "Password changed")];
    case "password_reset":
      return ["", tr("Mot de passe réinitialisé", "Password reset")];
    case "mfa.enabled":
      return ["f-ok", tr("Double authentification activée", "Two-factor authentication turned on")];
    case "mfa.disabled":
      return ["f-crit", tr("Double authentification désactivée", "Two-factor authentication turned off")];
    case "mfa.reset":
      return ["f-crit", tr("Double authentification réinitialisée", "Two-factor authentication reset")];
    case "session.ended":
      return ["", tr("Appareil déconnecté", "Device signed out")];
    case "profile.name_changed":
      return ["", tr("Nom modifié", "Name changed")];
    case "signup.completed":
      return ["f-ok", tr("Compte créé", "Account created")];
  }
  return ["", action];
}

function pwHint(score: number): string {
  return [
    tr("Trop court.", "Too short."),
    tr("Faible.", "Weak."),
    tr("Moyen : ajoutez des symboles ou allongez-le.", "Fair: add symbols or make it longer."),
    tr("Bon.", "Good."),
    tr("Très solide.", "Very strong."),
  ][score] ?? "";
}

export function ProfilPage() {
  const { me, org } = useOrg();
  const { refresh, signOut } = useAuth();
  const { toast } = useUI();
  const { lang } = useLang();
  const choose = useChooseLang();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(me.name);
  const [nameErr, setNameErr] = useState("");
  const [pwOpen, setPwOpen] = useState(false);
  const [cur, setCur] = useState("");
  const [pw, setPw] = useState("");
  const [pwErr, setPwErr] = useState("");
  const [sessions, setSessions] = useState<DeviceSession[]>([]);
  const [gone, setGone] = useState<string | null>(null);
  const [activity, setActivity] = useState<AuthActivity[]>([]);

  useEffect(() => {
    api.sessions().then((r) => setSessions(r.items), () => setSessions([]));
    api.authActivity().then((r) => setActivity(r.items), () => setActivity([]));
  }, []);

  const now = new Date();
  const saveName = async () => {
    const v = name.trim();
    if (v.length < 2) {
      setNameErr(tr("Saisissez votre nom.", "Enter your name."));
      return;
    }
    try {
      await api.updateMe(v);
      await refresh();
      setEditing(false);
      toast(tr("Nom enregistré", "Name saved"));
    } catch {
      setNameErr(tr("Nom non enregistré, réessayez.", "Name not saved, try again."));
    }
  };
  const savePw = async () => {
    if (pwScore(pw) < 3 || pw.length < 12) {
      setPwErr(tr("Ce mot de passe est trop faible. Allongez-le ou ajoutez des chiffres et des symboles.", "This password is too weak. Make it longer or add numbers and symbols."));
      return;
    }
    try {
      await api.changePassword(cur, pw);
      setPwOpen(false);
      setCur("");
      setPw("");
      toast(tr("Mot de passe mis à jour", "Password updated"));
      void refresh();
    } catch (e) {
      setPwErr(
        e instanceof ApiError && (e.status === 403 || e.status === 401)
          ? tr("Mot de passe actuel incorrect.", "Incorrect current password.")
          : tr("Mot de passe non modifié, réessayez.", "Password not changed, try again."),
      );
    }
  };
  const revoke = (id: string) => {
    setGone(id);
    api.endSession(id).then(
      () => {
        setTimeout(() => setSessions((s) => s.filter((x) => x.id !== id)), 380);
        toast(tr("Appareil déconnecté", "Device signed out"));
      },
      () => {
        setGone(null);
        toast(tr("Impossible de déconnecter cet appareil", "This device cannot be signed out"));
      },
    );
  };
  // The language is kept on the account, so every device and the emails
  // follow it; the whole interface then switches.
  const chooseLang = async (l: Lang) => {
    if (l === lang) return;
    try {
      await choose(l);
    } catch {
      toast(tr("Langue non enregistrée, réessayez", "Language not saved, try again"));
    }
  };
  const logout = async () => {
    await signOut();
    navigate("/connexion", { replace: true });
  };
  const score = pwScore(pw);

  return (
    <>
      <div className="rtop">
        <h1 className="hello" style={{ margin: 0, fontFamily: "inherit", fontWeight: 400, letterSpacing: 0 }}>
          {tr("Mon profil", "My profile")}
        </h1>
      </div>
      <div className="idcard">
        <span className="bigav" aria-hidden="true">
          {initials(me.name, me.email)}
        </span>
        <div style={{ minWidth: 0 }}>
          {editing ? (
            <>
              <div className="addrow" style={{ margin: 0 }}>
                <label className="vh" htmlFor="name-in">
                  {tr("Nom", "Name")}
                </label>
                <input id="name-in" type="text" value={name} autoComplete="name" autoFocus onChange={(e) => setName(e.target.value)} />
                <button className="btn" type="button" onClick={() => void saveName()}>
                  {tr("Enregistrer", "Save")}
                </button>
              </div>
              <p className="err" id="name-err" role="alert">
                {nameErr}
              </p>
            </>
          ) : (
            <p className="idname">
              {me.name || tr("Votre nom", "Your name")}
              <button className="link" type="button" style={{ minHeight: 0, fontSize: 14, marginLeft: 10 }} onClick={() => setEditing(true)}>
                {tr("Modifier", "Edit")}
              </button>
            </p>
          )}
          <p className="md" style={{ fontSize: 14 }}>
            {me.email}
          </p>
          <p className="idrole">
            <span>{org.role === "admin" ? tr("Administrateur", "Administrator") : tr("Lecteur", "Viewer")}</span>
            <span>{org.org_name}</span>
          </p>
        </div>
      </div>

      <div className="section">
        <h2>{tr("Sécurité du compte", "Account security")}</h2>
        <div className="rpanel" style={{ marginTop: 12 }}>
          <div className="set" style={{ borderTop: 0, paddingTop: 0 }}>
            <div>
              <p className="mt">{tr("Double authentification", "Two-factor authentication")}</p>
              <p className="md">
                {me.mfa_enabled
                  ? tr("Activée avec une application. Obligatoire pour les administrateurs.", "On, with an app. Required for administrators.")
                  : tr("Pas encore activée. Obligatoire pour les administrateurs.", "Not on yet. Required for administrators.")}
              </p>
            </div>
            {me.mfa_enabled ? (
              <span className="sev s-ok">
                <i />
                {tr("Active", "On")}
              </span>
            ) : (
              <Link className="link" to="/mfa/setup">
                {tr("Activer", "Turn on")}
              </Link>
            )}
          </div>
          {me.mfa_enabled && (
            <div className="set">
              <div>
                <p className="mt">{tr("Codes de secours", "Recovery codes")}</p>
                <p className="md">{tr(`${me.recovery_codes_left} codes restants sur 10.`, `${me.recovery_codes_left} of 10 codes left.`)}</p>
              </div>
              <button className="link" type="button" aria-disabled="true" onClick={() => toast(tr("Regénérer les codes : bientôt disponible", "Regenerating codes: coming soon"))}>
                {tr("Regénérer", "Regenerate")}
                <Soon />
              </button>
            </div>
          )}
          <div className="set" style={{ display: "block" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
              <div>
                <p className="mt">{tr("Mot de passe", "Password")}</p>
                <p className="md">
                  {me.password_changed_at
                    ? tr(`Modifié ${sinceText(me.password_changed_at, now)}.`, `Changed ${sinceText(me.password_changed_at, now)}.`)
                    : tr("Jamais modifié.", "Never changed.")}
                </p>
              </div>
              <button className="link" type="button" onClick={() => setPwOpen(!pwOpen)}>
                {pwOpen ? tr("Annuler", "Cancel") : tr("Changer", "Change")}
              </button>
            </div>
            {pwOpen && (
              <div className="pwbox">
                <label htmlFor="pw-cur" className="md">
                  {tr("Mot de passe actuel", "Current password")}
                </label>
                <input id="pw-cur" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />
                <label htmlFor="pw" className="md">
                  {tr("Nouveau mot de passe", "New password")}
                </label>
                <input
                  id="pw"
                  type="password"
                  autoComplete="new-password"
                  value={pw}
                  onChange={(e) => {
                    setPw(e.target.value);
                    setPwErr("");
                  }}
                />
                <div className={"pwmeter s" + score} id="pwmeter" aria-hidden="true">
                  <i />
                  <i />
                  <i />
                  <i />
                </div>
                <p className="md" id="pwhint" aria-live="polite">
                  {pw ? pwHint(score) : tr("12 caractères au moins, avec des chiffres et des symboles.", "At least 12 characters, with numbers and symbols.")}
                </p>
                <p className="err" id="pw-err" role="alert">
                  {pwErr}
                </p>
                <button className="btn" type="button" onClick={() => void savePw()}>
                  {tr("Mettre à jour", "Update")}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="section">
        <h2>{tr("Appareils connectés", "Signed-in devices")}</h2>
        <ul className="sess">
          {sessions.map((s) => (
            <li key={s.id} className={gone === s.id ? "gone" : ""}>
              <span className="mico">
                <Device />
              </span>
              <div>
                <p className="mt">
                  {s.current
                    ? tr(`Cet appareil, ${device(s.user_agent).split(", ")[1] ?? device(s.user_agent)}`, `This device, ${device(s.user_agent).split(", ")[1] ?? device(s.user_agent)}`)
                    : device(s.user_agent)}
                </p>
                <p className="md">{s.current ? tr("Session actuelle", "Current session") : whenActive(s.last_seen_at, now)}</p>
              </div>
              {s.current ? (
                <span className="sev s-ok">
                  <i />
                  {tr("Ici", "Here")}
                </span>
              ) : (
                <button className="link" type="button" onClick={() => revoke(s.id)}>
                  {tr("Déconnecter", "Sign out")}
                </button>
              )}
            </li>
          ))}
        </ul>
      </div>

      <div className="section">
        <h2>{tr("Préférences", "Preferences")}</h2>
        <div className="rpanel" style={{ marginTop: 12 }}>
          <div className="set" style={{ borderTop: 0, padding: 0 }}>
            <div>
              <p className="mt">{tr("Langue", "Language")}</p>
              <p className="md">{tr("Tout le site, vos rapports et vos emails.", "The whole site, your reports and your emails.")}</p>
            </div>
            <div className="seg2" role="group" aria-label={tr("Langue", "Language")}>
              {(
                [
                  ["fr", "Français"],
                  ["en", "English"],
                ] as const
              ).map(([k, l]) => (
                <button key={k} type="button" aria-pressed={lang === k} lang={k} onClick={() => void chooseLang(k)}>
                  {l}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="section">
        <h2>{tr("Activité récente", "Recent activity")}</h2>
        {activity.length ? (
          <ul className="feed">
            {activity.slice(0, 6).map((a, k) => {
              const [cls, label] = actionLabel(a.action);
              return (
                <li key={k} className={cls}>
                  <time dateTime={a.at}>
                    {feedDay(a.at, now)}, {new Date(a.at).toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" })}
                  </time>
                  <span>
                    {label}
                    {a.ip ? tr(` depuis ${a.ip}`, ` from ${a.ip}`) : ""}.
                  </span>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="hint">{tr("Aucune activité récente.", "No recent activity.")}</p>
        )}
      </div>

      <div className="section">
        <div className="actions">
          <Link className="btn ghost" to="/">
            {tr("Voir le site public", "See the public site")}
          </Link>
          <button className="btn ghost" type="button" onClick={() => void logout()}>
            {tr("Se déconnecter", "Sign out")}
          </button>
          <button className="btn ghost danger" type="button" aria-disabled="true" onClick={() => toast(tr("Suppression du compte : bientôt disponible", "Account deletion: coming soon"))}>
            {tr("Supprimer mon compte", "Delete my account")}
            <Soon />
          </button>
        </div>
      </div>
    </>
  );
}
