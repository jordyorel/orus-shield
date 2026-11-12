import { useEffect, useState } from "react";
import { api, ApiError } from "../../api/client";
import type { AuthActivity, DeviceSession } from "../../api/types";
import { useAuth } from "../../auth";
import { Link, navigate } from "../../router";
import { Device, Soon } from "../icons";
import { device, feedDay, initials, pwScore, sinceText, whenActive } from "../model";
import { useOrg } from "../OrgData";
import { useUI } from "../ui";

const ACTIONS: Record<string, [string, string]> = {
  "login.ok": ["f-ok", "Connexion"],
  "login.failed": ["f-crit", "Échec de connexion"],
  logout: ["", "Déconnexion"],
  "password.set": ["", "Mot de passe modifié"],
  password_reset: ["", "Mot de passe réinitialisé"],
  "mfa.enabled": ["f-ok", "Double authentification activée"],
  "mfa.disabled": ["f-crit", "Double authentification désactivée"],
  "mfa.reset": ["f-crit", "Double authentification réinitialisée"],
  "session.ended": ["", "Appareil déconnecté"],
  "profile.name_changed": ["", "Nom modifié"],
  "signup.completed": ["f-ok", "Compte créé"],
};

const PW_HINTS = ["Trop court.", "Faible.", "Moyen : ajoutez des symboles ou allongez-le.", "Bon.", "Très solide."];

export function ProfilPage() {
  const { me, org } = useOrg();
  const { refresh, signOut } = useAuth();
  const { toast } = useUI();
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
  const [lang, setLang] = useState<"fr" | "en">("fr");

  useEffect(() => {
    api.sessions().then((r) => setSessions(r.items), () => setSessions([]));
    api.authActivity().then((r) => setActivity(r.items), () => setActivity([]));
  }, []);

  const now = new Date();
  const saveName = async () => {
    const v = name.trim();
    if (v.length < 2) {
      setNameErr("Saisissez votre nom.");
      return;
    }
    try {
      await api.updateMe(v);
      await refresh();
      setEditing(false);
      toast("Nom enregistré");
    } catch {
      setNameErr("Nom non enregistré, réessayez.");
    }
  };
  const savePw = async () => {
    if (pwScore(pw) < 3 || pw.length < 12) {
      setPwErr("Ce mot de passe est trop faible. Allongez-le ou ajoutez des chiffres et des symboles.");
      return;
    }
    try {
      await api.changePassword(cur, pw);
      setPwOpen(false);
      setCur("");
      setPw("");
      toast("Mot de passe mis à jour");
      void refresh();
    } catch (e) {
      setPwErr(e instanceof ApiError && (e.status === 403 || e.status === 401) ? "Mot de passe actuel incorrect." : "Mot de passe non modifié, réessayez.");
    }
  };
  const revoke = (id: string) => {
    setGone(id);
    api.endSession(id).then(
      () => {
        setTimeout(() => setSessions((s) => s.filter((x) => x.id !== id)), 380);
        toast("Appareil déconnecté");
      },
      () => {
        setGone(null);
        toast("Impossible de déconnecter cet appareil");
      },
    );
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
          Mon profil
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
                  Nom
                </label>
                <input id="name-in" type="text" value={name} autoComplete="name" autoFocus onChange={(e) => setName(e.target.value)} />
                <button className="btn" type="button" onClick={() => void saveName()}>
                  Enregistrer
                </button>
              </div>
              <p className="err" id="name-err" role="alert">
                {nameErr}
              </p>
            </>
          ) : (
            <p className="idname">
              {me.name || "Votre nom"}
              <button className="link" type="button" style={{ minHeight: 0, fontSize: 14, marginLeft: 10 }} onClick={() => setEditing(true)}>
                Modifier
              </button>
            </p>
          )}
          <p className="md" style={{ fontSize: 14 }}>
            {me.email}
          </p>
          <p className="idrole">
            <span>{org.role === "admin" ? "Administrateur" : "Lecteur"}</span>
            <span>{org.org_name}</span>
          </p>
        </div>
      </div>

      <div className="section">
        <h2>Sécurité du compte</h2>
        <div className="rpanel" style={{ marginTop: 12 }}>
          <div className="set" style={{ borderTop: 0, paddingTop: 0 }}>
            <div>
              <p className="mt">Double authentification</p>
              <p className="md">{me.mfa_enabled ? "Activée avec une application. Obligatoire pour les administrateurs." : "Pas encore activée. Obligatoire pour les administrateurs."}</p>
            </div>
            {me.mfa_enabled ? (
              <span className="sev s-ok">
                <i />
                Active
              </span>
            ) : (
              <Link className="link" to="/mfa/setup">
                Activer
              </Link>
            )}
          </div>
          {me.mfa_enabled && (
            <div className="set">
              <div>
                <p className="mt">Codes de secours</p>
                <p className="md">{me.recovery_codes_left} codes restants sur 10.</p>
              </div>
              <button className="link" type="button" aria-disabled="true" onClick={() => toast("Regénérer les codes : bientôt disponible")}>
                Regénérer
                <Soon />
              </button>
            </div>
          )}
          <div className="set" style={{ display: "block" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
              <div>
                <p className="mt">Mot de passe</p>
                <p className="md">{me.password_changed_at ? `Modifié ${sinceText(me.password_changed_at, now)}.` : "Jamais modifié."}</p>
              </div>
              <button className="link" type="button" onClick={() => setPwOpen(!pwOpen)}>
                {pwOpen ? "Annuler" : "Changer"}
              </button>
            </div>
            {pwOpen && (
              <div className="pwbox">
                <label htmlFor="pw-cur" className="md">
                  Mot de passe actuel
                </label>
                <input id="pw-cur" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />
                <label htmlFor="pw" className="md">
                  Nouveau mot de passe
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
                  {pw ? PW_HINTS[score] : "12 caractères au moins, avec des chiffres et des symboles."}
                </p>
                <p className="err" id="pw-err" role="alert">
                  {pwErr}
                </p>
                <button className="btn" type="button" onClick={() => void savePw()}>
                  Mettre à jour
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="section">
        <h2>Appareils connectés</h2>
        <ul className="sess">
          {sessions.map((s) => (
            <li key={s.id} className={gone === s.id ? "gone" : ""}>
              <span className="mico">
                <Device />
              </span>
              <div>
                <p className="mt">{s.current ? `Cet appareil, ${device(s.user_agent).split(", ")[1] ?? device(s.user_agent)}` : device(s.user_agent)}</p>
                <p className="md">{s.current ? "Session actuelle" : whenActive(s.last_seen_at, now)}</p>
              </div>
              {s.current ? (
                <span className="sev s-ok">
                  <i />
                  Ici
                </span>
              ) : (
                <button className="link" type="button" onClick={() => revoke(s.id)}>
                  Déconnecter
                </button>
              )}
            </li>
          ))}
        </ul>
      </div>

      <div className="section">
        <h2>Préférences</h2>
        <div className="rpanel" style={{ marginTop: 12 }}>
          <div className="set" style={{ borderTop: 0, padding: 0 }}>
            <div>
              <p className="mt">Langue de l’interface</p>
              <p className="md">Les textes techniques des problèmes restent en anglais pour l’instant.</p>
            </div>
            <div className="seg2" role="group" aria-label="Langue">
              {(
                [
                  ["fr", "Français"],
                  ["en", "English"],
                ] as const
              ).map(([k, l]) => (
                <button
                  key={k}
                  type="button"
                  aria-pressed={lang === k}
                  onClick={() => {
                    if (k === "en") toast("Anglais : bientôt disponible");
                    else {
                      setLang("fr");
                      toast("Interface en français");
                    }
                  }}
                >
                  {l}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="section">
        <h2>Activité récente</h2>
        {activity.length ? (
          <ul className="feed">
            {activity.slice(0, 6).map((a, k) => {
              const [cls, label] = ACTIONS[a.action] ?? ["", a.action];
              return (
                <li key={k} className={cls}>
                  <time dateTime={a.at}>
                    {feedDay(a.at, now)}, {new Date(a.at).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}
                  </time>
                  <span>
                    {label}
                    {a.ip ? ` depuis ${a.ip}` : ""}.
                  </span>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="hint">Aucune activité récente.</p>
        )}
      </div>

      <div className="section">
        <div className="actions">
          <Link className="btn ghost" to="/">
            Voir le site public
          </Link>
          <button className="btn ghost" type="button" onClick={() => void logout()}>
            Se déconnecter
          </button>
          <button className="btn ghost danger" type="button" aria-disabled="true" onClick={() => toast("Suppression du compte : bientôt disponible")}>
            Supprimer mon compte
            <Soon />
          </button>
        </div>
      </div>
    </>
  );
}
