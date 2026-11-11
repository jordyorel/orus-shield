import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import { Alert, AuthLayout } from "../components/AuthLayout";
import { Link, navigate } from "../router";
import { fallback, msg, PASSWORD_MIN_LENGTH } from "./messages";

/**
 * The token may come in the URL fragment (#token=...): browsers never send
 * the fragment to the server, so it stays out of logs. It is removed from
 * the address bar as soon as it is read.
 */
function tokenFromFragment(): string {
  const t = new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
  if (t) window.history.replaceState(null, "", window.location.pathname);
  return t;
}

export function SetupPasswordPage() {
  const [initialToken] = useState(tokenFromFragment);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const password = String(form.get("password"));
    if (password !== String(form.get("confirm"))) return setError(msg.passwordMatch);
    // Characters, not UTF-16 units: the engine counts runes.
    if ([...password].length < PASSWORD_MIN_LENGTH) return setError(msg.passwordShort);
    setBusy(true);
    setError("");
    try {
      await api.setupPassword(String(form.get("token")).trim(), password);
      navigate("/login?ok=password", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError && err.status === 400 ? msg.setupToken : fallback(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout>
      <div className="stack">
        <div className="stack-sm">
          <h1>Définir votre mot de passe</h1>
          <p className="muted">
            {initialToken
              ? "Le code de votre lien est déjà saisi : choisissez votre nouveau mot de passe."
              : "Saisissez le code d’activation transmis par votre administrateur. Il ne sert qu’une fois."}
          </p>
        </div>
        {error && <Alert kind="error">{error}</Alert>}
        <form className="stack" onSubmit={submit}>
          <div className="field">
            <label htmlFor="token">Code d’activation</label>
            <input id="token" name="token" type="text" autoComplete="off" spellCheck={false} required defaultValue={initialToken} autoFocus={!initialToken} />
          </div>
          <div className="field">
            <label htmlFor="password">Nouveau mot de passe</label>
            <input id="password" name="password" type="password" autoComplete="new-password" minLength={PASSWORD_MIN_LENGTH} required aria-describedby="password-hint" autoFocus={!!initialToken} />
            <p className="hint" id="password-hint">
              Au moins {PASSWORD_MIN_LENGTH} caractères. Une phrase de plusieurs mots est plus sûre et plus facile à retenir.
            </p>
          </div>
          <div className="field">
            <label htmlFor="confirm">Confirmez le mot de passe</label>
            <input id="confirm" name="confirm" type="password" autoComplete="new-password" minLength={PASSWORD_MIN_LENGTH} required />
          </div>
          <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
            Enregistrer
          </button>
        </form>
        <p className="small">
          <Link to="/login">Retour à la connexion</Link>
        </p>
      </div>
    </AuthLayout>
  );
}
