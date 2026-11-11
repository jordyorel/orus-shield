import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import { Alert, AuthLayout } from "../components/AuthLayout";
import { Link, navigate } from "../router";
import { fallback, msg, PASSWORD_MIN_LENGTH } from "./messages";

/** The token arrives in the URL fragment; it is removed from the address bar once read. */
function tokenFromFragment(): string {
  const t = new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
  if (t) window.history.replaceState(null, "", window.location.pathname);
  return t;
}

/** The emailed link: choose a password, which creates the account and the organization. */
export function SignupCompletePage() {
  const [token] = useState(tokenFromFragment);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const password = String(form.get("password"));
    if (password !== String(form.get("confirm"))) return setError(msg.passwordMatch);
    if ([...password].length < PASSWORD_MIN_LENGTH) return setError(msg.passwordShort);
    setBusy(true);
    setError("");
    try {
      await api.completeSignup(token, password);
      navigate("/login?ok=signup", { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.code === "account_exists") setError(msg.accountExists);
      else if (err instanceof ApiError && err.status === 400) setError(msg.signupLink);
      else setError(fallback(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout>
      <div className="stack">
        <div className="stack-sm">
          <h1>Choisissez votre mot de passe</h1>
          <p className="muted">Dernière étape : votre compte et votre organisation sont créés dès que vous enregistrez.</p>
        </div>
        {!token && <Alert kind="error">{msg.signupLink}</Alert>}
        {error && <Alert kind="error">{error}</Alert>}
        {token && (
          <form className="stack" onSubmit={submit}>
            <div className="field">
              <label htmlFor="password">Mot de passe</label>
              <input id="password" name="password" type="password" autoComplete="new-password" minLength={PASSWORD_MIN_LENGTH} required autoFocus aria-describedby="password-hint" />
              <p className="hint" id="password-hint">
                Au moins {PASSWORD_MIN_LENGTH} caractères. Une phrase de plusieurs mots est plus sûre et plus facile à retenir.
              </p>
            </div>
            <div className="field">
              <label htmlFor="confirm">Confirmez le mot de passe</label>
              <input id="confirm" name="confirm" type="password" autoComplete="new-password" minLength={PASSWORD_MIN_LENGTH} required />
            </div>
            <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
              Créer mon compte
            </button>
          </form>
        )}
        <p className="small">
          <Link to="/signup">Recommencer l’inscription</Link> · <Link to="/login">Se connecter</Link>
        </p>
      </div>
    </AuthLayout>
  );
}
