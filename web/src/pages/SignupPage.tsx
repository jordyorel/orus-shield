import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import { Alert, AuthLayout } from "../components/AuthLayout";
import { Link } from "../router";
import { fallback, msg } from "./messages";

/**
 * Self-service signup: email and organization name. Nothing is created
 * until the emailed link is used; the confirmation reads the same whether
 * the address already has an account or not.
 */
export function SignupPage() {
  const [sent, setSent] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const email = String(form.get("email")).trim();
    setBusy(true);
    setError("");
    try {
      await api.signup(email, String(form.get("organization")).trim());
      setSent(email);
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) setError(msg.signupRateLimited);
      else if (err instanceof ApiError && err.status === 400) setError(msg.signupInvalid);
      else if (err instanceof ApiError && err.status === 404) setError(msg.signupClosed);
      else setError(fallback(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout>
      <div className="stack">
        <div className="stack-sm">
          <h1>Créer un compte</h1>
          <p className="muted">Surveillez la sécurité de vos domaines. Nous vous envoyons un lien pour confirmer votre adresse.</p>
        </div>
        {error && <Alert kind="error">{error}</Alert>}
        {sent ? (
          <Alert kind="notice">
            Un email vient d’être envoyé à {sent}. Ouvrez le lien qu’il contient (valable 24 heures) pour choisir votre mot de passe : votre compte sera créé à ce
            moment-là. Pensez à vérifier vos courriers indésirables.
          </Alert>
        ) : (
          <form className="stack" onSubmit={submit}>
            <div className="field">
              <label htmlFor="email">Adresse e-mail professionnelle</label>
              <input id="email" name="email" type="email" autoComplete="email" required autoFocus />
            </div>
            <div className="field">
              <label htmlFor="organization">Nom de votre organisation</label>
              <input id="organization" name="organization" type="text" autoComplete="organization" maxLength={200} required />
            </div>
            <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
              Recevoir le lien de confirmation
            </button>
          </form>
        )}
        <p className="small">
          Déjà un compte ? <Link to="/login">Se connecter</Link>
        </p>
      </div>
    </AuthLayout>
  );
}
