import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import { Alert, AuthLayout } from "../components/AuthLayout";
import { Link } from "../router";
import { fallback, msg } from "./messages";

/**
 * "Mot de passe oublié": asks for the address and always shows the same
 * confirmation, whether an account exists or not (the API answers 202 in
 * both cases). Only the rate limit is reported.
 */
export function ForgotPasswordPage() {
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const email = String(new FormData(e.currentTarget).get("email")).trim();
    setBusy(true);
    setError("");
    try {
      await api.forgotPassword(email);
      setSent(true);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 429 ? msg.resetRateLimited : fallback(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout>
      <div className="stack">
        <div className="stack-sm">
          <h1>Mot de passe oublié</h1>
          <p className="muted">Saisissez l’adresse de votre compte : nous vous enverrons un lien pour choisir un nouveau mot de passe.</p>
        </div>
        {error && <Alert kind="error">{error}</Alert>}
        {sent ? (
          <Alert kind="notice">
            Si un compte existe pour cette adresse, un email vient de lui être envoyé. Le lien est valable 1 heure et ne sert qu’une fois. Pensez à vérifier
            vos courriers indésirables.
          </Alert>
        ) : (
          <form className="stack" onSubmit={submit}>
            <div className="field">
              <label htmlFor="email">Adresse e-mail</label>
              <input id="email" name="email" type="email" autoComplete="username" required autoFocus />
            </div>
            <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
              Envoyer le lien
            </button>
          </form>
        )}
        <p className="small">
          <Link to="/login">Retour à la connexion</Link>
        </p>
      </div>
    </AuthLayout>
  );
}
