import { useState, type FormEvent } from "react";
import { api, ApiError, isMfaChallenge } from "../api/client";
import { useAuth } from "../auth";
import { Alert, AuthLayout } from "../components/AuthLayout";
import { Link, navigate, useLocation } from "../router";
import { fallback, msg, notices } from "./messages";

type Step = { kind: "password" } | { kind: "code"; token: string };

export function LoginPage() {
  const { signedIn } = useAuth();
  const { search } = useLocation();
  const [step, setStep] = useState<Step>({ kind: "password" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const notice = notices[search.get("ok") ?? ""];

  const submitPassword = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError("");
    try {
      const res = await api.login(String(form.get("email")), String(form.get("password")));
      if (isMfaChallenge(res)) {
        // The token stays in memory, never in the URL (history, logs).
        setStep({ kind: "code", token: res.mfa_token });
      } else {
        signedIn(res);
        navigate("/", { replace: true });
      }
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? msg.badCredentials : fallback(err));
    } finally {
      setBusy(false);
    }
  };

  const submitCode = (token: string, recovery: boolean) => async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const code = String(new FormData(e.currentTarget).get("code"));
    setBusy(true);
    setError("");
    try {
      signedIn(await api.loginMfa(token, code));
      navigate("/", { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.code === "login_expired") {
        setStep({ kind: "password" });
        setError(msg.loginExpired);
      } else if (err instanceof ApiError && err.status === 401) {
        setError(recovery ? msg.badRecovery : msg.badCode);
      } else {
        setError(fallback(err));
      }
    } finally {
      setBusy(false);
    }
  };

  if (step.kind === "code") {
    return (
      <AuthLayout>
        <div className="stack">
          <div className="stack-sm">
            <h1>Vérification en deux étapes</h1>
            <p className="muted">Saisissez le code à 6 chiffres affiché par votre application d’authentification.</p>
          </div>
          {error && <Alert kind="error">{error}</Alert>}
          <form className="stack" onSubmit={submitCode(step.token, false)}>
            <div className="field">
              <label htmlFor="code">Code</label>
              <input id="code" className="code" name="code" type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required autoFocus />
            </div>
            <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
              Vérifier
            </button>
          </form>
          <details className="alt">
            <summary>Vous n’avez pas votre téléphone ? Utilisez un code de secours</summary>
            <form className="stack" onSubmit={submitCode(step.token, true)}>
              <div className="field">
                <label htmlFor="recovery">Code de secours</label>
                <input id="recovery" name="code" type="text" autoComplete="off" autoCapitalize="characters" spellCheck={false} required />
                <p className="hint">Un des 10 codes reçus à l’activation, par exemple ABCD-EFGH-IJKL-MNOP. Chaque code ne sert qu’une fois.</p>
              </div>
              <button className="btn btn-secondary btn-block" type="submit" disabled={busy}>
                Utiliser ce code
              </button>
            </form>
          </details>
          <p className="small">
            <button type="button" className="link-button" onClick={() => { setStep({ kind: "password" }); setError(""); }}>
              Recommencer la connexion
            </button>
          </p>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <div className="stack">
        <div className="stack-sm">
          <h1>Connexion</h1>
          <p className="muted">Accédez au tableau de bord de votre organisation.</p>
        </div>
        {error && <Alert kind="error">{error}</Alert>}
        {!error && notice && <Alert kind="notice">{notice}</Alert>}
        <form className="stack" onSubmit={submitPassword}>
          <div className="field">
            <label htmlFor="email">Adresse e-mail</label>
            <input id="email" name="email" type="email" autoComplete="username" required autoFocus />
          </div>
          <div className="field">
            <label htmlFor="password">Mot de passe</label>
            <input id="password" name="password" type="password" autoComplete="current-password" required />
          </div>
          <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
            Se connecter
          </button>
        </form>
        <p className="small muted">
          Première connexion ? <Link to="/setup-password">Définissez votre mot de passe</Link> avec le code d’activation reçu de votre administrateur.
        </p>
      </div>
    </AuthLayout>
  );
}
