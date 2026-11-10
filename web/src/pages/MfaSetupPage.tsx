import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import type { MfaSetup } from "../api/types";
import { useAuth } from "../auth";
import { Alert, AuthLayout } from "../components/AuthLayout";
import { navigate, useLocation } from "../router";
import { fallback, msg } from "./messages";

type Step = { kind: "password" } | { kind: "enrol"; setup: MfaSetup } | { kind: "codes"; codes: string[] };

/** groups splits the secret by 4 characters, easier to type by hand. */
export function groups(secret: string): string {
  return secret.match(/.{1,4}/g)?.join(" ") ?? "";
}

/** otpauthLink keeps only the otpauth: scheme: never a link React would not have escaped. */
function otpauthLink(uri: string): string | undefined {
  return uri.startsWith("otpauth://") ? uri : undefined;
}

export function MfaSetupPage() {
  const { refresh, signOut } = useAuth();
  const { search } = useLocation();
  const [step, setStep] = useState<Step>({ kind: "password" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } finally {
      setBusy(false);
    }
  };

  const submitPassword = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const password = String(new FormData(e.currentTarget).get("password"));
    void run(async () => {
      try {
        // The secret is kept in memory only, for this enrolment.
        setStep({ kind: "enrol", setup: await api.mfaSetup(password) });
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) {
          await refresh();
          navigate("/", { replace: true });
        } else {
          setError(err instanceof ApiError && err.status === 403 ? msg.badPassword : fallback(err));
        }
      }
    });
  };

  const submitCode = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const code = String(new FormData(e.currentTarget).get("code"));
    void run(async () => {
      try {
        const res = await api.mfaConfirm(code);
        setStep({ kind: "codes", codes: res.recovery_codes });
      } catch (err) {
        setError(err instanceof ApiError && err.status === 400 ? msg.badCode : fallback(err));
      }
    });
  };

  const finish = () =>
    void run(async () => {
      // The session was upgraded by the enrolment: reload the user.
      await refresh();
      navigate("/", { replace: true });
    });

  const logout = async () => {
    await signOut();
    navigate("/login?ok=logout", { replace: true });
  };

  if (step.kind === "codes") {
    const text = step.codes.join("\n") + "\n";
    const copy = async () => {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    };
    const download = () => {
      const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = "orus-shield-codes-de-secours.txt";
      a.click();
      URL.revokeObjectURL(url);
    };
    return (
      <AuthLayout wide>
        <div className="stack">
          <div className="stack-sm">
            <h1>Double authentification activée</h1>
            <p className="muted">Si vous perdez votre téléphone, ces codes de secours vous permettront de vous connecter. Chacun ne sert qu’une fois.</p>
          </div>
          <Alert kind="warning">Conservez-les maintenant (gestionnaire de mots de passe ou papier rangé en lieu sûr) : ils ne seront plus jamais affichés.</Alert>
          <ul className="codes" aria-label="Codes de secours">
            {step.codes.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <div className="button-row">
            <button type="button" className="btn btn-secondary" onClick={() => void copy()}>
              {copied ? "Copiés" : "Copier"}
            </button>
            <button type="button" className="btn btn-secondary" onClick={download}>
              Télécharger
            </button>
          </div>
          <button type="button" className="btn btn-primary btn-block" onClick={finish} disabled={busy}>
            J’ai conservé mes codes, continuer
          </button>
        </div>
      </AuthLayout>
    );
  }

  if (step.kind === "enrol") {
    const link = otpauthLink(step.setup.otpauth_uri);
    return (
      <AuthLayout wide>
        <div className="stack">
          <h1>Ajoutez Orus Shield à votre application</h1>
          {error && <Alert kind="error">{error}</Alert>}
          <ol className="steps">
            <li>Installez une application d’authentification si vous n’en avez pas : Google Authenticator, Microsoft Authenticator, 2FAS ou Aegis.</li>
            <li>Ajoutez un compte en saisissant cette clé :</li>
          </ol>
          <p className="secret" aria-label="Clé secrète">
            {groups(step.setup.secret)}
          </p>
          {link && (
            <p className="small">
              Sur ce téléphone ? <a href={link}>Ouvrir directement dans l’application</a>
            </p>
          )}
          <p className="small muted">Ne communiquez cette clé à personne. Elle disparaît quand vous quittez cette page.</p>
          <form className="stack" onSubmit={submitCode}>
            <div className="field">
              <label htmlFor="code">Code à 6 chiffres affiché par l’application</label>
              <input id="code" className="code" name="code" type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required autoFocus />
            </div>
            <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
              Activer
            </button>
          </form>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <div className="stack">
        <div className="stack-sm">
          <h1>Activer la double authentification</h1>
          <p className="muted">En plus du mot de passe, un code à 6 chiffres généré par une application sur votre téléphone protège votre compte : un mot de passe volé ne suffit plus.</p>
        </div>
        {error && <Alert kind="error">{error}</Alert>}
        {!error && search.get("reason") === "admin" && <Alert kind="warning">{msg.adminNeedsMfa}</Alert>}
        <form className="stack" onSubmit={submitPassword}>
          <div className="field">
            <label htmlFor="password">Confirmez votre mot de passe</label>
            <input id="password" name="password" type="password" autoComplete="current-password" required autoFocus />
            <p className="hint">Nous le redemandons pour qu’une session volée ne puisse pas lier un autre téléphone à votre compte.</p>
          </div>
          <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
            Continuer
          </button>
        </form>
        <p className="small">
          <button type="button" className="link-button" onClick={() => void logout()}>
            Se déconnecter
          </button>
        </p>
      </div>
    </AuthLayout>
  );
}
