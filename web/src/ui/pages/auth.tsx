// The sign-in side of the mockup (connexion, inscription), wired to the
// real flows: login with TOTP, forgotten password, signup by emailed link,
// password setup from a link, MFA enrolment.

import { useEffect, useRef, useState, type ClipboardEvent, type FormEvent, type KeyboardEvent, type ReactNode } from "react";
import { api, ApiError, isMfaChallenge } from "../../api/client";
import { needsMfa, useAuth } from "../../auth";
import { fallback, msg } from "../../messages";
import { Link, navigate, useLocation } from "../../router";
import { Arrow, Envelope, Eye, Logo } from "../icons";
import { EMAIL_RE, pwScore } from "../model";
import { shake, useBodyClass, useUI } from "../ui";
import { HeroRadar } from "./public";

function AuthTop({ other }: { other: ReactNode }) {
  return (
    <div className="authtop">
      <Link className="brand" to="/">
        <Logo />
        <span>Orus Shield</span>
      </Link>
      {other}
    </div>
  );
}

function AuthAside({ kind }: { kind: "in" | "up" }) {
  const lines: [string, string][] =
    kind === "up"
      ? [
          ["Gratuit pour commencer", "Un domaine, sans carte bancaire."],
          ["Votre premier résultat en 5 minutes", "Contrôles passifs dès l’inscription."],
          ["Payez quand vous voulez", "Carte ou Mobile Money, sans engagement."],
        ]
      : [
          ["Ce que vous exposez sur internet", "Domaines, emails, serveurs, certificats."],
          ["Ce qu’il faut corriger en premier", "Classé par ce qui vous protège le plus."],
          ["Comment le corriger", "Étape par étape, en français."],
        ];
  return (
    <aside className="authside" aria-hidden="true">
      <HeroRadar scanning />
      <ul>
        {lines.map(([b, s]) => (
          <li key={b}>
            <b>{b}</b>
            <span>{s}</span>
          </li>
        ))}
      </ul>
    </aside>
  );
}

function AuthLayout({ top, aside, anim, children }: { top: ReactNode; aside: "in" | "up"; anim: string; children: ReactNode }) {
  useBodyClass(["public", "focus"]);
  return (
    <main>
      <div className="view">
        <div className="authwrap">
          <div className="authmain">
            <AuthTop other={top} />
            <div className="authbody" key={anim}>
              {children}
            </div>
          </div>
          <AuthAside kind={aside} />
        </div>
      </div>
    </main>
  );
}

const PW_HINTS = ["Trop court.", "Faible.", "Moyen : ajoutez des symboles ou allongez-le.", "Bon.", "Très solide."];

/** PasswordField is the mockup's new-password field with its meter. */
function PasswordField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const s = pwScore(value);
  return (
    <div className="field">
      <label htmlFor="pw">Mot de passe</label>
      <input id="pw" type="password" autoComplete="new-password" value={value} onChange={(e) => onChange(e.target.value)} />
      <div className={"pwmeter s" + s} id="pwmeter" aria-hidden="true">
        <i />
        <i />
        <i />
        <i />
      </div>
      <p className="md" id="pwhint" aria-live="polite">
        {value ? PW_HINTS[s] : "12 caractères au moins, avec des chiffres et des symboles."}
      </p>
    </div>
  );
}

/** afterSignIn sends a signed-in user to the app (or MFA enrolment). */
function afterSignIn(me: Parameters<typeof needsMfa>[0]) {
  navigate(needsMfa(me) ? "/mfa/setup?reason=admin" : "/app", { replace: true });
}

function Otp({ onComplete }: { onComplete: (code: string) => void }) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const [vals, setVals] = useState(["", "", "", "", "", ""]);
  const set = (next: string[]) => {
    setVals(next);
    if (next.every(Boolean)) onComplete(next.join(""));
  };
  const input = (i: number, v: string) => {
    const d = v.replace(/\D/g, "").slice(-1);
    const next = vals.map((x, j) => (j === i ? d : x));
    if (d && i < 5) refs.current[i + 1]?.focus();
    set(next);
  };
  const key = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !vals[i] && i > 0) {
      e.preventDefault();
      setVals(vals.map((x, j) => (j === i - 1 ? "" : x)));
      refs.current[i - 1]?.focus();
    } else if (e.key === "ArrowLeft" && i > 0) refs.current[i - 1]?.focus();
    else if (e.key === "ArrowRight" && i < 5) refs.current[i + 1]?.focus();
  };
  const paste = (e: ClipboardEvent<HTMLInputElement>) => {
    const digits = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
    if (!digits) return;
    e.preventDefault();
    const next = [0, 1, 2, 3, 4, 5].map((i) => digits[i] ?? "");
    refs.current[Math.min(digits.length, 5)]?.focus();
    set(next);
  };
  return (
    <div className="otp" role="group" aria-label="Code à 6 chiffres">
      {vals.map((v, i) => (
        <input
          key={i}
          ref={(el) => {
            refs.current[i] = el;
          }}
          type="text"
          inputMode="numeric"
          maxLength={1}
          autoComplete={i ? "off" : "one-time-code"}
          aria-label={`Chiffre ${i + 1}`}
          data-otp={i}
          className={v ? "filled" : ""}
          value={v}
          autoFocus={i === 0}
          onChange={(e) => input(i, e.target.value)}
          onKeyDown={(e) => key(i, e)}
          onPaste={paste}
        />
      ))}
    </div>
  );
}

type LoginStep = "creds" | "mfa" | "forgot" | "sent";

export function ConnexionPage() {
  const { signedIn } = useAuth();
  const { search } = useLocation();
  const [step, setStep] = useState<LoginStep>("creds");
  const [email, setEmail] = useState("");
  const [pw, setPw] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState("");
  const [recovery, setRecovery] = useState(false);
  const [rcode, setRcode] = useState("");
  const form = useRef<HTMLFormElement>(null);
  const notice =
    {
      password: "Mot de passe enregistré. Connectez-vous.",
      logout: "Vous êtes déconnecté.",
      signup: "Compte créé. Connectez-vous.",
      expired: "Votre session a expiré. Reconnectez-vous.",
    }[search.get("ok") ?? ""] ?? "";

  const fail = (m: string) => {
    setErr(m);
    shake(form.current);
  };
  const go = (s: LoginStep) => {
    setErr("");
    setStep(s);
  };
  /**
   * sessionKept checks that the browser kept the session cookie the login
   * set. Safari refuses Secure cookies on http://localhost: without this,
   * the dashboard would open and every request would fail.
   */
  const sessionKept = async (): Promise<boolean> => {
    try {
      await api.me();
      return true;
    } catch (e2) {
      if (!(e2 instanceof ApiError && e2.status === 401)) throw e2;
      go("creds");
      fail(msg.cookieRefused);
      return false;
    }
  };

  const login = async (e: FormEvent) => {
    e.preventDefault();
    const em = email.trim();
    if (!EMAIL_RE.test(em)) return fail(em ? "Cette adresse email n’est pas valide." : "Saisissez votre adresse email.");
    if (!pw) return fail("Saisissez votre mot de passe.");
    setBusy(true);
    try {
      const res = await api.login(em, pw);
      if (isMfaChallenge(res)) {
        setToken(res.mfa_token);
        go("mfa");
      } else if (await sessionKept()) {
        signedIn(res);
        afterSignIn(res);
      }
    } catch (e2) {
      fail(e2 instanceof ApiError && e2.status === 401 ? msg.badCredentials : fallback(e2));
    } finally {
      setBusy(false);
    }
  };

  const verify = async (code: string) => {
    if (!recovery && !/^\d{6}$/.test(code)) return fail("Saisissez les 6 chiffres du code.");
    if (recovery && !code.trim()) return fail("Saisissez l’un de vos codes de secours.");
    setBusy(true);
    try {
      const me = await api.loginMfa(token, code.trim());
      if (await sessionKept()) {
        signedIn(me);
        afterSignIn(me);
      }
    } catch (e2) {
      if (e2 instanceof ApiError && e2.code === "login_expired") {
        setPw("");
        go("creds");
        setErr(msg.loginExpired);
      } else fail(e2 instanceof ApiError && e2.status === 401 ? (recovery ? msg.badRecovery : msg.badCode) : fallback(e2));
    } finally {
      setBusy(false);
    }
  };

  const forgot = async (e: FormEvent) => {
    e.preventDefault();
    const em = email.trim();
    if (!EMAIL_RE.test(em)) return fail(em ? "Cette adresse email n’est pas valide." : "Saisissez votre adresse email.");
    try {
      await api.forgotPassword(em);
      go("sent");
    } catch (e2) {
      fail(e2 instanceof ApiError && e2.status === 429 ? msg.resetRateLimited : fallback(e2));
    }
  };

  let body: ReactNode;
  if (step === "creds") {
    body = (
      <>
        <h1>Bon retour.</h1>
        <p className="sub">{notice || "Connectez-vous pour voir votre périmètre."}</p>
        <form ref={form} className="aform" noValidate onSubmit={(e) => void login(e)}>
          <div className="field">
            <label htmlFor="li-email">Adresse email</label>
            <input id="li-email" type="email" autoComplete="email" placeholder="vous@entreprise.cg" value={email} autoFocus onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="field">
            <div className="flabel">
              <label htmlFor="li-pw">Mot de passe</label>
              <button className="link" type="button" onClick={() => go("forgot")}>
                Mot de passe oublié
              </button>
            </div>
            <div className="pwwrap">
              <input id="li-pw" type={showPw ? "text" : "password"} autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} />
              <button type="button" className="eye" aria-label={`${showPw ? "Masquer" : "Afficher"} le mot de passe`} aria-pressed={showPw} onClick={() => setShowPw(!showPw)}>
                <Eye />
              </button>
            </div>
          </div>
          <p className="err" role="alert">
            {err}
          </p>
          <button className="btn wide" type="submit" disabled={busy}>
            {busy ? (
              <>
                <span className="spin" />
                Connexion
              </>
            ) : (
              "Se connecter"
            )}
          </button>
        </form>
        <p className="swap">
          Pas encore de compte ? <Link to="/inscription">Créer un compte</Link>
        </p>
      </>
    );
  } else if (step === "mfa") {
    body = (
      <>
        <button className="back" type="button" onClick={() => go("creds")}>
          <Arrow />
          Retour
        </button>
        <h1>{recovery ? "Un code de secours." : "Votre code à 6 chiffres."}</h1>
        <p className="sub">{recovery ? `Saisissez l’un des codes de secours reçus à l’activation, pour ${email}.` : `Ouvrez votre application d’authentification pour ${email}.`}</p>
        <form
          ref={form}
          className="aform"
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            if (recovery) void verify(rcode);
            else void verify([...(form.current?.querySelectorAll<HTMLInputElement>("[data-otp]") ?? [])].map((i) => i.value).join(""));
          }}
        >
          {recovery ? (
            <div className="field">
              <label htmlFor="rc">Code de secours</label>
              <input id="rc" type="text" autoComplete="off" autoFocus value={rcode} onChange={(e) => setRcode(e.target.value)} />
            </div>
          ) : (
            <Otp onComplete={(c) => void verify(c)} />
          )}
          <p className="err" role="alert">
            {err}
          </p>
          <button className="btn wide" type="submit" disabled={busy}>
            Vérifier
          </button>
        </form>
        <p className="swap">
          <button
            className="link"
            type="button"
            onClick={() => {
              setRecovery(!recovery);
              setErr("");
            }}
          >
            {recovery ? "Utiliser le code de l’application" : "Utiliser un code de secours"}
          </button>
        </p>
      </>
    );
  } else if (step === "forgot") {
    body = (
      <>
        <button className="back" type="button" onClick={() => go("creds")}>
          <Arrow />
          Retour
        </button>
        <h1>Mot de passe oublié.</h1>
        <p className="sub">Nous vous envoyons un lien valable une heure.</p>
        <form ref={form} className="aform" noValidate onSubmit={(e) => void forgot(e)}>
          <div className="field">
            <label htmlFor="fg-email">Adresse email</label>
            <input id="fg-email" type="email" autoComplete="email" value={email} autoFocus onChange={(e) => setEmail(e.target.value)} />
          </div>
          <p className="err" role="alert">
            {err}
          </p>
          <button className="btn wide" type="submit">
            Envoyer le lien
          </button>
        </form>
      </>
    );
  } else {
    body = (
      <>
        <Envelope />
        <h1>Regardez votre boîte mail.</h1>
        <p className="sub">Si un compte existe pour {email}, vous allez recevoir un lien pour choisir un nouveau mot de passe.</p>
        <button className="btn ghost wide" type="button" onClick={() => go("creds")}>
          Retour à la connexion
        </button>
      </>
    );
  }
  return (
    <AuthLayout
      aside="in"
      anim={step + (recovery ? "r" : "")}
      top={
        <Link className="link" to="/inscription">
          Créer un compte
        </Link>
      }
    >
      {body}
    </AuthLayout>
  );
}

const OFFERS: Record<string, string> = { sme: "Essentiel", pro: "Pro" };

export function InscriptionPage() {
  const { search } = useLocation();
  const { toast } = useUI();
  const offer = OFFERS[search.get("offre") ?? ""];
  const [step, setStep] = useState<"form" | "sent">("form");
  const [email, setEmail] = useState("");
  const [orgName, setOrgName] = useState("");
  const [terms, setTerms] = useState(false);
  const [err, setErr] = useState("");
  const [cool, setCool] = useState(0);
  const form = useRef<HTMLFormElement>(null);

  useEffect(() => {
    if (!cool) return;
    const t = setTimeout(() => setCool(cool - 1), 1000);
    return () => clearTimeout(t);
  }, [cool]);

  const fail = (m: string) => {
    setErr(m);
    shake(form.current);
  };
  const send = async () => {
    await api.signup(email.trim(), orgName.trim());
  };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const em = email.trim();
    if (!EMAIL_RE.test(em)) return fail(em ? "Cette adresse email n’est pas valide." : "Saisissez votre adresse email.");
    if (orgName.trim().length < 2) return fail("Saisissez le nom de votre entreprise.");
    if (!terms) return fail("Acceptez les conditions pour continuer.");
    try {
      await send();
      setErr("");
      setStep("sent");
    } catch (e2) {
      fail(
        e2 instanceof ApiError && e2.status === 429
          ? msg.signupRateLimited
          : e2 instanceof ApiError && e2.status === 404
            ? msg.signupClosed
            : e2 instanceof ApiError && e2.status === 400
              ? msg.signupInvalid
              : fallback(e2),
      );
    }
  };
  const resend = async () => {
    try {
      await send();
      setCool(30);
      toast("Lien renvoyé");
    } catch (e2) {
      toast(e2 instanceof ApiError && e2.status === 429 ? msg.signupRateLimited : "Envoi impossible pour le moment");
    }
  };
  const dots = (
    <span className="sdots" aria-label="Étape">
      <i className="on" />
      <i className={step === "sent" ? "on" : ""} />
      <i />
    </span>
  );

  return (
    <AuthLayout aside="up" anim={step} top={dots}>
      {step === "form" ? (
        <>
          <h1>Créez votre compte.</h1>
          <p className="sub">{offer ? `Offre ${offer} choisie. 14 jours d’essai, sans carte bancaire.` : "Gratuit, sans carte bancaire. Votre premier résultat dans 5 minutes."}</p>
          <form ref={form} className="aform" noValidate onSubmit={(e) => void submit(e)}>
            <div className="field">
              <label htmlFor="su-email">Adresse email professionnelle</label>
              <input id="su-email" type="email" autoComplete="email" placeholder="vous@entreprise.cg" value={email} autoFocus onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="su-org">Nom de votre entreprise</label>
              <input id="su-org" type="text" autoComplete="organization" placeholder="Microfinance Exemple SA" value={orgName} onChange={(e) => setOrgName(e.target.value)} />
            </div>
            <label className="consent small">
              <input type="checkbox" id="su-terms" checked={terms} onChange={(e) => setTerms(e.target.checked)} />
              <span>
                J’accepte les{" "}
                <a href="/" onClick={(e) => (e.preventDefault(), toast("Conditions d’utilisation : bientôt disponibles"))}>
                  conditions d’utilisation
                </a>{" "}
                et la{" "}
                <a href="/" onClick={(e) => (e.preventDefault(), toast("Politique de confidentialité : bientôt disponible"))}>
                  politique de confidentialité
                </a>
                .
              </span>
            </label>
            <p className="err" role="alert">
              {err}
            </p>
            <button className="btn wide" type="submit">
              Recevoir mon lien
            </button>
          </form>
          <p className="swap">
            Déjà un compte ? <Link to="/connexion">Se connecter</Link>
          </p>
        </>
      ) : (
        <>
          <Envelope />
          <h1>Un lien vous attend.</h1>
          <p className="sub">
            Nous l’avons envoyé à <b style={{ color: "var(--ink)" }}>{email}</b>. Il crée votre compte et l’espace de {orgName}. Il est valable une heure.
          </p>
          <div className="actions">
            <button className="btn ghost" type="button" disabled={cool > 0} onClick={() => void resend()}>
              {cool ? `Renvoyer dans ${cool} s` : "Renvoyer le lien"}
            </button>
          </div>
          <p className="swap">
            <button className="link" type="button" onClick={() => setStep("form")}>
              Changer d’adresse
            </button>
          </p>
        </>
      )}
    </AuthLayout>
  );
}

/** The token arrives in the URL fragment; it is removed from the address bar once read. */
function tokenFromFragment(): string {
  const t = new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
  if (t) window.history.replaceState(null, "", window.location.pathname + window.location.search);
  return t;
}

/**
 * SetPasswordPage is the last step of a link: signup (/signup/complete),
 * an invitation or a reset (/setup-password).
 */
export function SetPasswordPage({ kind }: { kind: "signup" | "setup" }) {
  const [token] = useState(tokenFromFragment);
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const form = useRef<HTMLFormElement>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (pw.length < 12 || pwScore(pw) < 3) {
      setErr("Ce mot de passe est trop faible. Allongez-le ou ajoutez des chiffres et des symboles.");
      shake(form.current);
      return;
    }
    setBusy(true);
    try {
      if (kind === "signup") await api.completeSignup(token, pw);
      else await api.setupPassword(token, pw);
      navigate(`/connexion?ok=${kind === "signup" ? "signup" : "password"}`, { replace: true });
    } catch (e2) {
      setErr(
        e2 instanceof ApiError && e2.code === "account_exists"
          ? msg.accountExists
          : e2 instanceof ApiError && e2.status === 400
            ? kind === "signup"
              ? msg.signupLink
              : msg.setupToken
            : fallback(e2),
      );
      shake(form.current);
    } finally {
      setBusy(false);
    }
  };
  const dots = (
    <span className="sdots" aria-label="Étape">
      <i className="on" />
      <i className="on" />
      <i className="on" />
    </span>
  );
  return (
    <AuthLayout aside={kind === "signup" ? "up" : "in"} anim="password" top={dots}>
      <h1>Choisissez un mot de passe.</h1>
      <p className="sub">{token ? "Dernière étape." : kind === "signup" ? msg.signupLink : msg.setupToken}</p>
      {token && (
        <form ref={form} className="aform" noValidate onSubmit={(e) => void submit(e)}>
          <PasswordField
            value={pw}
            onChange={(v) => {
              setPw(v);
              setErr("");
            }}
          />
          <p className="err" id="pw-err" role="alert">
            {err}
          </p>
          <button className="btn wide" type="submit" disabled={busy}>
            {kind === "signup" ? "Créer mon compte" : "Enregistrer le mot de passe"}
          </button>
        </form>
      )}
    </AuthLayout>
  );
}

/** otpauthLink keeps only the otpauth: scheme. */
function otpauthLink(uri: string): string | undefined {
  return uri.startsWith("otpauth://") ? uri : undefined;
}

/** MfaSetupPage enrols the TOTP second factor (mandatory for admins). */
export function MfaSetupPage() {
  const { refresh, state } = useAuth();
  const { search } = useLocation();
  const [step, setStep] = useState<{ kind: "password" } | { kind: "enrol"; secret: string; uri: string } | { kind: "codes"; codes: string[] }>({ kind: "password" });
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const form = useRef<HTMLFormElement>(null);
  const fail = (m: string) => {
    setErr(m);
    shake(form.current);
  };
  const begin = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const s = await api.mfaSetup(pw);
      setErr("");
      setStep({ kind: "enrol", secret: s.secret, uri: s.otpauth_uri });
    } catch (e2) {
      fail(e2 instanceof ApiError && e2.status === 403 ? msg.badPassword : fallback(e2));
    }
  };
  const confirm = async (code: string) => {
    if (!/^\d{6}$/.test(code)) return fail("Saisissez les 6 chiffres du code.");
    try {
      const r = await api.mfaConfirm(code);
      setErr("");
      setStep({ kind: "codes", codes: r.recovery_codes });
    } catch (e2) {
      fail(e2 instanceof ApiError && (e2.status === 400 || e2.status === 401 || e2.status === 403) ? msg.badCode : fallback(e2));
    }
  };
  const email = state.status === "signed-in" ? state.me.email : "";
  let body: ReactNode;
  if (step.kind === "password") {
    body = (
      <>
        <h1>Protégez votre compte.</h1>
        <p className="sub">{search.get("reason") === "admin" ? msg.adminNeedsMfa : "Activez la double authentification avec une application (Google Authenticator, Authy, 1Password...)."}</p>
        <form ref={form} className="aform" noValidate onSubmit={(e) => void begin(e)}>
          <div className="field">
            <label htmlFor="mfa-pw">Mot de passe de {email}</label>
            <input id="mfa-pw" type="password" autoComplete="current-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} />
          </div>
          <p className="err" role="alert">
            {err}
          </p>
          <button className="btn wide" type="submit">
            Continuer
          </button>
        </form>
      </>
    );
  } else if (step.kind === "enrol") {
    const link = otpauthLink(step.uri);
    body = (
      <>
        <h1>Ajoutez Orus Shield à votre application.</h1>
        <p className="sub">Sur téléphone, touchez le lien ; sinon saisissez la clé dans l’application, puis le code qu’elle affiche.</p>
        <div className="record">
          <div>
            <small>Clé à saisir</small>
            <b>{step.secret}</b>
          </div>
          {link && (
            <div>
              <a className="link" href={link}>
                Ouvrir dans l’application d’authentification
              </a>
            </div>
          )}
        </div>
        <form
          ref={form}
          className="aform"
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            void confirm([...(form.current?.querySelectorAll<HTMLInputElement>("[data-otp]") ?? [])].map((i) => i.value).join(""));
          }}
        >
          <Otp onComplete={(c) => void confirm(c)} />
          <p className="err" role="alert">
            {err}
          </p>
          <button className="btn wide" type="submit">
            Vérifier
          </button>
        </form>
      </>
    );
  } else {
    body = (
      <>
        <h1>Gardez vos codes de secours.</h1>
        <p className="sub">Chacun remplace une fois le code de l’application si vous perdez votre téléphone. Ils ne seront plus affichés.</p>
        <pre className="record" style={{ fontFamily: "ui-monospace,Menlo,monospace", whiteSpace: "pre-wrap" }}>
          {step.codes.join("\n")}
        </pre>
        <div className="actions">
          <button
            className="btn wide"
            type="button"
            onClick={() =>
              void refresh().then(() => navigate("/app", { replace: true }))
            }
          >
            J’ai noté mes codes
          </button>
        </div>
      </>
    );
  }
  return (
    <AuthLayout aside="in" anim={step.kind} top={<span />}>
      {body}
    </AuthLayout>
  );
}
