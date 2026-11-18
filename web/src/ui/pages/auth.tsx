// The sign-in side of the mockup (connexion, inscription), wired to the
// real flows: login with TOTP, forgotten password, signup by emailed link,
// password setup from a link, MFA enrolment.

import { useEffect, useRef, useState, type ClipboardEvent, type FormEvent, type KeyboardEvent, type ReactNode } from "react";
import { api, ApiError, isMfaChallenge } from "../../api/client";
import { needsMfa, useAuth } from "../../auth";
import { tr } from "../../i18n";
import { fallback, msg } from "../../messages";
import { Link, navigate, useLocation } from "../../router";
import { Arrow, Envelope, Eye, Logo } from "../icons";
import { LangSwitch } from "../LangSwitch";
import { cleanDomain, rememberDomain } from "../prefill";
import { EMAIL_RE, pwScore } from "../model";
import { encodeQR, qrPath } from "../qr";
import { shake, useBodyClass, useUI } from "../ui";
import { HeroRadar } from "./public";

function AuthTop({ other }: { other: ReactNode }) {
  return (
    <div className="authtop">
      <Link className="brand" to="/">
        <Logo />
        <span>Orus Shield</span>
      </Link>
      <div className="authtopr">
        {other}
        <LangSwitch />
      </div>
    </div>
  );
}

function AuthAside({ kind }: { kind: "in" | "up" }) {
  const lines: [string, string][] =
    kind === "up"
      ? [
          [tr("Un audit gratuit pour commencer", "A free audit to start"), tr("Un domaine, sans carte bancaire.", "One domain, no card needed.")],
          [tr("Votre premier résultat en 5 minutes", "Your first result in 5 minutes"), tr("Contrôles passifs dès l’inscription.", "Passive checks as soon as you sign up.")],
          [tr("Payez quand vous voulez", "Pay when you are ready"), tr("Carte ou PayPal, sans engagement.", "Card or PayPal, no commitment.")],
        ]
      : [
          [tr("Ce que vous exposez sur internet", "What you expose on the internet"), tr("Domaines, emails, serveurs, certificats.", "Domains, email, servers, certificates.")],
          [tr("Ce qu’il faut corriger en premier", "What to fix first"), tr("Classé par ce qui vous protège le plus.", "Ranked by what protects you most.")],
          [tr("Comment le corriger", "How to fix it"), tr("Étape par étape, en français.", "Step by step, in plain English.")],
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

const pwHints = () => [
  tr("Trop court.", "Too short."),
  tr("Faible.", "Weak."),
  tr("Moyen : ajoutez des symboles ou allongez-le.", "Fair: add symbols or make it longer."),
  tr("Bon.", "Good."),
  tr("Très solide.", "Very strong."),
];

/** PasswordField is the mockup's new-password field with its meter. */
function PasswordField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const s = pwScore(value);
  return (
    <div className="field">
      <label htmlFor="pw">{tr("Mot de passe", "Password")}</label>
      <input id="pw" type="password" autoComplete="new-password" value={value} onChange={(e) => onChange(e.target.value)} />
      <div className={"pwmeter s" + s} id="pwmeter" aria-hidden="true">
        <i />
        <i />
        <i />
        <i />
      </div>
      <p className="md" id="pwhint" aria-live="polite">
        {value ? pwHints()[s] : tr("12 caractères au moins, avec des chiffres et des symboles.", "At least 12 characters, with numbers and symbols.")}
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
    <div className="otp" role="group" aria-label={tr("Code à 6 chiffres", "6-digit code")}>
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
          aria-label={tr(`Chiffre ${i + 1}`, `Digit ${i + 1}`)}
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
      password: tr("Mot de passe enregistré. Connectez-vous.", "Password saved. Sign in."),
      logout: tr("Vous êtes déconnecté.", "You are signed out."),
      signup: tr("Compte créé. Connectez-vous.", "Account created. Sign in."),
      expired: tr("Votre session a expiré. Reconnectez-vous.", "Your session has expired. Sign in again."),
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
    if (!EMAIL_RE.test(em)) return fail(em ? tr("Cette adresse email n’est pas valide.", "This email address is not valid.") : tr("Saisissez votre adresse email.", "Enter your email address."));
    if (!pw) return fail(tr("Saisissez votre mot de passe.", "Enter your password."));
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
    if (!recovery && !/^\d{6}$/.test(code)) return fail(tr("Saisissez les 6 chiffres du code.", "Enter the 6 digits of the code."));
    if (recovery && !code.trim()) return fail(tr("Saisissez l’un de vos codes de secours.", "Enter one of your recovery codes."));
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
    if (!EMAIL_RE.test(em)) return fail(em ? tr("Cette adresse email n’est pas valide.", "This email address is not valid.") : tr("Saisissez votre adresse email.", "Enter your email address."));
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
        <h1>{tr("Bon retour.", "Welcome back.")}</h1>
        <p className="sub">{notice || tr("Connectez-vous pour voir votre périmètre.", "Sign in to see your attack surface.")}</p>
        <form ref={form} className="aform" noValidate onSubmit={(e) => void login(e)}>
          <div className="field">
            <label htmlFor="li-email">{tr("Adresse email", "Email address")}</label>
            <input id="li-email" type="email" autoComplete="email" placeholder={tr("vous@entreprise.cg", "you@company.com")} value={email} autoFocus onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="field">
            <div className="flabel">
              <label htmlFor="li-pw">{tr("Mot de passe", "Password")}</label>
              <button className="link" type="button" onClick={() => go("forgot")}>
                {tr("Mot de passe oublié", "Forgot password")}
              </button>
            </div>
            <div className="pwwrap">
              <input id="li-pw" type={showPw ? "text" : "password"} autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} />
              <button type="button" className="eye" aria-label={showPw ? tr("Masquer le mot de passe", "Hide password") : tr("Afficher le mot de passe", "Show password")} aria-pressed={showPw} onClick={() => setShowPw(!showPw)}>
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
                {tr("Connexion", "Signing in")}
              </>
            ) : (
              tr("Se connecter", "Sign in")
            )}
          </button>
        </form>
        <p className="swap">
          {tr("Pas encore de compte ?", "No account yet?")} <Link to="/inscription">{tr("Créer un compte", "Create an account")}</Link>
        </p>
      </>
    );
  } else if (step === "mfa") {
    body = (
      <>
        <button className="back" type="button" onClick={() => go("creds")}>
          <Arrow />
          {tr("Retour", "Back")}
        </button>
        <h1>{recovery ? tr("Un code de secours.", "A recovery code.") : tr("Votre code à 6 chiffres.", "Your 6-digit code.")}</h1>
        <p className="sub">
          {recovery
            ? tr(`Saisissez l’un des codes de secours reçus à l’activation, pour ${email}.`, `Enter one of the recovery codes you received at activation, for ${email}.`)
            : tr(`Ouvrez votre application d’authentification pour ${email}.`, `Open your authenticator app for ${email}.`)}
        </p>
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
              <label htmlFor="rc">{tr("Code de secours", "Recovery code")}</label>
              <input id="rc" type="text" autoComplete="off" autoFocus value={rcode} onChange={(e) => setRcode(e.target.value)} />
            </div>
          ) : (
            <Otp onComplete={(c) => void verify(c)} />
          )}
          <p className="err" role="alert">
            {err}
          </p>
          <button className="btn wide" type="submit" disabled={busy}>
            {tr("Vérifier", "Verify")}
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
            {recovery ? tr("Utiliser le code de l’application", "Use the app’s code") : tr("Utiliser un code de secours", "Use a recovery code")}
          </button>
        </p>
      </>
    );
  } else if (step === "forgot") {
    body = (
      <>
        <button className="back" type="button" onClick={() => go("creds")}>
          <Arrow />
          {tr("Retour", "Back")}
        </button>
        <h1>{tr("Mot de passe oublié.", "Forgot your password.")}</h1>
        <p className="sub">{tr("Nous vous envoyons un lien valable une heure.", "We will send you a link, valid for one hour.")}</p>
        <form ref={form} className="aform" noValidate onSubmit={(e) => void forgot(e)}>
          <div className="field">
            <label htmlFor="fg-email">{tr("Adresse email", "Email address")}</label>
            <input id="fg-email" type="email" autoComplete="email" value={email} autoFocus onChange={(e) => setEmail(e.target.value)} />
          </div>
          <p className="err" role="alert">
            {err}
          </p>
          <button className="btn wide" type="submit">
            {tr("Envoyer le lien", "Send the link")}
          </button>
        </form>
      </>
    );
  } else {
    body = (
      <>
        <Envelope />
        <h1>{tr("Regardez votre boîte mail.", "Check your inbox.")}</h1>
        <p className="sub">{tr(`Si un compte existe pour ${email}, vous allez recevoir un lien pour choisir un nouveau mot de passe.`, `If an account exists for ${email}, you will receive a link to choose a new password.`)}</p>
        <button className="btn ghost wide" type="button" onClick={() => go("creds")}>
          {tr("Retour à la connexion", "Back to sign in")}
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
          {tr("Créer un compte", "Create an account")}
        </Link>
      }
    >
      {body}
    </AuthLayout>
  );
}

const OFFERS: Record<string, string> = { sme: "Essentiel", pro: "Pro" };
const offerName = (o: string) => (o === "Essentiel" ? tr("Essentiel", "Essential") : o);

// The offer chosen on Tarifs before signing up, kept in this browser until
// the new admin first reaches the dashboard, which then opens its payment
// (the 14-day trial starts there, with a card). A convenience only: without
// it the customer finds the offer in Réglages, Abonnement.
const OFFER_KEY = "orus.offer";

/** takeOffer returns the offer chosen before signup ("sme", "pro") once. */
export function takeOffer(): string {
  try {
    const o = localStorage.getItem(OFFER_KEY) ?? "";
    localStorage.removeItem(OFFER_KEY);
    return o in OFFERS ? o : "";
  } catch {
    return "";
  }
}

function rememberOffer(o: string) {
  try {
    if (o in OFFERS) localStorage.setItem(OFFER_KEY, o);
  } catch {
    // Private browsing: the offer stays in Réglages.
  }
}

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
    if (!EMAIL_RE.test(em)) return fail(em ? tr("Cette adresse email n’est pas valide.", "This email address is not valid.") : tr("Saisissez votre adresse email.", "Enter your email address."));
    if (orgName.trim().length < 2) return fail(tr("Saisissez le nom de votre entreprise.", "Enter your company’s name."));
    if (!terms) return fail(tr("Acceptez les conditions pour continuer.", "Accept the terms to continue."));
    try {
      await send();
      rememberOffer(search.get("offre") ?? "");
      // A domain tested on the public test page: Premiers pas offers it.
      rememberDomain(cleanDomain(search.get("domaine") ?? ""));
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
      toast(tr("Lien renvoyé", "Link sent again"));
    } catch (e2) {
      toast(e2 instanceof ApiError && e2.status === 429 ? msg.signupRateLimited : tr("Envoi impossible pour le moment", "Cannot send it right now"));
    }
  };
  const dots = (
    <span className="sdots" aria-label={tr("Étape", "Step")}>
      <i className="on" />
      <i className={step === "sent" ? "on" : ""} />
      <i />
    </span>
  );

  return (
    <AuthLayout aside="up" anim={step} top={dots}>
      {step === "form" ? (
        <>
          <h1>{tr("Créez votre compte.", "Create your account.")}</h1>
          <p className="sub">
            {offer
              ? tr(`Offre ${offer} choisie. Vous paierez à la fin, après 14 jours d’essai.`, `${offerName(offer)} plan chosen. You will pay at the end of the 14-day trial.`)
              : tr("Audit gratuit de votre domaine, sans carte bancaire. Votre premier résultat dans 5 minutes.", "A free audit of your domain, no card needed. Your first result in 5 minutes.")}
          </p>
          <form ref={form} className="aform" noValidate onSubmit={(e) => void submit(e)}>
            <div className="field">
              <label htmlFor="su-email">{tr("Adresse email professionnelle", "Work email address")}</label>
              <input id="su-email" type="email" autoComplete="email" placeholder={tr("vous@entreprise.cg", "you@company.com")} value={email} autoFocus onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="su-org">{tr("Nom de votre entreprise", "Company name")}</label>
              <input id="su-org" type="text" autoComplete="organization" placeholder={tr("Microfinance Exemple SA", "Example Microfinance Ltd")} value={orgName} onChange={(e) => setOrgName(e.target.value)} />
            </div>
            <label className="consent small">
              <input type="checkbox" id="su-terms" checked={terms} onChange={(e) => setTerms(e.target.checked)} />
              <span>
                {tr("J’accepte les", "I accept the")}{" "}
                <a href="/conditions" target="_blank" rel="noopener">
                  {tr("conditions d’utilisation", "terms of use")}
                </a>{" "}
                {tr("et la", "and the")}{" "}
                <a href="/confidentialite" target="_blank" rel="noopener">
                  {tr("politique de confidentialité", "privacy policy")}
                </a>
                .
              </span>
            </label>
            <p className="err" role="alert">
              {err}
            </p>
            <button className="btn wide" type="submit">
              {tr("Recevoir mon lien", "Get my link")}
            </button>
          </form>
          <p className="swap">
            {tr("Déjà un compte ?", "Already have an account?")} <Link to="/connexion">{tr("Se connecter", "Sign in")}</Link>
          </p>
        </>
      ) : (
        <>
          <Envelope />
          <h1>{tr("Un lien vous attend.", "A link is waiting for you.")}</h1>
          <p className="sub">
            {tr("Nous l’avons envoyé à", "We sent it to")} <b style={{ color: "var(--ink)" }}>{email}</b>.{" "}
            {tr(`Il crée votre compte et l’espace de ${orgName}. Il est valable une heure.`, `It creates your account and ${orgName}’s workspace. It is valid for one hour.`)}
          </p>
          <div className="actions">
            <button className="btn ghost" type="button" disabled={cool > 0} onClick={() => void resend()}>
              {cool ? tr(`Renvoyer dans ${cool} s`, `Resend in ${cool} s`) : tr("Renvoyer le lien", "Resend the link")}
            </button>
          </div>
          <p className="swap">
            <button className="link" type="button" onClick={() => setStep("form")}>
              {tr("Changer d’adresse", "Use another address")}
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
      setErr(tr("Ce mot de passe est trop faible. Allongez-le ou ajoutez des chiffres et des symboles.", "This password is too weak. Make it longer or add numbers and symbols."));
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
    <span className="sdots" aria-label={tr("Étape", "Step")}>
      <i className="on" />
      <i className="on" />
      <i className="on" />
    </span>
  );
  return (
    <AuthLayout aside={kind === "signup" ? "up" : "in"} anim="password" top={dots}>
      <h1>{tr("Choisissez un mot de passe.", "Choose a password.")}</h1>
      <p className="sub">{token ? tr("Dernière étape.", "Last step.") : kind === "signup" ? msg.signupLink : msg.setupToken}</p>
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
            {kind === "signup" ? tr("Créer mon compte", "Create my account") : tr("Enregistrer le mot de passe", "Save the password")}
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

/** QrCode draws text as a QR code: dark modules on a white tile with its
 * quiet zone, white in both themes because scanners need dark on light. */
function QrCode({ text }: { text: string }) {
  const m = encodeQR(text);
  const side = m.length + 8; // 4 modules of quiet zone on each side
  return (
    <svg className="qr" viewBox={`0 0 ${side} ${side}`} shapeRendering="crispEdges" role="img" aria-label={tr("Code QR à scanner avec votre application d’authentification", "QR code to scan with your authenticator app")}>
      <rect width={side} height={side} fill="#FFFFFF" />
      <path d={qrPath(m, 4)} fill="#14213D" />
    </svg>
  );
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
    if (!/^\d{6}$/.test(code)) return fail(tr("Saisissez les 6 chiffres du code.", "Enter the 6 digits of the code."));
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
        <h1>{tr("Protégez votre compte.", "Protect your account.")}</h1>
        <p className="sub">{search.get("reason") === "admin" ? msg.adminNeedsMfa : tr("Activez la double authentification avec une application (Google Authenticator, Authy, 1Password...).", "Turn on two-factor authentication with an app (Google Authenticator, Authy, 1Password...).")}</p>
        <form ref={form} className="aform" noValidate onSubmit={(e) => void begin(e)}>
          <div className="field">
            <label htmlFor="mfa-pw">{tr(`Mot de passe de ${email}`, `Password for ${email}`)}</label>
            <input id="mfa-pw" type="password" autoComplete="current-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} />
          </div>
          <p className="err" role="alert">
            {err}
          </p>
          <button className="btn wide" type="submit">
            {tr("Continuer", "Continue")}
          </button>
        </form>
      </>
    );
  } else if (step.kind === "enrol") {
    const link = otpauthLink(step.uri);
    body = (
      <>
        <h1>{tr("Ajoutez Orus Shield à votre application.", "Add Orus Shield to your app.")}</h1>
        <p className="sub">
          {tr(
            "Scannez le code avec votre application (Google Authenticator, Authy, 1Password...), puis saisissez le code à 6 chiffres qu’elle affiche.",
            "Scan the code with your app (Google Authenticator, Authy, 1Password...), then enter the 6-digit code it shows.",
          )}
        </p>
        <div className="mfakey">
          {link && <QrCode text={link} />}
          <div className="mfakey-txt">
            <small>{link ? tr("Pas d’appareil photo ? Saisissez cette clé", "No camera? Enter this key") : tr("Clé à saisir", "Key to enter")}</small>
            <b>{step.secret}</b>
            {link && (
              <a className="link" href={link}>
                {tr("Sur ce téléphone : ouvrir l’application", "On this phone: open the app")}
              </a>
            )}
          </div>
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
            {tr("Vérifier", "Verify")}
          </button>
        </form>
      </>
    );
  } else {
    body = (
      <>
        <h1>{tr("Gardez vos codes de secours.", "Keep your recovery codes.")}</h1>
        <p className="sub">
          {tr(
            "Chacun remplace une fois le code de l’application si vous perdez votre téléphone. Ils ne seront plus affichés.",
            "Each one replaces the app’s code once if you lose your phone. They will not be shown again.",
          )}
        </p>
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
            {tr("J’ai noté mes codes", "I have saved my codes")}
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

/** UnsubscribePage is the unsubscribe link of the trial reminders
 * (/desinscription#token=). It asks for a click: mail scanners that open
 * links must not unsubscribe anyone. */
export function UnsubscribePage() {
  const [token] = useState(tokenFromFragment);
  const [state, setState] = useState<"ask" | "busy" | "done" | "bad" | "error">(token ? "ask" : "bad");
  const go = async () => {
    setState("busy");
    try {
      await api.unsubscribe(token);
      setState("done");
    } catch (e) {
      setState(e instanceof ApiError && e.status === 404 ? "bad" : "error");
    }
  };
  return (
    <AuthLayout aside="in" anim={state} top={null}>
      {state === "done" ? (
        <>
          <h1>{tr("C’est fait.", "Done.")}</h1>
          <p className="sub">{tr("Vous ne recevrez plus nos rappels sur l’essai. Les alertes de sécurité de votre compte ne changent pas.", "You will no longer receive our trial reminders. Your account’s security alerts do not change.")}</p>
        </>
      ) : state === "bad" ? (
        <>
          <h1>{tr("Ce lien ne fonctionne pas.", "This link does not work.")}</h1>
          <p className="sub">{tr("Il est incomplet ou n’existe pas. Utilisez le lien de votre dernier email.", "It is incomplete or does not exist. Use the link in your latest email.")}</p>
        </>
      ) : (
        <>
          <h1>{tr("Ne plus recevoir nos rappels ?", "Stop receiving our reminders?")}</h1>
          <p className="sub">{tr("Nous arrêterons les rappels sur l’essai gratuit. Les alertes de sécurité de votre compte ne changent pas.", "We will stop the free trial reminders. Your account’s security alerts do not change.")}</p>
          <p className="err" role="alert">
            {state === "error" ? tr("Impossible pour le moment. Réessayez dans un instant.", "Not possible right now. Try again in a moment.") : ""}
          </p>
          <button className="btn wide" type="button" disabled={state === "busy"} onClick={() => void go()}>
            {tr("Me désinscrire", "Unsubscribe")}
          </button>
        </>
      )}
    </AuthLayout>
  );
}
