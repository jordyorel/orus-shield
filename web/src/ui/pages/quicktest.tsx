// The public domain test (/test): anyone tests a domain without an
// account and sees its score and its weak points; leaving an email gives
// the explanations and steps, and the report by email. Only passive checks
// of public data run (package quicktest): the page says so, and what an
// account adds (ports, subdomains, known vulnerabilities, every week).

import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, ApiError } from "../../api/client";
import type { QuickProblem, QuickResult } from "../../api/types";
import { tr, useLang } from "../../i18n";
import { fallback } from "../../messages";
import { Link, navigate, useLocation } from "../../router";
import { Tick } from "../icons";
import { EMAIL_RE, scoreVerdict, sevOf } from "../model";
import { cleanDomain, rememberDomain } from "../prefill";
import { SevTag } from "../sheets";
import { shake, useBodyClass } from "../ui";
import { HeroRadar, PubFoot, PubHead } from "./public";

function errorText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === "invalid_domain") return tr("Saisissez un nom de domaine public, par exemple votre-entreprise.cg.", "Enter a public domain name, such as your-company.com.");
    if (e.code === "rate_limited") return tr("Vous avez lancé beaucoup de tests : réessayez dans une heure.", "You ran many tests: try again in an hour.");
    if (e.code === "busy") return tr("Beaucoup de tests en cours : réessayez dans une minute.", "Many tests are running: try again in a minute.");
    if (e.code === "unreachable") return tr("Rien n’a pu être vérifié sur ce domaine. Existe-t-il bien ?", "Nothing could be checked on this domain. Does it exist?");
  }
  return fallback(e);
}

export function TestPage() {
  useBodyClass(["public"]);
  const { search } = useLocation();
  const asked = search.get("domaine") ?? "";
  const [domain, setDomain] = useState(asked);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [res, setRes] = useState<QuickResult | null>(null);
  const form = useRef<HTMLFormElement>(null);

  const run = async (d: string) => {
    setBusy(true);
    setErr("");
    setRes(null);
    try {
      setRes(await api.quickTest(d));
    } catch (e) {
      setErr(errorText(e));
      shake(form.current);
    } finally {
      setBusy(false);
    }
  };
  // A domain in the address (from the home page's form, or a shared link)
  // is tested at once.
  useEffect(() => {
    const d = cleanDomain(asked);
    if (d) void run(d);
  }, [asked]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const d = cleanDomain(domain);
    if (!d) {
      setErr(tr("Saisissez un nom de domaine.", "Enter a domain name."));
      shake(form.current);
      return;
    }
    setDomain(d);
    if (d === cleanDomain(asked)) void run(d);
    else navigate(`/test?domaine=${encodeURIComponent(d)}`, { replace: true });
  };

  return (
    <main>
      <div className="view">
        <PubHead cur="test" />
        <section className="phead">
          <h1>{tr("Testez la sécurité de votre domaine.", "Test your domain’s security.")}</h1>
          <p className="herosub">
            {tr(
              "Gratuit, sans compte, en 20 secondes : vos emails, votre certificat et votre site, notés sur 100.",
              "Free, no account, in 20 seconds: your email, your certificate and your website, scored out of 100.",
            )}
          </p>
          <form ref={form} className="addrow qtform" noValidate onSubmit={submit}>
            <label className="vh" htmlFor="qt-domain">
              {tr("Votre nom de domaine", "Your domain name")}
            </label>
            <input
              id="qt-domain"
              type="text"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              placeholder={tr("votre-entreprise.cg", "your-company.com")}
              value={domain}
              autoFocus={!asked}
              onChange={(e) => setDomain(e.target.value)}
            />
            <button className="btn" type="submit" disabled={busy}>
              {busy ? <span className="spin" /> : null}
              {tr("Tester mon domaine", "Test my domain")}
            </button>
          </form>
          <p className="err" role="alert">
            {err}
          </p>
        </section>

        {busy && (
          <section className="qtwait" role="status">
            <HeroRadar scanning />
            <p>{tr("Test en cours : emails, certificat, en-têtes du site…", "Testing: email, certificate, site headers…")}</p>
          </section>
        )}
        {res && <Result res={res} />}

        <section className="band">
          <h2>{tr("Ce que ce test vérifie, et ce qu’il ne vérifie pas", "What this test checks, and what it does not")}</h2>
          <p className="sub">
            {tr(
              "Il ne lit que des données publiques, sur le domaine et son www : enregistrements email (SPF, DMARC), certificat et chiffrement, en-têtes de sécurité du site. Il ne touche pas à vos serveurs autrement qu’un visiteur. Les ports ouverts, les sous-domaines, les vulnérabilités connues et la surveillance chaque semaine demandent un compte et la preuve que le domaine est à vous : nous ne testons en profondeur que ce qui vous appartient.",
              "It only reads public data, on the domain and its www: email records (SPF, DMARC), certificate and encryption, the site’s security headers. It touches your servers no more than a visitor does. Open ports, subdomains, known vulnerabilities and weekly monitoring need an account and proof that the domain is yours: we only test in depth what belongs to you.",
            )}
          </p>
        </section>
        <PubFoot />
      </div>
    </main>
  );
}

function Result({ res }: { res: QuickResult }) {
  const { lang } = useLang();
  const [problems, setProblems] = useState<QuickProblem[]>(res.problems);
  const [emailed, setEmailed] = useState(false);
  const passed = res.checks.filter((c) => c.status === "passed");
  const unlocked = problems.some((p) => p.details);
  const title = (p: { title: string; title_fr: string }) => (lang === "fr" && p.title_fr) || p.title;
  const signup = () => {
    rememberDomain(res.domain);
    navigate(`/inscription?domaine=${encodeURIComponent(res.domain)}`);
  };
  return (
    <section className="qtresult" aria-live="polite">
      <div className="rpanel qtscore">
        <div className="qtnum">
          <b>{res.score ?? "–"}</b>
          <span>{tr("sur 100", "out of 100")}</span>
        </div>
        <div>
          <p className="plankicker">{res.domain}</p>
          <p className="qtverdict">{scoreVerdict(res.score, problems.length)}</p>
          <p className="md">
            {tr(
              `${passed.length} contrôle${passed.length > 1 ? "s" : ""} réussi${passed.length > 1 ? "s" : ""}, ${problems.length} problème${problems.length > 1 ? "s" : ""} trouvé${problems.length > 1 ? "s" : ""}.`,
              `${passed.length} check${passed.length > 1 ? "s" : ""} passed, ${problems.length} problem${problems.length > 1 ? "s" : ""} found.`,
            )}
          </p>
        </div>
      </div>

      {problems.length > 0 && (
        <div className="section">
          <h2>{tr("À corriger", "To fix")}</h2>
          <ul className="qtlist">
            {problems.map((p) => (
              <li key={p.check_id}>
                <div className="qthead">
                  <SevTag s={sevOf(p.severity)} />
                  <b>{title(p)}</b>
                </div>
                <small>{p.hosts.join(", ")}</small>
                {p.details && (
                  <div className="qtdetails">
                    <p>{lang === "fr" ? p.details.description_fr || p.details.description : p.details.description}</p>
                    <ol>
                      {(lang === "fr" && p.details.remediation_fr.length ? p.details.remediation_fr : p.details.remediation).map((s, k) => (
                        <li key={k}>{s}</li>
                      ))}
                    </ol>
                  </div>
                )}
              </li>
            ))}
          </ul>
          {!unlocked && (
            <Unlock
              id={res.id}
              onUnlock={(p, sent) => {
                setProblems(p);
                setEmailed(sent);
              }}
            />
          )}
          {emailed && <p className="hint">{tr("Le rapport est aussi parti à votre adresse email.", "The report was also sent to your email address.")}</p>}
        </div>
      )}

      {passed.length > 0 && (
        <div className="section">
          <h2>{tr("Ce qui va bien", "What is fine")}</h2>
          <ul className="wellgroups">
            <li>
              <ul>
                {passed.map((c) => (
                  <li key={c.id}>
                    <i aria-hidden="true">
                      <Tick size={14} width={3} />
                    </i>
                    {title(c)}
                  </li>
                ))}
              </ul>
            </li>
          </ul>
        </div>
      )}

      <div className="rpanel qtcta">
        <div>
          <h2>{tr(`Surveillez ${res.domain} chaque semaine`, `Watch ${res.domain} every week`)}</h2>
          <p className="md">
            {tr(
              "Ports, sous-domaines, vulnérabilités connues, et une alerte dès que quelque chose casse. Audit gratuit, sans carte.",
              "Ports, subdomains, known vulnerabilities, and an alert as soon as something breaks. Free audit, no card.",
            )}
          </p>
        </div>
        <button className="btn" type="button" onClick={signup}>
          {tr("Créer mon compte", "Create my account")}
        </button>
      </div>
    </section>
  );
}

function Unlock({ id, onUnlock }: { id: string; onUnlock: (p: QuickProblem[], emailed: boolean) => void }) {
  const [email, setEmail] = useState("");
  const [marketing, setMarketing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const form = useRef<HTMLFormElement>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const em = email.trim();
    if (!EMAIL_RE.test(em)) {
      setErr(em ? tr("Cette adresse email n’est pas valide.", "This email address is not valid.") : tr("Saisissez votre adresse email.", "Enter your email address."));
      shake(form.current);
      return;
    }
    setBusy(true);
    setErr("");
    try {
      const r = await api.unlockQuickTest(id, em, marketing);
      onUnlock(r.problems, r.emailed);
    } catch (e2) {
      setErr(
        e2 instanceof ApiError && e2.code === "rate_limited"
          ? tr("Trop de rapports demandés : réessayez dans une heure.", "Too many reports asked: try again in an hour.")
          : e2 instanceof ApiError && e2.status === 404
            ? tr("Ce test a expiré : relancez-le.", "This test has expired: run it again.")
            : fallback(e2),
      );
      shake(form.current);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form ref={form} className="rpanel qtunlock" noValidate onSubmit={(e) => void submit(e)}>
      <h3>{tr("Comment corriger chaque problème", "How to fix each problem")}</h3>
      <p className="md">
        {tr(
          "Laissez votre email : les explications et les étapes s’affichent ici, et vous recevez le rapport.",
          "Leave your email: the explanations and steps appear here, and you receive the report.",
        )}
      </p>
      <div className="addrow">
        <label className="vh" htmlFor="qt-email">
          {tr("Adresse email", "Email address")}
        </label>
        <input id="qt-email" type="email" autoComplete="email" placeholder={tr("vous@entreprise.cg", "you@company.com")} value={email} onChange={(e) => setEmail(e.target.value)} />
        <button className="btn" type="submit" disabled={busy}>
          {busy ? <span className="spin" /> : null}
          {tr("Voir comment corriger", "See how to fix")}
        </button>
      </div>
      <label className="consent small">
        <input type="checkbox" checked={marketing} onChange={(e) => setMarketing(e.target.checked)} />
        <span>
          {tr("J’accepte aussi de recevoir les conseils et offres d’Orus Shield (facultatif, désinscription en un clic).", "I also agree to receive Orus Shield’s tips and offers (optional, unsubscribe in one click).")}
        </span>
      </label>
      <p className="err" role="alert">
        {err}
      </p>
      <p className="md">
        {tr("Voir notre ", "See our ")}
        <Link to="/confidentialite">{tr("politique de confidentialité", "privacy policy")}</Link>.
      </p>
    </form>
  );
}
