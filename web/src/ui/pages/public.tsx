// The public site of the mockup: home (accueil), pricing (tarifs) and
// payment (paiement), with their shared header and footer.

import { useEffect, useState } from "react";
import type { Overview, Plan, Severity } from "../../api/types";
import { useAuth } from "../../auth";
import { Link, navigate, useLocation } from "../../router";
import { api, ApiError } from "../../api/client";
import { Lock, Logo, MODS, ModIcon, Moon, Soon, Tick } from "../icons";
import { LangSwitch } from "../LangSwitch";
import { locale, tr } from "../../i18n";
import { openCheckout } from "../paddle";
import { COLOR, DIST, initials, money, SEV, type Sev } from "../model";
import { cleanDomain } from "../prefill";
import { useBodyClass, useUI } from "../ui";
import { limitRows } from "./Reglages";

export function PubHead({ cur }: { cur: "accueil" | "tarifs" | "legal" | "test" | "guides" }) {
  const { theme, setTheme } = useUI();
  const { state } = useAuth();
  return (
    <header className="pubhead">
      <Link className="brand" to="/">
        <Logo />
        <span>Orus Shield</span>
      </Link>
      <nav aria-label={tr("Site", "Site")}>
        <Link to="/" aria-current={cur === "accueil" ? "page" : undefined}>
          {tr("Accueil", "Home")}
        </Link>
        {state.status !== "signed-in" && (
          <Link to="/test" aria-current={cur === "test" ? "page" : undefined}>
            {tr("Test gratuit", "Free test")}
          </Link>
        )}
        <Link to="/guides" aria-current={cur === "guides" ? "page" : undefined}>
          {tr("Guides", "Guides")}
        </Link>
        <Link to="/tarifs" aria-current={cur === "tarifs" ? "page" : undefined}>
          {tr("Tarifs", "Pricing")}
        </Link>
        {state.status === "signed-in" ? (
          <>
            <Link className="btn sm" to="/app">
              {tr("Mon tableau de bord", "My dashboard")}
            </Link>
          </>
        ) : (
          <>
            <Link to="/connexion">{tr("Se connecter", "Sign in")}</Link>
            <Link className="btn sm" to="/inscription">
              {tr("Créer un compte", "Create an account")}
            </Link>
          </>
        )}
        <LangSwitch />
        <button className="iconbtn" type="button" aria-label={tr("Changer de thème", "Change theme")} onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          <Moon />
        </button>
        {/* The profile closes the header, at the far right, as in the dashboard. */}
        {state.status === "signed-in" && state.me.orgs[0] && (
          <Link className="iconbtn avatar" to={`/orgs/${encodeURIComponent(state.me.orgs[0].org_id)}/profil`} aria-label={tr("Mon profil", "My profile")} title={tr("Mon profil", "My profile")}>
            {initials(state.me.name, state.me.email)}
          </Link>
        )}
      </nav>
    </header>
  );
}

export function PubFoot() {
  return (
    <footer className="pubfoot">
      <span>Orus Shield</span>
      <span>
        <Link to="/guides">{tr("Guides", "Guides")}</Link>
        <Link to="/conditions">{tr("Conditions d’utilisation", "Terms of use")}</Link>
        <Link to="/confidentialite">{tr("Confidentialité", "Privacy")}</Link>
        <Link to="/tarifs">{tr("Tarifs", "Pricing")}</Link>
      </span>
    </footer>
  );
}

/** RadarDot is a problem drawn on the radar: the further from the centre,
 * the more serious (DIST), in its severity's colour. */
export interface RadarDot {
  sev: Sev;
  label: string;
}

/** The radar of the hero: the map of a perimeter. With dots and a score
 * it shows a result (an example for visitors, the customer's own once
 * signed in); without, the empty map (sign-in pages). */
export function HeroRadar({ scanning = false, score, dots = [], label }: { scanning?: boolean; score?: number | null | undefined; dots?: RadarDot[]; label?: string | undefined }) {
  // Spread the dots around the circle, starting top right, so they never
  // overlap whatever their number.
  const at = (i: number, d: RadarDot) => {
    const a = ((-60 + (i * 360) / Math.max(dots.length, 1)) * Math.PI) / 180;
    const r = DIST[d.sev];
    return [150 + r * Math.cos(a), 150 + r * Math.sin(a)] as const;
  };
  return (
    <svg className={"hradar" + (scanning ? " scanning" : "")} viewBox="0 0 300 300" role="img" aria-label={label ?? tr("Carte du périmètre", "Map of the attack surface")}>
      <circle cx="150" cy="150" r="128" fill="none" stroke="var(--ring)" strokeWidth="1.8" strokeDasharray="3 6" strokeLinecap="round" />
      <circle cx="150" cy="150" r="100" fill="none" stroke="var(--ring)" strokeWidth="1.8" />
      <circle cx="150" cy="150" r="74" fill="none" stroke="var(--ring)" strokeWidth="1.8" />
      <g className="sweep">
        <path d="M150 150 L150 22 A128 128 0 0 1 240 59 Z" fill="var(--azur)" opacity=".14" />
        <line x1="150" y1="150" x2="150" y2="22" stroke="var(--azur)" strokeWidth="2" strokeLinecap="round" />
      </g>
      {dots.map((d, i) => {
        const [x, y] = at(i, d);
        return (
          <g key={i} className="pt" style={{ animationDelay: `${0.4 + i * 0.25}s` }}>
            <circle cx={x} cy={y} r="8" fill={COLOR[d.sev]} stroke="var(--bg)" strokeWidth="3" />
          </g>
        );
      })}
      <circle cx="150" cy="150" r="44" fill="var(--surface)" stroke="var(--ring)" strokeWidth="1.8" />
      {score === undefined ? (
        <image href="/logo-mark.png" x="132" y="134" width="36" height="33" />
      ) : (
        <>
          <text className="core" x="150" y="156" textAnchor="middle" fontSize="30">
            {score ?? "–"}
          </text>
          <text x="150" y="172" textAnchor="middle" fontSize="10" fill="var(--ink2)">
            {tr("sur 100", "out of 100")}
          </text>
        </>
      )}
    </svg>
  );
}

/** SampleResult is the hero's picture for visitors: an example of what a
 * test finds, marked as such (never presented as a real result). */
function SampleResult() {
  const dots: RadarDot[] = [
    { sev: "crit", label: tr("Certificat expiré", "Expired certificate") },
    { sev: "high", label: tr("Emails usurpables (pas de DMARC)", "Spoofable email (no DMARC)") },
    { sev: "med", label: tr("HTTPS non imposé", "HTTPS not enforced") },
    { sev: "med", label: tr("Versions de logiciels visibles", "Software versions shown") },
  ];
  return (
    <>
      <HeroRadar scanning score={63} dots={dots} label={tr("Exemple de résultat : 63 sur 100, 4 problèmes", "Example result: 63 out of 100, 4 problems")} />
      <div className="herocard">
        <p className="plankicker">{tr("Exemple · votre-entreprise.cg", "Example · your-company.com")}</p>
        <ul>
          {dots.map((d) => (
            <li key={d.label}>
              <i style={{ background: COLOR[d.sev] }} aria-hidden="true" />
              {d.label}
            </li>
          ))}
        </ul>
      </div>
    </>
  );
}

/** MyPerimeter is the hero's picture once signed in: the customer's own
 * score and open problems (first organization), and the way to today's
 * actions. Without data (no scan yet, or MFA still to set up) it falls
 * back to the empty map and the way to the dashboard. */
function MyPerimeter() {
  const { state } = useAuth();
  const org = state.status === "signed-in" ? state.me.orgs[0] : undefined;
  const [ov, setOv] = useState<Overview | null>(null);
  useEffect(() => {
    if (!org) return;
    const ac = new AbortController();
    api.overview(org.org_id, 84, ac.signal).then(setOv, () => setOv(null));
    return () => ac.abort();
  }, [org?.org_id]);
  if (!org) return <HeroRadar />;
  const counts: [Severity, Sev][] = [
    ["critical", "crit"],
    ["high", "high"],
    ["medium", "med"],
    ["low", "low"],
  ];
  const open = counts.reduce((n, [k]) => n + (ov?.open_findings[k] ?? 0), 0);
  // One dot per open problem, the most serious first, twelve at most.
  const dots: RadarDot[] = counts.flatMap(([k, sev]) => Array.from({ length: ov?.open_findings[k] ?? 0 }, () => ({ sev, label: SEV[sev][0] }))).slice(0, 12);
  return (
    <>
      <HeroRadar score={ov ? ov.score : undefined} dots={dots} label={ov?.score != null ? tr(`Votre score : ${ov.score} sur 100`, `Your score: ${ov.score} out of 100`) : undefined} />
      <div className="herocard">
        <p className="plankicker">{org.org_name}</p>
        <p className="herostat">
          {!ov
            ? tr("Ouvrez votre tableau de bord pour voir votre sécurité.", "Open your dashboard to see your security.")
            : open === 0
              ? tr("Aucun problème ouvert.", "No open problem.")
              : tr(`${open} problème${open > 1 ? "s" : ""} ouvert${open > 1 ? "s" : ""}.`, `${open} open problem${open > 1 ? "s" : ""}.`)}
        </p>
        <Link className="link" to={`/orgs/${encodeURIComponent(org.org_id)}/aujourdhui`}>
          {tr("Voir mes actions du jour", "See today’s actions")}
        </Link>
      </div>
    </>
  );
}

/** usePlans loads the public offers, cheapest first. */
export function usePlans(): Plan[] {
  const [plans, setPlans] = useState<Plan[]>([]);
  useEffect(() => {
    api.plans().then(
      (r) => setPlans(r.items),
      () => setPlans([]),
    );
  }, []);
  return plans;
}

type Bill = "mois" | "an";

export function price(p: Plan | undefined, bill: Bill): string {
  if (!p) return "…";
  return money(bill === "an" ? p.usd_yearly : p.usd_monthly);
}

/** features describes an offer in the cards of Tarifs and Paiement. */
export function features(p: Plan | undefined): string[] {
  if (!p) return [];
  const freq = p.max_frequency
    ? {
        monthly: tr("Un scan par mois", "One scan a month"),
        weekly: tr("Scan chaque semaine", "Weekly scan"),
        daily: tr("Scan chaque jour", "Daily scan"),
      }[p.max_frequency]
    : "";
  const many = p.domains > 1;
  const doms = tr(`${p.domains} domaine${many ? "s" : ""}`, `${p.domains} domain${many ? "s" : ""}`);
  if (!p.monitoring) return [tr(`Un audit de ${doms}`, `One audit of ${doms}`), tr("Contrôles passifs", "Passive checks"), tr("Score et plan d’action", "Score and action plan")];
  return [
    tr(`${doms} vérifié${many ? "s" : ""}, ${p.hosts_per_scan} actifs par domaine`, `${doms} verified, ${p.hosts_per_scan} assets per domain`),
    tr(`${freq}, 50 ports courants`, `${freq}, 50 common ports`),
    p.threats ? tr("Vulnérabilités et menaces émergentes", "Vulnerabilities and emerging threats") : tr("Vulnérabilités connues", "Known vulnerabilities"),
    p.reports ? tr("Alertes email, rapports Direction et Technique", "Email alerts, executive and technical reports") : tr("Alertes email", "Email alerts"),
  ];
}

const discount = () => tr("À l’année, jusqu’à 20 % de moins", "Yearly, up to 20% less");

export function AccueilPage() {
  useBodyClass(["public"]);
  const plans = usePlans();
  const ess = plans.find((p) => p.id === "sme");
  const [demo, setDemo] = useState("");
  // The public test is for visitors; a signed-in customer goes to their
  // dashboard, where their domains are tested in depth.
  const { state } = useAuth();
  const signedIn = state.status === "signed-in";
  const first = state.status === "signed-in" ? state.me.name.split(/\s+/)[0] : "";
  return (
    <>
      <main>
        <div className="view">
          <PubHead cur="accueil" />
          <section className="hero">
            <div>
              <h1>
                {signedIn
                  ? first
                    ? tr(`Bon retour, ${first}.`, `Welcome back, ${first}.`)
                    : tr("Bon retour.", "Welcome back.")
                  : tr("Trouvez vos failles avant les pirates.", "Find your security gaps before attackers do.")}
              </h1>
              <p className="herosub">
                {signedIn
                  ? tr(
                      "Votre sécurité en un coup d’œil : votre score, vos problèmes ouverts, et ce qu’il faut faire aujourd’hui.",
                      "Your security at a glance: your score, your open problems, and what to do today.",
                    )
                  : tr(
                      "Orus Shield vérifie chaque semaine vos domaines, vos emails et vos serveurs, puis vous dit quoi corriger en premier, étape par étape et sans jargon.",
                      "Orus Shield checks your domains, your email and your servers every week, then tells you what to fix first, step by step and without jargon.",
                    )}
              </p>
              {signedIn ? (
                <div className="actions">
                  <Link className="btn" to="/app">
                    {tr("Aller à mon tableau de bord", "Go to my dashboard")}
                  </Link>
                </div>
              ) : (
              <>
              {/* The public test: the domain goes to /test, which runs it. */}
              <form
                className="addrow"
                noValidate
                onSubmit={(e) => {
                  e.preventDefault();
                  const d = cleanDomain(demo);
                  navigate(d ? `/test?domaine=${encodeURIComponent(d)}` : "/test");
                }}
              >
                <label className="vh" htmlFor="demo-in">
                  {tr("Votre nom de domaine", "Your domain name")}
                </label>
                <input
                  id="demo-in"
                  type="text"
                  inputMode="url"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={tr("votre-entreprise.cg", "your-company.com")}
                  value={demo}
                  onChange={(e) => setDemo(e.target.value)}
                />
                <button className="btn" type="submit">
                  {tr("Tester mon domaine", "Test my domain")}
                </button>
              </form>
              <p className="sub">
                {tr(
                  "Gratuit et sans compte : votre score sur 100 en 20 secondes. Contrôles passifs seulement, à partir de données publiques.",
                  "Free, no account: your score out of 100 in 20 seconds. Passive checks only, from public data.",
                )}
              </p>
              </>
              )}
            </div>
            <div className="herovis">{signedIn ? <MyPerimeter /> : <SampleResult />}</div>
          </section>

          <section className="band">
            <h2>{tr("Ce que nous vérifions", "What we check")}</h2>
            <ul className="feat">
              {MODS.map((m) => (
                <li key={m.key}>
                  <ModIcon>{m.icon}</ModIcon>
                  <div>
                    <p className="mt">
                      {m.title}
                      {m.module === null && <Soon />}
                    </p>
                    <p className="md">{m.desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </section>

          <section className="band two">
            <div>
              <h2>{tr("Du problème à la correction", "From problem to fix")}</h2>
              <ol className="path">
                <li>
                  <b>{tr("Ajoutez votre domaine", "Add your domain")}</b>
                  <span>{tr("Nous trouvons vos sous-domaines et vos serveurs.", "We find your subdomains and your servers.")}</span>
                </li>
                <li>
                  <b>{tr("Prouvez qu’il est à vous", "Prove it is yours")}</b>
                  <span>{tr("Un enregistrement DNS, et les contrôles complets démarrent.", "One DNS record, and the full checks start.")}</span>
                </li>
                <li>
                  <b>{tr("Corrigez, étape par étape", "Fix it, step by step")}</b>
                  <span>{tr("Chaque problème vient avec sa marche à suivre. Nous revérifions ensuite.", "Every problem comes with its steps. We check again afterwards.")}</span>
                </li>
              </ol>
            </div>
            <div className="sample" aria-hidden="true">
              <p className="mt">{tr("Protéger vos emails contre l’usurpation", "Protect your email against spoofing")}</p>
              <p className="md">{tr("exemple.cg, environ 15 min", "example.com, about 15 min")}</p>
              <div className="stepline">
                <b style={{ width: "50%" }} />
              </div>
              <div className="stepbtn on">
                <i>
                  <Tick />
                </i>
                <span>{tr("Lire les rapports DMARC pendant deux semaines.", "Read the DMARC reports for two weeks.")}</span>
              </div>
              <div className="stepbtn">
                <i />
                <span>{tr("Passer la règle à « quarantine », puis à « reject ».", "Move the policy to “quarantine”, then to “reject”.")}</span>
              </div>
            </div>
          </section>

          <section className="band dark">
            <h2>{tr("Nous ne testons que ce qui vous appartient", "We only test what belongs to you")}</h2>
            <ul className="trust">
              <li>
                <b>{tr("Propriété prouvée", "Proven ownership")}</b>
                <span>{tr("Aucun test actif sans preuve que le domaine et le serveur sont à vous.", "No active test without proof that the domain and the server are yours.")}</span>
              </li>
              <li>
                <b>{tr("Vos limites respectées", "Your limits respected")}</b>
                <span>{tr("Vous choisissez la vitesse, les horaires et ce qu’on ne touche pas.", "You choose the speed, the hours and what we leave alone.")}</span>
              </li>
              <li>
                <b>{tr("Tout est tracé", "Everything is logged")}</b>
                <span>{tr("Chaque scan est enregistré : qui l’a lancé, sur quoi, et quand.", "Every scan is recorded: who started it, on what, and when.")}</span>
              </li>
            </ul>
          </section>

          <section className="band cta">
            <h2>{tr(`Essentiel à partir de ${price(ess, "mois")} par mois`, `Essential from ${price(ess, "mois")} a month`)}</h2>
            <p className="sub">{tr("Un audit gratuit pour commencer. Paiement par carte ou PayPal.", "A free audit to start. Pay by card or PayPal.")}</p>
            <div className="actions" style={{ justifyContent: "center" }}>
              <Link className="btn" to="/tarifs">
                {tr("Voir les tarifs", "See pricing")}
              </Link>
              <Link className="btn ghost" to="/app">
                {tr("Voir le tableau de bord", "See the dashboard")}
              </Link>
            </div>
          </section>
          <PubFoot />
        </div>
      </main>
    </>
  );
}

export function TarifsPage() {
  useBodyClass(["public"]);
  const plans = usePlans();
  const [bill, setBill] = useState<Bill>("mois");
  const by = (id: Plan["id"]) => plans.find((p) => p.id === id);
  const cards: [Plan | undefined, string, string, string, boolean, string][] = [
    [by("discovery"), tr("Gratuit", "Free"), tr("Un audit pour voir où vous en êtes.", "One audit to see where you stand."), tr("Auditer mon domaine", "Audit my domain"), false, ""],
    [by("sme"), tr("Essentiel", "Essential"), tr("Pour une petite entreprise.", "For a small business."), tr("Essayer 14 jours", "Try it for 14 days"), true, "sme"],
    [by("pro"), "Pro", tr("Pour ceux qui ont un informaticien.", "For teams with an IT person."), tr("Essayer 14 jours", "Try it for 14 days"), false, "pro"],
  ];
  return (
    <main>
      <div className="view">
        <PubHead cur="tarifs" />
        <section className="phead">
          <h1>{tr("Un prix simple, payable comme vous voulez.", "A simple price, paid the way you like.")}</h1>
          <p className="herosub">{tr("Sans engagement : vous arrêtez quand vous voulez.", "No commitment: stop whenever you want.")}</p>
          <div className="toggles">
            <div className="seg2" role="group" aria-label={tr("Facturation", "Billing")}>
              {(
                [
                  ["mois", tr("Au mois", "Monthly")],
                  ["an", discount()],
                ] as const
              ).map(([k, l]) => (
                <button key={k} type="button" aria-pressed={bill === k} onClick={() => setBill(k)}>
                  {l}
                </button>
              ))}
            </div>
          </div>
        </section>
        <div className="plans">
          {cards.map(([p, n, d, cta, star, choose]) => (
            <div key={n} className={"plan" + (star ? " star" : "")}>
              {star && <span className="tagstar">{tr("Le plus choisi", "Most popular")}</span>}
              <h2>{n}</h2>
              <p className="md">{d}</p>
              <p className="price">
                <b>{!choose ? money(0) : price(p, bill)}</b>
                <span>{!choose ? tr("un audit, sans carte", "one audit, no card") : bill === "an" ? tr("par mois, payé à l’année", "a month, billed yearly") : tr("par mois", "a month")}</span>
              </p>
              <ul>
                {features(p).map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
              <Link className={"btn" + (star ? "" : " ghost")} to={choose ? `/inscription?offre=${choose}` : "/inscription"}>
                {cta}
              </Link>
            </div>
          ))}
        </div>
        <p className="sub" style={{ textAlign: "center", marginTop: 16 }}>
          {tr("Prestataires informatiques et grands comptes : tarif sur devis, par actif.", "IT providers and large accounts: price on quote, per asset.")}
        </p>
        <section className="band">
          <h2>{tr("Tout comparer", "Compare everything")}</h2>
          <div style={{ overflowX: "auto", marginTop: 8 }}>
            <table className="limits plan2">
              <thead>
                <tr>
                  <th scope="col" />
                  <th scope="col">{tr("Gratuit", "Free")}</th>
                  <th scope="col">{tr("Essentiel", "Essential")}</th>
                  <th scope="col">Pro</th>
                </tr>
              </thead>
              <tbody>
                {limitRows(plans).map(([name, ...cells]) => (
                  <tr key={name}>
                    <th scope="row">{name}</th>
                    {cells.map((c, i) => (
                      <td key={i}>{c}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
        <section className="band">
          <h2>{tr("Moyens de paiement", "Payment methods")}</h2>
          <div className="tags" style={{ marginTop: 12 }}>
            {[tr("Carte bancaire", "Bank card"), "PayPal"].map((x) => (
              <span key={x}>{x}</span>
            ))}
          </div>
        </section>
        <section className="band">
          <h2>{tr("Questions fréquentes", "Frequently asked questions")}</h2>
          <div className="faq">
            {[
              [
                tr("Puis-je tester un domaine qui n’est pas le mien ?", "Can I test a domain that is not mine?"),
                tr(
                  "Non. Les contrôles passifs lisent des données publiques. Tous les tests actifs demandent une preuve que le domaine et le serveur vous appartiennent.",
                  "No. Passive checks read public data. Every active test requires proof that the domain and the server belong to you.",
                ),
              ],
              [
                tr("Qui corrige les problèmes ?", "Who fixes the problems?"),
                tr(
                  "Vous ou votre informaticien, en suivant nos étapes. Nous revérifions ensuite. Un service d’accompagnement est proposé à part si vous préférez qu’on le fasse avec vous.",
                  "You or your IT person, following our steps. We check again afterwards. Hands-on support is offered separately if you would rather do it with us.",
                ),
              ],
              [
                tr("Puis-je arrêter quand je veux ?", "Can I stop whenever I want?"),
                tr("Oui. L’abonnement s’arrête à la fin de la période payée, et vos rapports restent téléchargeables.", "Yes. The subscription ends at the end of the paid period, and your reports stay downloadable."),
              ],
            ].map(([q, a]) => (
              <details key={q}>
                <summary>{q}</summary>
                <p>{a}</p>
              </details>
            ))}
          </div>
        </section>
        <PubFoot />
      </div>
    </main>
  );
}

/**
 * PaiementPage takes the payment: our API creates the Paddle transaction,
 * then Paddle's checkout (card inline, PayPal in an overlay) collects it.
 */
/** SYNC_TRIES: how many times the return page asks for the subscription
 * (every SYNC_MS) before saying it will appear on its own. */
const SYNC_TRIES = 20;
const SYNC_MS = 3000;

/** PayDone is the return from Paddle's checkout. It asks our API to record
 * the subscription from the transaction at once (the webhook may be late),
 * and says honestly whether it is active yet. */
function PayDone({ orgId, txn, signedIn }: { orgId: string; txn: string; signedIn: boolean }) {
  const canSync = signedIn && orgId !== "" && txn !== "";
  const [state, setState] = useState<"syncing" | "active" | "late">(canSync ? "syncing" : "late");
  useEffect(() => {
    if (!canSync) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const attempt = async (n: number) => {
      try {
        const r = await api.billingSync(orgId, txn);
        if (stop) return;
        if (r.state === "active") {
          setState("active");
          return;
        }
      } catch {
        // Paddle or our API unreachable for a moment: ask again.
      }
      if (stop) return;
      if (n + 1 >= SYNC_TRIES) setState("late");
      else timer = setTimeout(() => void attempt(n + 1), SYNC_MS);
    };
    void attempt(0);
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [canSync, orgId, txn]);
  return (
    <section className="paydone">
      <div className="okmark big" aria-hidden="true">
        <Tick size={40} width={3} />
      </div>
      <h1>{state === "active" ? tr("C’est activé, merci.", "It is active, thank you.") : tr("Paiement reçu, merci.", "Payment received, thank you.")}</h1>
      <p className="herosub" style={{ marginInline: "auto" }} role="status">
        {state === "active"
          ? tr(
              "Votre offre est active : scans chaque semaine, vérification de vos corrections, alertes. Vos factures sont dans Réglages, Abonnement.",
              "Your plan is active: weekly scans, verification of your fixes, alerts. Your invoices are in Settings, Subscription.",
            )
          : state === "syncing"
            ? tr("Activation de votre offre en cours…", "Activating your plan…")
            : tr(
                "Votre offre s’active dès que Paddle nous confirme le paiement. Cela peut prendre quelques minutes : vous recevrez aussi son email.",
                "Your plan becomes active as soon as Paddle confirms the payment. This can take a few minutes: you will also receive its email.",
              )}
      </p>
      <div className="actions" style={{ justifyContent: "center" }}>
        <Link className="btn" to={orgId ? `/orgs/${encodeURIComponent(orgId)}/aujourdhui` : "/app"}>
          {tr("Aller au tableau de bord", "Go to the dashboard")}
        </Link>
      </div>
    </section>
  );
}

export function PaiementPage() {
  useBodyClass(["pay"]);
  const { search } = useLocation();
  const { state } = useAuth();
  const plans = usePlans();
  const [plan, setPlan] = useState<"sme" | "pro">(search.get("offre") === "pro" ? "pro" : "sme");
  const [bill, setBill] = useState<Bill>("mois");
  const [method, setMethod] = useState<"card" | "paypal">("card");
  const p = plans.find((x) => x.id === plan);
  const per = price(p, bill);
  const total = p ? money((bill === "an" ? p.usd_yearly : p.usd_monthly) * (bill === "an" ? 12 : 1)) : "…";
  const back = state.status === "signed-in" ? "/app" : "/tarifs";
  const [busy, setBusy] = useState(false);
  const [opened, setOpened] = useState(false);
  const [payErr, setPayErr] = useState("");
  const me = state.status === "signed-in" ? state.me : null;
  const orgId = search.get("org") ?? me?.orgs.find((o) => o.role === "admin")?.org_id ?? "";
  const paid = search.get("statut") === "ok";
  // trial: the organization's first checkout starts the 14-day trial (card
  // required, charged at its end); afterwards it pays from the first day.
  // Unknown (signed out): a new customer, who gets the trial.
  const [trial, setTrial] = useState(true);
  useEffect(() => {
    if (!me || !orgId) return;
    const ac = new AbortController();
    api.subscription(orgId, ac.signal).then(
      (s) => setTrial(s.trial_available),
      () => {},
    );
    return () => ac.abort();
  }, [me, orgId]);
  const trialEnd = new Date(Date.now() + 14 * 86400000).toLocaleDateString(locale(), { day: "numeric", month: "long", year: "numeric" });
  /** pay creates the transaction on our side, then opens Paddle's checkout. */
  const pay = async (inline: boolean) => {
    if (!me) {
      navigate(`/connexion`);
      return;
    }
    setBusy(true);
    setPayErr("");
    try {
      const co = await api.checkout(orgId, plan, bill === "an" ? "yearly" : "monthly");
      await openCheckout({
        transactionId: co.transaction_id,
        orgId,
        clientToken: co.client_token,
        environment: co.environment,
        email: co.email,
        ...(inline ? { inlineTarget: "orus-checkout" } : {}),
      });
      if (inline) setOpened(true);
    } catch (e) {
      console.error("payment did not start", e); // the reason, for the developer console
      setPayErr(
        e instanceof ApiError && e.status === 409
          ? tr("Cette organisation a déjà un abonnement. Gérez-le dans Réglages, Abonnement.", "This organization already has a subscription. Manage it in Settings, Subscription.")
          : e instanceof ApiError && e.status === 503
            ? tr("Le paiement en ligne n’est pas encore ouvert sur ce serveur.", "Online payment is not open on this server yet.")
            : e instanceof ApiError && e.status === 403
              ? tr("Seul un administrateur de l’organisation peut payer l’abonnement.", "Only an administrator of the organization can pay for the subscription.")
              : tr("Le paiement n’a pas pu démarrer. Réessayez dans un instant.", "The payment could not start. Try again in a moment."),
      );
    } finally {
      setBusy(false);
    }
  };
  const names = { sme: tr("Essentiel", "Essential"), pro: "Pro" };
  const methods: ["card" | "paypal", string, string][] = [
    ["card", tr("Carte bancaire", "Bank card"), "Visa, Mastercard"],
    ["paypal", "PayPal", tr("Votre compte PayPal", "Your PayPal account")],
  ];

  return (
    <main>
      <div className="view">
        <div className="authtop paytop">
          <Link className="brand" to="/">
            <Logo />
            <span>Orus Shield</span>
          </Link>
          <ol className="stepper" aria-label={tr("Étapes", "Steps")}>
            <li className="on">{tr("Offre", "Plan")}</li>
            <li className={paid ? "on" : "on cur"}>{tr("Paiement", "Payment")}</li>
            <li className={paid ? "on cur" : ""}>{tr("Confirmation", "Confirmation")}</li>
          </ol>
          <div className="authtopr">
            <a
              className="link"
              href={back}
              onClick={(e) => {
                e.preventDefault();
                navigate(back);
              }}
            >
              {tr("Annuler", "Cancel")}
            </a>
            <LangSwitch />
          </div>
        </div>
        {paid ? (
          <PayDone orgId={orgId} txn={search.get("txn") ?? ""} signedIn={!!me} />
        ) : (
        <div className="paygrid">
          <section>
            <h1 className="payh">{tr("Votre abonnement", "Your subscription")}</h1>
            <div className="planpick" role="radiogroup" aria-label={tr("Offre", "Plan")}>
              {(["sme", "pro"] as const).map((k) => {
                const x = plans.find((y) => y.id === k);
                return (
                  <button key={k} type="button" role="radio" aria-checked={plan === k} onClick={() => setPlan(k)}>
                    <span className="radio" />
                    <span>
                      <b>{names[k]}</b>
                      <small>
                        {x
                          ? tr(
                              `${x.domains} domaines, ${x.hosts_per_scan} actifs par domaine, scan chaque ${x.max_frequency === "daily" ? "jour" : "semaine"}`,
                              `${x.domains} domains, ${x.hosts_per_scan} assets per domain, ${x.max_frequency === "daily" ? "daily" : "weekly"} scan`,
                            )
                          : ""}
                      </small>
                    </span>
                    <span className="pp">
                      {price(x, bill)}
                      <small>{tr("/mois", "/month")}</small>
                    </span>
                  </button>
                );
              })}
            </div>
            <div className="seg2" role="group" aria-label={tr("Facturation", "Billing")} style={{ marginTop: 12, display: "inline-flex" }}>
              {(
                [
                  ["mois", tr("Au mois", "Monthly")],
                  ["an", discount()],
                ] as const
              ).map(([k, l]) => (
                <button key={k} type="button" aria-pressed={bill === k} onClick={() => setBill(k)}>
                  {l}
                </button>
              ))}
            </div>
            <h2 className="payh2">{tr("Moyen de paiement", "Payment method")}</h2>
            <div className="methods" role="radiogroup" aria-label={tr("Moyen de paiement", "Payment method")}>
              {methods.map(([k, l, d]) => (
                <button key={k} type="button" role="radio" aria-checked={method === k} onClick={() => setMethod(k)}>
                  <b>{l}</b>
                  <small>{d}</small>
                </button>
              ))}
            </div>
            <div className="payform" key={method}>
              {method === "card" && (
                <div className="aform">
                  {/* Paddle's own card form appears here: card numbers never reach our servers.
                      Never name it "paddle-frame": that is the class of Paddle's own iframe, which
                      Paddle.js removes before opening a checkout, taking this container with it. */}
                  <div className="orus-checkout" />
                  {!opened && (
                    <>
                      <p className="sub" style={{ margin: 0 }}>
                        {tr(
                          "Vous saisirez votre carte dans le formulaire sécurisé de Paddle, notre prestataire de paiement.",
                          "You will enter your card in the secure form of Paddle, our payment provider.",
                        )}
                      </p>
                      <p className="err" role="alert">
                        {payErr}
                      </p>
                      <button className="btn wide" type="button" disabled={busy} onClick={() => void pay(true)}>
                        {busy ? <span className="spin" /> : null}
                        {tr("Continuer vers le paiement sécurisé", "Continue to secure payment")}
                      </button>
                    </>
                  )}
                </div>
              )}
              {method === "paypal" && (
                <div className="aform">
                  <p className="sub" style={{ margin: 0 }}>
                    {tr(
                      "La fenêtre sécurisée de Paddle, notre prestataire, vous propose PayPal ; vous revenez ensuite ici.",
                      "The secure window of Paddle, our provider, offers you PayPal; you then come back here.",
                    )}
                  </p>
                  <p className="err" role="alert">
                    {payErr}
                  </p>
                  <button className="btn wide paypal" type="button" disabled={busy} onClick={() => void pay(false)}>
                    {tr("Continuer avec PayPal", "Continue with PayPal")}
                  </button>
                </div>
              )}
            </div>
            <p className="secure">
              <Lock />
              {tr(
                "Paiement chiffré, traité par notre prestataire de paiement. Nous ne voyons jamais votre numéro de carte.",
                "Encrypted payment, handled by our payment provider. We never see your card number.",
              )}
            </p>
          </section>
          <aside className="summary">
            <p className="md">{tr("Récapitulatif", "Summary")}</p>
            <p className="sumplan">{names[plan]}</p>
            <div className="sumline">
              <span>{bill === "an" ? tr("Prix par mois, payé à l’année", "Price a month, billed yearly") : tr("Prix par mois", "Price a month")}</span>
              <b>{per}</b>
            </div>
            <div className="sumline">
              <span>{tr("Aujourd’hui", "Today")}</span>
              <b>{trial ? money(0) : total}</b>
            </div>
            <div className="sumline total">
              <span>{trial ? tr(`À partir du ${trialEnd}`, `From ${trialEnd}`) : tr("Ensuite", "Then")}</span>
              <b>
                {total}
                {bill === "an" ? tr(" / an", " / year") : tr(" / mois", " / month")}
              </b>
            </div>
            <ul>
              {features(p).map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
            <p className="md">
              {trial
                ? tr(
                    `Essai de 14 jours : rien n’est prélevé avant le ${trialEnd}. Annulable à tout moment d’ici là, sans frais.`,
                    `14-day trial: nothing is charged before ${trialEnd}. Cancel any time before then, free of charge.`,
                  )
                : tr("Sans engagement : l’abonnement s’arrête à la fin de la période payée.", "No commitment: the subscription ends at the end of the paid period.")}
            </p>
          </aside>
        </div>
        )}
      </div>
    </main>
  );
}

