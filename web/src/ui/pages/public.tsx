// The public site of the mockup: home (accueil), pricing (tarifs) and
// payment (paiement), with their shared header and footer.

import { useEffect, useState } from "react";
import { api } from "../../api/client";
import type { Plan } from "../../api/types";
import { useAuth } from "../../auth";
import { Link, navigate, useLocation } from "../../router";
import { Lock, Logo, MODS, ModIcon, Moon, Soon, Tick } from "../icons";
import { money } from "../model";
import { useBodyClass, useUI } from "../ui";
import { limitRows } from "./Reglages";

function PubHead({ cur }: { cur: "accueil" | "tarifs" }) {
  const { theme, setTheme } = useUI();
  const { state } = useAuth();
  return (
    <header className="pubhead">
      <Link className="brand" to="/">
        <Logo />
        <span>Orus Shield</span>
      </Link>
      <nav aria-label="Site">
        <Link to="/" aria-current={cur === "accueil" ? "page" : undefined}>
          Accueil
        </Link>
        <Link to="/tarifs" aria-current={cur === "tarifs" ? "page" : undefined}>
          Tarifs
        </Link>
        {state.status === "signed-in" ? (
          <Link className="btn sm" to="/app">
            Mon tableau de bord
          </Link>
        ) : (
          <>
            <Link to="/connexion">Se connecter</Link>
            <Link className="btn sm" to="/inscription">
              Créer un compte
            </Link>
          </>
        )}
        <button className="iconbtn" type="button" aria-label="Changer de thème" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          <Moon />
        </button>
      </nav>
    </header>
  );
}

function PubFoot() {
  const { toast } = useUI();
  return (
    <footer className="pubfoot">
      <span>Orus Shield</span>
      <span>
        <a href="/" onClick={(e) => (e.preventDefault(), toast("Conditions d’utilisation : bientôt disponibles"))}>
          Conditions d’utilisation
        </a>
        <a href="/" onClick={(e) => (e.preventDefault(), toast("Politique de confidentialité : bientôt disponible"))}>
          Confidentialité
        </a>
        <Link to="/tarifs">Tarifs</Link>
      </span>
    </footer>
  );
}

/** The static radar of the hero: the empty map of a perimeter. */
export function HeroRadar({ scanning = false }: { scanning?: boolean }) {
  return (
    <svg className={"hradar" + (scanning ? " scanning" : "")} viewBox="0 0 300 300" role="img" aria-label="Carte du périmètre">
      <circle cx="150" cy="150" r="128" fill="none" stroke="var(--ring)" strokeWidth="1.8" strokeDasharray="3 6" strokeLinecap="round" />
      <circle cx="150" cy="150" r="100" fill="none" stroke="var(--ring)" strokeWidth="1.8" />
      <circle cx="150" cy="150" r="74" fill="none" stroke="var(--ring)" strokeWidth="1.8" />
      <g className="sweep">
        <path d="M150 150 L150 22 A128 128 0 0 1 240 59 Z" fill="var(--azur)" opacity=".14" />
        <line x1="150" y1="150" x2="150" y2="22" stroke="var(--azur)" strokeWidth="2" strokeLinecap="round" />
      </g>
      <circle cx="150" cy="150" r="44" fill="var(--surface)" stroke="var(--ring)" strokeWidth="1.8" />
      <image href="/logo-mark.png" x="132" y="134" width="36" height="33" />
    </svg>
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

type Cur = "usd" | "xaf";
type Bill = "mois" | "an";

export function price(p: Plan | undefined, cur: Cur, bill: Bill): string {
  if (!p) return "…";
  const v = cur === "usd" ? (bill === "an" ? p.usd_yearly : p.usd_monthly) : bill === "an" ? p.xaf_yearly : p.xaf_monthly;
  return money(v, cur);
}

/** features describes an offer in the cards of Tarifs and Paiement. */
export function features(p: Plan | undefined): string[] {
  if (!p) return [];
  const freq = { monthly: "Un scan par mois", weekly: "Scan chaque semaine", daily: "Scan chaque jour" }[p.max_frequency];
  const doms = `${p.domains} domaine${p.domains > 1 ? "s" : ""}`;
  if (!p.active_modules) return [doms, "Contrôles passifs", freq];
  return [
    `${doms} vérifié${p.domains > 1 ? "s" : ""}, ${p.hosts_per_scan} actifs par domaine`,
    `${freq}, 50 ports courants`,
    p.threats ? "Vulnérabilités et menaces émergentes" : "Vulnérabilités connues",
    p.reports ? "Alertes email, rapports Direction et Technique" : "Alertes email",
  ];
}

const DISCOUNT = "À l’année, jusqu’à 20 % de moins";

export function AccueilPage() {
  useBodyClass(["public"]);
  const plans = usePlans();
  const ess = plans.find((p) => p.id === "sme");
  const { toast } = useUI();
  return (
    <>
      <main>
        <div className="view">
          <PubHead cur="accueil" />
          <section className="hero">
            <div>
              <h1>Voyez votre entreprise comme un attaquant la voit.</h1>
              <p className="herosub">Orus Shield surveille vos domaines, vos emails et vos serveurs, puis vous dit quoi corriger en premier, en français et sans jargon.</p>
              <div className="addrow is-soon">
                <label className="vh" htmlFor="demo-in">
                  Votre nom de domaine
                </label>
                <input id="demo-in" type="text" inputMode="url" autoComplete="off" placeholder="votre-entreprise.cg" disabled />
                <button className="btn" type="button" aria-disabled="true" onClick={() => toast("Test sans compte : bientôt disponible. Créez un compte gratuit pour tester votre domaine.")}>
                  Tester mon domaine
                  <Soon />
                </button>
              </div>
              <p className="err" role="alert" />
              <p className="sub">Gratuit, sans carte. Contrôles passifs seulement : rien n’est envoyé vers vos serveurs.</p>
            </div>
            <div className="herovis">
              <HeroRadar />
            </div>
          </section>

          <section className="band">
            <h2>Ce que nous vérifions</h2>
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
              <h2>Du problème à la correction</h2>
              <ol className="path">
                <li>
                  <b>Ajoutez votre domaine</b>
                  <span>Nous trouvons vos sous-domaines et vos serveurs.</span>
                </li>
                <li>
                  <b>Prouvez qu’il est à vous</b>
                  <span>Un enregistrement DNS, et les contrôles complets démarrent.</span>
                </li>
                <li>
                  <b>Corrigez, étape par étape</b>
                  <span>Chaque problème vient avec sa marche à suivre. Nous revérifions ensuite.</span>
                </li>
              </ol>
            </div>
            <div className="sample" aria-hidden="true">
              <p className="mt">Protéger vos emails contre l’usurpation</p>
              <p className="md">exemple.cg, environ 15 min</p>
              <div className="stepline">
                <b style={{ width: "50%" }} />
              </div>
              <div className="stepbtn on">
                <i>
                  <Tick />
                </i>
                <span>Lire les rapports DMARC pendant deux semaines.</span>
              </div>
              <div className="stepbtn">
                <i />
                <span>Passer la règle à « quarantine », puis à « reject ».</span>
              </div>
            </div>
          </section>

          <section className="band dark">
            <h2>Nous ne testons que ce qui vous appartient</h2>
            <ul className="trust">
              <li>
                <b>Propriété prouvée</b>
                <span>Aucun test actif sans preuve que le domaine et le serveur sont à vous.</span>
              </li>
              <li>
                <b>Vos limites respectées</b>
                <span>Vous choisissez la vitesse, les horaires et ce qu’on ne touche pas.</span>
              </li>
              <li>
                <b>Tout est tracé</b>
                <span>Chaque scan est enregistré : qui l’a lancé, sur quoi, et quand.</span>
              </li>
            </ul>
          </section>

          <section className="band cta">
            <h2>Essentiel à partir de {price(ess, "usd", "mois")} par mois</h2>
            <p className="sub">Une offre gratuite pour commencer. Paiement par carte ou Mobile Money bientôt disponible.</p>
            <div className="actions" style={{ justifyContent: "center" }}>
              <Link className="btn" to="/tarifs">
                Voir les tarifs
              </Link>
              <Link className="btn ghost" to="/app">
                Voir le tableau de bord
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
  const [cur, setCur] = useState<Cur>("usd");
  const by = (id: Plan["id"]) => plans.find((p) => p.id === id);
  const cards: [Plan | undefined, string, string, string, boolean, string][] = [
    [by("discovery"), "Gratuit", "Pour voir où vous en êtes.", "Commencer", false, ""],
    [by("sme"), "Essentiel", "Pour une petite entreprise.", "Essayer 14 jours", true, "sme"],
    [by("pro"), "Pro", "Pour ceux qui ont un informaticien.", "Essayer 14 jours", false, "pro"],
  ];
  return (
    <main>
      <div className="view">
        <PubHead cur="tarifs" />
        <section className="phead">
          <h1>Un prix simple, payable comme vous voulez.</h1>
          <p className="herosub">Sans engagement : vous arrêtez quand vous voulez.</p>
          <div className="toggles">
            <div className="seg2" role="group" aria-label="Facturation">
              {(
                [
                  ["mois", "Au mois"],
                  ["an", DISCOUNT],
                ] as const
              ).map(([k, l]) => (
                <button key={k} type="button" aria-pressed={bill === k} onClick={() => setBill(k)}>
                  {l}
                </button>
              ))}
            </div>
            <div className="seg2" role="group" aria-label="Monnaie">
              {(
                [
                  ["usd", "Dollars"],
                  ["xaf", "FCFA"],
                ] as const
              ).map(([k, l]) => (
                <button key={k} type="button" aria-pressed={cur === k} onClick={() => setCur(k)}>
                  {l}
                </button>
              ))}
            </div>
          </div>
        </section>
        <div className="plans">
          {cards.map(([p, n, d, cta, star, choose]) => (
            <div key={n} className={"plan" + (star ? " star" : "")}>
              {star && <span className="tagstar">Le plus choisi</span>}
              <h2>{n}</h2>
              <p className="md">{d}</p>
              <p className="price">
                <b>{n === "Gratuit" ? money(0, cur) : price(p, cur, bill)}</b>
                <span>{n === "Gratuit" ? "pour toujours" : bill === "an" ? "par mois, payé à l’année" : "par mois"}</span>
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
          Prestataires informatiques et grands comptes : tarif sur devis, par actif.
        </p>
        <section className="band">
          <h2>Tout comparer</h2>
          <div style={{ overflowX: "auto", marginTop: 8 }}>
            <table className="limits plan2">
              <thead>
                <tr>
                  <th scope="col" />
                  <th scope="col">Gratuit</th>
                  <th scope="col">Essentiel</th>
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
          <h2>
            Moyens de paiement
            <Soon />
          </h2>
          <div className="tags" style={{ marginTop: 12 }}>
            {["Carte bancaire", "MTN Mobile Money", "Airtel Money", "Orange Money", "PayPal"].map((x) => (
              <span key={x}>{x}</span>
            ))}
          </div>
        </section>
        <section className="band">
          <h2>Questions fréquentes</h2>
          <div className="faq">
            {[
              ["Puis-je tester un domaine qui n’est pas le mien ?", "Non. Les contrôles passifs lisent des données publiques. Tous les tests actifs demandent une preuve que le domaine et le serveur vous appartiennent."],
              ["Qui corrige les problèmes ?", "Vous ou votre informaticien, en suivant nos étapes. Nous revérifions ensuite. Un service d’accompagnement est proposé à part si vous préférez qu’on le fasse avec vous."],
              ["Comment payer en Mobile Money ?", "Vous choisissez votre opérateur au moment du paiement et vous validez sur votre téléphone. Le prix en FCFA est fixe."],
              ["Puis-je arrêter quand je veux ?", "Oui. L’abonnement s’arrête à la fin de la période payée, et vos rapports restent téléchargeables."],
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

const OPS: [string, string, string, string][] = [
  ["mtn", "MTN Mobile Money", "#FFCB05", "#1A1A1A"],
  ["airtel", "Airtel Money", "#E40000", "#FFFFFF"],
  ["orange", "Orange Money", "#FF7900", "#1A1A1A"],
];

/**
 * PaiementPage reproduces the payment flow; no payment provider is
 * connected yet, so the final buttons are greyed "Bientôt" and nothing is
 * charged or simulated.
 */
export function PaiementPage() {
  useBodyClass(["pay"]);
  const { search } = useLocation();
  const { state } = useAuth();
  const { toast } = useUI();
  const plans = usePlans();
  const [plan, setPlan] = useState<"sme" | "pro">(search.get("offre") === "pro" ? "pro" : "sme");
  const [bill, setBill] = useState<Bill>("mois");
  const [method, setMethod] = useState<"card" | "momo" | "paypal">("card");
  const [op, setOp] = useState("mtn");
  const p = plans.find((x) => x.id === plan);
  const cur: Cur = method === "momo" ? "xaf" : "usd";
  const per = price(p, cur, bill);
  const total = p ? money((cur === "usd" ? (bill === "an" ? p.usd_yearly : p.usd_monthly) : bill === "an" ? p.xaf_yearly : p.xaf_monthly) * (bill === "an" ? 12 : 1), cur) : "…";
  const back = state.status === "signed-in" ? "/app" : "/tarifs";
  const soon = () => toast("Paiement en ligne : bientôt disponible. Votre essai de 14 jours continue.");
  const names = { sme: "Essentiel", pro: "Pro" };
  const methods: ["card" | "momo" | "paypal", string, string][] = [
    ["card", "Carte bancaire", "Visa, Mastercard"],
    ["momo", "Mobile Money", "MTN, Airtel, Orange"],
    ["paypal", "PayPal", "Votre compte PayPal"],
  ];

  return (
    <main>
      <div className="view">
        <div className="authtop paytop">
          <Link className="brand" to="/">
            <Logo />
            <span>Orus Shield</span>
          </Link>
          <ol className="stepper" aria-label="Étapes">
            <li className="on">Offre</li>
            <li className="on cur">Paiement</li>
            <li>Confirmation</li>
          </ol>
          <a
            className="link"
            href={back}
            onClick={(e) => {
              e.preventDefault();
              navigate(back);
            }}
          >
            Annuler
          </a>
        </div>
        <div className="paygrid">
          <section>
            <h1 className="payh">Votre abonnement</h1>
            <div className="planpick" role="radiogroup" aria-label="Offre">
              {(["sme", "pro"] as const).map((k) => {
                const x = plans.find((y) => y.id === k);
                return (
                  <button key={k} type="button" role="radio" aria-checked={plan === k} onClick={() => setPlan(k)}>
                    <span className="radio" />
                    <span>
                      <b>{names[k]}</b>
                      <small>{x ? `${x.domains} domaines, ${x.hosts_per_scan} actifs par domaine, scan chaque ${x.max_frequency === "daily" ? "jour" : "semaine"}` : ""}</small>
                    </span>
                    <span className="pp">
                      {price(x, cur, bill)}
                      <small>/mois</small>
                    </span>
                  </button>
                );
              })}
            </div>
            <div className="seg2" role="group" aria-label="Facturation" style={{ marginTop: 12, display: "inline-flex" }}>
              {(
                [
                  ["mois", "Au mois"],
                  ["an", DISCOUNT],
                ] as const
              ).map(([k, l]) => (
                <button key={k} type="button" aria-pressed={bill === k} onClick={() => setBill(k)}>
                  {l}
                </button>
              ))}
            </div>
            <h2 className="payh2">
              Moyen de paiement
              <Soon />
            </h2>
            <div className="methods" role="radiogroup" aria-label="Moyen de paiement">
              {methods.map(([k, l, d]) => (
                <button key={k} type="button" role="radio" aria-checked={method === k} onClick={() => setMethod(k)}>
                  <b>{l}</b>
                  <small>{d}</small>
                </button>
              ))}
            </div>
            <div className="payform" key={method}>
              {method === "card" && (
                <form className="aform" noValidate onSubmit={(e) => (e.preventDefault(), soon())}>
                  <div className="field">
                    <label htmlFor="cc-num">Numéro de carte</label>
                    <div className="pwwrap">
                      <input id="cc-num" inputMode="numeric" autoComplete="cc-number" placeholder="1234 1234 1234 1234" disabled />
                    </div>
                  </div>
                  <div className="two">
                    <div className="field">
                      <label htmlFor="cc-exp">Expiration</label>
                      <input id="cc-exp" inputMode="numeric" autoComplete="cc-exp" placeholder="MM / AA" disabled />
                    </div>
                    <div className="field">
                      <label htmlFor="cc-cvc">Code de sécurité</label>
                      <input id="cc-cvc" inputMode="numeric" autoComplete="cc-csc" placeholder="3 chiffres" disabled />
                    </div>
                  </div>
                  <div className="field">
                    <label htmlFor="cc-name">Nom sur la carte</label>
                    <input id="cc-name" autoComplete="cc-name" disabled />
                  </div>
                  <p className="err" role="alert" />
                  <button className="btn wide" type="submit" aria-disabled="true">
                    Démarrer l’essai de 14 jours
                    <Soon />
                  </button>
                </form>
              )}
              {method === "momo" && (
                <form className="aform" noValidate onSubmit={(e) => (e.preventDefault(), soon())}>
                  <div className="ops" role="radiogroup" aria-label="Opérateur">
                    {OPS.map(([k, l, bg, fg]) => (
                      <button key={k} type="button" role="radio" aria-checked={op === k} onClick={() => setOp(k)}>
                        <span className="opdot" style={{ background: bg, color: fg }}>
                          {l[0]}
                        </span>
                        {l}
                      </button>
                    ))}
                  </div>
                  <div className="field">
                    <label htmlFor="mm-phone">Numéro de téléphone</label>
                    <div className="prefix">
                      <span>+242</span>
                      <input id="mm-phone" type="tel" inputMode="numeric" autoComplete="tel-national" placeholder="06 123 45 67" disabled />
                    </div>
                  </div>
                  <p className="md">Vous paierez {total} en FCFA. Le montant est fixe, sans conversion.</p>
                  <p className="err" role="alert" />
                  <button className="btn wide" type="submit" aria-disabled="true">
                    Envoyer la demande de paiement
                    <Soon />
                  </button>
                </form>
              )}
              {method === "paypal" && (
                <div className="aform">
                  <p className="sub" style={{ margin: 0 }}>
                    Vous allez être redirigé vers PayPal pour confirmer, puis revenir ici.
                  </p>
                  <button className="btn wide paypal" type="button" aria-disabled="true" onClick={soon}>
                    Continuer avec PayPal
                    <Soon />
                  </button>
                </div>
              )}
            </div>
            <p className="secure">
              <Lock />
              Paiement chiffré, traité par notre prestataire de paiement. Nous ne voyons jamais votre numéro de carte.
            </p>
          </section>
          <aside className="summary">
            <p className="md">Récapitulatif</p>
            <p className="sumplan">{names[plan]}</p>
            <div className="sumline">
              <span>{bill === "an" ? "Prix par mois, payé à l’année" : "Prix par mois"}</span>
              <b>{per}</b>
            </div>
            <div className="sumline">
              <span>Aujourd’hui</span>
              <b>{money(0, cur)}</b>
            </div>
            <div className="sumline total">
              <span>À la fin de l’essai de 14 jours</span>
              <b>
                {total}
                {bill === "an" ? " / an" : " / mois"}
              </b>
            </div>
            <ul>
              {features(p).map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
            <p className="md">Annulable à tout moment pendant l’essai, sans frais.</p>
          </aside>
        </div>
      </div>
    </main>
  );
}

