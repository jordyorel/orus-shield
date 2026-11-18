// The offer page after the free audit (/orgs/{org}/offre): what the audit
// found, what it did not check, and the trial. Every figure comes from the
// organization's own data; nothing is estimated.

import { tr } from "../../i18n";
import { Link } from "../../router";
import { appPath } from "../AppShell";
import { byPriority, SEV, type Sev } from "../model";
import { useOrg } from "../OrgData";
import { SevTag } from "../sheets";
import { features, price } from "./public";

const ORDER: Sev[] = ["crit", "high", "med", "low"];

export function OffrePage() {
  const { org, data, issues, me } = useOrg();
  if (!data) return null;
  const sub = data.subscription;
  const today = appPath(org.org_id, "aujourdhui");
  const first = me.name.split(/\s+/)[0];

  // An offer with monitoring already: nothing to sell here.
  if (sub.plan.monitoring) {
    return (
      <>
        <p className="hello">{first ? tr(`Bonjour ${first}`, `Hello ${first}`) : tr("Bonjour", "Hello")}</p>
        <h1 className="lead">{tr(`Votre offre ${sub.plan.name} est active.`, `Your ${sub.plan.name} plan is active.`)}</h1>
        <p className="sub">
          <Link className="link" to={today}>
            {tr("Voir mes résultats", "See my results")}
          </Link>
        </p>
      </>
    );
  }

  const open = issues.filter((i) => !i.fixed);
  const counts = ORDER.map((s) => [s, open.filter((i) => i.sev === s).length] as const).filter(([, n]) => n > 0);
  const top = open.slice().sort(byPriority)[0];
  const live = data.assets.filter((a) => !a.gone_at);
  const ips = live.filter((a) => a.kind === "ip").length;
  const score = data.overview.score;
  const trial = sub.trial_available;
  const ess = sub.plans.find((p) => p.id === "sme");
  const pro = sub.plans.find((p) => p.id === "pro");
  const pay = (id: "sme" | "pro") => `/paiement?offre=${id}&org=${encodeURIComponent(org.org_id)}`;

  return (
    <>
      <p className="hello">{first ? tr(`Bonjour ${first}`, `Hello ${first}`) : tr("Bonjour", "Hello")}</p>
      <h1 className="lead">{tr("Votre audit est prêt. Voici la suite.", "Your audit is ready. Here is what comes next.")}</h1>

      <div className="section offer">
        <div className="rhead">
          <h2>{tr("Ce que nous avons trouvé", "What we found")}</h2>
        </div>
        <p className="sub">
          {score !== null ? tr(`Score de sécurité : ${score}/100. `, `Security score: ${score}/100. `) : ""}
          {open.length === 0
            ? tr("Aucun problème à corriger pour le moment.", "Nothing to fix for now.")
            : tr(`${open.length} problème${open.length > 1 ? "s" : ""} à corriger.`, `${open.length} problem${open.length > 1 ? "s" : ""} to fix.`)}
        </p>
        {counts.length > 0 && (
          <p className="tags">
            {counts.map(([s, n]) => (
              <SevTag key={s} s={s} label={`${n} ${SEV[s][0].toLowerCase()}`} />
            ))}
          </p>
        )}
        {top && (
          <p className="sub">
            {tr("Le plus urgent : ", "Most urgent: ")}
            <b>{top.title}</b> ({top.host}).
          </p>
        )}
      </div>

      <div className="section offer">
        <div className="rhead">
          <h2>{tr("Ce que votre audit gratuit n’a pas vérifié", "What your free audit did not check")}</h2>
        </div>
        <ul className="upsell">
          <li>
            {ips > 0
              ? tr(`Les ports ouverts de vos ${ips} serveur${ips > 1 ? "s" : ""}`, `The open ports of your ${ips} server${ips > 1 ? "s" : ""}`)
              : tr("Les ports ouverts de vos serveurs", "The open ports of your servers")}
          </li>
          <li>{tr("Les vulnérabilités connues de vos sites web", "The known vulnerabilities of your websites")}</li>
          <li>{tr("La suite : rien ne sera revérifié, ni vos corrections, ni les nouveaux problèmes", "What comes next: nothing is checked again, neither your fixes nor new problems")}</li>
        </ul>
      </div>

      <div className="plans">
        {(
          [
            [ess, "sme", true],
            [pro, "pro", false],
          ] as const
        ).map(([p, id, star]) =>
          p ? (
            <div key={id} className={"plan" + (star ? " star" : "")}>
              {star && <span className="tagstar">{tr("Recommandé", "Recommended")}</span>}
              <h2>{p.name}</h2>
              <p className="price">
                <b>{price(p, "mois")}</b>
                <span>{trial ? tr("par mois, après 14 jours d’essai", "per month, after a 14-day trial") : tr("par mois", "per month")}</span>
              </p>
              <ul>
                {features(p).map((f) => (
                  <li key={f}>{f}</li>
                ))}
                <li>{tr("Vérification de chaque correction", "Every fix verified")}</li>
              </ul>
              <Link className={"btn" + (star ? "" : " ghost")} to={pay(id)}>
                {trial ? tr("Essayer 14 jours", "Try 14 days") : tr(`Choisir ${p.name}`, `Choose ${p.name}`)}
              </Link>
            </div>
          ) : null,
        )}
      </div>
      {trial && (
        <p className="sub offer-note">
          {tr("Aucun prélèvement pendant 14 jours. Annulable en un clic avant la fin de l’essai. Carte ou PayPal.", "No charge for 14 days. Cancel in one click before the trial ends. Card or PayPal.")}
        </p>
      )}
      <p className="hint">
        <Link className="link" to={today}>
          {tr("Plus tard, voir mes résultats", "Later, see my results")}
        </Link>
      </p>
    </>
  );
}
