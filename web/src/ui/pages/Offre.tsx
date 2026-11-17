// The offer page after the free audit (/orgs/{org}/offre): what the audit
// found, what it did not check, and the trial. Every figure comes from the
// organization's own data; nothing is estimated.

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
        <p className="hello">{first ? `Bonjour ${first}` : "Bonjour"}</p>
        <h1 className="lead">Votre offre {sub.plan.name} est active.</h1>
        <p className="sub">
          <Link className="link" to={today}>
            Voir mes résultats
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
      <p className="hello">{first ? `Bonjour ${first}` : "Bonjour"}</p>
      <h1 className="lead">Votre audit est prêt. Voici la suite.</h1>

      <div className="section offer">
        <div className="rhead">
          <h2>Ce que nous avons trouvé</h2>
        </div>
        <p className="sub">
          {score !== null ? `Score de sécurité : ${score}/100. ` : ""}
          {open.length === 0 ? "Aucun problème à corriger pour le moment." : `${open.length} problème${open.length > 1 ? "s" : ""} à corriger.`}
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
            Le plus urgent : <b>{top.title}</b> ({top.host}).
          </p>
        )}
      </div>

      <div className="section offer">
        <div className="rhead">
          <h2>Ce que votre audit gratuit n’a pas vérifié</h2>
        </div>
        <ul className="upsell">
          <li>{ips > 0 ? `Les ports ouverts de vos ${ips} serveur${ips > 1 ? "s" : ""}` : "Les ports ouverts de vos serveurs"}</li>
          <li>Les vulnérabilités connues de vos sites web</li>
          <li>La suite : rien ne sera revérifié, ni vos corrections, ni les nouveaux problèmes</li>
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
              {star && <span className="tagstar">Recommandé</span>}
              <h2>{p.name}</h2>
              <p className="price">
                <b>{price(p, "mois")}</b>
                <span>{trial ? "par mois, après 14 jours d’essai" : "par mois"}</span>
              </p>
              <ul>
                {features(p).map((f) => (
                  <li key={f}>{f}</li>
                ))}
                <li>Vérification de chaque correction</li>
              </ul>
              <Link className={"btn" + (star ? "" : " ghost")} to={pay(id)}>
                {trial ? "Essayer 14 jours" : `Choisir ${p.name}`}
              </Link>
            </div>
          ) : null,
        )}
      </div>
      {trial && <p className="sub offer-note">Aucun prélèvement pendant 14 jours. Annulable en un clic avant la fin de l’essai. Carte ou PayPal.</p>}
      <p className="hint">
        <Link className="link" to={today}>
          Plus tard, voir mes résultats
        </Link>
      </p>
    </>
  );
}
