import type { ReactNode } from "react";
import { api } from "../api/client";
import type { Finding, Me, Member, Membership, ModuleInfo, OrgAsset, Target } from "../api/types";
import { AppShell } from "../components/AppShell";
import { Alert } from "../components/AuthLayout";
import { Ring } from "../components/charts";
import { orgPath } from "../components/nav";
import { age, moduleLabel, plural } from "../format";
import { Link } from "../router";
import { useLoad } from "../useLoad";

// Attack surface (docs/design/Surface.dc.html), from the asset inventory,
// targets, modules, members and findings. Connectors (identities, cloud,
// alerts) and discovery do not exist yet: shown in place, as coming.

interface Data {
  targets: Target[];
  assets: OrgAsset[];
  modules: ModuleInfo[];
  members: Member[];
  findings: Finding[];
}

const DAY = 86400_000;

type Status = "ready" | "available" | "blocked" | "todo";

function Source({ status, name, action }: { status: Status; name: string; action: ReactNode }) {
  const tag = { ready: ["ok", "Prêt"], available: ["accepted", "Disponible"], blocked: ["sev-critical", "Bloqué"], todo: ["warn", "À faire"] }[status];
  return (
    <div className="source">
      <span className={`tag ${tag[0]}`}>{tag[1]}</span>
      <span className="source-name">{name}</span>
      {action}
    </div>
  );
}

const soonButton = (label = "Connecter") => (
  <button type="button" className="btn btn-primary btn-sm" disabled title="Bientôt disponible">
    {label}
  </button>
);

export function SurfacePage({ me, org }: { me: Me; org: Membership }) {
  const { data, error } = useLoad<Data>(
    async (signal) => {
      const [targets, assets, modules, members, findings] = await Promise.all([
        api.targets(org.org_id, signal),
        api.orgAssets(org.org_id, signal),
        api.modules(org.org_id, signal),
        api.members(org.org_id, signal),
        api.findings(org.org_id, signal),
      ]);
      return { targets: targets.items, assets: assets.items, modules: modules.items, members: members.items, findings: findings.items };
    },
    org.org_id,
  );

  const actions = (
    <Link className="btn btn-primary" to={orgPath(org.org_id, "actifs")}>
      Ajouter un actif
    </Link>
  );

  return (
    <AppShell me={me} org={org} section="surface" title="Surface d’attaque" actions={actions}>
      {error && <Alert kind="error">{error}</Alert>}
      {data && <SurfaceContent data={data} org={org} />}
    </AppShell>
  );
}

function SurfaceContent({ data, org }: { data: Data; org: Membership }) {
  const now = new Date();
  const count = (k: OrgAsset["kind"]) => data.assets.filter((a) => a.kind === k).length;
  const expiringSoon = data.assets.filter((a) => {
    const end = a.kind === "certificate" ? Date.parse(a.details.not_after ?? "") : NaN;
    return !Number.isNaN(end) && end - now.getTime() < 30 * DAY;
  }).length;
  const unverified = data.targets.filter((t) => !t.verified).length;
  const noMfa = data.members.filter((m) => m.activated && !m.mfa_enabled).length;
  const anyVerified = data.targets.some((t) => t.verified);
  // Categories with at least one source in place: DNS (a verified domain)
  // and scan modules today; identities, cloud and alerts need connectors.
  const covered = (anyVerified ? 1 : 0) + (data.modules.length > 0 ? 1 : 0);

  type Change = { at: string; kind: "new" | "fixed" | "asset"; text: string };
  const changes: Change[] = [
    ...data.findings.map((f) => ({ at: f.first_seen, kind: "new" as const, text: `${f.title} · ${f.asset}` })),
    ...data.findings.flatMap((f) => (f.fixed_at ? [{ at: f.fixed_at, kind: "fixed" as const, text: `${f.title} · ${f.asset}` }] : [])),
    ...data.assets.map((a) => ({ at: a.first_seen, kind: "asset" as const, text: `${a.value} (${a.domain})` })),
  ]
    .sort((a, b) => b.at.localeCompare(a.at))
    .slice(0, 8);

  return (
    <>
      <section className="card dark surface-banner">
        <p className="card-sub">Votre surface d’attaque</p>
        <div className="banner-grid">
          <div className="banner-split">
            <div>
              <span className="banner-value">{data.assets.length}</span> {plural(data.assets.length, "actif exposé", "actifs exposés")} sur internet
            </div>
            <div>
              <span className="banner-value">—</span> services cloud et SaaS <span className="soon-dark">bientôt</span>
            </div>
            <div className="banner-bar" aria-hidden="true">
              <span />
            </div>
          </div>
          <div>
            <p className="banner-value">{data.targets.length}</p>
            <p className="banner-label">Actifs surveillés</p>
          </div>
          <div>
            <p className="banner-value">—</p>
            <p className="banner-label">Identités · bientôt</p>
          </div>
          <div>
            <p className="banner-value">—</p>
            <p className="banner-label">Administrateurs · bientôt</p>
          </div>
        </div>
      </section>

      <div className="section-head">
        <h2>Actions prioritaires</h2>
        <Link className="strong-link" to={orgPath(org.org_id, "priorisation")}>
          Voir la priorisation
        </Link>
      </div>
      <div className="cards-3">
        <div className="card">
          <p className="action-big">
            <span className="big">—</span> actifs découverts non surveillés
          </p>
          <p className="card-sub">La découverte des sous-domaines et adresses IP arrive bientôt.</p>
          <p className="soon card-note">Bientôt disponible</p>
        </div>
        <div className="card">
          <p className="action-big">
            <span className="big">{unverified}</span> {plural(unverified, "domaine non vérifié", "domaines non vérifiés")}
          </p>
          <p className="card-sub">Les scans actifs (ports, applications) sont bloqués tant que la propriété n’est pas prouvée.</p>
          {unverified > 0 && (
            <Link className="card-link" to={orgPath(org.org_id, "actifs")}>
              Vérifier le domaine
            </Link>
          )}
        </div>
        <div className="card">
          <p className="action-big">
            <span className="big">{noMfa}</span> {plural(noMfa, "compte sans double authentification", "comptes sans double authentification")}
          </p>
          <p className="card-sub">Les comptes Orus Shield protégés par un simple mot de passe.</p>
          {noMfa > 0 && (
            <Link className="card-link" to={`${orgPath(org.org_id, "parametres")}?onglet=equipe`}>
              Corriger
            </Link>
          )}
        </div>
      </div>

      <div className="section-head">
        <h2>Couverture</h2>
        <p className="small muted">Connectez au moins une source par catégorie</p>
      </div>
      <div className="cards-3">
        <div className="card ring-card">
          <Ring value={covered} max={5} text={`${covered}/5`} />
          <div>
            <p className="strong">Sources recommandées</p>
            <p className="small muted">Catégories sans source : identités, cloud, alertes{anyVerified ? "" : ", DNS"}</p>
          </div>
        </div>
        <div className="card">
          <h3>DNS et domaines</h3>
          <Source
            status={anyVerified ? "ready" : "todo"}
            name="Vérification TXT Orus"
            action={
              <Link className="btn btn-secondary btn-sm" to={orgPath(org.org_id, "actifs")}>
                Configurer
              </Link>
            }
          />
          <Source status="available" name="Cloudflare" action={soonButton()} />
        </div>
        <div className="card">
          <h3>Identités</h3>
          <Source status="available" name="Microsoft 365" action={soonButton()} />
          <Source status="available" name="Google Workspace" action={soonButton()} />
        </div>
        <div className="card">
          <h3>Cloud</h3>
          <Source status="available" name="AWS" action={soonButton()} />
          <Source status="available" name="Azure" action={soonButton()} />
          <Source status="available" name="Google Cloud" action={soonButton()} />
        </div>
        <div className="card">
          <h3>Modules de scan</h3>
          {data.modules.map((m) => {
            const blocked = m.kind === "active" && !anyVerified;
            return (
              <Source
                key={m.id}
                status={blocked ? "blocked" : "ready"}
                name={moduleLabel(m.id)}
                action={
                  <Link className={blocked ? "btn btn-primary btn-sm" : "btn btn-secondary btn-sm"} to={orgPath(org.org_id, blocked ? "actifs" : "scans")}>
                    {blocked ? "Résoudre" : "Configurer"}
                  </Link>
                }
              />
            );
          })}
        </div>
        <div className="card">
          <h3>Alertes</h3>
          <Source status="available" name="WhatsApp Business" action={soonButton()} />
          <Source status="available" name="Slack" action={soonButton()} />
        </div>
      </div>

      <div className="section-head">
        <h2>Actifs externes</h2>
        <Link className="strong-link" to={orgPath(org.org_id, "actifs")}>
          Tout voir
        </Link>
      </div>
      <div className="kpis">
        <div className="kpi">
          <p className="kpi-value">{count("hostname")}</p>
          <p className="strong">Domaines</p>
          <p className="kpi-sub">Domaines et sous-domaines accessibles</p>
        </div>
        <div className="kpi">
          <p className="kpi-value">{count("ip")}</p>
          <p className="strong">Adresses IP</p>
          <p className="kpi-sub">Hôtes joignables depuis internet</p>
        </div>
        <div className="kpi">
          <p className="kpi-value">{count("certificate")}</p>
          <p className="strong">Certificats</p>
          <p className="kpi-sub">dont {expiringSoon} {plural(expiringSoon, "expire", "expirent")} dans moins de 30 jours</p>
        </div>
        <div className="kpi">
          <p className="kpi-value">{count("service")}</p>
          <p className="strong">Services exposés</p>
          <p className="kpi-sub">Ports ouverts sur vos adresses IP</p>
        </div>
      </div>

      <section className="card row-single">
        <h2>Changements récents</h2>
        {changes.length === 0 ? (
          <p className="small muted card-note">Aucun changement pour l’instant : ils apparaissent après les scans.</p>
        ) : (
          <ul className="changes">
            {changes.map((c, i) => (
              <li key={i}>
                <span>
                  <span className={c.kind === "new" ? "change-new" : c.kind === "fixed" ? "change-fixed" : "strong"}>
                    {c.kind === "new" ? "Nouvelle vulnérabilité" : c.kind === "fixed" ? "Corrigé" : "Nouvel actif"}
                  </span>{" "}
                  · {c.text}
                </span>
                <span className="small muted">{age(c.at, now)}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
