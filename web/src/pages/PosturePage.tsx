import { useState } from "react";
import { api } from "../api/client";
import type { Category, Check, Me, Membership, OrgAsset, Overview, Target } from "../api/types";
import { AppShell } from "../components/AppShell";
import { Alert } from "../components/AuthLayout";
import { orgPath } from "../components/nav";
import { dayAndTime, plural, severityLabel, signed } from "../format";
import { Link } from "../router";
import { useLoad } from "../useLoad";

// Posture and compliance (docs/design/Posture.dc.html), from the checks'
// latest statuses, the overview and the asset inventory. Framework
// mappings are not written yet: the compliance cards say so.

interface Data {
  overview: Overview;
  checks: Check[];
  assets: OrgAsset[];
  targets: Target[];
}

interface CategoryDef {
  id: Category;
  label: string;
  /** What the big number counts, from the inventory. */
  unit: (d: Data) => { n: number | null; one: string; many: string };
}

const CATEGORIES: CategoryDef[] = [
  { id: "email", label: "Emails", unit: (d) => ({ n: d.targets.length, one: "domaine", many: "domaines" }) },
  { id: "web", label: "Web", unit: (d) => ({ n: d.assets.filter((a) => a.kind === "hostname").length, one: "site", many: "sites" }) },
  { id: "tls", label: "TLS et certificats", unit: (d) => ({ n: d.assets.filter((a) => a.kind === "certificate").length, one: "certificat", many: "certificats" }) },
  { id: "dns", label: "DNS", unit: (d) => ({ n: d.targets.length, one: "domaine", many: "domaines" }) },
  { id: "identity", label: "Identités et accès", unit: () => ({ n: null, one: "compte", many: "comptes" }) },
  { id: "network", label: "Réseau et ports", unit: (d) => ({ n: d.assets.filter((a) => a.kind === "ip").length, one: "adresse IP", many: "adresses IP" }) },
  { id: "cloud", label: "Cloud", unit: () => ({ n: null, one: "compte", many: "comptes" }) },
  { id: "leaks", label: "Fuites de données", unit: () => ({ n: null, one: "adresse", many: "adresses" }) },
];

const FRAMEWORKS = [
  { code: "ISO", name: "ISO 27001", version: "v2022" },
  { code: "PCI", name: "PCI DSS", version: "v4.0.1" },
  { code: "DP", name: "Protection des données", version: "RGPD et lois africaines" },
  { code: "CIS", name: "CIS Microsoft 365", version: "v4.0" },
];

const statusLabel = { passed: "Réussi", failed: "Échoué", not_applicable: "Non applicable" } as const;

export function PosturePage({ me, org }: { me: Me; org: Membership }) {
  const [tab, setTab] = useState<"home" | "inventory">("home");
  const { data, error } = useLoad<Data>(
    async (signal) => {
      const [overview, checks, assets, targets] = await Promise.all([
        api.overview(org.org_id, 30, signal),
        api.checks(org.org_id, signal),
        api.orgAssets(org.org_id, signal),
        api.targets(org.org_id, signal),
      ]);
      return { overview, checks: checks.items, assets: assets.items, targets: targets.items };
    },
    org.org_id,
  );

  return (
    <AppShell me={me} org={org} section="posture" title="Posture et conformité">
      <div className="underline-tabs" role="tablist">
        <button type="button" role="tab" aria-selected={tab === "home"} onClick={() => setTab("home")}>
          Accueil
        </button>
        <button type="button" role="tab" aria-selected={tab === "inventory"} onClick={() => setTab("inventory")}>
          Inventaire des ressources
        </button>
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      {data && tab === "home" && <Home data={data} org={org} />}
      {data && tab === "inventory" && <Inventory data={data} />}
    </AppShell>
  );
}

function Home({ data, org }: { data: Data; org: Membership }) {
  const [selected, setSelected] = useState<Category>("email");
  const { overview: ov, checks } = data;
  const critical = ov.open_findings.critical ?? 0;
  const high = ov.open_findings.high ?? 0;
  const others = (ov.open_findings.medium ?? 0) + (ov.open_findings.low ?? 0);
  const evaluated = checks.filter((c) => c.status !== "not_applicable");
  const failed = checks.filter((c) => c.status === "failed");
  const verified = data.targets.filter((t) => t.verified).length;
  const inCategory = (id: Category) => checks.filter((c) => c.category === id);
  const selectedDef = CATEGORIES.find((c) => c.id === selected)!;
  const selectedFailed = inCategory(selected).filter((c) => c.status === "failed");

  return (
    <>
      <div className="kpis">
        <div className="kpi">
          <p className="kpi-label">Menaces</p>
          <p className="kpi-value">{critical + high}</p>
          <p className="tags">
            <span className="tag sev-critical">{critical} CRITIQUES</span> <span className="tag sev-high">{high} ÉLEVÉES</span>{" "}
            {others > 0 && <span className="tag accepted">+{others}</span>}
          </p>
          <Link className="card-link small" to={orgPath(org.org_id, "vulnerabilites")}>
            Voir les menaces ›
          </Link>
        </div>
        <div className="kpi">
          <p className="kpi-label">Mauvaises configurations</p>
          <p className="kpi-value">
            {failed.length}
            <span className="kpi-unit"> / {evaluated.length}</span>
          </p>
          <div className="bar" aria-hidden="true">
            <span className="sev-critical" style={{ width: `${evaluated.length ? (100 * failed.length) / evaluated.length : 0}%` }} />
          </div>
          <button type="button" className="link-button small card-link" onClick={() => document.querySelector<HTMLButtonElement>(".underline-tabs button:last-child")?.click()}>
            Voir les ressources ›
          </button>
        </div>
        <div className="kpi">
          <p className="kpi-label">Score de posture</p>
          <p className="kpi-value">
            {ov.score !== null ? `${ov.score} %` : "—"}{" "}
            {ov.score_change !== null && <span className={ov.score_change < 0 ? "tag sev-critical" : "tag ok"}>{signed(ov.score_change)} PTS</span>}
          </p>
          <div className="bar" aria-hidden="true">
            <span className="ok-fill" style={{ width: `${ov.score ?? 0}%` }} />
          </div>
          <Link className="card-link small" to={orgPath(org.org_id)}>
            Voir le détail ›
          </Link>
        </div>
        <div className="kpi">
          <p className="kpi-label">Couverture</p>
          <dl className="facts compact">
            <dt>Comptes SaaS et cloud</dt>
            <dd>— <span className="soon">bientôt</span></dd>
            <dt>Actifs vérifiés</dt>
            <dd>
              {verified} / {data.targets.length}
            </dd>
          </dl>
          <Link className="card-link small" to={orgPath(org.org_id, "actifs")}>
            Configurer ›
          </Link>
        </div>
      </div>

      <section className="risk-panel">
        <h2>Comprenez ce qui est à risque, et où se concentrent les attaques</h2>
        <div className="risk-grid">
          {CATEGORIES.map((c) => {
            const unit = c.unit(data);
            const list = inCategory(c.id);
            const risks = list.filter((x) => x.status === "failed").length;
            const evaluatedHere = list.some((x) => x.status !== "not_applicable");
            const connector = c.id === "identity" || c.id === "cloud" || c.id === "leaks";
            return (
              <button key={c.id} type="button" className="risk-card" aria-pressed={selected === c.id} onClick={() => setSelected(c.id)}>
                <span className="risk-label">{c.label.toUpperCase()}</span>
                <span className="risk-row">
                  <span>
                    <span className="risk-value">{unit.n ?? "—"}</span> {unit.n !== null ? plural(unit.n, unit.one, unit.many) : unit.many}
                  </span>
                  {connector ? (
                    <span className="tag accepted">BIENTÔT</span>
                  ) : !evaluatedHere ? (
                    <span className="tag accepted">NON ÉVALUÉ</span>
                  ) : risks > 0 ? (
                    <span className={risks > 3 ? "tag sev-critical" : "tag sev-high"}>
                      {risks} {plural(risks, "RISQUE", "RISQUES")}
                    </span>
                  ) : (
                    <span className="tag ok">OK</span>
                  )}
                </span>
              </button>
            );
          })}
        </div>
        <div className="card risk-detail">
          <p className="strong">{selectedDef.label.toUpperCase()} : principaux contrôles en échec</p>
          {selectedFailed.length > 0 ? (
            <ul>
              {selectedFailed.slice(0, 6).map((c) => (
                <li key={`${c.target_id}:${c.id}`}>
                  {c.title} <span className="muted">· {severityLabel(c.severity)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="small muted">
              {inCategory(selected).length === 0 ? "Aucun contrôle de cette catégorie n’a encore été évalué." : "Aucun contrôle en échec."}
            </p>
          )}
        </div>
      </section>

      <section className="card compliance">
        <h2>Vos rapports de conformité</h2>
        <p className="card-sub">Des rapports continus, tenus à jour par Orus Shield, pour atteindre et garder la conformité.</p>
        <div className="compliance-grid">
          {FRAMEWORKS.map((f) => (
            <div className="framework" key={f.code}>
              <div className="framework-head">
                <span className="framework-code">{f.code}</span>
                <div>
                  <p className="strong">{f.name}</p>
                  <p className="small muted">{f.version}</p>
                </div>
              </div>
              <div className="framework-body">
                <p>Évaluation des règles</p>
                <div className="pass-fail">
                  <div>
                    <span className="pass">RÉUSSIS</span>
                    <span className="pf-value">—</span>
                  </div>
                  <div>
                    <span className="fail">ÉCHOUÉS</span>
                    <span className="pf-value">—</span>
                  </div>
                </div>
                <p className="small soon">Correspondances en cours de rédaction</p>
              </div>
            </div>
          ))}
        </div>
        <p className="small muted card-note">Un scan externe ne couvre qu’une partie de chaque référentiel : les rapports indiqueront les contrôles automatisés associés, jamais une conformité complète.</p>
      </section>
    </>
  );
}

function Inventory({ data }: { data: Data }) {
  const now = new Date();
  const domain = (id?: string) => data.targets.find((t) => t.id === id)?.domain ?? "";
  const rows = [...data.checks].sort((a, b) => (a.status === b.status ? a.title.localeCompare(b.title) : a.status === "failed" ? -1 : b.status === "failed" ? 1 : 0));
  return (
    <section className="card">
      <h2>Contrôles évalués</h2>
      <p className="card-sub">
        {data.checks.length} {plural(data.checks.length, "contrôle", "contrôles")} sur {data.targets.length} {plural(data.targets.length, "domaine", "domaines")}
      </p>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Domaine</th>
              <th scope="col">Contrôle</th>
              <th scope="col">Catégorie</th>
              <th scope="col">Gravité</th>
              <th scope="col">Statut</th>
              <th scope="col">Évalué</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={`${c.target_id}:${c.id}`}>
                <td className="name">{domain(c.target_id)}</td>
                <td>{c.title}</td>
                <td className="muted">{CATEGORIES.find((x) => x.id === c.category)?.label ?? c.category}</td>
                <td>{severityLabel(c.severity)}</td>
                <td>
                  <span className={c.status === "failed" ? "tag sev-critical" : c.status === "passed" ? "tag ok" : "tag accepted"}>{statusLabel[c.status]}</span>
                </td>
                <td className="muted">{dayAndTime(c.evaluated_at, now)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
