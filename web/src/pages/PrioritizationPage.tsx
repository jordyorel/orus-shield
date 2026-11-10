import { api } from "../api/client";
import type { Finding, Me, Membership, OrgAsset, Severity } from "../api/types";
import { AppShell } from "../components/AppShell";
import { Alert } from "../components/AuthLayout";
import { SEV_COLORS } from "../components/charts";
import { orgPath } from "../components/nav";
import { moduleLabel, plural, severityLabel } from "../format";
import { Link } from "../router";
import { useLoad } from "../useLoad";

// Prioritization by real risk (docs/design/Priorisation.dc.html). The
// contextual risk function and the threat feed (CISA KEV) do not exist
// yet: the table is sorted by raw severity, the funnel waits, and the
// columns without a source say so instead of guessing.

interface Data {
  findings: Finding[];
  assets: OrgAsset[];
}

const SEVERITIES: Exclude<Severity, "info">[] = ["critical", "high", "medium", "low"];
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const DAY = 86400_000;

/** host of a finding's asset: "www.example.com:443" -> "www.example.com". */
function hostOf(asset: string): string {
  return asset.replace(/:\d+$/, "").toLowerCase();
}

/** protections lists the CDN and WAF the cdn module saw in front of a host. */
export function protections(asset: string, assets: OrgAsset[]): string {
  const host = assets.find((a) => a.kind === "hostname" && a.value === hostOf(asset));
  const found = [host?.details.waf, host?.details.cdn].filter((x): x is string => !!x && x !== "none");
  return found.length > 0 ? [...new Set(found)].join(", ") : "Aucune";
}

function csv(rows: string[][]): string {
  return rows.map((r) => r.map((c) => `"${c.replace(/"/g, '""')}"`).join(",")).join("\n") + "\n";
}

export function PrioritizationPage({ me, org }: { me: Me; org: Membership }) {
  const { data, error } = useLoad<Data>(
    async (signal) => {
      const [f, a] = await Promise.all([api.findings(org.org_id, signal), api.orgAssets(org.org_id, signal)]);
      return { findings: f.items, assets: a.items };
    },
    org.org_id,
  );

  return (
    <AppShell me={me} org={org} section="priorisation" title="Vulnérabilités par risque réel">
      {error && <Alert kind="error">{error}</Alert>}
      {data && <Content data={data} org={org} />}
    </AppShell>
  );
}

function Content({ data, org }: { data: Data; org: Membership }) {
  const now = Date.now();
  const open = data.findings
    .filter((f) => f.status === "open" && f.severity !== "info")
    .sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.first_seen.localeCompare(b.first_seen));
  const bySev = Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((f) => f.severity === s).length])) as Record<(typeof SEVERITIES)[number], number>;
  const urgent = bySev.critical + bySev.high;
  const max = Math.max(1, ...Object.values(bySev));
  const days = (f: Finding) => Math.max(0, Math.floor((now - Date.parse(f.first_seen)) / DAY));

  const exportCsv = () => {
    const rows = [
      ["Identifiant", "Titre", "Actif", "Composant", "Exposition (jours)", "Exposé à internet", "Protections", "Gravité"],
      ...open.map((f) => [f.check_id, f.title, f.asset, moduleLabel(f.module_id), String(days(f)), "Oui", protections(f.asset, data.assets), severityLabel(f.severity)]),
    ];
    const url = URL.createObjectURL(new Blob([csv(rows)], { type: "text/csv;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "orus-shield-vulnerabilites.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <section className="card funnel">
        <div className="funnel-head">
          <div>
            <p className="strong">
              Sévérité brute <span className="muted">({urgent} critiques et élevées)</span>
            </p>
            <p className="card-note context">Contexte Orus</p>
          </div>
          <div className="funnel-bars" aria-label="Vulnérabilités ouvertes par gravité">
            {SEVERITIES.map((s) => (
              <div key={s} className="funnel-col">
                <span className="funnel-bar" style={{ height: `${(bySev[s] / max) * 100}%`, background: SEV_COLORS[s] }} />
                <span className="small">
                  {severityLabel(s)} · {bySev[s]}
                </span>
              </div>
            ))}
          </div>
        </div>
        <div className="funnel-foot">
          <span className="bubble critical">{urgent}</span>
          <span className="muted">→</span>
          <span className="bubble soon-bubble">?</span>
          <div>
            <p className="big">—</p>
            <p className="small muted">
              des alertes critiques et élevées ramenées à moyen ou faible. <span className="soon">Bientôt</span> : le risque réel tiendra compte de l’exposition, de
              l’exploitation active et des protections.
            </p>
          </div>
        </div>
      </section>

      <section className="card filters">
        <span className="chip on">Exposé à internet : oui</span>
        <span className="chip" title="Bientôt disponible">
          Menace : exploitée activement +
        </span>
        <span className="filters-right">
          <button type="button" className="btn btn-secondary btn-sm" disabled title="Bientôt disponible">
            Filtres
          </button>
        </span>
      </section>

      <section className="card row-single">
        <div className="card-head">
          <h2>
            Vulnérabilités filtrées <span className="count-badge">{open.length}</span>
          </h2>
          <div className="button-row">
            <select disabled title="Bientôt disponible" aria-label="Grouper par">
              <option>Grouper par : aucun</option>
            </select>
            <button type="button" className="btn btn-secondary btn-sm" onClick={exportCsv} disabled={open.length === 0}>
              Exporter
            </button>
          </div>
        </div>
        {open.length === 0 ? (
          <p className="small muted card-note">Aucune vulnérabilité ouverte.</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Identifiant</th>
                  <th scope="col">Actif</th>
                  <th scope="col">Composant</th>
                  <th scope="col">Exposition</th>
                  <th scope="col">En service</th>
                  <th scope="col">Exposé à internet</th>
                  <th scope="col">Menace</th>
                  <th scope="col">Protections</th>
                  <th scope="col">Risque réel ↓</th>
                  <th scope="col">
                    <span className="visually-hidden">Détail</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {open.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <span className="strong">{f.check_id.toUpperCase()}</span>
                      <br />
                      <span className="small muted">{f.title}</span>
                    </td>
                    <td className="name">{f.asset}</td>
                    <td>{moduleLabel(f.module_id)}</td>
                    <td>{days(f)} j</td>
                    <td className="muted" title="Détection des services à venir">
                      —
                    </td>
                    <td className="ok-text">Oui</td>
                    <td className="muted">Non connue</td>
                    <td>{protections(f.asset, data.assets)}</td>
                    <td>
                      <span className={`tag sev-${f.severity}`}>{severityLabel(f.severity)}</span>
                      <br />
                      <span className="small muted">Brut · risque réel bientôt</span>
                    </td>
                    <td>
                      <Link className="btn btn-primary btn-sm" to={`${orgPath(org.org_id, "vulnerabilites")}?id=${encodeURIComponent(f.id)}`}>
                        Voir le détail
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="small muted card-note">
          {open.length} {plural(open.length, "vulnérabilité", "vulnérabilités")} triées par gravité brute, puis par ancienneté.
        </p>
      </section>
    </>
  );
}
