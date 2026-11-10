import type { ReactNode } from "react";
import { api } from "../api/client";
import type { Category, Check, Me, Membership, Month, Overview } from "../api/types";
import { AppShell } from "../components/AppShell";
import { Alert } from "../components/AuthLayout";
import { Bars, Donut, Legend, Lines, SEV_COLORS } from "../components/charts";
import { dayAndTime, duration, plural, severityLabel } from "../format";
import { useLoad } from "../useLoad";

// Governance and risks (docs/design/Gouvernance.dc.html). What scans
// measure is computed: vulnerabilities over time, by severity, controls
// in place, remediation time. The risk register, policies and audit
// findings are business data the GRC module will hold: shown as coming.

interface Data {
  overview: Overview;
  checks: Check[];
  months: Month[];
}

const MONTHS = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."];
const monthLabel = (m: string) => MONTHS[Number(m.slice(5, 7)) - 1] ?? m;

const DOMAINS: { label: string; categories: Category[] }[] = [
  { label: "Contrôle d’accès", categories: ["identity"] },
  { label: "Sécurité réseau", categories: ["network", "tls"] },
  { label: "Protection des données", categories: ["leaks", "web"] },
  { label: "Messagerie", categories: ["email", "dns"] },
];

function Panel({ title, tone, children }: { title: string; tone: "red" | "blue"; children: ReactNode }) {
  return (
    <section className="card gov-panel">
      <h2 className="gov-title">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={tone === "red" ? "#B42318" : "#5B8DEF"} strokeWidth="2" aria-hidden="true">
          <path d="M12 3l7 3v6c0 4.5-3 7.7-7 9-4-1.3-7-4.5-7-9V6l7-3z" />
        </svg>
        {title}
      </h2>
      <div className="gov-body">{children}</div>
    </section>
  );
}

const Soon = ({ children }: { children: ReactNode }) => (
  <p className="small muted">
    <span className="soon">Bientôt</span> — {children}
  </p>
);

export function GovernancePage({ me, org }: { me: Me; org: Membership }) {
  const { data, error } = useLoad<Data>(
    async (signal) => {
      const [overview, checks, months] = await Promise.all([api.overview(org.org_id, 30, signal), api.checks(org.org_id, signal), api.trends(org.org_id, 6, signal)]);
      return { overview, checks: checks.items, months: months.items };
    },
    org.org_id,
  );
  const actions = (
    <button type="button" className="btn btn-primary" disabled title="Bientôt disponible">
      Exporter pour la direction
    </button>
  );
  return (
    <AppShell me={me} org={org} section="gouvernance" title="Gouvernance et risques" actions={actions}>
      {error && <Alert kind="error">{error}</Alert>}
      {data && <Content data={data} />}
    </AppShell>
  );
}

function Content({ data }: { data: Data }) {
  const now = new Date();
  const { overview: ov, checks, months } = data;
  const open = (["critical", "high", "medium", "low"] as const).map((s) => ({ s, n: ov.open_findings[s] ?? 0 }));
  const openTotal = open.reduce((n, x) => n + x.n, 0);
  const evaluated = checks.filter((c) => c.status !== "not_applicable");
  const passed = checks.filter((c) => c.status === "passed");
  const inPlace = evaluated.length ? Math.round((100 * passed.length) / evaluated.length) : null;
  const rate = (cats: Category[]) => {
    const ev = evaluated.filter((c) => cats.includes(c.category));
    return ev.length ? Math.round((100 * ev.filter((c) => c.status === "passed").length) / ev.length) : null;
  };
  const sevSlices = open.map((x) => ({ label: severityLabel(x.s), value: x.n, color: SEV_COLORS[x.s] }));
  const controlSlices = [
    { label: "Réussis", value: passed.length, color: "#17B26A" },
    { label: "En échec", value: checks.filter((c) => c.status === "failed").length, color: "#B42318" },
    { label: "Non applicables", value: checks.filter((c) => c.status === "not_applicable").length, color: "#D5DAE1" },
  ];

  return (
    <div className="gov-grid">
      <Panel title="Vue de direction" tone="red">
        <div className="tiles">
          <div className="tile">
            <p className="small muted">Risques élevés</p>
            <p className="tile-value">—</p>
            <p className="small soon">Registre bientôt</p>
          </div>
          <div className="tile">
            <p className="small muted">Score de conformité</p>
            <p className="tile-value">—</p>
            <p className="small soon">Référentiels bientôt</p>
          </div>
          <div className="tile">
            <p className="small muted">Vulnérabilités ouvertes</p>
            <p className="tile-value">{openTotal}</p>
            <p className="small muted">
              dont {ov.open_findings.critical ?? 0} {plural(ov.open_findings.critical ?? 0, "critique", "critiques")}
            </p>
          </div>
          <div className="tile">
            <p className="small muted">Contrôles en place</p>
            <p className="tile-value ok-text">{inPlace !== null ? `${inPlace} %` : "—"}</p>
            <p className="small muted">
              {passed.length} sur {evaluated.length}
            </p>
          </div>
        </div>
        <div className="gov-charts">
          <div className="donut-legend">
            <Donut slices={sevSlices} label="Vulnérabilités ouvertes par gravité" />
            <Legend slices={sevSlices} />
          </div>
          <Lines
            label="Vulnérabilités nouvelles et corrigées par mois"
            labels={months.map((m) => monthLabel(m.month))}
            series={[
              { label: "Nouvelles", color: "#B42318", values: months.map((m) => m.opened) },
              { label: "Corrigées", color: "#17B26A", values: months.map((m) => m.fixed) },
            ]}
          />
        </div>
      </Panel>

      <Panel title="Gestion des risques" tone="blue">
        <p className="strong">Carte de chaleur</p>
        <div className="heatmap" aria-hidden="true">
          {Array.from({ length: 25 }, (_, i) => {
            const row = Math.floor(i / 5);
            const col = i % 5;
            const level = 4 - row + col;
            return <span key={i} className={`heat h${Math.min(4, Math.max(0, level - 2))}`} />;
          })}
        </div>
        <p className="strong card-note">Registre des risques</p>
        <Soon>le registre (risques, probabilité, impact, responsables, statut) arrive avec le module de gouvernance.</Soon>
      </Panel>

      <Panel title="État de conformité" tone="blue">
        <div className="two-cols">
          <div>
            <p className="strong">Conformité par référentiel</p>
            <Soon>ISO 27001, PCI DSS, protection des données et CIS, une fois les correspondances relues.</Soon>
          </div>
          <div>
            <p className="strong">Domaines de risque</p>
            <div className="bars">
              {DOMAINS.map((d) => {
                const r = rate(d.categories);
                return (
                  <div key={d.label}>
                    <div className="bar-head">
                      <span>{d.label}</span>
                      <span className="strong">{r !== null ? `${r} %` : "—"}</span>
                    </div>
                    <div className="bar" aria-hidden="true">
                      <span className={r !== null && r >= 70 ? "ok-fill" : "sev-high"} style={{ width: `${r ?? 0}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="tiles two card-note">
              <div className="tile">
                <p className="tile-value">{inPlace !== null ? `${inPlace} %` : "—"}</p>
                <p className="small muted">contrôles mis en œuvre</p>
              </div>
              <div className="tile">
                <p className="tile-value">—</p>
                <p className="small muted">constats d’audit clôturés · bientôt</p>
              </div>
            </div>
          </div>
        </div>
      </Panel>

      <Panel title="Efficacité des contrôles" tone="red">
        <div className="donut-legend">
          <Donut slices={controlSlices} label="Contrôles réussis, en échec et non applicables" />
          <Legend slices={controlSlices} />
        </div>
        <p className="strong card-note">Liste des contrôles</p>
        <table className="table compact">
          <thead>
            <tr>
              <th scope="col">Contrôle</th>
              <th scope="col">Statut</th>
              <th scope="col">Dernière revue</th>
            </tr>
          </thead>
          <tbody>
            {[...checks]
              .sort((a, b) => (a.status === "failed" ? -1 : 0) - (b.status === "failed" ? -1 : 0))
              .slice(0, 6)
              .map((c) => (
                <tr key={`${c.target_id}:${c.id}`}>
                  <td>{c.title}</td>
                  <td className={c.status === "failed" ? "change-new" : c.status === "passed" ? "ok-text" : "muted"}>
                    {c.status === "failed" ? "Échec" : c.status === "passed" ? "Validé" : "N/A"}
                  </td>
                  <td className="muted">{dayAndTime(c.evaluated_at, now)}</td>
                </tr>
              ))}
          </tbody>
        </table>
        {checks.length === 0 && <p className="small muted">Aucun contrôle évalué pour l’instant.</p>}
      </Panel>

      <Panel title="Incidents et vulnérabilités" tone="red">
        <div className="two-cols">
          <div>
            <p className="strong">Vulnérabilités dans le temps</p>
            <Lines
              label="Nouvelles et corrigées par mois"
              labels={months.map((m) => monthLabel(m.month))}
              series={[
                { label: "Nouvelles", color: "#0C5DA5", values: months.map((m) => m.opened) },
                { label: "Corrigées", color: "#F79009", values: months.map((m) => m.fixed) },
              ]}
            />
            <Legend
              slices={[
                { label: "Nouvelles", value: months.reduce((n, m) => n + m.opened, 0), color: "#0C5DA5" },
                { label: "Corrigées", value: months.reduce((n, m) => n + m.fixed, 0), color: "#F79009" },
              ]}
            />
          </div>
          <div>
            <p className="strong">Vulnérabilités par gravité</p>
            <Bars bars={sevSlices} label="Vulnérabilités ouvertes par gravité" />
          </div>
        </div>
        <div className="tiles two card-note">
          <div className="tile">
            <p className="small muted">Délai moyen de détection</p>
            <p className="tile-value">—</p>
            <p className="small soon">Mesure bientôt</p>
          </div>
          <div className="tile">
            <p className="small muted">Délai moyen de correction</p>
            <p className="tile-value">{ov.remediation.mean_seconds !== null ? duration(ov.remediation.mean_seconds) : "—"}</p>
          </div>
        </div>
      </Panel>

      <Panel title="Gouvernance et audit" tone="red">
        <div className="two-cols">
          <div>
            <p className="strong">Constats d’audit par gravité</p>
            <Soon>les constats d’audit arrivent avec le module de gouvernance.</Soon>
          </div>
          <div>
            <p className="strong">Politiques</p>
            <Soon>politiques (mots de passe, accès à distance, usage de l’IA) et leur statut de revue.</Soon>
          </div>
        </div>
      </Panel>
    </div>
  );
}
