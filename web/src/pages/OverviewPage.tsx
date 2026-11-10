import { useEffect, useState } from "react";
import { api, ApiError } from "../api/client";
import type { Me, Membership, Overview, OverviewTarget, Severity } from "../api/types";
import { AppShell } from "../components/AppShell";
import { orgPath } from "../components/nav";
import { CHART, chartGeometry } from "../chart";
import { dayAndTime, duration, durationChange, plural, priorityText, scoreBand, severityLabel, signed } from "../format";
import { Link, navigate } from "../router";
import { fallback } from "./messages";

const PERIODS = [7, 30, 90] as const;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
/** Frameworks of the compliance panel: no figures until the check mappings are reviewed. */
const FRAMEWORKS = ["ISO 27001", "PCI-DSS (paiements)", "Protection des données personnelles"];

const openCount = (counts: Partial<Record<Severity, number>>) => SEVERITIES.reduce((n, s) => n + (counts[s] ?? 0), 0);

/** Most exposed first: lowest score, then most open findings; no score last. */
function byExposure(a: OverviewTarget, b: OverviewTarget): number {
  if (a.posture_score === null || b.posture_score === null) {
    if (a.posture_score !== b.posture_score) return a.posture_score === null ? 1 : -1;
  } else if (a.posture_score !== b.posture_score) {
    return a.posture_score - b.posture_score;
  }
  return openCount(b.open_findings) - openCount(a.open_findings);
}

export function OverviewPage({ me, org }: { me: Me; org: Membership }) {
  const [days, setDays] = useState<number>(30);
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
    api
      .overview(org.org_id, days, ctrl.signal)
      .then((ov) => {
        setData(ov);
        setError("");
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        if (err instanceof ApiError && err.code === "mfa_required") navigate("/mfa/setup?reason=admin", { replace: true });
        else setError(fallback(err));
      })
      .finally(() => {
        if (!ctrl.signal.aborted) setLoading(false);
      });
    return () => ctrl.abort();
  }, [org.org_id, days]);

  const actions = (
    <>
      <div className="segmented" role="group" aria-label="Période">
        {PERIODS.map((p) => (
          <button key={p} type="button" aria-pressed={p === days} onClick={() => setDays(p)}>
            {p} j
          </button>
        ))}
      </div>
      <Link className="btn btn-primary" to={orgPath(org.org_id, "scans")}>
        Lancer un scan
      </Link>
    </>
  );

  return (
    <AppShell me={me} org={org} section="" title="Vue d'ensemble" actions={actions}>
      {error && <p className="alert alert-error" role="alert">{error}</p>}
      {data && <OverviewContent data={data} org={org} loading={loading} />}
    </AppShell>
  );
}

function OverviewContent({ data, org, loading }: { data: Overview; org: Membership; loading: boolean }) {
  const now = new Date();
  if (data.targets === 0) {
    return (
      <section className="card empty">
        <h2>Aucun domaine surveillé</h2>
        <p>Ajoutez le domaine de votre entreprise pour lancer la première analyse. Le score, les vulnérabilités et les actifs exposés s’afficheront ici.</p>
      </section>
    );
  }
  const open = openCount(data.open_findings);
  const critical = data.open_findings.critical ?? 0;
  const rem = data.remediation;
  const remChange =
    rem.mean_seconds !== null && rem.previous_mean_seconds !== null ? durationChange(rem.mean_seconds, rem.previous_mean_seconds) : null;
  const chart = chartGeometry(data.trend);
  const rows = [...data.per_target].sort(byExposure);

  return (
    <div className={loading ? "loading" : undefined} aria-busy={loading}>
      <div className="kpis">
        <div className="kpi">
          <p className="kpi-label">Score de sécurité</p>
          {data.score !== null ? (
            <>
              <p className="kpi-value">
                {data.score}
                <span className="kpi-unit">/100</span>
              </p>
              {data.score_change !== null ? (
                <p className={data.score_change < 0 ? "kpi-sub down" : "kpi-sub accent"}>
                  {data.score_change === 0 ? "Stable" : `${signed(data.score_change)} ${plural(data.score_change, "point", "points")}`}
                </p>
              ) : (
                <p className="kpi-sub">Pas encore d’évolution</p>
              )}
            </>
          ) : (
            <>
              <p className="kpi-value">—</p>
              <p className="kpi-sub">Aucun contrôle évalué pour l’instant</p>
            </>
          )}
        </div>
        <div className="kpi">
          <p className="kpi-label">Vulnérabilités ouvertes</p>
          <p className="kpi-value">{open}</p>
          <p className="kpi-sub">
            dont {critical} {plural(critical, "critique", "critiques")}
          </p>
        </div>
        <div className="kpi">
          <p className="kpi-label">Actifs surveillés</p>
          <p className="kpi-value">{data.assets}</p>
          <p className="kpi-sub">
            {data.new_assets} {plural(data.new_assets, "nouveau", "nouveaux")} en {data.days} jours
          </p>
        </div>
        <div className="kpi">
          <p className="kpi-label">Délai moyen de correction</p>
          {rem.mean_seconds !== null ? (
            <>
              <p className="kpi-value">{duration(rem.mean_seconds)}</p>
              {remChange ? (
                <p className={remChange.worse ? "kpi-sub down" : "kpi-sub accent"}>{remChange.text}</p>
              ) : (
                <p className="kpi-sub">
                  {rem.fixed} {plural(rem.fixed, "correction", "corrections")} en {data.days} jours
                </p>
              )}
            </>
          ) : (
            <>
              <p className="kpi-value">—</p>
              <p className="kpi-sub">Aucune correction en {data.days} jours</p>
            </>
          )}
        </div>
      </div>

      <div className="row">
        <section className="card grow-2">
          <div className="card-head">
            <h2>Évolution du score</h2>
            <p className="small muted">{data.days} derniers jours</p>
          </div>
          {chart.measured > 0 ? (
            <>
              <svg
                className="chart"
                viewBox={`0 0 ${CHART.width} ${CHART.height}`}
                role="img"
                aria-label={`Score de sécurité sur les ${data.days} derniers jours${data.score !== null ? `, ${data.score} sur 100 aujourd’hui` : ""}`}
              >
                {chart.grid.map((g) => (
                  <g key={g.label}>
                    <line className="grid" x1={0} x2={CHART.width} y1={g.y} y2={g.y} />
                    <text className="axis" x={0} y={g.y} dy={-6}>
                      {g.label}
                    </text>
                  </g>
                ))}
                {chart.lines.map((points) => (
                  <polyline key={points} className="line" pathLength={1} points={points} />
                ))}
                {chart.dots.map((d) => (
                  <circle key={`${d.x},${d.y}`} className="dot" cx={d.x} cy={d.y} r={4} />
                ))}
              </svg>
              {chart.measured < 2 && <p className="small muted">Un seul jour mesuré : chaque nouveau scan ajoutera un point à la courbe.</p>}
            </>
          ) : (
            <p className="muted chart-empty">Pas encore de score sur cette période. Il apparaît après le premier scan.</p>
          )}
        </section>
        <section className="card grow-1">
          <h2>Par gravité</h2>
          <div className="bars">
            {SEVERITIES.map((s) => {
              const n = data.open_findings[s] ?? 0;
              return (
                <div key={s}>
                  <div className="bar-head">
                    <span>{severityLabel(s)}</span>
                    <span className="strong">{n}</span>
                  </div>
                  <div className="bar" aria-hidden="true">
                    <span className={`sev-${s}`} style={{ width: `${open ? Math.round((100 * n) / open) : 0}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      </div>

      <div className="row">
        <section className="card dark grow-half">
          <div className="card-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#84CAFF" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
              <path d="M12 3v3M12 18v3M3 12h3M18 12h3M6 6l2 2M16 16l2 2M6 18l2-2M16 8l2-2" />
            </svg>
            <h2>Priorités de la semaine</h2>
          </div>
          <p className="card-sub">Classées par gravité, puis par ancienneté.</p>
          {data.priorities.length > 0 ? (
            <ol className="action-list">
              {data.priorities.map((p, i) => {
                const t = priorityText(p, now);
                return (
                  <li key={`${p.kind}:${p.target_id}:${p.kind === "finding" ? p.finding_id : ""}`}>
                    <span className="num">{i + 1}</span>
                    <div>
                      <p className="action-title">{t.title}</p>
                      <p className="action-detail">{t.detail}</p>
                    </div>
                  </li>
                );
              })}
            </ol>
          ) : (
            <p className="card-sub">Rien d’urgent : aucune vulnérabilité critique ou élevée, vos domaines sont vérifiés et scannés récemment.</p>
          )}
          <Link className="dark-link" to={orgPath(org.org_id, "vulnerabilites")}>
            Voir toutes les vulnérabilités →
          </Link>
        </section>
        <section className="card grow-half">
          <h2>Conformité</h2>
          <div className="bars loose">
            {FRAMEWORKS.map((f) => (
              <div key={f}>
                <div className="bar-head">
                  <span>{f}</span>
                  <span className="soon">Bientôt disponible</span>
                </div>
                <div className="bar" aria-hidden="true" />
              </div>
            ))}
          </div>
          <p className="small muted card-note">
            Les contrôles automatisés associés à ces référentiels sont en cours de rédaction. Un scan externe ne couvre qu’une partie de chaque référentiel.
          </p>
        </section>
      </div>

      <section className="card row-single">
        <div className="card-head">
          <h2>Actifs les plus exposés</h2>
          <Link className="strong-link" to={orgPath(org.org_id, "actifs")}>
            Tous les actifs
          </Link>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Actif</th>
                <th scope="col">Type</th>
                <th scope="col">Score</th>
                <th scope="col">Ouvertes</th>
                <th scope="col">Dernier scan</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.id}>
                  <td className="name">
                    {t.domain}
                    {!t.verified && <span className="badge warn">À vérifier</span>}
                  </td>
                  <td className="muted">Domaine</td>
                  <td>{t.posture_score !== null ? <span className={`score ${scoreBand(t.posture_score)}`}>{t.posture_score}</span> : <span className="muted">—</span>}</td>
                  <td>{openCount(t.open_findings)}</td>
                  <td className={t.stale ? "stale" : undefined}>{t.last_scan_at ? dayAndTime(t.last_scan_at, now) : "Jamais"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
