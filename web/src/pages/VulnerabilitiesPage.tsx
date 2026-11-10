import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type { Finding, Me, Membership, Severity } from "../api/types";
import { AppShell } from "../components/AppShell";
import { orgPath } from "../components/nav";
import { age, moduleLabel, relativeDay, severityLabel } from "../format";
import { Link, navigate, useLocation } from "../router";
import { fallback } from "./messages";

type Filter = "all" | Exclude<Severity, "info">;

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "Toutes" },
  { id: "critical", label: "Critiques" },
  { id: "high", label: "Élevées" },
  { id: "medium", label: "Moyennes" },
  { id: "low", label: "Faibles" },
];

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** How often a running re-check is polled, and for how long at most. */
const POLL_MS = 3000;
const POLL_MAX = 100;

/**
 * Listed: open findings and accepted risks, most severe first, then newest.
 * Fixed ones leave the list (a scan decided it); info findings describe,
 * they are not vulnerabilities.
 */
function listed(all: Finding[]): Finding[] {
  return all
    .filter((f) => f.status !== "fixed" && f.severity !== "info")
    .sort((a, b) => RANK[b.severity] - RANK[a.severity] || b.first_seen.localeCompare(a.first_seen));
}

type Recheck = { findingId: string; state: "running" | "fixed" | "still-open" | "failed" };

export function VulnerabilitiesPage({ me, org }: { me: Me; org: Membership }) {
  const { search } = useLocation();
  const selectedId = search.get("id");
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [recheck, setRecheck] = useState<Recheck | null>(null);
  const alive = useRef(true);
  const isAdmin = org.role === "admin";

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const res = await api.findings(org.org_id, signal);
      setFindings(res.items);
      setError("");
      return res.items;
    } catch (err) {
      if (signal?.aborted) return null;
      if (err instanceof ApiError && err.code === "mfa_required") navigate("/mfa/setup?reason=admin", { replace: true });
      else setError(fallback(err));
      return null;
    }
  }, [org.org_id]);

  useEffect(() => {
    alive.current = true;
    const ctrl = new AbortController();
    void load(ctrl.signal);
    return () => {
      alive.current = false;
      ctrl.abort();
    };
  }, [load]);

  const visible = findings ? listed(findings) : [];
  const shown = visible.filter((f) => filter === "all" || f.severity === filter);
  const counts = (id: Filter) => (id === "all" ? visible.length : visible.filter((f) => f.severity === id).length);
  // The selection: ?id= if it is a finding of this organization (also a
  // fixed one, right after its re-check), else the first in the list.
  const selected = (findings ?? []).find((f) => f.id === selectedId) ?? shown[0] ?? null;

  const select = (f: Finding) => navigate(`${orgPath(org.org_id, "vulnerabilites")}?id=${encodeURIComponent(f.id)}`, { replace: true });

  /** Re-check: scan the finding's module again; the scan decides whether it is fixed. */
  const startRecheck = async (f: Finding) => {
    setBusy(true);
    setError("");
    // Pin the selection in the URL: once fixed, the finding leaves the
    // list, and its detail must stay on screen with the verdict.
    select(f);
    try {
      const scan = await api.startScan(org.org_id, f.target_id, [f.module_id]);
      setRecheck({ findingId: f.id, state: "running" });
      for (let i = 0; i < POLL_MAX && alive.current; i++) {
        await new Promise((r) => setTimeout(r, POLL_MS));
        const sc = await api.scan(org.org_id, scan.id);
        if (sc.status === "done" || sc.status === "failed") {
          const fresh = await load();
          const now = fresh?.find((x) => x.id === f.id);
          if (sc.status === "failed") setRecheck({ findingId: f.id, state: "failed" });
          else setRecheck({ findingId: f.id, state: now?.status === "fixed" ? "fixed" : "still-open" });
          return;
        }
      }
    } catch (err) {
      setError(fallback(err));
      setRecheck(null);
    } finally {
      setBusy(false);
    }
  };

  const setRisk = async (f: Finding, accepted: boolean) => {
    setBusy(true);
    setError("");
    try {
      await api.setFindingStatus(org.org_id, f.target_id, f.id, accepted ? "accepted_risk" : "open");
      await load();
    } catch (err) {
      setError(fallback(err));
    } finally {
      setBusy(false);
    }
  };

  const filters = (
    <div className="pills" role="group" aria-label="Gravité">
      {FILTERS.map((f) => (
        <button key={f.id} type="button" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>
          {f.label} <span className="count">{counts(f.id)}</span>
        </button>
      ))}
    </div>
  );

  const now = new Date();
  return (
    <AppShell me={me} org={org} section="vulnerabilites" title="Vulnérabilités" actions={filters}>
      {error && <p className="alert alert-error" role="alert">{error}</p>}
      {findings && visible.length === 0 && !selected && (
        <section className="card empty">
          <h2>Aucune vulnérabilité ouverte</h2>
          <p>Les derniers scans de vos domaines ne détectent aucun problème. Ils continuent de surveiller.</p>
        </section>
      )}
      {findings && (visible.length > 0 || selected) && (
        <div className="split">
          <section className="card list" aria-label="Liste des vulnérabilités">
            {shown.length === 0 && <p className="muted list-empty">Aucune vulnérabilité de cette gravité.</p>}
            {shown.map((f) => (
              <button key={f.id} type="button" className="list-item" aria-current={selected?.id === f.id ? "true" : undefined} onClick={() => select(f)}>
                <span className="list-head">
                  <StatusTag f={f} />
                  <span className="small muted">{age(f.first_seen, now)}</span>
                </span>
                <span className="list-title">{f.title}</span>
                <span className="small muted">
                  {f.asset} · {moduleLabel(f.module_id)}
                </span>
              </button>
            ))}
          </section>

          {selected && (
            <section className="card detail" aria-label="Détail">
              <div className="detail-head">
                <StatusTag f={selected} />
                <span className="small muted">
                  {moduleLabel(selected.module_id)} · détectée {relativeDay(selected.first_seen, now).toLowerCase()}
                </span>
              </div>
              <h2 className="detail-title">{selected.title}</h2>
              <p className="small muted">
                Actif concerné : <Link to={orgPath(org.org_id, "actifs")}>{selected.asset}</Link>
              </p>

              {recheck?.findingId === selected.id && (
                <p className={`alert ${recheck.state === "fixed" ? "alert-notice" : recheck.state === "running" ? "alert-warning" : "alert-error"}`} role="status">
                  {
                    {
                      running: "Vérification en cours : le module relance ses contrôles sur ce domaine…",
                      fixed: "Corrigée : le scan ne détecte plus ce problème.",
                      "still-open": "Toujours détectée par le scan. Vérifiez les étapes de correction ; un changement DNS peut prendre quelques minutes à se propager.",
                      failed: "Le scan n’a pas pu aboutir. Réessayez dans quelques minutes.",
                    }[recheck.state]
                  }
                </p>
              )}

              {isAdmin && selected.status !== "fixed" ? (
                <div className="detail-actions">
                  <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void startRecheck(selected)}>
                    J’ai corrigé, revérifier
                  </button>
                  <button type="button" className="btn btn-secondary" disabled title="Bientôt disponible">
                    Créer un ticket
                  </button>
                  <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => void setRisk(selected, selected.status !== "accepted_risk")}>
                    {selected.status === "accepted_risk" ? "Retirer l’acceptation du risque" : "Accepter le risque"}
                  </button>
                </div>
              ) : (
                !isAdmin && <p className="small muted detail-actions">Les actions (revérifier, accepter le risque) sont réservées aux administrateurs.</p>
              )}

              <div className="explain">
                <p className="explain-label">Explication</p>
                <p>{selected.description}</p>
              </div>

              {selected.remediation && selected.remediation.length > 0 && (
                <>
                  <h3>Étapes de correction</h3>
                  <ol className="remediation">
                    {selected.remediation.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ol>
                </>
              )}

              {selected.evidence && (
                <>
                  <h3>Preuve technique</h3>
                  <pre className="evidence">{selected.evidence}</pre>
                </>
              )}

              {selected.references && selected.references.length > 0 && (
                <>
                  <h3>Références</h3>
                  <ul className="references">
                    {selected.references.map((r) => (
                      <li key={r}>{/^https:\/\//.test(r) ? <a href={r} target="_blank" rel="noopener noreferrer">{r}</a> : r}</li>
                    ))}
                  </ul>
                </>
              )}
            </section>
          )}
        </div>
      )}
    </AppShell>
  );
}

function StatusTag({ f }: { f: Finding }) {
  if (f.status === "fixed") return <span className="tag ok">Corrigée</span>;
  if (f.status === "accepted_risk") return <span className="tag accepted">Risque accepté</span>;
  return <span className={`tag sev-${f.severity}`}>{severityLabel(f.severity)}</span>;
}
