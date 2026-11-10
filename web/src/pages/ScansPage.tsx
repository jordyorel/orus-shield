import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type { Me, Membership, ModuleInfo, Scan, Target } from "../api/types";
import { AppShell } from "../components/AppShell";
import { Alert } from "../components/AuthLayout";
import { formatExclusions, parseExclusions } from "../exclusions";
import { plural } from "../format";
import { navigate } from "../router";
import { fallback } from "./messages";

/** French names and descriptions of the engine's modules, by ID. */
const MODULE_TEXT: Record<string, { name: string; desc: string }> = {
  email: { name: "Sécurité des emails", desc: "SPF, DKIM, DMARC." },
  tls: { name: "Certificats et TLS", desc: "Expiration, protocoles faibles, chaînes invalides." },
  ports: { name: "Ports et services", desc: "Services exposés et configurations dangereuses. Uniquement sur les adresses dont la propriété est prouvée." },
  cdn: { name: "CDN et protection web", desc: "Détection des CDN et des pare-feux applicatifs (WAF)." },
};

/** Modules of the mockup the engine does not have yet. */
const UPCOMING = [
  { name: "Découverte de la surface d’attaque", desc: "Sous-domaines, certificats publics, plages IP associées." },
  { name: "Applications web", desc: "Injections, authentification, en-têtes, CMS obsolètes." },
  { name: "Microsoft 365", desc: "Double authentification, administrateurs, partages externes." },
  { name: "Fuites de données", desc: "Adresses et identifiants dans des fuites publiques." },
];

type Profile = "quick" | "standard";

const POLL_MS = 3000;

function profileOf(modules: string[], all: ModuleInfo[]): string {
  const passive = all.filter((m) => m.kind === "passive").map((m) => m.id);
  const ids = [...modules].sort().join(",");
  if (ids === all.map((m) => m.id).sort().join(",")) return "Standard";
  if (ids === [...passive].sort().join(",")) return "Rapide";
  return "Personnalisé";
}

function when(iso: string): string {
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getDate())}/${p(d.getMonth() + 1)}, ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function took(s: Scan): string {
  if (!s.started_at || !s.finished_at) return "—";
  const sec = (new Date(s.finished_at).getTime() - new Date(s.started_at).getTime()) / 1000;
  if (sec < 60) return `${Math.max(1, Math.round(sec))} s`;
  if (sec < 3600) return `${Math.round(sec / 60)} min`;
  return `${Math.floor(sec / 3600)} h ${String(Math.round((sec % 3600) / 60)).padStart(2, "0")}`;
}

function rateHint(r: number): string {
  if (r <= 5) return "Doux : adapté aux serveurs fragiles ou aux connexions lentes.";
  if (r <= 30) return "Équilibré : recommandé pour la plupart des PME.";
  return "Rapide : à réserver aux infrastructures robustes.";
}

export function ScansPage({ me, org }: { me: Me; org: Membership }) {
  const isAdmin = org.role === "admin";
  const [modules, setModules] = useState<ModuleInfo[] | null>(null);
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [targetId, setTargetId] = useState("");
  const [rate, setRate] = useState(5);
  const [exclusions, setExclusions] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState<{ kind: "notice" | "warning" | "error"; text: string } | null>(null);
  const [savedMsg, setSavedMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);

  const loadScans = useCallback(async () => setScans((await api.scans(org.org_id)).items), [org.org_id]);

  useEffect(() => {
    alive.current = true;
    const ctrl = new AbortController();
    Promise.all([api.modules(org.org_id, ctrl.signal), api.targets(org.org_id, ctrl.signal), api.scans(org.org_id, ctrl.signal)])
      .then(([m, t, s]) => {
        setModules(m.items);
        setSelected(new Set(m.items.map((x) => x.id)));
        setTargets(t.items);
        setScans(s.items);
        const first = t.items[0];
        if (first) {
          setTargetId(first.id);
          setRate(first.rate_per_sec);
          setExclusions(formatExclusions(first.exclusions));
        }
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        if (err instanceof ApiError && err.code === "mfa_required") navigate("/mfa/setup?reason=admin", { replace: true });
        else setError(fallback(err));
      });
    return () => {
      alive.current = false;
      ctrl.abort();
    };
  }, [org.org_id]);

  // While a scan is queued or running, the history refreshes by itself.
  const active = scans.some((s) => s.status === "queued" || s.status === "running");
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => void loadScans().catch(() => undefined), POLL_MS);
    return () => clearInterval(id);
  }, [active, loadScans]);

  const pickTarget = (id: string) => {
    const t = targets?.find((x) => x.id === id);
    if (!t) return;
    setTargetId(id);
    setRate(t.rate_per_sec);
    setExclusions(formatExclusions(t.exclusions));
    setSavedMsg("");
  };

  const pickProfile = (p: Profile) => {
    if (!modules) return;
    setSelected(new Set(modules.filter((m) => p === "standard" || m.kind === "passive").map((m) => m.id)));
  };

  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };

  const launch = async () => {
    if (!targets || selected.size === 0) return;
    setBusy(true);
    setNotice(null);
    try {
      const mods = [...selected];
      for (const t of targets) await api.startScan(org.org_id, t.id, mods);
      const activeMods = modules?.filter((m) => m.kind === "active" && selected.has(m.id)) ?? [];
      const unverified = targets.filter((t) => !t.verified).map((t) => t.domain);
      setNotice({
        kind: activeMods.length > 0 && unverified.length > 0 ? "warning" : "notice",
        text:
          `${targets.length} ${plural(targets.length, "scan lancé", "scans lancés")}.` +
          (activeMods.length > 0 && unverified.length > 0
            ? ` Les vérifications actives ne s’exécuteront pas sur ${unverified.join(", ")} : propriété non vérifiée.`
            : ""),
      });
      await loadScans();
    } catch (err) {
      setNotice({ kind: "error", text: fallback(err) });
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const save = async () => {
    const parsed = parseExclusions(exclusions);
    if (parsed.errors.length > 0) {
      setNotice({ kind: "error", text: `Exclusions illisibles : ${parsed.errors.join(", ")}. Un chemin (/admin), une adresse ou plage IP, un port ou un nom d’hôte par ligne.` });
      return;
    }
    setBusy(true);
    setNotice(null);
    try {
      const t = await api.updateTarget(org.org_id, targetId, { rate_per_sec: rate, exclusions: parsed.value });
      setTargets((ts) => ts?.map((x) => (x.id === t.id ? t : x)) ?? null);
      setSavedMsg("Configuration enregistrée");
    } catch (err) {
      setNotice({ kind: "error", text: err instanceof ApiError && err.status === 400 ? "Configuration refusée : vérifiez les exclusions et l’intensité." : fallback(err) });
    } finally {
      setBusy(false);
    }
  };

  const allIds = modules?.map((m) => m.id).sort().join(",") ?? "";
  const passiveIds = modules?.filter((m) => m.kind === "passive").map((m) => m.id).sort().join(",") ?? "";
  const current = [...selected].sort().join(",");
  const target = targets?.find((t) => t.id === targetId);

  const actions = isAdmin && (
    <>
      {savedMsg && <span className="saved" role="status">{savedMsg}</span>}
      <button type="button" className="btn btn-secondary" disabled={busy || !targets?.length || selected.size === 0} onClick={() => void launch()}>
        Lancer maintenant
      </button>
      <button type="button" className="btn btn-primary" disabled={busy || !target} onClick={() => void save()}>
        Enregistrer
      </button>
    </>
  );

  return (
    <AppShell me={me} org={org} section="scans" title="Configuration des scans" actions={actions || undefined}>
      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind={notice.kind}>{notice.text}</Alert>}
      {!isAdmin && <p className="small muted">Le lancement des scans et leur configuration sont réservés aux administrateurs.</p>}
      {modules && targets && (
        <>
          <section>
            <h2>Profil de scan</h2>
            <div className="profiles">
              <button type="button" className="profile" aria-pressed={current === passiveIds} disabled={!isAdmin} onClick={() => pickProfile("quick")}>
                <span className="profile-name">Rapide</span>
                <span className="profile-desc">Vérifications passives uniquement : données publiques, sans sonde.</span>
                <span className="profile-time">
                  {modules.filter((m) => m.kind === "passive").length} modules
                </span>
              </button>
              <button type="button" className="profile" aria-pressed={current === allIds} disabled={!isAdmin} onClick={() => pickProfile("standard")}>
                <span className="profile-name">Standard</span>
                <span className="profile-desc">Tous les modules, dont les ports exposés, sans test intrusif.</span>
                <span className="profile-time">{modules.length} modules</span>
              </button>
              <button type="button" className="profile" aria-pressed={false} disabled>
                <span className="profile-name">Approfondi</span>
                <span className="profile-desc">Tous les ports, tests applicatifs étendus.</span>
                <span className="profile-time soon">Bientôt disponible</span>
              </button>
            </div>
          </section>

          <div className="row">
            <section className="card grow-2">
              <h2>Modules</h2>
              <p className="card-sub">
                {selected.size} {plural(selected.size, "module actif", "modules actifs")}
              </p>
              <div className="modules">
                {modules.map((m) => {
                  const text = MODULE_TEXT[m.id] ?? { name: m.name || m.id, desc: "" };
                  const on = selected.has(m.id);
                  return (
                    <div className="module" key={m.id}>
                      <div>
                        <p className="module-name">
                          {text.name} {m.kind === "active" && <span className="tag warn">Actif</span>}
                        </p>
                        <p className="small muted">{text.desc}</p>
                      </div>
                      <button type="button" className="switch" aria-pressed={on} aria-label={(on ? "Désactiver " : "Activer ") + text.name} disabled={!isAdmin} onClick={() => toggle(m.id)}>
                        <span />
                      </button>
                    </div>
                  );
                })}
                {UPCOMING.map((m) => (
                  <div className="module upcoming" key={m.name}>
                    <div>
                      <p className="module-name">
                        {m.name} <span className="tag accepted">Bientôt</span>
                      </p>
                      <p className="small muted">{m.desc}</p>
                    </div>
                    <button type="button" className="switch" aria-pressed={false} aria-label={`${m.name} : bientôt disponible`} disabled>
                      <span />
                    </button>
                  </div>
                ))}
              </div>
            </section>

            <div className="column grow-1">
              <section className="card">
                <h2>Planification</h2>
                <div className="stack plan">
                  <div className="field">
                    <label htmlFor="freq">Fréquence</label>
                    <select id="freq" disabled>
                      <option>Manuelle (bientôt automatique)</option>
                    </select>
                  </div>
                  <p className="small muted">
                    La planification automatique arrive bientôt : pour l’instant, lancez les scans avec « Lancer maintenant ». Fuseau horaire :{" "}
                    {Intl.DateTimeFormat().resolvedOptions().timeZone}.
                  </p>
                </div>
              </section>

              <section className="card">
                <h2>Intensité</h2>
                {targets.length === 0 ? (
                  <p className="small muted card-note">Ajoutez un domaine dans Actifs pour régler son intensité et ses exclusions.</p>
                ) : (
                  <div className="stack plan">
                    {targets.length > 1 && (
                      <div className="field">
                        <label htmlFor="target">Domaine</label>
                        <select id="target" value={targetId} onChange={(e) => pickTarget(e.target.value)}>
                          {targets.map((t) => (
                            <option key={t.id} value={t.id}>
                              {t.domain}
                            </option>
                          ))}
                        </select>
                      </div>
                    )}
                    <div className="field">
                      <div className="bar-head">
                        <label htmlFor="rate">Requêtes par seconde{targets.length === 1 ? ` (${targets[0]?.domain})` : ""}</label>
                        <span className="strong">{rate}</span>
                      </div>
                      <input
                        id="rate"
                        type="range"
                        min={1}
                        max={100}
                        step={1}
                        value={rate}
                        disabled={!isAdmin}
                        onChange={(e) => {
                          setRate(Number(e.target.value));
                          setSavedMsg("");
                        }}
                      />
                      <p className="hint">{rateHint(rate)}</p>
                    </div>
                    <div className="field">
                      <label htmlFor="excl">Exclusions</label>
                      <textarea
                        id="excl"
                        rows={3}
                        value={exclusions}
                        disabled={!isAdmin}
                        spellCheck={false}
                        onChange={(e) => {
                          setExclusions(e.target.value);
                          setSavedMsg("");
                        }}
                      />
                      <p className="hint">Chemins, adresses ou ports à ne jamais tester. Un par ligne : /admin, 192.0.2.10, 10.0.0.0/8, 3389, intranet.exemple.com.</p>
                    </div>
                  </div>
                )}
              </section>
            </div>
          </div>

          <section className="card row-single">
            <h2>Historique</h2>
            {scans.length === 0 ? (
              <p className="small muted card-note">Aucun scan pour l’instant.</p>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Date</th>
                      <th scope="col">Profil</th>
                      <th scope="col">Actif</th>
                      <th scope="col">Durée</th>
                      <th scope="col">Nouvelles</th>
                      <th scope="col">Statut</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map((s) => (
                      <tr key={s.id}>
                        <td>{when(s.created_at)}</td>
                        <td>{profileOf(s.modules, modules)}</td>
                        <td className="name">{s.domain}</td>
                        <td>{took(s)}</td>
                        <td>{s.new_findings ?? "—"}</td>
                        <td>
                          {s.status === "done" && <span className="muted">Terminé</span>}
                          {s.status === "failed" && <span className="stale">Échec</span>}
                          {(s.status === "queued" || s.status === "running") && (
                            <span className="progress">
                              <span className="progress-bar" aria-hidden="true">
                                <span />
                              </span>
                              {s.status === "queued" ? "En attente" : "En cours"}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </AppShell>
  );
}
