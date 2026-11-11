import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type { Frequency, Me, Membership, ModuleInfo, Scan, Target } from "../api/types";
import { AppShell } from "../components/AppShell";
import { Alert } from "../components/AuthLayout";
import { formatExclusions, parseExclusions } from "../exclusions";
import { plural } from "../format";
import { navigate } from "../router";
import { fallback } from "./messages";

// The Scans screen of docs/design/Scans.dc.html. Every control of the mockup
// is here and clickable; what the engine cannot do yet is marked
// "Bientôt", never pretended.

type ProfileId = "quick" | "standard" | "deep";

interface ProfileDef {
  id: ProfileId;
  name: string;
  desc: string;
  /** Module IDs the profile selects, from the engine's catalog. */
  modules: (all: ModuleInfo[]) => string[];
}

const PROFILES: ProfileDef[] = [
  { id: "quick", name: "Rapide", desc: "Vérifications passives uniquement, sans sonde.", modules: (all) => all.filter((m) => m.kind === "passive").map((m) => m.id) },
  { id: "standard", name: "Standard", desc: "Tous les modules actifs, sans test intrusif.", modules: (all) => all.map((m) => m.id) },
  { id: "deep", name: "Approfondi", desc: "Tous les ports, tests applicatifs étendus.", modules: (all) => all.map((m) => m.id) },
];

/**
 * The mockup's modules, in its order, mapped to the engine's module IDs.
 * engine is null for a module the engine does not have yet.
 */
const MODULES: { engine: string | null; name: string; desc: string; tag?: "Intrusif" | "Nouveau" }[] = [
  { engine: "discovery", name: "Découverte de la surface d’attaque", desc: "Sous-domaines, certificats publics, plages IP associées." },
  { engine: "ports", name: "Ports et services", desc: "Services exposés, versions et configurations dangereuses." },
  { engine: "web", name: "Applications web", desc: "Injections, authentification, en-têtes, CMS obsolètes." },
  { engine: "email", name: "Sécurité des emails", desc: "SPF, DKIM, DMARC, serveurs de messagerie." },
  { engine: "tls", name: "Certificats et TLS", desc: "Expiration, protocoles faibles, chaînes invalides." },
  { engine: "cdn", name: "CDN et protection web", desc: "Détection des CDN et des pare-feux applicatifs (WAF)." },
  { engine: null, name: "Microsoft 365", desc: "Double authentification, administrateurs, partages externes." },
  { engine: null, name: "Fuites de données", desc: "Adresses et identifiants dans des fuites publiques." },
  { engine: null, name: "Validation par agents IA", desc: "Tente d’exploiter les failles de façon contrôlée pour éliminer les faux positifs.", tag: "Intrusif" },
  { engine: null, name: "Audit de l’usage de l’IA", desc: "Clés d’API exposées, chatbots vulnérables à l’injection de prompt.", tag: "Nouveau" },
];

/** The mockup's frequencies. "Continue" needs change detection: not yet. */
const FREQUENCIES: { id: Frequency | "continuous"; label: string; soon?: boolean }[] = [
  { id: "daily", label: "Quotidienne" },
  { id: "weekly", label: "Hebdomadaire" },
  { id: "monthly", label: "Mensuelle" },
  { id: "continuous", label: "Continue (surveillance) : bientôt", soon: true },
];
/** In the mockup's order; value is the weekday number of the API (0 = Sunday). */
const DAYS: { label: string; value: number }[] = [
  { label: "Lundi", value: 1 },
  { label: "Mardi", value: 2 },
  { label: "Mercredi", value: 3 },
  { label: "Jeudi", value: 4 },
  { label: "Vendredi", value: 5 },
  { label: "Samedi", value: 6 },
  { label: "Dimanche", value: 0 },
];
const HOURS = Array.from({ length: 24 }, (_, h) => h);
const hourLabel = (h: number) => `${String(h).padStart(2, "0")}:00`;
const dayLabel = (wd: number) => DAYS.find((d) => d.value === wd)?.label ?? "";

/** The browser's time zone: schedules are wall-clock times there. */
function browserTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
}

/** "dimanche 15/11 à 02:00", in the viewer's time zone. */
function nextRunText(iso: string): string {
  const d = new Date(iso);
  const weekday = d.toLocaleDateString("fr-FR", { weekday: "long" });
  const p = (n: number) => String(n).padStart(2, "0");
  return `${weekday} ${p(d.getDate())}/${p(d.getMonth() + 1)} à ${p(d.getHours())}:${p(d.getMinutes())}`;
}

const POLL_MS = 3000;
const ADMIN_ONLY = "Réservé aux administrateurs";

/** A launch: the scans "Lancer maintenant" queued together, one per domain. */
interface Run {
  key: string;
  createdAt: string;
  modules: string[];
  scans: Scan[];
}

/** groupRuns puts together the scans one person requested within a minute with the same modules. */
export function groupRuns(scans: Scan[]): Run[] {
  const runs: Run[] = [];
  for (const s of scans) {
    const mods = [...s.modules].sort();
    const last = runs[runs.length - 1];
    const close = last && Math.abs(new Date(last.createdAt).getTime() - new Date(s.created_at).getTime()) < 60_000;
    if (last && close && last.scans[0]?.requested_by === s.requested_by && last.modules.join() === mods.join()) {
      last.scans.push(s);
      if (s.created_at < last.createdAt) last.createdAt = s.created_at;
    } else {
      runs.push({ key: s.id, createdAt: s.created_at, modules: mods, scans: [s] });
    }
  }
  return runs;
}

function profileName(modules: string[], all: ModuleInfo[]): string {
  const ids = [...modules].sort().join();
  if (ids === PROFILES[1]!.modules(all).sort().join()) return "Standard";
  if (ids === PROFILES[0]!.modules(all).sort().join()) return "Rapide";
  return "Personnalisé";
}

/** runSeconds: from the first start to the last end, once every scan ended. */
function runSeconds(r: Run): number | null {
  if (r.scans.some((s) => !s.started_at || !s.finished_at)) return null;
  const start = Math.min(...r.scans.map((s) => new Date(s.started_at!).getTime()));
  const end = Math.max(...r.scans.map((s) => new Date(s.finished_at!).getTime()));
  return (end - start) / 1000;
}

function durationText(sec: number): string {
  if (sec < 60) return `${Math.max(1, Math.round(sec))} s`;
  if (sec < 3600) return `${Math.round(sec / 60)} min`;
  return `${Math.floor(sec / 3600)} h ${String(Math.round((sec % 3600) / 60)).padStart(2, "0")}`;
}

function when(iso: string): string {
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getDate())}/${p(d.getMonth() + 1)}, ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function rateHint(r: number): string {
  if (r <= 30) return "Doux : adapté aux serveurs fragiles ou aux connexions lentes.";
  if (r <= 100) return "Équilibré : recommandé pour la plupart des PME.";
  return "Rapide : à réserver aux infrastructures robustes.";
}

function timeZoneLabel(): string {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const minutes = -new Date().getTimezoneOffset();
  const sign = minutes >= 0 ? "+" : "−";
  const h = Math.floor(Math.abs(minutes) / 60);
  const m = Math.abs(minutes) % 60;
  return `${tz} (UTC${sign}${h}${m ? ":" + String(m).padStart(2, "0") : ""})`;
}

export function ScansPage({ me, org }: { me: Me; org: Membership }) {
  const isAdmin = org.role === "admin";
  const [catalog, setCatalog] = useState<ModuleInfo[] | null>(null);
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [profile, setProfile] = useState<ProfileId>("standard");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [frequency, setFrequency] = useState<Frequency>("weekly");
  const [day, setDay] = useState(0);
  const [hour, setHour] = useState(2);
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
        setCatalog(m.items);
        setSelected(new Set(m.items.map((x) => x.id)));
        setTargets(t.items);
        setScans(s.items);
        // One configuration for every domain, as in the mockup: shown from
        // the first domain, applied to all on save.
        const first = t.items[0];
        if (first) {
          setRate(Math.min(200, Math.max(5, Math.round(first.rate_per_sec / 5) * 5)));
          setExclusions(formatExclusions(first.exclusions));
        }
        // The schedule shown is the first saved one; its modules become
        // the selection, so saving again keeps them.
        const planned = t.items.find((x) => x.schedule)?.schedule;
        if (planned) {
          setFrequency(planned.frequency);
          setDay(planned.weekday);
          setHour(planned.hour);
          setSelected(new Set(planned.modules.filter((id) => m.items.some((x) => x.id === id))));
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

  const changed = () => setSavedMsg("");

  const pickProfile = (p: ProfileDef) => {
    setProfile(p.id);
    if (catalog) setSelected(new Set(p.modules(catalog)));
    changed();
  };

  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
    changed();
  };

  const launch = async () => {
    if (!targets || targets.length === 0 || selected.size === 0) return;
    setBusy(true);
    setNotice(null);
    try {
      const mods = [...selected];
      for (const t of targets) await api.startScan(org.org_id, t.id, mods);
      const activeMods = catalog?.some((m) => m.kind === "active" && selected.has(m.id)) ?? false;
      const unverified = targets.filter((t) => !t.verified).map((t) => t.domain);
      setNotice({
        kind: activeMods && unverified.length > 0 ? "warning" : "notice",
        text:
          `${targets.length} ${plural(targets.length, "scan lancé", "scans lancés")}.` +
          (activeMods && unverified.length > 0 ? ` Les vérifications actives ne s’exécuteront pas sur ${unverified.join(", ")} : propriété non vérifiée.` : ""),
      });
      await loadScans();
    } catch (err) {
      setNotice({ kind: "error", text: fallback(err) });
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const save = async () => {
    if (!targets || targets.length === 0) {
      setNotice({ kind: "warning", text: "Ajoutez d’abord un domaine dans Actifs : l’intensité et les exclusions s’appliquent à vos domaines." });
      return;
    }
    if (selected.size === 0) {
      setNotice({ kind: "warning", text: "Activez au moins un module : ce sont eux que les scans planifiés lanceront." });
      return;
    }
    const parsed = parseExclusions(exclusions);
    if (parsed.errors.length > 0) {
      setNotice({ kind: "error", text: `Exclusions illisibles : ${parsed.errors.join(", ")}. Un chemin (/admin), une adresse ou plage IP, un port ou un nom d’hôte par ligne.` });
      return;
    }
    setBusy(true);
    setNotice(null);
    try {
      const updated: Target[] = [];
      const schedule = { frequency, weekday: day, hour, timezone: browserTimeZone(), modules: [...selected].sort() };
      for (const t of targets) updated.push(await api.updateTarget(org.org_id, t.id, { rate_per_sec: rate, exclusions: parsed.value, schedule }));
      setTargets(updated);
      setSavedMsg("Configuration enregistrée");
    } catch (err) {
      setNotice({ kind: "error", text: err instanceof ApiError && err.status === 400 ? "Configuration refusée : vérifiez les exclusions, l’intensité et la planification." : fallback(err) });
    } finally {
      setBusy(false);
    }
  };

  const runs = catalog ? groupRuns(scans) : [];
  /** The earliest scheduled run among the domains. */
  const nextRun =
    targets
      ?.map((t) => t.schedule?.next_scan_at)
      .filter((x): x is string => !!x)
      .sort()[0] ?? null;
  /** Average duration of the past launches with this profile's modules. */
  const typical = (p: ProfileDef): string => {
    if (!catalog) return "";
    const ids = p.modules(catalog).sort().join();
    const secs = runs.filter((r) => r.modules.join() === ids).map(runSeconds).filter((x): x is number => x !== null);
    if (p.id === "deep") return "Tous les ports : bientôt";
    if (secs.length === 0) return "Durée connue après un premier scan";
    return `Environ ${durationText(secs.reduce((a, b) => a + b, 0) / secs.length)}`;
  };
  const distinctSettings =
    targets && targets.length > 1 && new Set(targets.map((t) => `${t.rate_per_sec}|${JSON.stringify(t.exclusions)}`)).size > 1;

  const actions = (
    <>
      {savedMsg && (
        <span className="saved" role="status">
          {savedMsg}
        </span>
      )}
      <button
        type="button"
        className="btn btn-secondary"
        disabled={!isAdmin || busy || !targets?.length || selected.size === 0}
        title={isAdmin ? undefined : ADMIN_ONLY}
        onClick={() => void launch()}
      >
        Lancer maintenant
      </button>
      <button type="button" className="btn btn-primary" disabled={!isAdmin || busy} title={isAdmin ? undefined : ADMIN_ONLY} onClick={() => void save()}>
        Enregistrer
      </button>
    </>
  );

  return (
    <AppShell me={me} org={org} section="scans" title="Configuration des scans" actions={actions}>
      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind={notice.kind}>{notice.text}</Alert>}
      {catalog && targets && (
        <>
          <section className="profiles-section">
            <h2>Profil de scan</h2>
            <div className="profiles">
              {PROFILES.map((p) => (
                <button key={p.id} type="button" className="profile" aria-pressed={profile === p.id} onClick={() => pickProfile(p)}>
                  <span className="profile-name">{p.name}</span>
                  <span className="profile-desc">{p.desc}</span>
                  <span className="profile-time">{typical(p)}</span>
                </button>
              ))}
            </div>
            {profile === "deep" && (
              <p className="small muted profile-note">
                Pour l’instant, Approfondi lance les mêmes modules que Standard : le scan de tous les ports et les tests applicatifs étendus arrivent bientôt.
              </p>
            )}
          </section>

          <div className="row">
            <section className="card grow-2">
              <h2>Modules</h2>
              <p className="card-sub">
                {selected.size} {plural(selected.size, "module actif", "modules actifs")}
              </p>
              <div className="modules">
                {MODULES.map((m) => {
                  const known = m.engine !== null && catalog.some((c) => c.id === m.engine);
                  const on = known && selected.has(m.engine!);
                  return (
                    <div className={known ? "module" : "module upcoming"} key={m.name}>
                      <div>
                        <p className="module-name">
                          {m.name} {m.tag && <span className={m.tag === "Intrusif" ? "tag warn" : "tag new"}>{m.tag}</span>}{" "}
                          {!known && <span className="tag accepted">Bientôt</span>}
                        </p>
                        <p className="small muted">{m.desc}</p>
                      </div>
                      <button
                        type="button"
                        className="switch"
                        aria-pressed={on}
                        aria-label={known ? (on ? "Désactiver " : "Activer ") + m.name : `${m.name} : bientôt disponible`}
                        disabled={!known}
                        onClick={() => known && toggle(m.engine!)}
                      >
                        <span />
                      </button>
                    </div>
                  );
                })}
              </div>
            </section>

            <div className="column grow-1">
              <section className="card">
                <h2>Planification</h2>
                <div className="stack plan">
                  <div className="field">
                    <label htmlFor="freq">Fréquence</label>
                    <select id="freq" value={frequency} onChange={(e) => (setFrequency(e.target.value as Frequency), changed())}>
                      {FREQUENCIES.map((f) => (
                        <option key={f.id} value={f.id} disabled={f.soon}>
                          {f.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="two-cols">
                    <div className="field">
                      <label htmlFor="day">Jour</label>
                      <select id="day" value={day} disabled={frequency === "daily"} onChange={(e) => (setDay(Number(e.target.value)), changed())}>
                        {DAYS.map((d) => (
                          <option key={d.value} value={d.value}>
                            {d.label}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="field">
                      <label htmlFor="hour">Heure</label>
                      <select id="hour" value={hour} onChange={(e) => (setHour(Number(e.target.value)), changed())}>
                        {HOURS.map((h) => (
                          <option key={h} value={h}>
                            {hourLabel(h)}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                  <p className="small muted">
                    {frequency === "monthly" && `Le premier ${dayLabel(day).toLowerCase()} de chaque mois. `}
                    Fuseau horaire : {timeZoneLabel()}
                  </p>
                  <p className="small muted" role="status">
                    {nextRun ? `Prochain scan planifié : ${nextRunText(nextRun)}.` : "Aucun scan planifié : enregistrez la configuration pour activer la planification."}
                  </p>
                </div>
              </section>

              <section className="card">
                <h2>Intensité</h2>
                <div className="stack plan">
                  <div className="field">
                    <div className="bar-head">
                      <label htmlFor="rate">Requêtes par seconde, par actif</label>
                      <span className="strong">{rate}</span>
                    </div>
                    <input id="rate" type="range" min={5} max={200} step={5} value={rate} onChange={(e) => (setRate(Number(e.target.value)), changed())} />
                    <p className="hint">{rateHint(rate)}</p>
                  </div>
                  <div className="field">
                    <label htmlFor="excl">Exclusions</label>
                    <textarea id="excl" rows={3} value={exclusions} spellCheck={false} onChange={(e) => (setExclusions(e.target.value), changed())} />
                    <p className="hint">Chemins, adresses ou ports à ne jamais tester.</p>
                  </div>
                  {distinctSettings && <p className="small soon">Vos domaines ont des réglages différents : « Enregistrer » applique ceux-ci à tous.</p>}
                </div>
              </section>
            </div>
          </div>

          <section className="card row-single">
            <h2>Historique</h2>
            {runs.length === 0 ? (
              <p className="small muted card-note">Aucun scan pour l’instant.</p>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Date</th>
                      <th scope="col">Profil</th>
                      <th scope="col">Actifs</th>
                      <th scope="col">Durée</th>
                      <th scope="col">Nouvelles</th>
                      <th scope="col">Statut</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((r) => {
                      const ended = r.scans.filter((s) => s.status === "done" || s.status === "failed").length;
                      const running = ended < r.scans.length;
                      const failed = r.scans.filter((s) => s.status === "failed").length;
                      const secs = runSeconds(r);
                      const pct = Math.round((100 * ended) / r.scans.length);
                      return (
                        <tr key={r.key}>
                          <td>{when(r.createdAt)}</td>
                          <td>{profileName(r.modules, catalog)}</td>
                          <td title={r.scans.map((s) => s.domain).join(", ")}>{r.scans.length}</td>
                          <td>{secs === null ? "—" : durationText(secs)}</td>
                          <td>{running ? "—" : r.scans.reduce((n, s) => n + (s.new_findings ?? 0), 0)}</td>
                          <td>
                            {running ? (
                              <span className="progress">
                                <span className="progress-bar" aria-hidden="true">
                                  <span style={{ width: `${Math.max(pct, 4)}%` }} />
                                </span>
                                En cours · {pct} %
                              </span>
                            ) : failed === r.scans.length ? (
                              <span className="stale">Échec</span>
                            ) : (
                              <span className="muted">
                                Terminé{failed > 0 ? ` · ${failed} ${plural(failed, "échec", "échecs")}` : ""}
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
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
