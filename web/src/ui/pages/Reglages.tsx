import { useEffect, useRef, useState, type CSSProperties } from "react";
import { api, ApiError } from "../../api/client";
import type { Member, OrgSettings, Plan, Role, Target } from "../../api/types";
import { formatExclusions, parseExclusions } from "../../exclusions";
import { Link } from "../../router";
import { MODS, ModIcon, Soon } from "../icons";
import { DAYS, byPriority, sinceText } from "../model";
import { useOrg } from "../OrgData";
import { useUI } from "../ui";

/** The mockup's day buttons start on Monday; the API's weekday 0 is Sunday. */
const toApiDay = (i: number) => (i + 1) % 7;
const fromApiDay = (d: number) => (d + 6) % 7;
const FREQ: Record<string, string> = { jour: "daily", semaine: "weekly", mois: "monthly" };

function schedText(s: OrgSettings): string {
  if (!s.frequency) return "Aucun scan automatique pour l’instant : choisissez quand scanner.";
  const h = String(s.hour).padStart(2, "0") + ":00";
  const day = DAYS[fromApiDay(s.weekday)];
  return s.frequency === "daily"
    ? `Scan automatique chaque jour à ${h}`
    : s.frequency === "weekly"
      ? `Scan automatique chaque ${day} à ${h}`
      : `Scan automatique le premier ${day} du mois à ${h}`;
}

function rateHint(r: number): string {
  return r <= 30 ? "Doux : pour les serveurs fragiles ou les connexions lentes." : r <= 100 ? "Équilibré : convient à la plupart des entreprises." : "Rapide : à réserver aux serveurs solides.";
}

/** The worker's rate when a target has none (ORUS default). */
const DEFAULT_RATE = 5;

/** LIMITS: the mockup's comparison table, filled with the real offers. */
export function limitRows(plans: Plan[]): [string, ...string[]][] {
  const pick = ["discovery", "sme", "pro"].map((id) => plans.find((p) => p.id === id));
  const col = (f: (p: Plan) => string) => pick.map((p) => (p ? f(p) : ""));
  const freq = { monthly: "Mensuelle", weekly: "Hebdomadaire", daily: "Quotidienne" };
  const n = (v: number, unit: string) => (v === 0 ? "Illimité" : `${v.toLocaleString("fr-FR")} ${unit}`.trim());
  return [
    ["Domaines", ...col((p) => n(p.domains, ""))],
    ["Actifs surveillés", ...col((p) => n(p.hosts_per_scan, "par domaine"))],
    ["Membres de l’équipe", ...col((p) => n(p.members, ""))],
    ["Fréquence des scans", ...col((p) => freq[p.max_frequency])],
    ["Ports vérifiés", ...col((p) => (p.active_modules ? "50 ports courants" : "Aucun"))],
    ["Vulnérabilités connues", ...col((p) => (p.active_modules ? "Oui" : "Non"))],
    ["Fuites de données", "Bientôt", "Bientôt", "Bientôt"],
    ["Menaces émergentes", ...col((p) => (p.threats ? "Oui" : "Non"))],
    ["Alertes email", ...col((p) => (p.alerts ? "Oui" : "Non"))],
    ["Rapports PDF", ...col((p) => (p.reports ? "Direction et Technique" : "Non"))],
    ["Profil approfondi", "Bientôt", "Bientôt", "Bientôt"],
  ];
}

function Switch({ on, label, disabled, onClick }: { on: boolean; label: string; disabled?: boolean; onClick?: () => void }) {
  return (
    <button className="switch" type="button" role="switch" aria-checked={on} aria-label={label} aria-disabled={disabled || undefined} onClick={disabled ? undefined : onClick} />
  );
}

export function ReglagesPage() {
  const { data, org, isAdmin, setSettings, issues } = useOrg();
  const { toast, theme, setTheme } = useUI();
  const [preview, setPreview] = useState<{ name: string; msg: string; typing: boolean } | null>(null);
  const saveTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const [draft, setDraft] = useState<OrgSettings | null>(data?.settings ?? null);

  useEffect(() => {
    if (data) setDraft((d) => d ?? data.settings);
  }, [data]);

  if (!data || !draft) return null;
  const s = draft;
  const plan = data.subscription.plan;

  /** save stores the settings (after delay ms, for the sliders). */
  const save = (next: OrgSettings, delay = 0) => {
    if (!isAdmin) {
      toast("Réservé aux administrateurs");
      return;
    }
    const prev = s;
    setDraft(next);
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
      api
        .saveSettings(org.org_id, { ...next, timezone: next.frequency ? tz : next.timezone })
        .then(setSettings)
        .catch((e: unknown) => {
          setDraft(prev);
          toast(
            e instanceof ApiError && e.code === "plan_limit"
              ? "Cette fréquence n’est pas incluse dans votre offre. Changez d’offre plus bas."
              : "Réglage non enregistré, réessayez",
          );
        });
    }, delay);
  };

  const modOn = (m: (typeof MODS)[number]) => m.module !== null && !s.disabled_modules.includes(m.module) && (plan.active_modules || !["ports", "vulns"].includes(m.module));
  const active = MODS.filter(modOn).length;
  const toggleMod = (module: string) => {
    const off = s.disabled_modules.includes(module);
    save({ ...s, disabled_modules: off ? s.disabled_modules.filter((x) => x !== module) : [...s.disabled_modules, module] });
  };
  const modStatus = (module: string | null): string => {
    if (module === null) return "";
    if (!plan.active_modules && (module === "ports" || module === "vulns")) return `Non inclus dans l’offre ${plan.name}`;
    const cs = data.checks.filter((c) => c.module === module);
    if (!cs.length) return "Pas encore vérifié";
    const ids = new Set(cs.map((c) => c.id));
    const last = cs.reduce((a, c) => (c.evaluated_at > a ? c.evaluated_at : a), "");
    return `${ids.size} contrôle${ids.size > 1 ? "s" : ""}, vérifiés ${sinceText(last, new Date())}`;
  };

  const prof: [OrgSettings["profile"] | "deep", string, number, string, string][] = [
    ["quick", "Rapide", 1, "5 minutes", "Contrôles passifs et ports principaux"],
    ["standard", "Standard", 2, "40 minutes", "Tous les contrôles, 50 ports courants"],
    ["deep", "Approfondi", 3, "2 à 3 heures", "1 000 ports, versions et tests étendus"],
  ];
  const freqKey = s.frequency === "daily" ? "jour" : s.frequency === "monthly" ? "mois" : s.frequency === "weekly" ? "semaine" : "";
  const day = fromApiDay(s.weekday);
  const rate = s.rate_per_sec || DEFAULT_RATE;

  const top = issues.filter((i) => !i.fixed).sort(byPriority)[0];
  const showPreview = () => {
    const msg = top
      ? `Objet : nouveau problème sur ${top.domain}. Le dernier scan a trouvé : ${top.title} (${top.host}). Voici comment le corriger, environ ${top.mins} minutes.`
      : "Objet : rien de nouveau. Le dernier scan n’a trouvé aucun nouveau problème.";
    setPreview({ name: "Email", msg, typing: true });
    setTimeout(() => setPreview({ name: "Email", msg, typing: false }), 900);
  };

  const planCol = { discovery: 1, sme: 2, pro: 3, enterprise: 3 }[plan.id];
  const sub = data.subscription;
  const until = sub.until ? new Date(sub.until).toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric" }) : "";
  const price = plan.on_quote ? "sur devis" : plan.usd_monthly ? `à ${plan.usd_monthly} $ par mois` : "gratuite";
  const subLine =
    sub.status === "trialing" && until
      ? ` ${price}. Essai gratuit jusqu’au ${until}.`
      : sub.in_grace && until
        ? ` ${price}. Paiement attendu avant le ${until}.`
        : until
          ? ` ${price}. Prochaine échéance le ${until}.`
          : ` ${price}.`;
  const monthStart = new Date();
  monthStart.setDate(1);
  monthStart.setHours(0, 0, 0, 0);
  const scansThisMonth = data.scans.filter((x) => new Date(x.created_at) >= monthStart).length;
  const assetsCap = plan.hosts_per_scan * Math.max(1, data.targets.length);
  const hostCount = data.assets.filter((a) => a.kind === "hostname" && !a.gone_at).length;
  const prog: [string, number, number][] = [
    ["Domaines", sub.usage.domains, plan.domains],
    ["Actifs surveillés", hostCount, assetsCap],
    ["Scans ce mois-ci", scansThisMonth, 0],
  ];

  return (
    <>
      <div className="rtop">
        <h1 className="hello" style={{ margin: 0, fontFamily: "inherit", fontWeight: 400, letterSpacing: 0 }}>
          Réglages
        </h1>
      </div>
      <div className="cover">
        <div className="covernum">
          <b id="cov-n">{active}</b>
          <span>vérifications actives sur {MODS.length}</span>
        </div>
        <div className="covertrack">
          {MODS.map((m) => (
            <i key={m.key} data-cov={m.key} className={modOn(m) ? "on" : ""} />
          ))}
        </div>
        <p id="next-scan">{schedText(s)}</p>
      </div>

      <div className="section">
        <h2>Ce qu’on vérifie</h2>
        <div className="mods">
          {MODS.map((m) => {
            const on = modOn(m);
            const soon = m.module === null;
            const locked = !soon && !plan.active_modules && (m.module === "ports" || m.module === "vulns");
            return (
              <div key={m.key} className={"mod" + (on ? "" : " off") + (soon ? " is-soon" : "")}>
                <ModIcon>{m.icon}</ModIcon>
                <div>
                  <p className="mt">
                    {m.title}
                    {soon && <Soon />}
                  </p>
                  <p className="md">{m.desc}</p>
                  <p className="ms">
                    <i />
                    <span>{modStatus(m.module)}</span>
                  </p>
                </div>
                <Switch on={on} label={m.title} disabled={soon || locked} onClick={() => m.module && toggleMod(m.module)} />
              </div>
            );
          })}
        </div>
      </div>

      <div className="section">
        <h2>Profondeur du scan</h2>
        <div className="profs" role="group" aria-label="Profil de scan">
          {prof.map(([k, l, lvl, dur, d]) => (
            <button
              key={k}
              type="button"
              className={"prof" + (k === "deep" ? " is-soon" : "")}
              aria-pressed={s.profile === k}
              aria-disabled={k === "deep" || undefined}
              onClick={() => (k === "deep" ? toast("Profil approfondi : bientôt disponible") : save({ ...s, profile: k }))}
            >
              <span className="bars" aria-hidden="true">
                {[1, 2, 3].map((x) => (
                  <i key={x} className={x <= lvl ? "on" : ""} style={{ height: 6 + x * 6 + "px" }} />
                ))}
              </span>
              <span className="pt2">
                {l}
                {k === "deep" && <Soon />}
              </span>
              <span className="pd">{d}</span>
              <span className="pdur">{dur}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="section">
        <h2>Quand scanner</h2>
        <div className="rpanel" style={{ marginTop: 12 }}>
          <div className="seg2" role="group" aria-label="Fréquence">
            {(
              [
                ["jour", "Chaque jour"],
                ["semaine", "Chaque semaine"],
                ["mois", "Chaque mois"],
              ] as const
            ).map(([k, l]) => (
              <button key={k} type="button" aria-pressed={freqKey === k} onClick={() => save({ ...s, frequency: FREQ[k] as OrgSettings["frequency"] })}>
                {l}
              </button>
            ))}
          </div>
          <div className={"days" + (s.frequency === "daily" ? " mute" : "")} role="group" aria-label="Jour">
            {["L", "M", "M", "J", "V", "S", "D"].map((d, i) => (
              <button key={i} type="button" aria-pressed={day === i} aria-label={DAYS[i]} onClick={() => save({ ...s, weekday: toApiDay(i), frequency: s.frequency || "weekly" })}>
                {d}
              </button>
            ))}
          </div>
          <div className="slide">
            <label htmlFor="hour">Heure de départ</label>
            <output id="hour-out" htmlFor="hour">
              {String(s.hour).padStart(2, "0")}:00
            </output>
            <input id="hour" type="range" min="0" max="23" step="1" value={s.hour} onChange={(e) => save({ ...s, hour: Number(e.target.value), frequency: s.frequency || "weekly" }, 600)} />
            <div className="clock" aria-hidden="true">
              {Array.from({ length: 24 }, (_, h) => (
                <i key={h} className={(h === s.hour ? "on" : "") + (h < 6 || h >= 20 ? " night" : "")} />
              ))}
            </div>
            <small>Les heures foncées sont la nuit : c’est là que le scan gêne le moins.</small>
          </div>
          <div className="slide">
            <label htmlFor="rate">Vitesse du scan</label>
            <output id="rate-out" htmlFor="rate">
              {rate} requêtes par seconde
            </output>
            <input id="rate" type="range" min="5" max="200" step="5" value={rate} onChange={(e) => save({ ...s, rate_per_sec: Number(e.target.value) }, 600)} />
            <div className="pulse" id="pulse" aria-hidden="true" style={{ "--spd": (3.2 - rate / 80).toFixed(2) + "s" } as CSSProperties}>
              {Array.from({ length: 7 }, (_, i) => (
                <i key={i} />
              ))}
            </div>
            <small id="rate-hint">{rateHint(rate)}</small>
          </div>
        </div>
      </div>

      <div className="section">
        <h2>Comment on vous prévient</h2>
        <div className="rpanel" style={{ marginTop: 12 }}>
          <p className="sub" style={{ margin: "0 0 8px" }}>
            À partir de quelle gravité
          </p>
          <div className="seg2" role="group" aria-label="Seuil d'alerte">
            {(
              [
                ["critical", "Critique seulement"],
                ["high", "Élevé et plus"],
                ["all", "Tout"],
              ] as const
            ).map(([k, l]) => (
              <button key={k} type="button" aria-pressed={s.alert_level === k} onClick={() => save({ ...s, alert_level: k })}>
                {l}
              </button>
            ))}
          </div>
          <div className="chans">
            <div className="chan off is-soon">
              <div>
                <p className="mt">
                  WhatsApp
                  <Soon />
                </p>
                <p className="md">Tout de suite, sur votre téléphone</p>
              </div>
              <button className="link" type="button" aria-disabled="true" onClick={() => toast("WhatsApp : bientôt disponible")}>
                Envoyer un test
              </button>
              <Switch on={false} label="WhatsApp" disabled />
            </div>
            <div className={"chan" + (s.email_alerts && plan.alerts ? "" : " off")}>
              <div>
                <p className="mt">Email</p>
                <p className="md">{plan.alerts ? "Avec le détail et les étapes" : `Non inclus dans l’offre ${plan.name}`}</p>
              </div>
              <button className="link" type="button" onClick={showPreview}>
                Envoyer un test
              </button>
              <Switch on={s.email_alerts && plan.alerts} label="Email" disabled={!plan.alerts} onClick={() => save({ ...s, email_alerts: !s.email_alerts })} />
            </div>
            <div className="chan off is-soon">
              <div>
                <p className="mt">
                  Résumé du lundi
                  <Soon />
                </p>
                <p className="md">Le score et les actions de la semaine</p>
              </div>
              <button className="link" type="button" aria-disabled="true" onClick={() => toast("Résumé du lundi : bientôt disponible")}>
                Envoyer un test
              </button>
              <Switch on={false} label="Résumé du lundi" disabled />
            </div>
          </div>
          <div className="preview" id="preview" aria-live="polite">
            {preview && (
              <>
                <p className="pfrom">Aperçu du message, {preview.name}</p>
                <div className={"bubble" + (preview.typing ? "" : " in")}>
                  {preview.typing ? (
                    <span className="typing">
                      <i />
                      <i />
                      <i />
                    </span>
                  ) : (
                    preview.msg
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="section">
        <h2>Apparence</h2>
        <div className="themes" role="group" aria-label="Thème">
          {(
            [
              ["light", "Clair", "#F4F6FB", "#FFFFFF", "#14213D"],
              ["dark", "Sombre", "#0D1526", "#162036", "#E8EDF7"],
            ] as const
          ).map(([k, l, bg, sf, ink]) => (
            <button key={k} type="button" aria-pressed={theme === k} onClick={() => setTheme(k)}>
              <span className="tprev" style={{ background: bg }}>
                <i style={{ background: sf }} />
                <i style={{ background: sf }} />
                <b style={{ background: ink }} />
              </span>
              {l}
            </button>
          ))}
        </div>
      </div>

      <Domains targets={data.targets} />
      <Team />
      <ScanHistory />

      <div className="section">
        <h2>Abonnement</h2>
        <div className="rpanel" style={{ marginTop: 12 }}>
          <p>
            <b style={{ fontFamily: "'Bricolage Grotesque Variable',sans-serif", fontSize: 22 }}>Offre {plan.name}</b>
            <span style={{ color: "var(--ink2)" }}>{subLine}</span>
          </p>
          <div className="prog" style={{ marginTop: 16 }}>
            {prog.map(([n, a, b]) => (
              <div key={n}>
                <div>
                  <span>{n}</span>
                  <span style={{ color: "var(--ink2)" }}>{b ? `${a} sur ${b}` : `${a}, sans limite`}</span>
                </div>
                <div className="bar" style={{ marginTop: 6, height: 4 }}>
                  <b style={{ width: (b ? Math.min(100, (a / b) * 100) : 0) + "%", background: "var(--azur)" }} />
                </div>
              </div>
            ))}
          </div>
          <div className="actions">
            <Link className="btn" to={`/paiement?offre=${plan.id === "pro" ? "pro" : "sme"}`}>
              Changer d’offre
            </Link>
            <button className="btn ghost" type="button" aria-disabled="true" onClick={() => toast("Factures : bientôt disponible")}>
              Voir les factures
              <Soon />
            </button>
          </div>
          <p className="sub" style={{ marginTop: 14 }}>
            Paiement par carte, MTN Mobile Money ou Airtel Money : bientôt disponible.
          </p>
          <div style={{ overflowX: "auto", marginTop: 18 }}>
            <table className={"limits plan" + planCol}>
              <thead>
                <tr>
                  <th scope="col">Comparer les offres</th>
                  <th scope="col">Gratuit</th>
                  <th scope="col">Essentiel</th>
                  <th scope="col">Pro</th>
                </tr>
              </thead>
              <tbody>
                {limitRows(sub.plans).map(([name, ...cells]) => (
                  <tr key={name}>
                    <th scope="row">{name}</th>
                    {cells.map((c, i) => (
                      <td key={i}>{c}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}

/** Domains: per-domain exclusions (rule 2), kept from the previous dashboard. */
function Domains({ targets }: { targets: Target[] }) {
  const { org, isAdmin, reload } = useOrg();
  const { toast } = useUI();
  const [open, setOpen] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [err, setErr] = useState("");
  const edit = (t: Target) => {
    setOpen(open === t.id ? null : t.id);
    setText(formatExclusions(t.exclusions));
    setErr("");
  };
  const saveEx = async (t: Target) => {
    const { value, errors } = parseExclusions(text);
    if (errors.length) {
      setErr(`Lignes non comprises : ${errors.join(", ")}`);
      return;
    }
    try {
      await api.updateTarget(org.org_id, t.id, { exclusions: value });
      setOpen(null);
      toast("Exclusions enregistrées");
      void reload();
    } catch {
      setErr("Exclusions non enregistrées, réessayez.");
    }
  };
  return (
    <div className="section">
      <h2>Domaines et exclusions</h2>
      <p className="hint">Ce qu’on ne touche jamais : une adresse, un port, un chemin ou un nom par ligne.</p>
      <div className="rpanel" style={{ marginTop: 12 }}>
        {targets.length === 0 && <p className="md">Aucun domaine pour l’instant : ajoutez-en un dans Actifs.</p>}
        {targets.map((t) => (
          <div key={t.id} className="set" style={{ display: "block" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
              <div>
                <p className="mt">{t.domain}</p>
                <p className="md">
                  {t.verified ? "Propriété prouvée" : "Propriété à prouver"} · {formatExclusions(t.exclusions).split("\n").filter(Boolean).length} exclusion(s)
                </p>
              </div>
              {isAdmin && (
                <button className="link" type="button" onClick={() => edit(t)}>
                  {open === t.id ? "Annuler" : "Modifier"}
                </button>
              )}
            </div>
            {open === t.id && (
              <div className="pwbox">
                <label className="md" htmlFor={"ex-" + t.id}>
                  Exclusions de {t.domain}
                </label>
                <textarea
                  id={"ex-" + t.id}
                  rows={4}
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder={"/admin\n3389\n192.0.2.10\nintranet." + t.domain}
                  style={{ borderRadius: 14, border: "1px solid var(--line)", background: "var(--bg)", color: "var(--ink)", font: "inherit", padding: "10px 14px" }}
                />
                <p className="err" role="alert">
                  {err}
                </p>
                <button className="btn" type="button" onClick={() => void saveEx(t)}>
                  Enregistrer
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/** Team: members, invitations and roles, kept from the previous dashboard. */
function Team() {
  const { org, me, isAdmin, data } = useOrg();
  const { toast } = useUI();
  const [members, setMembers] = useState<Member[] | null>(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [err, setErr] = useState("");
  const [code, setCode] = useState<{ email: string; token: string } | null>(null);

  const load = () =>
    api
      .members(org.org_id)
      .then((r) => setMembers(r.items))
      .catch(() => setMembers([]));
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [org.org_id]);

  const act = async (f: () => Promise<unknown>, ok: string) => {
    try {
      await f();
      toast(ok);
      void load();
    } catch (e) {
      toast(e instanceof ApiError && e.status === 409 ? "Il faut garder au moins un administrateur" : "Action impossible pour le moment");
    }
  };
  const invite = async () => {
    setErr("");
    try {
      const inv = await api.invite(org.org_id, email.trim(), role);
      setEmail("");
      setCode(inv.setup_token ? { email: inv.member.email, token: inv.setup_token } : null);
      toast(inv.emailed ? "Invitation envoyée" : "Membre ajouté");
      void load();
    } catch (e) {
      setErr(
        e instanceof ApiError && e.code === "plan_limit"
          ? `L’offre ${data?.subscription.plan.name ?? ""} ne permet pas d’autre membre.`
          : e instanceof ApiError && e.status === 400
            ? "Cette adresse email n’est pas valide."
            : "Invitation impossible pour le moment.",
      );
    }
  };

  return (
    <div className="section">
      <h2>Équipe</h2>
      <ul className="sess">
        {(members ?? []).map((m) => (
          <li key={m.user_id}>
            <span className="mico" aria-hidden="true">
              {(m.email[0] ?? "?").toUpperCase()}
            </span>
            <div>
              <p className="mt">{m.email}</p>
              <p className="md">
                {m.role === "admin" ? "Administrateur" : "Lecteur"}
                {m.activated ? "" : " · invitation en attente"}
                {m.mfa_enabled ? " · double authentification active" : ""}
              </p>
            </div>
            {isAdmin && m.user_id !== me.user_id ? (
              <span style={{ display: "flex", gap: 12 }}>
                <button
                  className="link"
                  type="button"
                  onClick={() => void act(() => api.setMemberRole(org.org_id, m.user_id, m.role === "admin" ? "viewer" : "admin"), "Rôle modifié")}
                >
                  {m.role === "admin" ? "Passer lecteur" : "Passer admin"}
                </button>
                {!m.activated && (
                  <button
                    className="link"
                    type="button"
                    onClick={() =>
                      void api
                        .newSetupToken(org.org_id, m.user_id)
                        .then((r) => setCode({ email: m.email, token: r.setup_token }))
                        .catch(() => toast("Action impossible pour le moment"))
                    }
                  >
                    Nouveau code
                  </button>
                )}
                <button
                  className="link"
                  type="button"
                  onClick={() => {
                    if (window.confirm(`Retirer ${m.email} de ${org.org_name} ?`)) void act(() => api.removeMember(org.org_id, m.user_id), "Membre retiré");
                  }}
                >
                  Retirer
                </button>
              </span>
            ) : (
              <span />
            )}
          </li>
        ))}
      </ul>
      {isAdmin && (
        <div className="rpanel" style={{ marginTop: 12 }}>
          <p className="mt">Inviter quelqu’un</p>
          <div className="addrow">
            <label className="vh" htmlFor="inv-email">
              Adresse email
            </label>
            <input id="inv-email" type="email" autoComplete="off" placeholder="collegue@entreprise.cg" value={email} onChange={(e) => setEmail(e.target.value)} />
            <div className="seg2" role="group" aria-label="Rôle">
              {(
                [
                  ["viewer", "Lecteur"],
                  ["admin", "Administrateur"],
                ] as const
              ).map(([k, l]) => (
                <button key={k} type="button" aria-pressed={role === k} onClick={() => setRole(k)}>
                  {l}
                </button>
              ))}
            </div>
            <button className="btn" type="button" onClick={() => void invite()}>
              Inviter
            </button>
          </div>
          <p className="err" role="alert">
            {err}
          </p>
          {code && (
            <div className="record">
              <div>
                <small>Code d’activation pour {code.email}, à transmettre si l’email n’arrive pas (affiché une seule fois)</small>
                <b>{code.token}</b>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** ScanHistory: the latest scans, kept from the previous dashboard. */
function ScanHistory() {
  const { data } = useOrg();
  if (!data) return null;
  const label = { queued: "En attente", running: "En cours", done: "Terminé", failed: "Échoué" };
  const now = new Date();
  return (
    <div className="section">
      <h2>Derniers scans</h2>
      {data.scans.length ? (
        <ul className="feed">
          {data.scans.slice(0, 8).map((sc) => (
            <li key={sc.id} className={sc.status === "failed" ? "f-crit" : sc.status === "done" ? "f-ok" : ""}>
              <time dateTime={sc.created_at}>
                {new Date(sc.created_at).toLocaleString("fr-FR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })} · {sinceText(sc.created_at, now)}
              </time>
              <span>
                {label[sc.status]} sur <b>{sc.domain}</b>
                {sc.status === "done" && sc.new_findings !== undefined ? ` : ${sc.new_findings} nouveau(x), ${sc.fixed_findings ?? 0} corrigé(s)` : ""}.
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="hint">Aucun scan pour l’instant.</p>
      )}
    </div>
  );
}
