import { useEffect, useRef, useState, type CSSProperties } from "react";
import { api, ApiError } from "../../api/client";
import type { DeclaredAPI, Member, OrgSettings, Plan, Role, Target, TestAccount } from "../../api/types";
import { formatExclusions, parseExclusions } from "../../exclusions";
import { tr } from "../../i18n";
import { Link } from "../../router";
import { MODS, ModIcon, Soon } from "../icons";
import { CloseButton, SevTag, UpsellSheet } from "../sheets";
import { byPriority, dayName, sinceText } from "../model";
import { useOrg } from "../OrgData";
import { useUI } from "../ui";

/** The mockup's day buttons start on Monday; the API's weekday 0 is Sunday. */
const toApiDay = (i: number) => (i + 1) % 7;
const fromApiDay = (d: number) => (d + 6) % 7;
const FREQ: Record<string, string> = { jour: "daily", semaine: "weekly", mois: "monthly" };

function schedText(s: OrgSettings): string {
  if (!s.frequency) return tr("Aucun scan automatique pour l’instant : choisissez quand scanner.", "No automatic scan for now: choose when to scan.");
  const h = String(s.hour).padStart(2, "0") + ":00";
  const day = dayName(fromApiDay(s.weekday));
  return s.frequency === "daily"
    ? tr(`Scan automatique chaque jour à ${h}`, `Automatic scan every day at ${h}`)
    : s.frequency === "weekly"
      ? tr(`Scan automatique chaque ${day} à ${h}`, `Automatic scan every ${day} at ${h}`)
      : tr(`Scan automatique le premier ${day} du mois à ${h}`, `Automatic scan on the first ${day} of the month at ${h}`);
}

function rateHint(r: number): string {
  return r <= 30
    ? tr("Doux : pour les serveurs fragiles ou les connexions lentes.", "Gentle: for fragile servers or slow connections.")
    : r <= 100
      ? tr("Équilibré : convient à la plupart des entreprises.", "Balanced: suits most businesses.")
      : tr("Rapide : à réserver aux serveurs solides.", "Fast: for robust servers only.");
}

/** The worker's rate when a target has none (ORUS default). */
const DEFAULT_RATE = 5;

/** LIMITS: the mockup's comparison table, filled with the real offers. */
export function limitRows(plans: Plan[]): [string, ...string[]][] {
  const pick = ["discovery", "sme", "pro"].map((id) => plans.find((p) => p.id === id));
  const col = (f: (p: Plan) => string) => pick.map((p) => (p ? f(p) : ""));
  const freq = { monthly: tr("Mensuelle", "Monthly"), weekly: tr("Hebdomadaire", "Weekly"), daily: tr("Quotidienne", "Daily") };
  const n = (v: number, unit: string) => (v === 0 ? tr("Illimité", "Unlimited") : `${v.toLocaleString(tr("fr-FR", "en-GB"))} ${unit}`.trim());
  const yes = tr("Oui", "Yes");
  const no = tr("Non", "No");
  const soon = tr("Bientôt", "Soon");
  return [
    [tr("Domaines", "Domains"), ...col((p) => n(p.domains, ""))],
    [tr("Actifs surveillés", "Monitored assets"), ...col((p) => n(p.hosts_per_scan, tr("par domaine", "per domain")))],
    [tr("Membres de l’équipe", "Team members"), ...col((p) => n(p.members, ""))],
    [tr("Fréquence des scans", "Scan frequency"), ...col((p) => (p.max_frequency ? freq[p.max_frequency] : tr("Audit unique", "Single audit")))],
    [tr("Ports vérifiés", "Ports checked"), ...col((p) => (p.active_modules ? tr("50 ports courants", "50 common ports") : tr("Aucun", "None")))],
    [tr("Vulnérabilités connues", "Known vulnerabilities"), ...col((p) => (p.active_modules ? yes : no))],
    [tr("Analyse des API", "API testing"), ...col((p) => (p.api_scans ? yes : no))],
    [tr("Scan authentifié (compte de test)", "Authenticated scan (test account)"), ...col((p) => (p.auth_scans ? yes : no))],
    [tr("Réseaux internes (agents)", "Internal networks (agents)"), ...col((p) => (p.agents ? yes : tr("Sur devis", "Custom plan")))],
    [tr("Fuites de données", "Data leaks"), soon, soon, soon],
    [tr("Menaces émergentes", "Emerging threats"), ...col((p) => (p.threats ? yes : no))],
    [tr("Alertes email", "Email alerts"), ...col((p) => (p.alerts ? yes : no))],
    [tr("Rapports PDF", "PDF reports"), ...col((p) => (p.reports ? tr("Direction et Technique", "Executive and Technical") : no))],
    [
      tr("Profil approfondi", "Deep profile"),
      ...col((p) => (!p.deep_scans ? no : p.deep_scans_per_month ? tr(`${p.deep_scans_per_month} scans par mois`, `${p.deep_scans_per_month} scans per month`) : tr("Illimité", "Unlimited"))),
    ],
  ];
}

function Switch({ on, label, disabled, onClick }: { on: boolean; label: string; disabled?: boolean; onClick?: () => void }) {
  return (
    <button className="switch" type="button" role="switch" aria-checked={on} aria-label={label} aria-disabled={disabled || undefined} onClick={disabled ? undefined : onClick} />
  );
}

export function ReglagesPage() {
  const { data, org, isAdmin, setSettings, issues } = useOrg();
  const { toast, theme, setTheme, showSheet, closeAll } = useUI();
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
      toast(tr("Réservé aux administrateurs", "Administrators only"));
      return;
    }
    // After the free audit no schedule runs: the trial offer instead.
    if (!plan.monitoring && next.frequency && (next.frequency !== s.frequency || next.weekday !== s.weekday || next.hour !== s.hour)) {
      showSheet(<UpsellSheet what="scan" />);
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
              ? tr("Cette fréquence n’est pas incluse dans votre offre. Changez d’offre plus bas.", "This frequency is not included in your plan. Change plans below.")
              : tr("Réglage non enregistré, réessayez", "Setting not saved, try again"),
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
    if (!plan.active_modules && (module === "ports" || module === "vulns")) return tr(`Non inclus dans l’offre ${plan.name}`, `Not included in the ${plan.name} plan`);
    const cs = data.checks.filter((c) => c.module === module);
    if (!cs.length) return tr("Pas encore vérifié", "Not checked yet");
    const ids = new Set(cs.map((c) => c.id));
    const last = cs.reduce((a, c) => (c.evaluated_at > a ? c.evaluated_at : a), "");
    return tr(`${ids.size} contrôle${ids.size > 1 ? "s" : ""}, vérifiés ${sinceText(last, new Date())}`, `${ids.size} check${ids.size > 1 ? "s" : ""}, checked ${sinceText(last, new Date())}`);
  };

  const prof: [OrgSettings["profile"], string, number, string, string][] = [
    ["quick", tr("Rapide", "Quick"), 1, "5 minutes", tr("Contrôles passifs et ports principaux", "Passive checks and main ports")],
    ["standard", "Standard", 2, "40 minutes", tr("Tous les contrôles, 50 ports courants", "Every check, 50 common ports")],
    ["deep", tr("Approfondi", "Deep"), 3, tr("2 à 3 heures", "2 to 3 hours"), tr("1 000 ports, versions et tests étendus", "1,000 ports, versions and extended tests")],
  ];
  const freqKey = s.frequency === "daily" ? "jour" : s.frequency === "monthly" ? "mois" : s.frequency === "weekly" ? "semaine" : "";
  const day = fromApiDay(s.weekday);
  const rate = s.rate_per_sec || DEFAULT_RATE;

  const top = issues.filter((i) => !i.fixed).sort(byPriority)[0];
  const showPreview = () => {
    const msg = top
      ? tr(
          `Objet : nouveau problème sur ${top.domain}. Le dernier scan a trouvé : ${top.title} (${top.host}). Voici comment le corriger, environ ${top.mins} minutes.`,
          `Subject: new problem on ${top.domain}. The latest scan found: ${top.title} (${top.host}). Here is how to fix it, about ${top.mins} minutes.`,
        )
      : tr("Objet : rien de nouveau. Le dernier scan n’a trouvé aucun nouveau problème.", "Subject: nothing new. The latest scan found no new problem.");
    setPreview({ name: "Email", msg, typing: true });
    setTimeout(() => setPreview({ name: "Email", msg, typing: false }), 900);
  };

  const planCol = { discovery: 1, sme: 2, pro: 3, enterprise: 3 }[plan.id];
  const sub = data.subscription;
  const until = sub.until ? new Date(sub.until).toLocaleDateString(tr("fr-FR", "en-GB"), { day: "numeric", month: "long", year: "numeric" }) : "";
  const price = plan.on_quote
    ? tr("sur devis", "on quote")
    : sub.period === "yearly"
      ? tr(`à ${plan.usd_yearly * 12} $ par an`, `at $${plan.usd_yearly * 12} per year`)
      : plan.usd_monthly
        ? tr(`à ${plan.usd_monthly} $ par mois`, `at $${plan.usd_monthly} per month`)
        : tr("gratuite", "free");
  const subLine =
    sub.status === "trialing" && until
      ? tr(` ${price}. Essai gratuit jusqu’au ${until}.`, ` ${price}. Free trial until ${until}.`)
      : sub.status === "canceled" && until && !sub.lapsed
        ? tr(` ${price}. Abonnement annulé : il se termine le ${until}, sans nouveau prélèvement.`, ` ${price}. Subscription cancelled: it ends on ${until}, with no further charge.`)
        : sub.in_grace && until
          ? tr(` ${price}. Paiement attendu avant le ${until}.`, ` ${price}. Payment expected before ${until}.`)
          : until
            ? tr(` ${price}. Prochaine échéance le ${until}.`, ` ${price}. Next renewal on ${until}.`)
            : ` ${price}.`;
  const monthStart = new Date();
  monthStart.setDate(1);
  monthStart.setHours(0, 0, 0, 0);
  const scansThisMonth = data.scans.filter((x) => new Date(x.created_at) >= monthStart).length;
  const assetsCap = plan.hosts_per_scan * Math.max(1, data.targets.length);
  const hostCount = data.assets.filter((a) => a.kind === "hostname" && !a.gone_at).length;
  const prog: [string, number, number][] = [
    [tr("Domaines", "Domains"), sub.usage.domains, plan.domains],
    [tr("Actifs surveillés", "Monitored assets"), hostCount, assetsCap],
    [tr("Scans ce mois-ci", "Scans this month"), scansThisMonth, 0],
  ];
  if (plan.deep_scans) prog.push([tr("Scans approfondis ce mois-ci", "Deep scans this month"), sub.usage.deep_scans, plan.deep_scans_per_month]);

  return (
    <>
      <div className="rtop">
        <h1 className="hello" style={{ margin: 0, fontFamily: "inherit", fontWeight: 400, letterSpacing: 0 }}>
          {tr("Réglages", "Settings")}
        </h1>
      </div>
      <div className="cover">
        <div className="covernum">
          <b id="cov-n">{active}</b>
          <span>{tr(`vérifications actives sur ${MODS.length}`, `of ${MODS.length} checks active`)}</span>
        </div>
        <div className="covertrack">
          {MODS.map((m) => (
            <i key={m.key} data-cov={m.key} className={modOn(m) ? "on" : ""} />
          ))}
        </div>
        <p id="next-scan">{schedText(s)}</p>
      </div>

      <div className="section">
        <h2>{tr("Ce qu’on vérifie", "What we check")}</h2>
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
        <h2>{tr("Profondeur du scan", "Scan depth")}</h2>
        <div className="profs" role="group" aria-label={tr("Profil de scan", "Scan profile")}>
          {prof.map(([k, l, lvl, dur, d]) => (
            <button
              key={k}
              type="button"
              className="prof"
              aria-pressed={s.profile === k}
              aria-disabled={(k === "deep" && !plan.deep_scans) || undefined}
              onClick={() => {
                if (k !== "deep") save({ ...s, profile: k });
                else if (!isAdmin) toast(tr("Réservé aux administrateurs", "Administrators only"));
                else if (!plan.deep_scans) toast(tr("Le profil approfondi est inclus dans l’offre Pro. Changez d’offre plus bas.", "The deep profile is included in the Pro plan. Change plans below."));
                else if (s.profile !== "deep")
                  showSheet(
                    <ConsentSheet
                      onConfirm={async () => {
                        const next: OrgSettings = { ...s, profile: "deep", deep_consent: true };
                        const saved = await api.saveSettings(org.org_id, next);
                        setDraft(saved);
                        setSettings(saved);
                        closeAll();
                        toast(tr("Profil approfondi activé", "Deep profile turned on"));
                      }}
                    />,
                  );
              }}
            >
              <span className="bars" aria-hidden="true">
                {[1, 2, 3].map((x) => (
                  <i key={x} className={x <= lvl ? "on" : ""} style={{ height: 6 + x * 6 + "px" }} />
                ))}
              </span>
              <span className="pt2">{l}</span>
              <span className="pd">{d}</span>
              <span className="pdur">{dur}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="section">
        <h2>{tr("Quand scanner", "When to scan")}</h2>
        <div className="rpanel" style={{ marginTop: 12 }}>
          <div className="seg2" role="group" aria-label={tr("Fréquence", "Frequency")}>
            {(
              [
                ["jour", tr("Chaque jour", "Every day")],
                ["semaine", tr("Chaque semaine", "Every week")],
                ["mois", tr("Chaque mois", "Every month")],
              ] as const
            ).map(([k, l]) => (
              <button key={k} type="button" aria-pressed={freqKey === k} onClick={() => save({ ...s, frequency: FREQ[k] as OrgSettings["frequency"] })}>
                {l}
              </button>
            ))}
          </div>
          <div className={"days" + (s.frequency === "daily" ? " mute" : "")} role="group" aria-label={tr("Jour", "Day")}>
            {(tr("L M M J V S D", "M T W T F S S").split(" ")).map((d, i) => (
              <button key={i} type="button" aria-pressed={day === i} aria-label={dayName(i)} onClick={() => save({ ...s, weekday: toApiDay(i), frequency: s.frequency || "weekly" })}>
                {d}
              </button>
            ))}
          </div>
          <div className="slide">
            <label htmlFor="hour">{tr("Heure de départ", "Start time")}</label>
            <output id="hour-out" htmlFor="hour">
              {String(s.hour).padStart(2, "0")}:00
            </output>
            <input id="hour" type="range" min="0" max="23" step="1" value={s.hour} onChange={(e) => save({ ...s, hour: Number(e.target.value), frequency: s.frequency || "weekly" }, 600)} />
            <div className="clock" aria-hidden="true">
              {Array.from({ length: 24 }, (_, h) => (
                <i key={h} className={(h === s.hour ? "on" : "") + (h < 6 || h >= 20 ? " night" : "")} />
              ))}
            </div>
            <small>{tr("Les heures foncées sont la nuit : c’est là que le scan gêne le moins.", "The dark hours are night time: that is when the scan disturbs least.")}</small>
          </div>
          <div className="slide">
            <label htmlFor="rate">{tr("Vitesse du scan", "Scan speed")}</label>
            <output id="rate-out" htmlFor="rate">
              {tr(`${rate} requêtes par seconde`, `${rate} requests per second`)}
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
        <h2>{tr("Comment on vous prévient", "How we alert you")}</h2>
        <div className="rpanel" style={{ marginTop: 12 }}>
          <p className="sub" style={{ margin: "0 0 8px" }}>
            {tr("À partir de quelle gravité", "From which severity")}
          </p>
          <div className="seg2" role="group" aria-label={tr("Seuil d'alerte", "Alert threshold")}>
            {(
              [
                ["critical", tr("Critique seulement", "Critical only")],
                ["high", tr("Élevé et plus", "High and above")],
                ["all", tr("Tout", "Everything")],
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
                <p className="md">{tr("Tout de suite, sur votre téléphone", "Right away, on your phone")}</p>
              </div>
              <button className="link" type="button" aria-disabled="true" onClick={() => toast(tr("WhatsApp : bientôt disponible", "WhatsApp: coming soon"))}>
                {tr("Envoyer un test", "Send a test")}
              </button>
              <Switch on={false} label="WhatsApp" disabled />
            </div>
            <div className={"chan" + (s.email_alerts && plan.alerts ? "" : " off")}>
              <div>
                <p className="mt">Email</p>
                <p className="md">{plan.alerts ? tr("Avec le détail et les étapes", "With the details and the steps") : tr(`Non inclus dans l’offre ${plan.name}`, `Not included in the ${plan.name} plan`)}</p>
              </div>
              <button className="link" type="button" onClick={showPreview}>
                {tr("Envoyer un test", "Send a test")}
              </button>
              <Switch on={s.email_alerts && plan.alerts} label="Email" disabled={!plan.alerts} onClick={() => save({ ...s, email_alerts: !s.email_alerts })} />
            </div>
            <div className="chan off is-soon">
              <div>
                <p className="mt">
                  {tr("Résumé du lundi", "Monday summary")}
                  <Soon />
                </p>
                <p className="md">{tr("Le score et les actions de la semaine", "The score and the week's actions")}</p>
              </div>
              <button className="link" type="button" aria-disabled="true" onClick={() => toast(tr("Résumé du lundi : bientôt disponible", "Monday summary: coming soon"))}>
                {tr("Envoyer un test", "Send a test")}
              </button>
              <Switch on={false} label={tr("Résumé du lundi", "Monday summary")} disabled />
            </div>
          </div>
          <div className="preview" id="preview" aria-live="polite">
            {preview && (
              <>
                <p className="pfrom">{tr(`Aperçu du message, ${preview.name}`, `Message preview, ${preview.name}`)}</p>
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
        <h2>{tr("Apparence", "Appearance")}</h2>
        <div className="themes" role="group" aria-label={tr("Thème", "Theme")}>
          {(
            [
              ["light", tr("Clair", "Light"), "#F4F6FB", "#FFFFFF", "#14213D"],
              ["dark", tr("Sombre", "Dark"), "#0D1526", "#162036", "#E8EDF7"],
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

      <Domains targets={data.targets.filter((t) => !t.internal)} />
      <Team />
      <ScanHistory />

      <div className="section">
        <h2>{tr("Abonnement", "Subscription")}</h2>
        <div className="rpanel" style={{ marginTop: 12 }}>
          <p>
            <b style={{ fontFamily: "'Bricolage Grotesque Variable',sans-serif", fontSize: 22 }}>{tr(`Offre ${plan.name}`, `${plan.name} plan`)}</b>
            <span style={{ color: "var(--ink2)" }}>{subLine}</span>
          </p>
          <div className="prog" style={{ marginTop: 16 }}>
            {prog.map(([n, a, b]) => (
              <div key={n}>
                <div>
                  <span>{n}</span>
                  <span style={{ color: "var(--ink2)" }}>{b ? tr(`${a} sur ${b}`, `${a} of ${b}`) : tr(`${a}, sans limite`, `${a}, no limit`)}</span>
                </div>
                <div className="bar" style={{ marginTop: 6, height: 4 }}>
                  <b style={{ width: (b ? Math.min(100, (a / b) * 100) : 0) + "%", background: "var(--azur)" }} />
                </div>
              </div>
            ))}
          </div>
          <div className="actions">
            <Link className="btn" to={`/paiement?offre=${plan.id === "pro" ? "pro" : "sme"}&org=${encodeURIComponent(org.org_id)}`}>
              {tr("Changer d’offre", "Change plan")}
            </Link>
            <button
              className="btn ghost"
              type="button"
              onClick={() =>
                void api.billingPortal(org.org_id).then(
                  (r) => window.location.assign(r.url),
                  (e: unknown) =>
                    toast(
                      e instanceof ApiError && e.status === 404
                        ? tr("Pas encore de facture : vous ne payez pas en ligne pour l’instant", "No invoice yet: you are not paying online for now")
                        : e instanceof ApiError && e.status === 403
                          ? tr("Réservé aux administrateurs", "Administrators only")
                          : tr("Factures indisponibles pour le moment", "Invoices unavailable right now"),
                    ),
                )
              }
            >
              {tr("Voir les factures", "See the invoices")}
            </button>
          </div>
          <p className="sub" style={{ marginTop: 14 }}>
            {tr("Paiement par carte ou PayPal, avec Paddle.", "Payment by card or PayPal, with Paddle.")}
          </p>
          <div style={{ overflowX: "auto", marginTop: 18 }}>
            <table className={"limits plan" + planCol}>
              <thead>
                <tr>
                  <th scope="col">{tr("Comparer les offres", "Compare the plans")}</th>
                  <th scope="col">{tr("Gratuit", "Free")}</th>
                  <th scope="col">{tr("Essentiel", "Essential")}</th>
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
      setErr(tr(`Lignes non comprises : ${errors.join(", ")}`, `Lines not understood: ${errors.join(", ")}`));
      return;
    }
    try {
      await api.updateTarget(org.org_id, t.id, { exclusions: value });
      setOpen(null);
      toast(tr("Exclusions enregistrées", "Exclusions saved"));
      void reload();
    } catch {
      setErr(tr("Exclusions non enregistrées, réessayez.", "Exclusions not saved, try again."));
    }
  };
  return (
    <div className="section">
      <h2>{tr("Domaines et exclusions", "Domains and exclusions")}</h2>
      <p className="hint">{tr("Ce qu’on ne touche jamais : une adresse, un port, un chemin ou un nom par ligne.", "What we never touch: one address, port, path or name per line.")}</p>
      <div className="rpanel" style={{ marginTop: 12 }}>
        {targets.length === 0 && <p className="md">{tr("Aucun domaine pour l’instant : ajoutez-en un dans Actifs.", "No domain yet: add one in Assets.")}</p>}
        {targets.map((t) => (
          <div key={t.id} className="set" style={{ display: "block" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
              <div>
                <p className="mt">{t.domain}</p>
                <p className="md">
                  {t.verified ? tr("Propriété prouvée", "Ownership proven") : tr("Propriété à prouver", "Ownership to prove")} ·{" "}
                  {tr(`${formatExclusions(t.exclusions).split("\n").filter(Boolean).length} exclusion(s)`, `${formatExclusions(t.exclusions).split("\n").filter(Boolean).length} exclusion(s)`)}
                </p>
              </div>
              {isAdmin && (
                <button className="link" type="button" onClick={() => edit(t)}>
                  {open === t.id ? tr("Annuler", "Cancel") : tr("Modifier", "Edit")}
                </button>
              )}
            </div>
            {open === t.id && (
              <div className="pwbox">
                <label className="md" htmlFor={"ex-" + t.id}>
                  {tr(`Exclusions de ${t.domain}`, `Exclusions of ${t.domain}`)}
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
                  {tr("Enregistrer", "Save")}
                </button>
              </div>
            )}
            <TargetAPIs target={t} />
            <TestAccountPanel target={t} />
          </div>
        ))}
      </div>
    </div>
  );
}

/** maxSpec mirrors the API's limit on an uploaded description. */
const MAX_SPEC = 900 * 1024;

/** TargetAPIs lists and declares the APIs of one domain (step H). */
function TargetAPIs({ target }: { target: Target }) {
  const { org, isAdmin, data } = useOrg();
  const { toast } = useUI();
  const [apis, setApis] = useState<DeclaredAPI[]>([]);
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"openapi" | "graphql">("openapi");
  const [base, setBase] = useState("");
  const [specURL, setSpecURL] = useState("");
  const [spec, setSpec] = useState<{ name: string; text: string } | null>(null);
  const [err, setErr] = useState("");
  const included = data?.subscription.plan.api_scans ?? false;

  const load = () =>
    api.apis(org.org_id, target.id).then(
      (r) => setApis(r.items),
      () => setApis([]),
    );
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target.id]);

  const pickFile = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > MAX_SPEC) {
      setErr(tr("Ce fichier dépasse 900 Ko : donnez plutôt l’adresse de la spécification.", "This file is over 900 KB: give the address of the specification instead."));
      return;
    }
    setSpec({ name: f.name, text: await f.text() });
    setErr("");
  };
  const add = async () => {
    setErr("");
    try {
      await api.createAPI(org.org_id, target.id, {
        name: name.trim(),
        kind,
        base_url: base.trim(),
        ...(specURL.trim() ? { spec_url: specURL.trim() } : {}),
        ...(spec ? { spec: spec.text } : {}),
      });
      setAdding(false);
      setName("");
      setBase("");
      setSpecURL("");
      setSpec(null);
      toast(tr("API ajoutée : elle sera analysée au prochain scan", "API added: it will be tested at the next scan"));
      void load();
    } catch (e) {
      setErr(
        e instanceof ApiError && e.status === 409
          ? tr("Une API avec cette adresse est déjà déclarée.", "An API with this address is already declared.")
          : e instanceof ApiError && e.code === "plan_limit"
            ? tr("L’analyse des API est incluse dans l’offre Pro.", "API testing is included in the Pro plan.")
            : e instanceof ApiError && e.status === 400
              ? tr(
                  `Vérifiez les adresses : elles doivent être sur ${target.domain} ou un de ses sous-domaines, et une API OpenAPI a besoin de sa spécification.`,
                  `Check the addresses: they must be on ${target.domain} or one of its subdomains, and an OpenAPI API needs its specification.`,
                )
              : tr("API non enregistrée, réessayez.", "API not saved, try again."),
      );
    }
  };
  const remove = async (a: DeclaredAPI) => {
    if (!window.confirm(tr(`Retirer l’API ${a.name} ?`, `Remove the API ${a.name}?`))) return;
    try {
      await api.deleteAPI(org.org_id, target.id, a.id);
      toast(tr("API retirée", "API removed"));
      void load();
    } catch {
      toast(tr("Suppression impossible pour le moment", "Removal is not possible right now"));
    }
  };
  const field = { height: 44, borderRadius: 14, border: "1px solid var(--line)", background: "var(--bg)", color: "var(--ink)", font: "inherit", padding: "0 14px" };

  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
        <p className="md">
          {tr(`API de ${target.domain} : `, `APIs of ${target.domain}: `)}
          {apis.length ? apis.length : tr("aucune", "none")}
          {!included && <span className="soon">{tr("Offre Pro", "Pro plan")}</span>}
        </p>
        {isAdmin && included && (
          <button className="link" type="button" onClick={() => setAdding(!adding)}>
            {adding ? tr("Annuler", "Cancel") : tr("Ajouter une API", "Add an API")}
          </button>
        )}
      </div>
      {apis.length > 0 && (
        <ul className="svc">
          {apis.map((a) => (
            <li key={a.id}>
              <b>{a.kind === "graphql" ? "GQL" : "REST"}</b>
              <span>
                {a.name}
                {isAdmin && (
                  <button className="link" type="button" style={{ minHeight: 0, marginLeft: 10, fontSize: 13 }} onClick={() => void remove(a)}>
                    {tr("Retirer", "Remove")}
                  </button>
                )}
              </span>
              <small>
                {a.base_url}
                {a.spec_url ? tr(` · spécification ${a.spec_url}`, ` · specification ${a.spec_url}`) : a.spec_size ? tr(" · spécification envoyée", " · specification uploaded") : ""}
              </small>
            </li>
          ))}
        </ul>
      )}
      {adding && (
        <div className="pwbox">
          <label className="md" htmlFor={"api-name-" + target.id}>
            {tr("Nom", "Name")}
          </label>
          <input id={"api-name-" + target.id} style={field} value={name} placeholder={tr("API clients", "Customer API")} onChange={(e) => setName(e.target.value)} />
          <div className="seg2" role="group" aria-label={tr("Type d’API", "API type")} style={{ display: "inline-flex" }}>
            {(
              [
                ["openapi", "OpenAPI (REST)"],
                ["graphql", "GraphQL"],
              ] as const
            ).map(([k, l]) => (
              <button key={k} type="button" aria-pressed={kind === k} onClick={() => setKind(k)}>
                {l}
              </button>
            ))}
          </div>
          <label className="md" htmlFor={"api-base-" + target.id}>
            {kind === "graphql" ? tr("Adresse de l’API GraphQL", "Address of the GraphQL API") : tr("Adresse de base de l’API", "Base address of the API")}
          </label>
          <input id={"api-base-" + target.id} style={field} value={base} placeholder={`https://api.${target.domain}/v1`} onChange={(e) => setBase(e.target.value)} />
          <label className="md" htmlFor={"api-spec-" + target.id}>
            {kind === "graphql"
              ? tr("Schéma (facultatif : sinon l’API est interrogée)", "Schema (optional: otherwise the API is queried)")
              : tr("Adresse de la spécification OpenAPI, ou un fichier ci-dessous", "Address of the OpenAPI specification, or a file below")}
          </label>
          <input
            id={"api-spec-" + target.id}
            style={field}
            value={specURL}
            placeholder={`https://api.${target.domain}/openapi.json`}
            onChange={(e) => setSpecURL(e.target.value)}
          />
          <input type="file" accept=".json,.yaml,.yml,.graphql,.gql,application/json" aria-label={tr("Fichier de spécification", "Specification file")} onChange={(e) => void pickFile(e.target.files?.[0])} />
          {spec && <p className="md">{tr(`Fichier : ${spec.name}`, `File: ${spec.name}`)}</p>}
          <p className="md">{tr("L’analyse envoie des requêtes de test à cette API : utilisez si possible un environnement de test.", "Testing sends test requests to this API: use a test environment if you can.")}</p>
          <p className="err" role="alert">
            {err}
          </p>
          <button className="btn" type="button" onClick={() => void add()}>
            {tr("Ajouter", "Add")}
          </button>
        </div>
      )}
    </div>
  );
}

/** TestAccountPanel sets the test account of one domain (step I): admins only. */
function TestAccountPanel({ target }: { target: Target }) {
  const { org, isAdmin, data } = useOrg();
  const { toast } = useUI();
  const [account, setAccount] = useState<TestAccount | null>(null);
  const [editing, setEditing] = useState(false);
  const [kind, setKind] = useState<"header" | "form">("header");
  const [headerName, setHeaderName] = useState("Authorization");
  const [headerValue, setHeaderValue] = useState("");
  const [loginURL, setLoginURL] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [userField, setUserField] = useState("");
  const [passField, setPassField] = useState("");
  const [consent, setConsent] = useState(false);
  const [err, setErr] = useState("");
  const included = data?.subscription.plan.auth_scans ?? false;

  useEffect(() => {
    if (!isAdmin) return;
    api.testAccount(org.org_id, target.id).then(setAccount, () => setAccount(null));
  }, [org.org_id, target.id, isAdmin]);
  if (!isAdmin) return null;

  const field = { height: 44, borderRadius: 14, border: "1px solid var(--line)", background: "var(--bg)", color: "var(--ink)", font: "inherit", padding: "0 14px" };
  const save = async () => {
    if (!consent) {
      setErr(tr("Cochez la case pour confirmer qu’il s’agit d’un compte de test.", "Tick the box to confirm it is a test account."));
      return;
    }
    setErr("");
    try {
      const saved = await api.setTestAccount(
        org.org_id,
        target.id,
        kind === "header"
          ? { kind, header_name: headerName.trim(), header_value: headerValue, consent }
          : {
              kind,
              login_url: loginURL.trim(),
              username,
              password,
              ...(userField.trim() ? { username_field: userField.trim() } : {}),
              ...(passField.trim() ? { password_field: passField.trim() } : {}),
              consent,
            },
      );
      setAccount(saved);
      setEditing(false);
      setHeaderValue("");
      setPassword("");
      setConsent(false);
      toast(tr("Compte de test enregistré : il servira au prochain scan approfondi et aux scans d’API", "Test account saved: it will be used at the next deep scan and API scans"));
    } catch (e) {
      setErr(
        e instanceof ApiError && e.code === "plan_limit"
          ? tr("Le scan authentifié est inclus dans l’offre Pro.", "The authenticated scan is included in the Pro plan.")
          : e instanceof ApiError && e.status === 503
            ? tr("Les comptes de test ne sont pas encore activés sur ce serveur.", "Test accounts are not enabled on this server yet.")
            : e instanceof ApiError && e.status === 400
              ? tr(
                  `Vérifiez les champs : l’adresse de connexion doit être sur ${target.domain}, et les valeurs tenir sur une ligne.`,
                  `Check the fields: the sign-in address must be on ${target.domain}, and the values must fit on one line.`,
                )
              : tr("Compte de test non enregistré, réessayez.", "Test account not saved, try again."),
      );
    }
  };
  const remove = async () => {
    if (!window.confirm(tr("Supprimer le compte de test ? Les scans ne se connecteront plus.", "Delete the test account? Scans will no longer sign in."))) return;
    try {
      await api.deleteTestAccount(org.org_id, target.id);
      setAccount(null);
      toast(tr("Compte de test supprimé", "Test account deleted"));
    } catch {
      toast(tr("Suppression impossible pour le moment", "Deletion is not possible right now"));
    }
  };

  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
        <p className="md">
          {tr("Compte de test : ", "Test account: ")}
          {account
            ? account.kind === "header"
              ? tr(`en-tête ${account.header_name ?? ""}`, `header ${account.header_name ?? ""}`)
              : tr(`formulaire, ${account.username ?? ""} sur ${account.login_url ?? ""}`, `form, ${account.username ?? ""} on ${account.login_url ?? ""}`)
            : tr("aucun", "none")}
          {!included && <span className="soon">{tr("Offre Pro", "Pro plan")}</span>}
        </p>
        {included && (
          <span style={{ display: "flex", gap: 12 }}>
            {account && (
              <button className="link" type="button" onClick={() => void remove()}>
                {tr("Supprimer", "Delete")}
              </button>
            )}
            <button className="link" type="button" onClick={() => setEditing(!editing)}>
              {editing ? tr("Annuler", "Cancel") : account ? tr("Remplacer", "Replace") : tr("Ajouter un compte de test", "Add a test account")}
            </button>
          </span>
        )}
      </div>
      {editing && (
        <div className="pwbox">
          <p className="md">
            {tr(
              "Les scans approfondis et d’API se connectent avec ce compte pour tester ce qui est derrière la connexion. Utilisez un compte de test, jamais celui d’un administrateur. Le secret est chiffré et ne sera plus jamais affiché.",
              "Deep and API scans sign in with this account to test what is behind the sign-in. Use a test account, never an administrator's. The secret is encrypted and will never be shown again.",
            )}
          </p>
          <div className="seg2" role="group" aria-label={tr("Type de compte", "Account type")} style={{ display: "inline-flex" }}>
            {(
              [
                ["header", tr("Jeton ou clé d’API", "Token or API key")],
                ["form", tr("Formulaire de connexion", "Sign-in form")],
              ] as const
            ).map(([k, l]) => (
              <button key={k} type="button" aria-pressed={kind === k} onClick={() => setKind(k)}>
                {l}
              </button>
            ))}
          </div>
          {kind === "header" ? (
            <>
              <label className="md" htmlFor={"ta-hn-" + target.id}>
                {tr("Nom de l’en-tête", "Header name")}
              </label>
              <input id={"ta-hn-" + target.id} style={field} value={headerName} onChange={(e) => setHeaderName(e.target.value)} />
              <label className="md" htmlFor={"ta-hv-" + target.id}>
                {tr("Valeur (par exemple : Bearer …)", "Value (for example: Bearer …)")}
              </label>
              <input id={"ta-hv-" + target.id} style={field} type="password" autoComplete="off" value={headerValue} onChange={(e) => setHeaderValue(e.target.value)} />
            </>
          ) : (
            <>
              <label className="md" htmlFor={"ta-lu-" + target.id}>
                {tr("Adresse de la page de connexion", "Address of the sign-in page")}
              </label>
              <input id={"ta-lu-" + target.id} style={field} value={loginURL} placeholder={`https://${target.domain}/login`} onChange={(e) => setLoginURL(e.target.value)} />
              <label className="md" htmlFor={"ta-un-" + target.id}>
                {tr("Identifiant du compte de test", "Test account username")}
              </label>
              <input id={"ta-un-" + target.id} style={field} autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
              <label className="md" htmlFor={"ta-pw-" + target.id}>
                {tr("Mot de passe du compte de test", "Test account password")}
              </label>
              <input id={"ta-pw-" + target.id} style={field} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
              <label className="md" htmlFor={"ta-uf-" + target.id}>
                {tr("Noms des champs, si ce ne sont pas « username » et « password » (facultatif)", "Field names, if not “username” and “password” (optional)")}
              </label>
              <span style={{ display: "flex", gap: 8 }}>
                <input id={"ta-uf-" + target.id} style={{ ...field, flex: 1, minWidth: 0 }} placeholder="username" value={userField} onChange={(e) => setUserField(e.target.value)} />
                <input aria-label={tr("Nom du champ mot de passe", "Password field name")} style={{ ...field, flex: 1, minWidth: 0 }} placeholder="password" value={passField} onChange={(e) => setPassField(e.target.value)} />
              </span>
            </>
          )}
          <label className="consent small">
            <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
            <span>{tr("Je confirme que c’est un compte de test, que les scans peuvent utiliser.", "I confirm this is a test account that scans may use.")}</span>
          </label>
          <p className="err" role="alert">
            {err}
          </p>
          <button className="btn" type="button" onClick={() => void save()}>
            {tr("Enregistrer le compte de test", "Save the test account")}
          </button>
        </div>
      )}
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
      toast(e instanceof ApiError && e.status === 409 ? tr("Il faut garder au moins un administrateur", "At least one administrator must remain") : tr("Action impossible pour le moment", "This action is not possible right now"));
    }
  };
  const invite = async () => {
    setErr("");
    try {
      const inv = await api.invite(org.org_id, email.trim(), role);
      setEmail("");
      setCode(inv.setup_token ? { email: inv.member.email, token: inv.setup_token } : null);
      toast(inv.emailed ? tr("Invitation envoyée", "Invitation sent") : tr("Membre ajouté", "Member added"));
      void load();
    } catch (e) {
      setErr(
        e instanceof ApiError && e.code === "plan_limit"
          ? tr(`L’offre ${data?.subscription.plan.name ?? ""} ne permet pas d’autre membre.`, `The ${data?.subscription.plan.name ?? ""} plan allows no other member.`)
          : e instanceof ApiError && e.status === 400
            ? tr("Cette adresse email n’est pas valide.", "This email address is not valid.")
            : tr("Invitation impossible pour le moment.", "The invitation is not possible right now."),
      );
    }
  };

  return (
    <div className="section">
      <h2>{tr("Équipe", "Team")}</h2>
      <ul className="sess">
        {(members ?? []).map((m) => (
          <li key={m.user_id}>
            <span className="mico" aria-hidden="true">
              {(m.email[0] ?? "?").toUpperCase()}
            </span>
            <div>
              <p className="mt">{m.email}</p>
              <p className="md">
                {m.role === "admin" ? tr("Administrateur", "Administrator") : tr("Lecteur", "Viewer")}
                {m.activated ? "" : tr(" · invitation en attente", " · invitation pending")}
                {m.mfa_enabled ? tr(" · double authentification active", " · two-factor authentication on") : ""}
              </p>
            </div>
            {isAdmin && m.user_id !== me.user_id ? (
              <span style={{ display: "flex", gap: 12 }}>
                <button
                  className="link"
                  type="button"
                  onClick={() => void act(() => api.setMemberRole(org.org_id, m.user_id, m.role === "admin" ? "viewer" : "admin"), tr("Rôle modifié", "Role changed"))}
                >
                  {m.role === "admin" ? tr("Passer lecteur", "Make viewer") : tr("Passer admin", "Make admin")}
                </button>
                {!m.activated && (
                  <button
                    className="link"
                    type="button"
                    onClick={() =>
                      void api
                        .newSetupToken(org.org_id, m.user_id)
                        .then((r) => setCode({ email: m.email, token: r.setup_token }))
                        .catch(() => toast(tr("Action impossible pour le moment", "This action is not possible right now")))
                    }
                  >
                    {tr("Nouveau code", "New code")}
                  </button>
                )}
                <button
                  className="link"
                  type="button"
                  onClick={() => {
                    if (window.confirm(tr(`Retirer ${m.email} de ${org.org_name} ?`, `Remove ${m.email} from ${org.org_name}?`)))
                      void act(() => api.removeMember(org.org_id, m.user_id), tr("Membre retiré", "Member removed"));
                  }}
                >
                  {tr("Retirer", "Remove")}
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
          <p className="mt">{tr("Inviter quelqu’un", "Invite someone")}</p>
          <div className="addrow">
            <label className="vh" htmlFor="inv-email">
              {tr("Adresse email", "Email address")}
            </label>
            <input id="inv-email" type="email" autoComplete="off" placeholder={tr("collegue@entreprise.cg", "colleague@company.com")} value={email} onChange={(e) => setEmail(e.target.value)} />
            <div className="seg2" role="group" aria-label={tr("Rôle", "Role")}>
              {(
                [
                  ["viewer", tr("Lecteur", "Viewer")],
                  ["admin", tr("Administrateur", "Administrator")],
                ] as const
              ).map(([k, l]) => (
                <button key={k} type="button" aria-pressed={role === k} onClick={() => setRole(k)}>
                  {l}
                </button>
              ))}
            </div>
            <button className="btn" type="button" onClick={() => void invite()}>
              {tr("Inviter", "Invite")}
            </button>
          </div>
          <p className="err" role="alert">
            {err}
          </p>
          {code && (
            <div className="record">
              <div>
                <small>
                  {tr(
                    `Code d’activation pour ${code.email}, à transmettre si l’email n’arrive pas (affiché une seule fois)`,
                    `Activation code for ${code.email}, to pass on if the email does not arrive (shown only once)`,
                  )}
                </small>
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
  const label = { queued: tr("En attente", "Queued"), running: tr("En cours", "Running"), done: tr("Terminé", "Done"), failed: tr("Échoué", "Failed") };
  const now = new Date();
  return (
    <div className="section">
      <h2>{tr("Derniers scans", "Latest scans")}</h2>
      {data.scans.length ? (
        <ul className="feed">
          {data.scans.slice(0, 8).map((sc) => (
            <li key={sc.id} className={sc.status === "failed" ? "f-crit" : sc.status === "done" ? "f-ok" : ""}>
              <time dateTime={sc.created_at}>
                {new Date(sc.created_at).toLocaleString(tr("fr-FR", "en-GB"), { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })} · {sinceText(sc.created_at, now)}
              </time>
              <span>
                {label[sc.status]}
                {tr(" sur ", " on ")}
                <b>{sc.domain}</b>
                {sc.status === "done" && sc.new_findings !== undefined
                  ? tr(` : ${sc.new_findings} nouveau(x), ${sc.fixed_findings ?? 0} corrigé(s)`, `: ${sc.new_findings} new, ${sc.fixed_findings ?? 0} fixed`)
                  : ""}
                .
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="hint">{tr("Aucun scan pour l’instant.", "No scan yet.")}</p>
      )}
    </div>
  );
}

/** ConsentSheet is the mockup's openConsent: the deep profile needs an explicit consent. */
function ConsentSheet({ onConfirm }: { onConfirm: () => Promise<void> }) {
  const { closeAll } = useUI();
  const [checked, setChecked] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const confirm = async () => {
    if (!checked) {
      setErr(tr("Cochez la case pour confirmer votre autorisation.", "Tick the box to confirm your authorization."));
      return;
    }
    setBusy(true);
    try {
      await onConfirm();
    } catch {
      setErr(tr("Profil non enregistré, réessayez.", "Profile not saved, try again."));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <div className="shead">
        <SevTag s="high" label={tr("À lire avant d’activer", "Read before turning on")} />
        <CloseButton />
      </div>
      <h2 id="sheet-title">{tr("Le profil approfondi teste vos serveurs plus fort", "The deep profile tests your servers harder")}</h2>
      <p className="why">
        {tr(
          "Il vérifie 1 000 ports, identifie la version de chaque service et lance des tests applicatifs étendus.",
          "It checks 1,000 ports, identifies the version of each service and runs extended application tests.",
        )}
      </p>
      <h3>{tr("Ce que cela implique", "What this means")}</h3>
      <ul className="steps plain">
        <li>
          <span>{tr("Le scan peut durer 2 à 3 heures.", "The scan can take 2 to 3 hours.")}</span>
        </li>
        <li>
          <span>{tr("Un serveur ancien ou fragile peut ralentir pendant le test.", "An old or fragile server may slow down during the test.")}</span>
        </li>
        <li>
          <span>
            {tr(
              "Votre hébergeur peut voir ce trafic comme une attaque : prévenez-le si son contrat l’exige.",
              "Your host may see this traffic as an attack: tell them if their contract requires it.",
            )}
          </span>
        </li>
      </ul>
      <label className="consent">
        <input type="checkbox" id="consent-box" checked={checked} onChange={(e) => setChecked(e.target.checked)} />
        <span>{tr("Je confirme être autorisé à faire tester ces serveurs, et j’accepte ces risques.", "I confirm I am authorized to have these servers tested, and I accept these risks.")}</span>
      </label>
      <p id="consent-err" role="alert" className="err">
        {err}
      </p>
      <div className="actions sticky">
        <button className="btn" type="button" disabled={busy} onClick={() => void confirm()}>
          {tr("Activer le profil approfondi", "Turn on the deep profile")}
        </button>
        <button className="btn ghost" type="button" onClick={closeAll}>
          {tr("Annuler", "Cancel")}
        </button>
      </div>
    </>
  );
}
