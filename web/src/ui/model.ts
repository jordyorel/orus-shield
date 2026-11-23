// The mockup's vocabulary (severities, the five check columns, assets) built
// from the API's data. Pure functions: every screen and the tests use them.

import type { Category, Check, Finding, OrgAsset, Severity, Target } from "../api/types";
import { locale, tr } from "../i18n";
import { findingText, localTitle } from "./lang";

/** label is a [key, label] pair whose label follows the current language. */
function label<K>(k: K, fr: string, en: string): [K, string] {
  const t: [K, string] = [k, ""];
  Object.defineProperty(t, 1, { get: () => tr(fr, en), enumerable: true });
  return t;
}

/** The mockup's severity keys, plus "low" (shown "Faible") which it lacks. */
export type Sev = "crit" | "high" | "med" | "low";
export type SevOrOk = Sev | "ok";

// Getters: the labels follow the current language.
export const SEV: Record<SevOrOk, [string, string]> = {
  get crit(): [string, string] {
    return [tr("Critique", "Critical"), "s-crit"];
  },
  get high(): [string, string] {
    return [tr("Élevé", "High"), "s-high"];
  },
  get med(): [string, string] {
    return [tr("Moyen", "Medium"), "s-med"];
  },
  get low(): [string, string] {
    return [tr("Faible", "Low"), "s-med"];
  },
  get ok(): [string, string] {
    return [tr("Corrigé", "Fixed"), "s-ok"];
  },
};

export const RANK: Record<SevOrOk, number> = { crit: 0, high: 1, med: 2, low: 3, ok: 4 };

export const COLOR: Record<SevOrOk, string> = {
  crit: "var(--corail)",
  high: "var(--ambre)",
  med: "var(--ciel)",
  low: "var(--ciel)",
  ok: "var(--lagon)",
};

/** Distance from the radar's centre: the further, the more exposed. */
export const DIST: Record<SevOrOk, number> = { crit: 128, high: 100, med: 74, low: 74, ok: 44 };

export function sevOf(s: Severity): Sev {
  if (s === "critical") return "crit";
  if (s === "high") return "high";
  if (s === "medium") return "med";
  return "low";
}

/** The five columns of the mockup: Emails, TLS, Ports, Fuites, Menaces. */
export type Cat = "emails" | "tls" | "ports" | "fuites" | "menaces";
export const CATS: [Cat, string][] = [
  label<Cat>("emails", "Emails", "Email"),
  label<Cat>("tls", "TLS", "TLS"),
  label<Cat>("ports", "Ports", "Ports"),
  label<Cat>("fuites", "Fuites", "Leaks"),
  label<Cat>("menaces", "Menaces", "Threats"),
];
export const CATNAME: Record<Cat, string> = {
  get emails() {
    return tr("Emails", "Email");
  },
  get tls() {
    return tr("Chiffrement", "Encryption");
  },
  get ports() {
    return tr("Ports et services", "Ports and services");
  },
  get fuites() {
    return tr("Fuites de données", "Data leaks");
  },
  get menaces() {
    return tr("Menaces émergentes", "Emerging threats");
  },
};

/**
 * catOfModule maps an engine module to a column. web (headers, cookies,
 * HTTPS redirect) goes with TLS, "Chiffrement" of the site; vulns and zap
 * (deep web scan) are the known and application flaws of "Menaces"; cdn
 * and discovery have no findings of their own; leaks (XposedOrNot) feeds
 * "Fuites".
 */
export function catOfModule(moduleId: string): Cat | null {
  switch (moduleId) {
    case "email":
      return "emails";
    case "tls":
    case "web":
      return "tls";
    case "ports":
      return "ports";
    case "vulns":
    case "zap":
    case "api":
      return "menaces";
    case "leaks":
      return "fuites";
  }
  return null;
}

/** The module label of a problem row (the mockup's i.module). */
export function moduleName(f: Finding): string {
  if (f.emerging) return tr("Menaces émergentes", "Emerging threats");
  switch (f.module_id) {
    case "email":
      return tr("Emails", "Email");
    case "tls":
      return "TLS";
    case "web":
      return tr("Site web", "Website");
    case "ports":
      return "Ports";
    case "vulns":
      return tr("Vulnérabilités", "Vulnerabilities");
    case "zap":
      return tr("Application web", "Web application");
    case "api":
      return "API";
    case "m365":
      return "Microsoft 365";
  }
  return f.module_id;
}

export type IssueType = "vuln" | "fuite" | "menace";

export interface Issue {
  id: string;
  targetId: string;
  domain: string;
  moduleId: string;
  sev: Sev;
  /** open is "to do"; fixed and accepted_risk are done. */
  fixed: boolean;
  accepted: boolean;
  title: string;
  host: string;
  module: string;
  cat: Cat | null;
  mins: number;
  gain: number;
  type: IssueType;
  why: string;
  steps: string[];
  proof: string;
  cve?: Finding["cve"];
  finding: Finding;
}

/**
 * hostOf returns the hostname a finding's asset is about: the host of a
 * URL, the name before a port, the domain of "_dmarc.example.com" or
 * "s1._domainkey.example.com". An "ip:port" (ports module) is looked up in
 * the services' "host" detail.
 */
export function hostOf(assetValue: string, domain: string, ipHost: Map<string, string>): string {
  // An email address (leaks module) is about the registered domain.
  if (assetValue.includes("@") && !assetValue.includes("://")) return domain;
  let a = assetValue.split("#")[0] ?? "";
  if (a.includes("://")) {
    try {
      a = new URL(a).hostname;
    } catch {
      return domain;
    }
  }
  const v6 = /^\[([0-9a-f:]+)\](?::\d+)?$/i.exec(a);
  if (v6?.[1]) a = v6[1];
  else if (/^[^:]+:\d+$/.test(a)) a = a.slice(0, a.lastIndexOf(":"));
  if (ipHost.has(a)) return ipHost.get(a) ?? a;
  a = a.toLowerCase().replace(/\.$/, "");
  const labels = a.split(".");
  let i = 0;
  while (i < labels.length - 1 && (labels[i]?.startsWith("_") || labels[i + 1]?.startsWith("_"))) i++;
  const host = labels.slice(i).join(".");
  return host || domain;
}

/** ipHosts maps the IPs of open services to the hostname they came from. */
export function ipHosts(assets: OrgAsset[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const a of assets) {
    if (a.kind !== "service" || a.gone_at) continue;
    const host = a.details.host;
    const ip = serviceIP(a.value);
    if (host && ip && !m.has(ip)) m.set(ip, host);
  }
  return m;
}

/** serviceIP: "192.0.2.1:443/tcp" or "[2001:db8::1]:443/tcp" -> the IP. */
export function serviceIP(value: string): string {
  const v = value.replace(/\/tcp$/, "");
  const v6 = /^\[([^\]]+)\]:\d+$/.exec(v);
  if (v6?.[1]) return v6[1];
  return v.slice(0, v.lastIndexOf(":"));
}

export function servicePort(value: string): string {
  const v = value.replace(/\/tcp$/, "");
  return v.slice(v.lastIndexOf(":") + 1);
}

export function toIssues(findings: Finding[], assets: OrgAsset[]): Issue[] {
  const ips = ipHosts(assets);
  return findings
    .filter((f) => f.severity !== "info")
    .map((f) => ({ f, txt: findingText(f) }))
    .map(({ f, txt }) => ({
      id: f.id,
      targetId: f.target_id,
      domain: f.target,
      moduleId: f.module_id,
      sev: sevOf(f.severity),
      fixed: f.status !== "open",
      accepted: f.status === "accepted_risk",
      title: txt.title,
      host: hostOf(f.asset, f.target, ips),
      module: moduleName(f),
      cat: f.emerging ? "menaces" : catOfModule(f.module_id),
      mins: f.minutes,
      gain: f.gain,
      type: f.emerging ? "menace" : f.module_id === "leaks" ? "fuite" : "vuln",
      why: txt.description,
      steps: txt.remediation ?? [],
      proof: f.evidence,
      cve: f.cve,
      finding: f,
    }));
}

/** byPriority: most severe first, then what wins the most points. */
export function byPriority(a: Issue, b: Issue): number {
  return RANK[a.sev] - RANK[b.sev] || b.gain - a.gain || a.mins - b.mins || a.title.localeCompare(b.title);
}

export interface AssetView {
  /** The hostname. */
  n: string;
  targetId: string;
  domain: string;
  /** Kind, in the mockup's words. */
  k: string;
  /** Angle on the radar, in degrees. */
  a: number;
  tech: string[];
  svc: [string, string, string][];
  /** ips: the addresses its services were found on. */
  ips: string[];
  /** cert: the certificate covering the name, when one was seen. */
  cert?: { notAfter: string; issuer: string };
}

/** certFor finds the certificate whose names cover host (exact or a
 * one-label wildcard), the latest to expire first. */
function certFor(host: string, certs: OrgAsset[]): { notAfter: string; issuer: string } | undefined {
  const covers = (name: string) => name === host || (name.startsWith("*.") && host.endsWith(name.slice(1)) && !host.slice(0, host.length - name.length + 1).includes("."));
  const c = certs
    .filter((x) => (x.details.names ?? "").split(" ").some(covers) || x.details.subject === host)
    .sort((a, b) => (b.details.not_after ?? "").localeCompare(a.details.not_after ?? ""))[0];
  return c?.details.not_after ? { notAfter: c.details.not_after, issuer: c.details.issuer ?? "" } : undefined;
}


const MAIL_PORTS = new Set(["25", "465", "587", "110", "143", "993", "995"]);
const WEB_PORTS = new Set(["80", "443", "8080", "8443"]);

/** toAssets lists the current hostnames, with their services and technologies. */
export function toAssets(assets: OrgAsset[]): AssetView[] {
  const current = assets.filter((a) => !a.gone_at);
  const services = current.filter((a) => a.kind === "service");
  const certs = current.filter((a) => a.kind === "certificate");
  const hosts = current
    .filter((a) => a.kind === "hostname")
    .sort((x, y) => (x.value === x.domain ? -1 : y.value === y.domain ? 1 : x.value.localeCompare(y.value)));
  const n = hosts.length;
  return hosts.map((h, i) => {
    const svc = services
      .filter((s) => s.details.host === h.value)
      .map((s): [string, string, string] => {
        const port = servicePort(s.value);
        return [port, s.details.expected ?? "", s.details.banner ?? ""];
      })
      .sort((x, y) => Number(x[0]) - Number(y[0]));
    const ports = new Set(svc.map((s) => s[0]));
    const tech = (h.details.technologies ?? "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    const cdn = h.details.cdn;
    if (cdn && cdn !== "none") tech.push(cdn);
    let k = tr("Sous-domaine", "Subdomain");
    if (h.value === h.domain) k = tr("Domaine", "Domain");
    else if ([...ports].some((p) => MAIL_PORTS.has(p))) k = tr("Messagerie", "Mail");
    else if ([...ports].some((p) => WEB_PORTS.has(p)) || (!ports.size && h.details.technologies)) k = tr("Site", "Website");
    else if (ports.size) k = tr("Serveur", "Server");
    const ips = [...new Set(services.filter((s) => s.details.host === h.value).map((s) => serviceIP(s.value)))];
    const cert = certFor(h.value, certs);
    return { n: h.value, targetId: h.target_id, domain: h.domain, k, a: n ? (20 + (i * 360) / n) % 360 : 0, tech, svc, ips, ...(cert ? { cert } : {}) };
  });
}

/** worst returns the most severe open problem of an asset, "ok" without. */
export function worst(open: Issue[]): SevOrOk {
  let w: SevOrOk = "ok";
  for (const i of open) if (RANK[i.sev] < RANK[w]) w = i.sev;
  return w;
}

export type CellState = SevOrOk | "na";

/**
 * catState is the state of one cell of the heat map: "na" when the column
 * does not apply to the asset (emails and fuites apply to registered
 * domains, the others to targets where a check of the column was
 * evaluated).
 */
export function catState(asset: AssetView, cat: Cat, issues: Issue[], evaluated: Map<string, Set<Cat>>): CellState {
  if ((cat === "emails" || cat === "fuites") && asset.n !== asset.domain) return "na";
  const open = issues.filter((i) => !i.fixed && i.host === asset.n && i.cat === cat);
  if (!open.length && !evaluated.get(asset.targetId)?.has(cat)) return "na";
  const w = worst(open);
  return w === "low" ? "med" : w;
}

/** evaluatedCats: for each target, the columns with at least one evaluated check. */
export function evaluatedCats(checks: Check[]): Map<string, Set<Cat>> {
  const m = new Map<string, Set<Cat>>();
  for (const c of checks) {
    if (c.status === "not_applicable" || !c.target_id) continue;
    const cat = catOfModule(c.module);
    if (!cat) continue;
    const set = m.get(c.target_id) ?? new Set<Cat>();
    set.add(cat);
    m.set(c.target_id, set);
  }
  return m;
}

export const STATE_LABEL: Record<CellState, string> = {
  get crit() {
    return tr("Critique", "Critical");
  },
  get high() {
    return tr("Élevé", "High");
  },
  get med() {
    return tr("Moyen", "Medium");
  },
  get low() {
    return tr("Faible", "Low");
  },
  get ok() {
    return tr("Rien à signaler", "All clear");
  },
  get na() {
    return tr("Non concerné", "Not applicable");
  },
};

/** The mockup's password strength, 0 to 4. */
export function pwScore(v: string): number {
  let s = 0;
  if (v.length >= 8) s++;
  if (v.length >= 12) s++;
  if (/[a-z]/.test(v) && /[A-Z]/.test(v) && /\d/.test(v)) s++;
  if (/[^A-Za-z0-9]/.test(v)) s++;
  return s;
}

export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;
export const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;

/** device turns a User-Agent into "iPhone, Safari". */
export function device(ua: string): string {
  const os = /iPhone/.test(ua)
    ? "iPhone"
    : /iPad/.test(ua)
      ? "iPad"
      : /Android/.test(ua)
        ? "Android"
        : /Windows/.test(ua)
          ? "Windows"
          : /Mac OS X|Macintosh/.test(ua)
            ? "Mac"
            : /Linux/.test(ua)
              ? "Linux"
              : tr("Appareil inconnu", "Unknown device");
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /OPR\//.test(ua)
      ? "Opera"
      : /Firefox\//.test(ua)
        ? "Firefox"
        : /Chrome\//.test(ua)
          ? "Chrome"
          : /Safari\//.test(ua)
            ? "Safari"
            : "";
  return browser ? `${os}, ${browser}` : os;
}

const DAY_MS = 86_400_000;

/** daysAgo counts calendar days between iso and now, in local time. */
export function daysAgo(iso: string, now: Date): number {
  const d = new Date(iso);
  const a = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const b = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  return Math.round((b - a) / DAY_MS);
}

/** dayName is a weekday's name, Monday first (0) to Sunday (6), lowercase in French. */
export function dayName(i: number): string {
  const fr = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
  const en = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  return tr(fr[i] ?? "", en[i] ?? "");
}

/** feedDay: "Aujourd’hui", "Hier", then the weekday name within a week. */
export function feedDay(iso: string, now: Date): string {
  const n = daysAgo(iso, now);
  if (n <= 0) return tr("Aujourd’hui", "Today");
  if (n === 1) return tr("Hier", "Yesterday");
  const d = new Date(iso);
  if (n < 7) {
    const name = dayName((d.getDay() + 6) % 7);
    return name.charAt(0).toUpperCase() + name.slice(1);
  }
  return d.toLocaleDateString(locale(), { day: "numeric", month: "long" });
}

/** whenActive: "Actif aujourd’hui", "Actif hier", "Actif il y a 6 jours". */
export function whenActive(iso: string, now: Date): string {
  const n = daysAgo(iso, now);
  if (n <= 0) return tr("Actif aujourd’hui", "Active today");
  if (n === 1) return tr("Actif hier", "Active yesterday");
  return tr(`Actif il y a ${n} jours`, `Active ${n} days ago`);
}

/** sinceText: "il y a 2 h", "il y a 3 jours", "il y a 3 mois". */
export function sinceText(iso: string, now: Date): string {
  const ms = now.getTime() - new Date(iso).getTime();
  const h = Math.floor(ms / 3_600_000);
  if (h < 1) return tr("il y a moins d’une heure", "less than an hour ago");
  if (h < 24) return tr(`il y a ${h} h`, `${h} h ago`);
  const d = Math.floor(h / 24);
  if (d < 31) return tr(`il y a ${d} jour${d > 1 ? "s" : ""}`, `${d} day${d > 1 ? "s" : ""} ago`);
  const m = Math.floor(d / 30);
  if (m < 12) return tr(`il y a ${m} mois`, `${m} month${m > 1 ? "s" : ""} ago`);
  const y = Math.floor(m / 12);
  return tr(`il y a ${y} an${y > 1 ? "s" : ""}`, `${y} year${y > 1 ? "s" : ""} ago`);
}

/** weekly keeps one score per week, the last of each, oldest first. */
/** weeklySlots is the score at the end of each of the last weeks, oldest
 * first, null for a week before any scan: the chart keeps its whole period. */
export function weeklySlots(points: { at: string; score: number | null }[], weeks: number, now: Date): (number | null)[] {
  const out: (number | null)[] = [];
  for (let w = weeks - 1; w >= 0; w--) {
    const end = now.getTime() - w * 7 * DAY_MS;
    let v: number | null = null;
    for (const p of points) {
      if (p.score !== null && new Date(p.at).getTime() <= end) v = p.score;
    }
    out.push(v);
  }
  return out;
}

export function weekly(points: { at: string; score: number | null }[], weeks: number, now: Date): number[] {
  const out: number[] = [];
  for (let w = weeks - 1; w >= 0; w--) {
    const end = now.getTime() - w * 7 * DAY_MS;
    let v: number | null = null;
    for (const p of points) {
      if (p.score !== null && new Date(p.at).getTime() <= end) v = p.score;
    }
    if (v !== null) out.push(v);
  }
  return out;
}

/** initials: "Jordy Konda" -> "JK"; falls back to the email's first letter. */
export function initials(name: string, email: string): string {
  const s = name
    .split(/\s+/)
    .filter(Boolean)
    .map((x) => x[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
  return s || (email[0] ?? "?").toUpperCase();
}

/** money formats a price in dollars: "35 $". */
export function money(v: number): string {
  return `${v} $`;
}

/**
 * IssueGroup is one problem as the customer sees it: the same check failing
 * on several names of a domain (the root and www, one certificate) is one
 * line, fixed in one gesture. lead is the member shown (the first open one,
 * most severe).
 */
export interface IssueGroup {
  key: string;
  lead: Issue;
  members: Issue[];
  hosts: string[];
  /** fixed: every member is done (fixed or accepted). */
  fixed: boolean;
  /** gain: the points its open members win (all of them once done). */
  gain: number;
}

export function groupIssues(issues: Issue[]): IssueGroup[] {
  const by = new Map<string, Issue[]>();
  for (const i of issues) {
    const k = `${i.targetId}/${i.finding.check_id}/${i.title}`;
    const list = by.get(k);
    if (list) list.push(i);
    else by.set(k, [i]);
  }
  return [...by].map(([key, members]) => {
    const sorted = members.slice().sort((a, b) => Number(a.fixed) - Number(b.fixed) || byPriority(a, b));
    const open = sorted.filter((m) => !m.fixed);
    return {
      key,
      lead: sorted[0]!,
      members: sorted,
      hosts: [...new Set(sorted.map((m) => m.host))],
      fixed: open.length === 0,
      gain: (open.length ? open : sorted).reduce((s, m) => s + m.gain, 0),
    };
  });
}

/** hostsText names a group's hosts: "a, b" or "a, b et 3 autres". */
export function hostsText(hosts: string[]): string {
  if (hosts.length <= 2) return hosts.join(", ");
  const more = hosts.length - 2;
  return tr(`${hosts[0]}, ${hosts[1]} et ${more} autre${more > 1 ? "s" : ""}`, `${hosts[0]}, ${hosts[1]} and ${more} more`);
}

/** Verdict is what the verification scan said after a problem was marked fixed. */
export type Verdict = { state: "checking" } | { state: "confirmed" } | { state: "still"; at: string } | { state: "late" };

/** groupVerdict sums up its members' verdicts: still beats checking beats confirmed. */
export function groupVerdict(members: Issue[], verdicts: Record<string, Verdict>): Verdict | undefined {
  const vs = members.map((m) => verdicts[m.targetId + "/" + m.id]).filter((v): v is Verdict => v !== undefined);
  if (!vs.length) return undefined;
  return vs.find((v) => v.state === "still") ?? vs.find((v) => v.state === "checking") ?? vs.find((v) => v.state === "late") ?? vs[0];
}

/** verdictText words a verdict for the problem lines. */
export function verdictText(v: Verdict): string {
  switch (v.state) {
    case "checking":
      return tr("Vérification en cours…", "Checking…");
    case "confirmed":
      return tr("Confirmé par le contrôle", "Confirmed by the check");
    case "still": {
      const at = new Date(v.at).toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" });
      return tr(`Toujours présent au contrôle de ${at}`, `Still there at the ${at} check`);
    }
    case "late":
      return tr("Vérification en attente : le résultat arrivera ici", "Check pending: the result will appear here");
  }
}

// The score explained. It is the engine's (package posture): the evaluated
// checks, each weighted by its severity, and the share of that weight that
// passed. Info checks weigh nothing: they describe, they do not warn. The
// dashboard only words it and lists its parts; it never computes its own.

/** WEIGHT mirrors posture.Weight, to rank what lowers the score. */
export const WEIGHT: Record<Severity, number> = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };

/** scoreLevel words a score's level: "Bon niveau". */
export function scoreLevel(score: number | null): string {
  if (score === null) return tr("Pas encore de score", "No score yet");
  return score >= 90
    ? tr("Très bon niveau", "Very good level")
    : score >= 75
      ? tr("Bon niveau", "Good level")
      : score >= 50
        ? tr("Niveau moyen", "Fair level")
        : tr("Niveau faible", "Weak level");
}

/** scoreVerdict words a score in one sentence, with the problems to fix.
 * open counts problem lines, as Problèmes and Aujourd'hui do (the same
 * check failing on several names is one), so every screen gives the same
 * number. */
export function scoreVerdict(score: number | null, open: number): string {
  if (score === null) return tr("Pas encore de score : il apparaît après le premier scan.", "No score yet: it appears after the first scan.");
  const pb =
    open === 0
      ? tr("aucun problème à corriger", "nothing to fix")
      : tr(`${open} problème${open > 1 ? "s" : ""} à corriger`, `${open} problem${open > 1 ? "s" : ""} to fix`);
  return `${scoreLevel(score)}, ${pb}.`;
}

/** WeakCheck is a failed check that lowers the score, with its problem. */
export interface WeakCheck {
  key: string;
  title: string;
  domain: string;
  severity: Severity;
  /** gain: the points its open problems win once fixed (as on Aujourd'hui). */
  gain: number;
  /** issue: its first open problem, to open its sheet; absent when none is open. */
  issue?: Issue;
}

/** weakChecks lists the failed checks that weigh in the score, heaviest
 * first, then those winning the most points. */
export function weakChecks(checks: Check[], issues: Issue[], targets: Target[]): WeakCheck[] {
  const domain = new Map(targets.map((t) => [t.id, t.domain]));
  return checks
    .filter((c) => c.status === "failed" && WEIGHT[c.severity] > 0)
    .map((c) => {
      const open = issues.filter((i) => !i.fixed && i.targetId === c.target_id && i.finding.check_id === c.id).sort(byPriority);
      const w: WeakCheck = {
        key: `${c.target_id ?? ""}/${c.id}`,
        title: localTitle(c.title, c.title_fr),
        domain: domain.get(c.target_id ?? "") ?? "",
        severity: c.severity,
        gain: open.reduce((n, i) => n + i.gain, 0),
      };
      if (open[0]) w.issue = open[0];
      return w;
    })
    .sort((a, b) => WEIGHT[b.severity] - WEIGHT[a.severity] || b.gain - a.gain || a.title.localeCompare(b.title));
}

/** The categories of the check catalog, worded for "Ce qui va bien". */
export const CATEGORY_LABEL: Record<Category, string> = {
  get email() {
    return tr("Vos emails", "Your email");
  },
  get web() {
    return tr("Vos sites web", "Your websites");
  },
  get tls() {
    return tr("Vos certificats et le chiffrement", "Your certificates and encryption");
  },
  get dns() {
    return tr("Vos noms de domaine", "Your domain names");
  },
  get network() {
    return tr("Vos serveurs et leurs ports", "Your servers and their ports");
  },
  get identity() {
    return tr("Vos accès et identités", "Your access and identities");
  },
  get cloud() {
    return tr("Votre cloud", "Your cloud");
  },
  get leaks() {
    return tr("Vos fuites de données", "Your data leaks");
  },
};

/** StrongGroup is what passed in one category: each check once, even when
 * it passed on several domains. */
export interface StrongGroup {
  category: Category;
  label: string;
  titles: string[];
}

/** strongChecks groups the passed checks that weigh in the score by
 * category, the categories with the most first. */
export function strongChecks(checks: Check[]): { total: number; groups: StrongGroup[] } {
  const passed = checks.filter((c) => c.status === "passed" && WEIGHT[c.severity] > 0);
  const by = new Map<Category, Set<string>>();
  for (const c of passed) {
    const set = by.get(c.category) ?? new Set<string>();
    set.add(localTitle(c.title, c.title_fr));
    by.set(c.category, set);
  }
  const groups = [...by].map(([category, titles]) => ({ category, label: CATEGORY_LABEL[category] ?? category, titles: [...titles].sort((a, b) => a.localeCompare(b)) }));
  groups.sort((a, b) => b.titles.length - a.titles.length || a.label.localeCompare(b.label));
  return { total: passed.length, groups };
}

// Progress on Aujourd'hui: what the customer achieved lately, the reason
// to stay after the trial. Over the last 30 days rather than the calendar
// month, which would be nearly empty on its first days.

export const PROGRESS_DAYS = 30;

export interface Progress {
  /** fixed: problem lines fixed in the period (as Problèmes counts them). */
  fixed: number;
  /** from, to: the score at the start of the period and now. */
  from: number | null;
  to: number | null;
  /** sinceFirst: the organization is younger than the period, so it
   * counts from its first scored day. */
  sinceFirst: boolean;
}

/** progressOf sums up the last PROGRESS_DAYS days, or null before any
 * score exists (nothing to compare). */
export function progressOf(issues: Issue[], trend: { at: string; score: number | null }[], score: number | null, now: Date): Progress | null {
  const start = now.getTime() - PROGRESS_DAYS * 86400000;
  const points = trend.filter((p) => p.score !== null).sort((a, b) => a.at.localeCompare(b.at));
  if (!points.length || score === null) return null;
  // The score when the period began: the last one known by then (scans can
  // be days apart), else the first ever, for an organization younger than
  // the period.
  const before = points.filter((p) => new Date(p.at).getTime() <= start);
  const sinceFirst = before.length === 0;
  const inPeriod = before[before.length - 1] ?? points[0]!;
  const fixedLately = issues.filter((i) => i.finding.status === "fixed" && i.finding.fixed_at && new Date(i.finding.fixed_at).getTime() >= start);
  return { fixed: groupIssues(fixedLately).length, from: inPeriod.score, to: score, sinceFirst };
}

/** progressText words a Progress in one or two sentences. */
export function progressText(p: Progress): string {
  const when = p.sinceFirst ? tr("Depuis votre premier scan", "Since your first scan") : tr(`Ces ${PROGRESS_DAYS} derniers jours`, `Over the last ${PROGRESS_DAYS} days`);
  const fixed =
    p.fixed === 0
      ? tr("aucun problème corrigé pour l’instant", "no problem fixed yet")
      : tr(`vous avez corrigé ${p.fixed} problème${p.fixed > 1 ? "s" : ""}`, `you fixed ${p.fixed} problem${p.fixed > 1 ? "s" : ""}`);
  let score = "";
  if (p.from !== null && p.to !== null) {
    score =
      p.to > p.from
        ? tr(` Votre score est passé de ${p.from} à ${p.to}.`, ` Your score went from ${p.from} to ${p.to}.`)
        : p.to < p.from
          ? tr(` Votre score est descendu de ${p.from} à ${p.to} : de nouveaux points faibles sont apparus.`, ` Your score went down from ${p.from} to ${p.to}: new weak points appeared.`)
          : tr(` Votre score reste à ${p.to}.`, ` Your score stays at ${p.to}.`);
  }
  return `${when}, ${fixed}.${score}`;
}

/** families are the families of automated checks, with how many passed
 * out of those evaluated (Aujourd'hui and Rapports). Identities appear
 * once a Microsoft 365 tenant has been audited: without a connection there
 * is nothing to show. */
export function families(checks: Check[]): [string, number, number][] {
  const tally = (modules: string[]): [number, number] => {
    const cs = checks.filter((c) => modules.includes(c.module) && c.status !== "not_applicable");
    return [cs.filter((c) => c.status === "passed").length, cs.length];
  };
  const out: [string, number, number][] = [
    [tr("Emails", "Email"), ...tally(["email"])],
    [tr("Chiffrement", "Encryption"), ...tally(["tls", "web"])],
    [tr("Ports et services", "Ports and services"), ...tally(["ports"])],
    [tr("Fuites de données", "Data leaks"), ...tally(["leaks"])],
  ];
  const identities = tally(["m365"]);
  if (identities[1] > 0) out.push([tr("Identités", "Identities"), ...identities]);
  return out;
}
