// The mockup's vocabulary (severities, the five check columns, assets) built
// from the API's data. Pure functions: every screen and the tests use them.

import type { Check, Finding, OrgAsset, Severity } from "../api/types";

/** The mockup's severity keys, plus "low" (shown "Faible") which it lacks. */
export type Sev = "crit" | "high" | "med" | "low";
export type SevOrOk = Sev | "ok";

export const SEV: Record<SevOrOk, [string, string]> = {
  crit: ["Critique", "s-crit"],
  high: ["Élevé", "s-high"],
  med: ["Moyen", "s-med"],
  low: ["Faible", "s-med"],
  ok: ["Corrigé", "s-ok"],
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
  ["emails", "Emails"],
  ["tls", "TLS"],
  ["ports", "Ports"],
  ["fuites", "Fuites"],
  ["menaces", "Menaces"],
];
export const CATNAME: Record<Cat, string> = {
  emails: "Emails",
  tls: "Chiffrement",
  ports: "Ports et services",
  fuites: "Fuites de données",
  menaces: "Menaces émergentes",
};

/**
 * catOfModule maps an engine module to a column. web (headers, cookies,
 * HTTPS redirect) goes with TLS, "Chiffrement" of the site; vulns and zap
 * (deep web scan) are the known and application flaws of "Menaces"; cdn
 * and discovery have no findings of their own. Fuites has no module yet.
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
      return "menaces";
  }
  return null;
}

/** The module label of a problem row (the mockup's i.module). */
export function moduleName(f: Finding): string {
  if (f.emerging) return "Menaces émergentes";
  switch (f.module_id) {
    case "email":
      return "Emails";
    case "tls":
      return "TLS";
    case "web":
      return "Site web";
    case "ports":
      return "Ports";
    case "vulns":
      return "Vulnérabilités";
    case "zap":
      return "Application web";
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
    .map((f) => ({
      id: f.id,
      targetId: f.target_id,
      domain: f.target,
      moduleId: f.module_id,
      sev: sevOf(f.severity),
      fixed: f.status !== "open",
      accepted: f.status === "accepted_risk",
      title: f.title,
      host: hostOf(f.asset, f.target, ips),
      module: moduleName(f),
      cat: f.emerging ? "menaces" : catOfModule(f.module_id),
      mins: f.minutes,
      gain: f.gain,
      type: f.emerging ? "menace" : f.module_id === "leaks" ? "fuite" : "vuln",
      why: f.description,
      steps: f.remediation ?? [],
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
}

const MAIL_PORTS = new Set(["25", "465", "587", "110", "143", "993", "995"]);
const WEB_PORTS = new Set(["80", "443", "8080", "8443"]);

/** toAssets lists the current hostnames, with their services and technologies. */
export function toAssets(assets: OrgAsset[]): AssetView[] {
  const current = assets.filter((a) => !a.gone_at);
  const services = current.filter((a) => a.kind === "service");
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
    let k = "Sous-domaine";
    if (h.value === h.domain) k = "Domaine";
    else if ([...ports].some((p) => MAIL_PORTS.has(p))) k = "Messagerie";
    else if ([...ports].some((p) => WEB_PORTS.has(p)) || (!ports.size && h.details.technologies)) k = "Site";
    else if (ports.size) k = "Serveur";
    return { n: h.value, targetId: h.target_id, domain: h.domain, k, a: n ? (20 + (i * 360) / n) % 360 : 0, tech, svc };
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
 * does not apply to the asset (emails apply to registered domains, fuites
 * has no module yet, the others to targets where a check of the column
 * was evaluated).
 */
export function catState(asset: AssetView, cat: Cat, issues: Issue[], evaluated: Map<string, Set<Cat>>): CellState {
  if (cat === "fuites") return "na";
  if (cat === "emails" && asset.n !== asset.domain) return "na";
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
  crit: "Critique",
  high: "Élevé",
  med: "Moyen",
  low: "Faible",
  ok: "Rien à signaler",
  na: "Non concerné",
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
              : "Appareil inconnu";
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

export const DAYS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];

/** feedDay: "Aujourd’hui", "Hier", then the weekday name within a week. */
export function feedDay(iso: string, now: Date): string {
  const n = daysAgo(iso, now);
  if (n <= 0) return "Aujourd’hui";
  if (n === 1) return "Hier";
  const d = new Date(iso);
  if (n < 7) {
    const name = DAYS[(d.getDay() + 6) % 7] ?? "";
    return name.charAt(0).toUpperCase() + name.slice(1);
  }
  return d.toLocaleDateString("fr-FR", { day: "numeric", month: "long" });
}

/** whenActive: "Actif aujourd’hui", "Actif hier", "Actif il y a 6 jours". */
export function whenActive(iso: string, now: Date): string {
  const n = daysAgo(iso, now);
  if (n <= 0) return "Actif aujourd’hui";
  if (n === 1) return "Actif hier";
  return `Actif il y a ${n} jours`;
}

/** sinceText: "il y a 2 h", "il y a 3 jours", "il y a 3 mois". */
export function sinceText(iso: string, now: Date): string {
  const ms = now.getTime() - new Date(iso).getTime();
  const h = Math.floor(ms / 3_600_000);
  if (h < 1) return "il y a moins d’une heure";
  if (h < 24) return `il y a ${h} h`;
  const d = Math.floor(h / 24);
  if (d < 31) return `il y a ${d} jour${d > 1 ? "s" : ""}`;
  const m = Math.floor(d / 30);
  if (m < 12) return `il y a ${m} mois`;
  const y = Math.floor(m / 12);
  return `il y a ${y} an${y > 1 ? "s" : ""}`;
}

/** weekly keeps one score per week, the last of each, oldest first. */
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

/** money formats a price: "35 $" or "20 000 FCFA". */
export function money(v: number, cur: "usd" | "xaf"): string {
  return cur === "usd" ? `${v} $` : `${v.toLocaleString("fr-FR")} FCFA`;
}
