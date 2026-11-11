// French wording and number formats. Everything shown to the user is
// written here or in the pages, never taken from the API's English texts.

import type { Priority, Severity } from "./api/types";

const HOUR = 3600;
const DAY = 24 * HOUR;

/** severityLabel: masculine forms, as in the mockups ("Élevé"). */
export function severityLabel(s: Severity): string {
  return { critical: "Critique", high: "Élevé", medium: "Moyen", low: "Faible", info: "Info" }[s];
}

/** plural picks the French form: singular for 0 and 1, plural above. */
export function plural(n: number, one: string, many: string): string {
  return Math.abs(n) > 1 ? many : one;
}

/** signed writes a change with its sign: "+16", "−3" (U+2212, the minus sign). */
export function signed(n: number): string {
  if (n > 0) return "+" + n;
  if (n < 0) return "−" + Math.abs(n);
  return "0";
}

/** decimal writes one decimal with a French comma: 4.2 -> "4,2". */
function decimal(n: number): string {
  return n.toFixed(1).replace(".", ",");
}

/** duration writes a remediation time: hours under a day, else days ("4,2 j"). */
export function duration(seconds: number): string {
  if (seconds < HOUR) return "< 1 h";
  if (seconds < DAY) return `${Math.round(seconds / HOUR)} h`;
  return `${decimal(seconds / DAY)} j`;
}

/**
 * durationChange compares two remediation times. Under an hour of
 * difference is "Stable". worse is true when fixes got slower.
 */
export function durationChange(current: number, previous: number): { text: string; worse: boolean } {
  const d = current - previous;
  if (Math.abs(d) < HOUR) return { text: "Stable", worse: false };
  return d < 0 ? { text: "−" + duration(-d), worse: false } : { text: "+" + duration(d), worse: true };
}

function startOfDay(d: Date): number {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

/** relativeDay counts calendar days in the browser's time zone. */
export function relativeDay(iso: string, now: Date): string {
  const days = Math.round((startOfDay(now) - startOfDay(new Date(iso))) / (DAY * 1000));
  if (days <= 0) return "Aujourd’hui";
  if (days === 1) return "Hier";
  return `Il y a ${days} jours`;
}

/** dayAndTime: "Aujourd’hui, 06:00", as in the mockups' tables. */
export function dayAndTime(iso: string, now: Date): string {
  const d = new Date(iso);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${relativeDay(iso, now)}, ${hh}:${mm}`;
}

const months = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."];

export function shortDate(iso: string): string {
  const d = new Date(iso);
  return `${d.getDate()} ${months[d.getMonth()]}`;
}

/** scoreBand colors a score: red under 50, orange under 80, green above. */
export function scoreBand(score: number): "bad" | "mid" | "ok" {
  if (score < 50) return "bad";
  if (score < 80) return "mid";
  return "ok";
}

/**
 * priorityText writes one entry of the priority list. The API says which
 * rule produced it and gives the facts; the sentence is the dashboard's.
 */
export function priorityText(p: Priority, now: Date): { title: string; detail: string } {
  switch (p.kind) {
    case "finding":
      return {
        title: p.title,
        detail: `${severityLabel(p.severity)} · ${p.asset} · ouverte ${relativeDay(p.first_seen, now).toLowerCase()}`,
      };
    case "verify_target":
      return {
        title: `Vérifier la propriété de ${p.domain}`,
        detail: "Un enregistrement TXT dans votre DNS. Nécessaire pour les vérifications actives (ports exposés).",
      };
    case "scan_target":
      return p.last_scan_at
        ? {
            title: `Relancer un scan de ${p.domain}`,
            detail: `Dernier scan ${relativeDay(p.last_scan_at, now).toLowerCase()} : les résultats peuvent être dépassés.`,
          }
        : { title: `Lancer un premier scan de ${p.domain}`, detail: "Aucun résultat pour ce domaine." };
  }
}

/** initial is the avatar letter. */
export function initial(email: string): string {
  return (email[0] ?? "?").toUpperCase();
}

/** moduleLabel: the family of a check, as the mockups name them. */
export function moduleLabel(moduleId: string): string {
  return ({ email: "Emails", tls: "TLS et certificats", ports: "Ports et services", cdn: "Protection web", web: "Web", discovery: "Découverte" } as Record<string, string>)[moduleId] ?? moduleId;
}

/** age: "il y a 2 j", as in the vulnerabilities list. */
export function age(iso: string, now: Date): string {
  const days = Math.round((startOfDay(now) - startOfDay(new Date(iso))) / (DAY * 1000));
  if (days <= 0) return "aujourd’hui";
  return `il y a ${days} j`;
}
