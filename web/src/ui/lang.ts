// The language the dashboard shows customer data in. French for now; the
// English interface (step 2 of the bilingual product) will make it the
// user's choice.

import type { Finding, FindingText } from "../api/types";

export type Lang = "fr" | "en";

export const LANG: Lang = "fr";

/** findingText is a finding's title, explanation and steps in lang, or its
 * English text when it has no translation (older findings, until their
 * next scan). */
export function findingText(f: Finding, lang: Lang = LANG): FindingText {
  const t = lang === "en" ? undefined : f.translations?.[lang];
  return t ?? { title: f.title, description: f.description, remediation: f.remediation ?? [] };
}

/** localTitle picks the title in lang among an English one and its French
 * translation (activity, priorities, checks). */
export function localTitle(en: string | undefined, fr: string | undefined, lang: Lang = LANG): string {
  return (lang === "fr" && fr) || en || "";
}
