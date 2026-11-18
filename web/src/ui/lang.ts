// Customer data in the user's language: findings carry their French text
// (translations.fr), the English one is their own fields.

import type { Finding, FindingText } from "../api/types";
import { getLang, type Lang } from "../i18n";

/** findingText is a finding's title, explanation and steps in lang, or its
 * English text when it has no translation (older findings, until their
 * next scan). */
export function findingText(f: Finding, lang: Lang = getLang()): FindingText {
  const t = lang === "en" ? undefined : f.translations?.[lang];
  return t ?? { title: f.title, description: f.description, remediation: f.remediation ?? [] };
}

/** localTitle picks the title in lang among an English one and its French
 * translation (activity, priorities, checks). */
export function localTitle(en: string | undefined, fr: string | undefined, lang: Lang = getLang()): string {
  return (lang === "fr" && fr) || en || "";
}
