// "Envoyer à mon prestataire": most small businesses do not fix things
// themselves. Their web agency, host or part-time IT person does. This
// builds the message the customer sends them, by email or WhatsApp, with
// everything needed to fix the problem without an Orus Shield account:
// what, where, why, the steps and the technical evidence.
//
// The message is written in the language the customer picks for it, which
// may differ from the dashboard's (a provider abroad). Nothing leaves the
// browser until the customer clicks: email and WhatsApp open through
// their standard links (mailto:, wa.me), and the customer sends it.

import type { Lang } from "../i18n";
import { findingText } from "./lang";
import type { Issue, Sev } from "./model";

const SEV_TEXT: Record<Lang, Record<Sev, string>> = {
  fr: { crit: "critique", high: "élevée", med: "moyenne", low: "faible" },
  en: { crit: "critical", high: "high", med: "medium", low: "low" },
};

/** PROOF_MAX bounds the evidence quoted: email and WhatsApp links carry the
 * whole text in their URL, and some clients cut long ones. */
export const PROOF_MAX = 800;

export interface ProviderMessage {
  subject: string;
  body: string;
}

/**
 * providerMessage writes the message about issue i, found on hosts (all the
 * names of its problem line), in lang. sender signs it when known.
 */
export function providerMessage(i: Issue, hosts: string[], lang: Lang, sender: string): ProviderMessage {
  const t = findingText(i.finding, lang);
  const where = (hosts.length ? hosts : [i.host]).join(", ");
  const steps = (t.remediation ?? []).map((s, k) => `${k + 1}. ${s}`).join("\n");
  let proof = i.proof.trim();
  if (proof.length > PROOF_MAX) proof = proof.slice(0, PROOF_MAX) + "…";
  const name = sender.trim();
  if (lang === "en") {
    return {
      subject: `To fix on ${i.domain}: ${t.title}`,
      body: [
        "Hello,",
        "",
        `Our security monitoring (Orus Shield) found a problem on ${i.domain} that we would like you to fix.`,
        "",
        `Problem: ${t.title}`,
        `Severity: ${SEV_TEXT.en[i.sev]}`,
        `Concerns: ${where}`,
        `Estimated time: about ${i.mins} minutes`,
        "",
        "Why it matters:",
        t.description,
        ...(steps ? ["", "How to fix it:", steps] : []),
        ...(proof ? ["", "Technical evidence:", proof] : []),
        "",
        "Once it is done, please let us know: we will run a check to confirm it.",
        "",
        name ? `Thank you,\n${name}` : "Thank you",
      ].join("\n"),
    };
  }
  return {
    subject: `À corriger sur ${i.domain} : ${t.title}`,
    body: [
      "Bonjour,",
      "",
      `Notre surveillance de sécurité (Orus Shield) a relevé un problème sur ${i.domain}, que nous vous demandons de corriger.`,
      "",
      `Problème : ${t.title}`,
      `Gravité : ${SEV_TEXT.fr[i.sev]}`,
      `Concerne : ${where}`,
      `Temps estimé : environ ${i.mins} minutes`,
      "",
      "Pourquoi c’est important :",
      t.description,
      ...(steps ? ["", "Comment corriger :", steps] : []),
      ...(proof ? ["", "Preuve technique :", proof] : []),
      "",
      "Une fois la correction faite, merci de nous prévenir : nous lancerons un contrôle pour la confirmer.",
      "",
      name ? `Merci,\n${name}` : "Merci",
    ].join("\n"),
  };
}

/** mailtoLink opens the customer's email app with the message, no recipient
 * set: they choose their provider's address there. */
export function mailtoLink(m: ProviderMessage): string {
  return `mailto:?subject=${encodeURIComponent(m.subject)}&body=${encodeURIComponent(m.body)}`;
}

/** whatsappLink opens WhatsApp (app or web) with the message, ready to send
 * to a chosen contact. WhatsApp has no subject: it leads the text. */
export function whatsappLink(m: ProviderMessage): string {
  return `https://wa.me/?text=${encodeURIComponent(`*${m.subject}*\n\n${m.body}`)}`;
}
