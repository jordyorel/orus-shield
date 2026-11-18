import { describe, expect, it } from "vitest";
import type { Finding } from "../api/types";
import { toIssues } from "./model";
import { mailtoLink, PROOF_MAX, providerMessage, whatsappLink } from "./share";

const dmarc: Finding = {
  target_id: "t1",
  schema_version: "1",
  id: "f1",
  module_id: "email",
  check_id: "email-dmarc-missing",
  target: "example.cg",
  asset: "_dmarc.example.cg",
  severity: "high",
  title: "No DMARC record",
  description: "Anyone can send email in your name.",
  evidence: "_dmarc.example.cg: no TXT record",
  remediation: ["Publish a DMARC record.", "Read the reports for two weeks."],
  references: null,
  first_seen: "",
  last_seen: "",
  status: "open",
  translations: {
    fr: {
      title: "Aucun enregistrement DMARC",
      description: "N’importe qui peut envoyer des emails en votre nom.",
      remediation: ["Publiez un enregistrement DMARC.", "Lisez les rapports pendant deux semaines."],
    },
  },
  minutes: 15,
  gain: 9,
  emerging: false,
};

const issue = (f: Finding = dmarc) => toIssues([f], [])[0]!;

describe("providerMessage", () => {
  it("writes the whole problem in French, signed by the sender", () => {
    const m = providerMessage(issue(), ["example.cg", "shop.example.cg"], "fr", "Jordy Konda");
    expect(m.subject).toBe("À corriger sur example.cg : Aucun enregistrement DMARC");
    for (const want of [
      "Gravité : élevée",
      "Concerne : example.cg, shop.example.cg",
      "environ 15 minutes",
      "N’importe qui peut envoyer des emails en votre nom.",
      "1. Publiez un enregistrement DMARC.\n2. Lisez les rapports pendant deux semaines.",
      "Preuve technique :\n_dmarc.example.cg: no TXT record",
      "Merci,\nJordy Konda",
    ]) {
      expect(m.body).toContain(want);
    }
  });

  it("writes it in English whatever the dashboard's language", () => {
    const m = providerMessage(issue(), [], "en", "");
    expect(m.subject).toBe("To fix on example.cg: No DMARC record");
    expect(m.body).toContain("Severity: high");
    expect(m.body).toContain("Concerns: example.cg");
    expect(m.body).toContain("1. Publish a DMARC record.");
    expect(m.body.endsWith("Thank you")).toBe(true);
    expect(m.body).not.toMatch(/Bonjour|Gravité|Merci/);
  });

  it("bounds the evidence it quotes", () => {
    const m = providerMessage(issue({ ...dmarc, evidence: "x".repeat(5000) }), [], "fr", "");
    expect(m.body).toContain("x".repeat(PROOF_MAX) + "…");
    expect(m.body).not.toContain("x".repeat(PROOF_MAX + 1));
  });
});

describe("share links", () => {
  it("carries the message, encoded, without a recipient", () => {
    const m = { subject: "À corriger & vite", body: "Ligne 1\nLigne 2" };
    expect(mailtoLink(m)).toBe("mailto:?subject=%C3%80%20corriger%20%26%20vite&body=Ligne%201%0ALigne%202");
    const wa = new URL(whatsappLink(m));
    expect(wa.origin).toBe("https://wa.me");
    expect(wa.searchParams.get("text")).toBe("*À corriger & vite*\n\nLigne 1\nLigne 2");
  });
});
