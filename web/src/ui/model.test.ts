import { describe, expect, it } from "vitest";
import type { Check, Finding, OrgAsset, Target } from "../api/types";
import { catState, device, evaluatedCats, feedDay, hostOf, initials, money, pwScore, progressOf, progressText, scoreVerdict, strongChecks, toAssets, toIssues, weakChecks, weekly, worst } from "./model";

const asset = (kind: OrgAsset["kind"], value: string, details: Record<string, string> = {}, domain = "example.cg"): OrgAsset => ({
  target_id: "t1",
  domain,
  id: kind + value,
  kind,
  value,
  details,
  sources: ["x"],
  first_seen: "2026-11-01T00:00:00Z",
  last_seen: "2026-11-01T00:00:00Z",
  gone_at: null,
});

const finding = (over: Partial<Finding>): Finding => ({
  target_id: "t1",
  schema_version: "1",
  id: "f1",
  module_id: "email",
  check_id: "dmarc-missing",
  target: "example.cg",
  asset: "_dmarc.example.cg",
  severity: "high",
  title: "No DMARC",
  description: "d",
  evidence: "e",
  remediation: ["a", "b"],
  references: null,
  first_seen: "2026-11-01T00:00:00Z",
  last_seen: "2026-11-01T00:00:00Z",
  status: "open",
  minutes: 15,
  gain: 9,
  emerging: false,
  ...over,
});

describe("hostOf", () => {
  const ips = new Map([["192.0.2.10", "srv.example.cg"]]);
  it.each([
    ["_dmarc.example.cg", "example.cg"],
    ["s1._domainkey.example.cg", "example.cg"],
    ["https://www.example.cg/login#tpl-id", "www.example.cg"],
    ["mail.example.cg:443", "mail.example.cg"],
    ["192.0.2.10:3389", "srv.example.cg"],
    ["[2001:db8::1]:22", "2001:db8::1"],
  ])("%s -> %s", (a, want) => expect(hostOf(a, "example.cg", ips)).toBe(want));
});

describe("toIssues and toAssets", () => {
  const assets = [
    asset("hostname", "example.cg"),
    asset("hostname", "srv.example.cg", { technologies: "OpenSSH 9.6p1, Ubuntu" }),
    asset("service", "192.0.2.10:3389/tcp", { host: "srv.example.cg", expected: "rdp", banner: "ms-wbt-server" }),
    asset("hostname", "old.example.cg"),
  ];
  assets[3] = { ...assets[3]!, gone_at: "2026-11-02T00:00:00Z" };
  const issues = toIssues(
    [
      finding({}),
      finding({ id: "f2", module_id: "ports", asset: "192.0.2.10:3389", severity: "critical", check_id: "rdp" }),
      finding({ id: "f3", severity: "info" }),
      finding({ id: "f4", module_id: "vulns", emerging: true, status: "fixed" }),
    ],
    assets,
  );

  it("maps findings to the mockup's problems", () => {
    expect(issues.map((i) => [i.id, i.host, i.sev, i.cat, i.type, i.fixed])).toEqual([
      ["f1", "example.cg", "high", "emails", "vuln", false],
      ["f2", "srv.example.cg", "crit", "ports", "vuln", false],
      ["f4", "example.cg", "high", "menaces", "menace", true],
    ]);
  });

  it("lists current hostnames with their services and technologies", () => {
    const views = toAssets(assets);
    expect(views.map((v) => [v.n, v.k])).toEqual([
      ["example.cg", "Domaine"],
      ["srv.example.cg", "Serveur"],
    ]);
    expect(views[1]?.svc).toEqual([["3389", "rdp", "ms-wbt-server"]]);
    expect(views[1]?.tech).toEqual(["OpenSSH 9.6p1", "Ubuntu"]);
  });

  it("colours the heat map cells", () => {
    const views = toAssets(assets);
    const checks: Check[] = [
      { target_id: "t1", id: "rdp", title: "", module: "ports", category: "network", severity: "critical", status: "failed", findings: 1, evaluated_at: "" },
      { target_id: "t1", id: "dmarc-missing", title: "", module: "email", category: "email", severity: "high", status: "failed", findings: 1, evaluated_at: "" },
    ];
    const ev = evaluatedCats(checks);
    const [root, srv] = views;
    expect(catState(root!, "emails", issues, ev)).toBe("high");
    expect(catState(srv!, "emails", issues, ev)).toBe("na");
    expect(catState(srv!, "ports", issues, ev)).toBe("crit");
    expect(catState(root!, "ports", issues, ev)).toBe("ok");
    expect(catState(root!, "tls", issues, ev)).toBe("na");
    expect(catState(root!, "fuites", issues, ev)).toBe("na");
    expect(worst(issues.filter((i) => !i.fixed))).toBe("crit");
  });
});

describe("helpers", () => {
  it("scores passwords as the mockup does", () => {
    expect(pwScore("")).toBe(0);
    expect(pwScore("Abcdefgh1234")).toBe(3);
    expect(pwScore("Abcdefgh1234!")).toBe(4);
  });
  it("names devices", () => {
    expect(device("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit Version/17.0 Mobile Safari/604.1")).toBe("iPhone, Safari");
    expect(device("Mozilla/5.0 (Windows NT 10.0) AppleWebKit Chrome/131.0 Safari/537.36")).toBe("Windows, Chrome");
  });
  it("writes days", () => {
    const now = new Date(2026, 10, 12, 15);
    expect(feedDay(new Date(2026, 10, 12, 9).toISOString(), now)).toBe("Aujourd’hui");
    expect(feedDay(new Date(2026, 10, 11, 9).toISOString(), now)).toBe("Hier");
    expect(feedDay(new Date(2026, 10, 9, 9).toISOString(), now)).toBe("Lundi");
  });
  it("keeps one score per week", () => {
    const now = new Date("2026-11-12T12:00:00Z");
    const pts = [
      { at: "2026-10-28T12:00:00Z", score: 50 },
      { at: "2026-11-02T12:00:00Z", score: 60 },
      { at: "2026-11-04T12:00:00Z", score: null },
      { at: "2026-11-11T12:00:00Z", score: 70 },
    ];
    expect(weekly(pts, 4, now)).toEqual([50, 60, 70]);
  });
  it("formats names and money", () => {
    expect(initials("Jordy Konda", "j@x.cg")).toBe("JK");
    expect(initials("", "j@x.cg")).toBe("J");
    expect(money(35)).toBe("35 $");
  });
});

describe("the score explained", () => {
  const check = (over: Partial<Check>): Check => ({
    target_id: "t1",
    id: "dmarc-missing",
    title: "DMARC record published",
    title_fr: "Enregistrement DMARC publié",
    module: "email",
    category: "email",
    severity: "high",
    status: "passed",
    findings: 0,
    evaluated_at: "",
    ...over,
  });
  const targets = [
    { id: "t1", domain: "example.cg" },
    { id: "t2", domain: "shop.cg" },
  ] as Target[];

  it("words the level and the weak points", () => {
    expect(scoreVerdict(null, 0)).toBe("Pas encore de score : il apparaît après le premier scan.");
    expect(scoreVerdict(95, 0)).toBe("Très bon niveau, aucun point faible.");
    expect(scoreVerdict(83, 2)).toBe("Bon niveau, 2 points faibles à régler.");
    expect(scoreVerdict(74, 1)).toBe("Niveau moyen, 1 point faible à régler.");
    expect(scoreVerdict(40, 5)).toBe("Niveau faible, 5 points faibles à régler.");
  });

  it("lists what lowers the score, heaviest first, with its problem", () => {
    const checks = [
      check({ id: "tls-weak", title: "Strong ciphers", title_fr: "Chiffrements solides", category: "tls", severity: "medium", status: "failed" }),
      check({ status: "failed", target_id: "t2" }),
      check({ id: "tls-info", severity: "info", status: "failed" }), // weighs nothing
      check({ id: "spf", title: "SPF", title_fr: "SPF publié" }), // passed
    ];
    const issues = toIssues([finding({ target_id: "t2", id: "f2", check_id: "dmarc-missing", gain: 7 })], []);
    const weak = weakChecks(checks, issues, targets);
    expect(weak.map((w) => [w.title, w.domain, w.gain])).toEqual([
      ["Enregistrement DMARC publié", "shop.cg", 7],
      ["Chiffrements solides", "example.cg", 0],
    ]);
    expect(weak[0]?.issue?.id).toBe("f2");
    expect(weak[1]?.issue).toBeUndefined();
  });

  it("groups what is fine by category, each check once", () => {
    const checks = [
      check({}),
      check({ target_id: "t2" }), // passed on a second domain: listed once, counted twice
      check({ id: "spf", title_fr: "SPF publié" }),
      check({ id: "https", title_fr: "Redirection vers HTTPS", category: "web" }),
      check({ id: "tech", title_fr: "Technologies", category: "web", severity: "info" }), // weighs nothing
      check({ id: "tls", title_fr: "Certificat valide", category: "tls", status: "failed" }),
    ];
    const { total, groups } = strongChecks(checks);
    expect(total).toBe(4);
    expect(groups.map((g) => [g.label, g.titles])).toEqual([
      ["Vos emails", ["Enregistrement DMARC publié", "SPF publié"]],
      ["Vos sites web", ["Redirection vers HTTPS"]],
    ]);
  });
});

describe("progress", () => {
  const now = new Date("2026-11-18T12:00:00Z");
  const fixed = (id: string, at: string, over: Partial<Finding> = {}) => finding({ id, status: "fixed", fixed_at: at, ...over });

  it("counts the problem lines fixed in the last 30 days and the score since", () => {
    const issues = toIssues(
      [
        fixed("f1", "2026-11-10T00:00:00Z"),
        fixed("f2", "2026-11-11T00:00:00Z", { asset: "shop.example.cg" }), // same check, another name: one line
        fixed("f3", "2026-11-12T00:00:00Z", { check_id: "spf-missing", title: "No SPF" }),
        fixed("f4", "2026-09-01T00:00:00Z", { check_id: "old", title: "Old" }), // before the period
        finding({ id: "f5", check_id: "tls", title: "TLS" }), // open
      ],
      [],
    );
    const trend = [
      { at: "2026-10-01T00:00:00Z", score: 55 },
      { at: "2026-10-15T00:00:00Z", score: 61 }, // the last score known when the period began
      { at: "2026-11-01T00:00:00Z", score: null },
      { at: "2026-11-17T00:00:00Z", score: 83 },
    ];
    const p = progressOf(issues, trend, 83, now);
    expect(p).toEqual({ fixed: 2, from: 61, to: 83, sinceFirst: false });
    expect(progressText(p!)).toBe("Ces 30 derniers jours, vous avez corrigé 2 problèmes. Votre score est passé de 61 à 83.");
  });

  it("counts from the first scan for a young organization, and says a drop plainly", () => {
    const p = progressOf([], [{ at: "2026-11-10T00:00:00Z", score: 80 }], 72, now);
    expect(p).toEqual({ fixed: 0, from: 80, to: 72, sinceFirst: true });
    expect(progressText(p!)).toBe(
      "Depuis votre premier scan, aucun problème corrigé pour l’instant. Votre score est descendu de 80 à 72 : de nouveaux points faibles sont apparus.",
    );
  });

  it("shows nothing before any score", () => {
    expect(progressOf([], [{ at: "2026-11-10T00:00:00Z", score: null }], null, now)).toBeNull();
    expect(progressOf([], [], 70, now)).toBeNull();
  });
});
