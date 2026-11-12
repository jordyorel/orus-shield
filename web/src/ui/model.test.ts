import { describe, expect, it } from "vitest";
import type { Check, Finding, OrgAsset } from "../api/types";
import { catState, device, evaluatedCats, feedDay, hostOf, initials, money, pwScore, toAssets, toIssues, weekly, worst } from "./model";

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
    expect(money(35, "usd")).toBe("35 $");
    expect(money(20000, "xaf").replace(/\s/g, " ")).toBe("20 000 FCFA");
  });
});
