import { describe, expect, it } from "vitest";
import { formatExclusions, parseExclusions } from "./exclusions";

describe("exclusions", () => {
  it("sorts lines into the engine's kinds", () => {
    const { value, errors } = parseExclusions("/admin/paiements\n196.200.1.20\n10.0.0.0/8\n3389\n\nIntranet.Example.com\n2001:db8::/32");
    expect(errors).toEqual([]);
    expect(value).toEqual({
      paths: ["/admin/paiements"],
      ips: ["196.200.1.20", "10.0.0.0/8", "2001:db8::/32"],
      ports: [3389],
      hosts: ["intranet.example.com"],
    });
  });

  it("reports what it cannot read", () => {
    expect(parseExclusions("70000\nnot a host\nlocalhost").errors).toEqual(["70000", "not a host", "localhost"]);
  });

  it("round-trips", () => {
    const text = "/admin\n192.0.2.1\n22\nold.example.com";
    expect(formatExclusions(parseExclusions(text).value)).toBe(text);
    expect(formatExclusions({})).toBe("");
  });
});
