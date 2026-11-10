import { describe, expect, it } from "vitest";
import { duration, durationChange, plural, priorityText, relativeDay, signed } from "./format";

describe("format", () => {
  it("writes durations in French", () => {
    expect(duration(1800)).toBe("< 1 h");
    expect(duration(5 * 3600 + 1200)).toBe("5 h");
    expect(duration(36 * 3600)).toBe("1,5 j");
  });

  it("compares remediation times", () => {
    expect(durationChange(4.2 * 86400, 6 * 86400)).toEqual({ text: "−1,8 j", worse: false });
    expect(durationChange(2 * 86400, 86400)).toEqual({ text: "+1,0 j", worse: true });
    expect(durationChange(3600, 3000)).toEqual({ text: "Stable", worse: false });
  });

  it("signs and pluralizes", () => {
    expect(signed(16)).toBe("+16");
    expect(signed(-3)).toBe("−3");
    expect(plural(0, "critique", "critiques")).toBe("critique");
    expect(plural(2, "critique", "critiques")).toBe("critiques");
  });

  it("counts calendar days", () => {
    const now = new Date(2026, 10, 10, 9, 0);
    expect(relativeDay(new Date(2026, 10, 10, 1, 0).toISOString(), now)).toBe("Aujourd’hui");
    expect(relativeDay(new Date(2026, 10, 9, 23, 0).toISOString(), now)).toBe("Hier");
    expect(relativeDay(new Date(2026, 10, 7, 12, 0).toISOString(), now)).toBe("Il y a 3 jours");
  });

  it("writes priorities from the API's facts", () => {
    const now = new Date(2026, 10, 10, 9, 0);
    expect(
      priorityText(
        { kind: "finding", target_id: "t", domain: "a.example", finding_id: "f", severity: "critical", title: "SPF allows every server", asset: "a.example", first_seen: new Date(2026, 10, 7).toISOString() },
        now,
      ),
    ).toEqual({ title: "SPF allows every server", detail: "Critique · a.example · ouverte il y a 3 jours" });
    expect(priorityText({ kind: "scan_target", target_id: "t", domain: "a.example" }, now).title).toBe("Lancer un premier scan de a.example");
  });
});
