import { describe, expect, it } from "vitest";
import { chartGeometry, scale } from "./chart";

const trend = (scores: (number | null)[]) => scores.map((score, i) => ({ at: new Date(2026, 10, i + 1).toISOString(), score }));

describe("chartGeometry", () => {
  it("never bridges a day without a score", () => {
    const g = chartGeometry(trend([null, 50, 60, null, 70, null]));
    expect(g.measured).toBe(3);
    expect(g.lines).toHaveLength(1); // days 1-2
    expect(g.dots).toHaveLength(1); // day 4 alone, also the last value
  });

  it("draws nothing without data", () => {
    const g = chartGeometry(trend([null, null]));
    expect(g).toMatchObject({ measured: 0, lines: [], dots: [] });
  });

  it("maps 0 and 100 to the chart's bounds", () => {
    const g = chartGeometry(trend([0, 100]));
    expect(g.lines[0]).toBe("40,196 640,24");
  });

  it("fits the axis to the scores, as in the mockup", () => {
    expect(scale([50, 62, 75])).toEqual({ lo: 40, hi: 80 });
    expect(scale([97, 100])).toEqual({ lo: 60, hi: 100 });
    expect(scale([0, 3])).toEqual({ lo: 0, hi: 40 });
    expect(scale([])).toEqual({ lo: 0, hi: 100 });
    expect(chartGeometry(trend([50, 75])).grid.map((g) => g.label)).toEqual([80, 60, 40]);
  });
});
