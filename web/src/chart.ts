// The score trend as SVG geometry. A day without a score leaves a gap in
// the line: the chart never draws a value that was not measured.

import type { TrendPoint } from "./api/types";

export const CHART = { width: 640, height: 220, top: 16, bottom: 204 } as const;

export interface ChartGeometry {
  /** Runs of consecutive days with a score, as SVG polyline points. */
  lines: string[];
  /** Runs of a single day, and the last measured value. */
  dots: { x: number; y: number }[];
  /** Horizontal grid lines with their labels. */
  grid: { y: number; label: number }[];
  /** Days with a score: under two, there is no trend. */
  measured: number;
}

const round1 = (n: number) => Math.round(n * 10) / 10;

export function scoreY(score: number): number {
  return round1(CHART.bottom - (score / 100) * (CHART.bottom - CHART.top));
}

export function chartGeometry(trend: TrendPoint[]): ChartGeometry {
  const g: ChartGeometry = { lines: [], dots: [], grid: [], measured: 0 };
  for (const label of [100, 50, 0]) g.grid.push({ y: scoreY(label), label });
  const left = 40;
  const step = (CHART.width - left) / Math.max(trend.length - 1, 1);
  let run: { x: number; y: number }[] = [];
  let last: { x: number; y: number } | null = null;
  const flush = () => {
    if (run.length === 1 && run[0]) g.dots.push(run[0]);
    else if (run.length > 1) g.lines.push(run.map((p) => `${p.x},${p.y}`).join(" "));
    run = [];
  };
  trend.forEach((p, i) => {
    if (p.score === null) {
      flush();
      return;
    }
    g.measured++;
    last = { x: round1(left + i * step), y: scoreY(p.score) };
    run.push(last);
  });
  flush();
  const end = last as { x: number; y: number } | null;
  const prev = g.dots[g.dots.length - 1];
  if (end && !(prev && prev.x === end.x && prev.y === end.y)) g.dots.push(end);
  return g;
}
