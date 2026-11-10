// The score trend as SVG geometry. A day without a score leaves a gap in
// the line: the chart never draws a value that was not measured.

import type { TrendPoint } from "./api/types";

export const CHART = { width: 640, height: 220, top: 24, bottom: 196 } as const;

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

/**
 * scale fits the vertical axis to the measured scores, as in the mockup
 * (40 to 80 for scores between 50 and 75): a 0-100 axis would flatten
 * every change. Bounds are multiples of 20 with a margin, at least 40
 * points apart, within 0-100.
 */
export function scale(scores: number[]): { lo: number; hi: number } {
  if (scores.length === 0) return { lo: 0, hi: 100 };
  let lo = Math.max(0, Math.floor((Math.min(...scores) - 5) / 20) * 20);
  let hi = Math.min(100, Math.ceil((Math.max(...scores) + 5) / 20) * 20);
  while (hi - lo < 40) {
    if (hi < 100) hi += 20;
    else lo -= 20;
  }
  return { lo, hi };
}

const round1 = (n: number) => Math.round(n * 10) / 10;

function yFor(lo: number, hi: number) {
  return (score: number) => round1(CHART.bottom - ((score - lo) / (hi - lo)) * (CHART.bottom - CHART.top));
}

export function chartGeometry(trend: TrendPoint[]): ChartGeometry {
  const g: ChartGeometry = { lines: [], dots: [], grid: [], measured: 0 };
  const { lo, hi } = scale(trend.flatMap((p) => (p.score === null ? [] : [p.score])));
  const scoreY = yFor(lo, hi);
  for (const label of [hi, (hi + lo) / 2, lo]) g.grid.push({ y: scoreY(label), label });
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
