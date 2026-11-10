// Small SVG charts drawn from real figures. No chart library: a few
// shapes are enough, and every value shown comes from the API.

export interface Slice {
  label: string;
  value: number;
  color: string;
}

/** Donut: slices around a ring; an empty ring when everything is zero. */
export function Donut({ slices, size = 120, label }: { slices: Slice[]; size?: number; label: string }) {
  const total = slices.reduce((n, s) => n + s.value, 0);
  const r = 42;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" role="img" aria-label={label}>
      <circle cx="50" cy="50" r={r} fill="none" stroke="#EEF1F4" strokeWidth="14" />
      {total > 0 &&
        slices.map((s) => {
          const len = (s.value / total) * c;
          const el = (
            <circle
              key={s.label}
              cx="50"
              cy="50"
              r={r}
              fill="none"
              stroke={s.color}
              strokeWidth="14"
              strokeDasharray={`${len} ${c - len}`}
              strokeDashoffset={-offset}
              transform="rotate(-90 50 50)"
            />
          );
          offset += len;
          return el;
        })}
    </svg>
  );
}

export function Legend({ slices }: { slices: Slice[] }) {
  return (
    <ul className="legend">
      {slices.map((s) => (
        <li key={s.label}>
          <span className="dot-key" style={{ background: s.color }} aria-hidden="true" />
          {s.label} <span className="muted">{s.value}</span>
        </li>
      ))}
    </ul>
  );
}

export interface Series {
  label: string;
  color: string;
  values: number[];
}

/** Lines: one polyline per series over shared x labels. */
export function Lines({ series, labels, label }: { series: Series[]; labels: string[]; label: string }) {
  const w = 300;
  const h = 120;
  const max = Math.max(1, ...series.flatMap((s) => s.values));
  const x = (i: number) => (labels.length > 1 ? (i / (labels.length - 1)) * (w - 20) + 10 : w / 2);
  const y = (v: number) => h - 20 - (v / max) * (h - 34);
  return (
    <svg className="mini-chart" viewBox={`0 0 ${w} ${h}`} role="img" aria-label={label}>
      <line x1="10" x2={w - 10} y1={h - 20} y2={h - 20} stroke="#EEF1F4" />
      {series.map((s) => (
        <polyline key={s.label} fill="none" stroke={s.color} strokeWidth="2.5" strokeLinejoin="round" points={s.values.map((v, i) => `${x(i)},${y(v)}`).join(" ")} />
      ))}
      {labels.map((l, i) =>
        i === 0 || i === labels.length - 1 || i === Math.floor(labels.length / 2) ? (
          <text key={l + i} x={x(i)} y={h - 4} textAnchor="middle" fontSize="10" fill="#5B6570">
            {l}
          </text>
        ) : null,
      )}
    </svg>
  );
}

/** Bars: vertical bars with their value above. */
export function Bars({ bars, label }: { bars: Slice[]; label: string }) {
  const w = 260;
  const h = 130;
  const max = Math.max(1, ...bars.map((b) => b.value));
  const bw = Math.min(40, (w - 20) / bars.length - 14);
  return (
    <svg className="mini-chart" viewBox={`0 0 ${w} ${h}`} role="img" aria-label={label}>
      {bars.map((b, i) => {
        const x = 10 + i * ((w - 20) / bars.length) + ((w - 20) / bars.length - bw) / 2;
        const bh = (b.value / max) * (h - 44);
        return (
          <g key={b.label}>
            <rect x={x} y={h - 22 - bh} width={bw} height={bh} fill={b.color} rx="2" />
            <text x={x + bw / 2} y={h - 26 - bh} textAnchor="middle" fontSize="10" fill="#0E1116">
              {b.value}
            </text>
            <text x={x + bw / 2} y={h - 6} textAnchor="middle" fontSize="10" fill="#5B6570">
              {b.label}
            </text>
          </g>
        );
      })}
      <line x1="10" x2={w - 10} y1={h - 22} y2={h - 22} stroke="#EEF1F4" />
    </svg>
  );
}

/** Ring: a single share as a gauge ("4/5"). */
export function Ring({ value, max, text }: { value: number; max: number; text: string }) {
  const r = 40;
  const c = 2 * Math.PI * r;
  const len = max > 0 ? (value / max) * c : 0;
  return (
    <svg width="96" height="96" viewBox="0 0 100 100" role="img" aria-label={text}>
      <circle cx="50" cy="50" r={r} fill="none" stroke="#EEF1F4" strokeWidth="9" />
      <circle cx="50" cy="50" r={r} fill="none" stroke="#0C5DA5" strokeWidth="9" strokeDasharray={`${len} ${c - len}`} transform="rotate(-90 50 50)" strokeLinecap="round" />
      <text x="50" y="57" textAnchor="middle" fontSize="20" fontWeight="600" fill="#0E1116">
        {text}
      </text>
    </svg>
  );
}

export const SEV_COLORS = { critical: "#B42318", high: "#F79009", medium: "#FDB022", low: "#5B8DEF" } as const;
