// Line icons of the public pages (home capabilities, guides, pricing):
// one stroke path each, drawn in the current colour.

/** Glyph draws the small line icons of the capability grid. */
export function Glyph({ d, size = 22 }: { d: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}

export const G = {
  mail: "M3 6h18v12H3zM3 7l9 6 9-6",
  lock: "M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18",
  server: "M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01",
  bug: "M12 3 2 20h20zM12 10v4M12 17h.01",
  bolt: "M13 2 4 14h7l-1 8 9-12h-7z",
  code: "M8 8l-4 4 4 4M16 8l4 4-4 4M14 5l-4 14",
  key: "M7 14a3 3 0 1 0 0 .01M9.5 12.5 19 3M15 7l2 2",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
  net: "M12 3v6M5 21v-4h14v4M12 9a2 2 0 1 0 0 .01M12 11v6",
  file: "M6 3h9l4 4v14H6zM14 3v5h5M9 13h6M9 17h6",
  bell: "M6 16V11a6 6 0 0 1 12 0v5l2 2H4zM10 21h4",
  check: "M5 12l5 5 9-10",
  card: "M3 6h18v12H3zM3 10h18M7 15h3",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2",
  arrow: "M5 12h14M13 6l6 6-6 6",
  chart: "M4 20V11M10 20V5M16 20v-7M21 20H3",
  pulse: "M3 12h4l3-8 4 16 3-8h4",
  list: "M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01",
  grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  target: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 12h.01",
};

/** Ico is a glyph in a small tinted tile: the visual cue before a figure's
 * label or a panel's title in the console. */
export function Ico({ d, tone = "blue" }: { d: string; tone?: "blue" | "red" | "green" | "amber" | "violet" | "slate" }) {
  return (
    <span className={"ico t-" + tone} aria-hidden="true">
      <Glyph d={d} size={15} />
    </span>
  );
}
