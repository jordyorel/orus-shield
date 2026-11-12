import { useLayoutEffect, useRef, useState, type PointerEvent as RPointerEvent } from "react";
import { reportURL } from "../../api/client";
import { Tick } from "../icons";
import { CATNAME, CATS, COLOR, SEV, catState, evaluatedCats, weekly, type AssetView, type Cat, type CellState, type Issue } from "../model";
import { useOrg } from "../OrgData";
import { AssetSheet } from "../sheets";
import { useUI } from "../ui";

function ScoreCard({ hist, score, fixed, open }: { hist: number[]; score: number | null; fixed: number; open: number }) {
  const n = hist.length;
  const [hover, setHover] = useState<number | null>(null);
  const [tipPos, setTipPos] = useState<{ left: number; top: number; below: boolean } | null>(null);
  const svg = useRef<SVGSVGElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const SX = (i: number) => 34 + i * (276 / Math.max(1, n - 1));
  const SY = (v: number) => 102 - ((v - 40) / 60) * 92;
  const pts = hist.map((v, i) => [SX(i), SY(Math.max(40, v))] as const);
  // Smooth curve through the points (Catmull-Rom converted to cubic Béziers).
  const spark = pts
    .map((q, i) => {
      if (!i) return "M" + q[0].toFixed(1) + " " + q[1].toFixed(1);
      const p0 = pts[Math.max(0, i - 2)] ?? q;
      const p1 = pts[i - 1] ?? q;
      const p3 = pts[Math.min(n - 1, i + 1)] ?? q;
      const k = 0.18;
      return (
        "C" +
        (p1[0] + (q[0] - p0[0]) * k).toFixed(1) +
        " " +
        (p1[1] + (q[1] - p0[1]) * k).toFixed(1) +
        " " +
        (q[0] - (p3[0] - p1[0]) * k).toFixed(1) +
        " " +
        (q[1] - (p3[1] - p1[1]) * k).toFixed(1) +
        " " +
        q[0].toFixed(1) +
        " " +
        q[1].toFixed(1)
      );
    })
    .join(" ");
  const cur = score ?? hist[n - 1] ?? null;
  const delta = cur !== null && n ? cur - (hist[0] ?? cur) : 0;

  const move = (e: RPointerEvent<SVGSVGElement>) => {
    const r = svg.current?.getBoundingClientRect();
    if (!r || n < 2) return;
    const x = ((e.clientX - r.left) / r.width) * 320;
    setHover(Math.max(0, Math.min(n - 1, Math.round((x - 34) / (276 / (n - 1))))));
  };
  // Placed once the tooltip holds the hovered week, before paint.
  useLayoutEffect(() => {
    const r = svg.current?.getBoundingClientRect();
    const t = tipRef.current;
    const host = t?.parentElement?.getBoundingClientRect();
    if (hover === null || !r || !t || !host) return;
    const cx = SX(hover);
    const cy = SY(Math.max(40, hist[hover] ?? 40));
    const px = r.left - host.left + (cx / 320) * r.width;
    const py = r.top + (cy / 124) * r.height;
    const below = py - t.offsetHeight - 18 < 84;
    setTipPos({ left: Math.max(92, Math.min(host.width - 92, px)), top: py - host.top + (below ? 8 : 0), below });
    // SX, SY and hist follow n and the period: hover is what changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hover]);
  const leave = () => {
    setHover(null);
    setTipPos(null);
  };
  const hv = hover !== null ? (hist[hover] ?? 0) : 0;
  const prev = hover ? (hist[hover - 1] ?? hv) : hv;
  const back = hover !== null ? n - 1 - hover : 0;

  return (
    <section className="card2 scorecard" aria-label="Score">
      <div className="scorehead">
        <p className="big" aria-label={`Score : ${cur ?? "aucun"} sur 100`}>
          {cur ?? "–"}
        </p>
        <div className="scoremeta">
          <p className="up">
            {delta >= 0 ? "+" : ""}
            {delta} points
          </p>
          <p>en {n} semaine{n > 1 ? "s" : ""}</p>
        </div>
      </div>
      <div className="plot">
        {n >= 2 ? (
          <svg ref={svg} className="chart spark" id="spark" viewBox="0 0 320 124" role="img" aria-label={`Le score passe de ${hist[0]} à ${cur} en ${n} semaines`} onPointerMove={move} onPointerDown={move} onPointerLeave={leave}>
            {[40, 60, 80, 100].map((v) => (
              <g key={v}>
                <line x1="34" x2="312" y1={SY(v)} y2={SY(v)} stroke="var(--ring)" strokeWidth="1.2" />
                <text x="28" y={SY(v) + 4} textAnchor="end" fontSize="11" fill="var(--ink2)">
                  {v}
                </text>
              </g>
            ))}
            {hist.map((_, i) =>
              n <= 6 || i % 3 === 2 || i === 0 ? <line key={i} x1={SX(i).toFixed(1)} x2={SX(i).toFixed(1)} y1="102" y2="106" stroke="var(--ring)" strokeWidth="1.2" /> : null,
            )}
            <text x="34" y="120" fontSize="11" fill="var(--ink2)">
              Il y a {n} sem.
            </text>
            <text x="310" y="120" fontSize="11" fill="var(--ink2)" textAnchor="end">
              Aujourd’hui
            </text>
            <path className="area" d={`${spark} L310 102 L34 102 Z`} fill="var(--azur)" />
            <path className="draw" pathLength={1} d={spark} fill="none" stroke="var(--azur)" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
            {pts.map(([x, y], i) => (
              <circle
                key={i}
                className="pt"
                style={{ animationDelay: (0.3 + (i * 0.8) / n).toFixed(2) + "s" }}
                cx={x.toFixed(1)}
                cy={y.toFixed(1)}
                r={i === n - 1 ? 5.5 : 3}
                fill={i === n - 1 ? "var(--azur)" : "var(--surface)"}
                stroke="var(--azur)"
                strokeWidth="2"
              />
            ))}
            <line id="ch-line" x1={hover !== null ? SX(hover) : 0} x2={hover !== null ? SX(hover) : 0} y1="6" y2="102" stroke="var(--ink)" strokeWidth="1.2" strokeDasharray="3 4" opacity={hover !== null ? 1 : 0} />
            <circle id="ch-dot" r="6.5" cx={hover !== null ? SX(hover) : 0} cy={hover !== null ? SY(Math.max(40, hv)) : 0} fill="var(--azur)" stroke="var(--surface)" strokeWidth="3" opacity={hover !== null ? 1 : 0} />
            <rect x="20" y="0" width="300" height="110" fill="transparent" />
          </svg>
        ) : (
          <p className="sub">La courbe apparaît après deux semaines de scans.</p>
        )}
        <div ref={tipRef} className={"hmtip" + (tipPos ? " on" : "") + (tipPos?.below ? " below" : "")} id="chtip" role="tooltip" style={tipPos ? { left: tipPos.left + "px", top: tipPos.top + "px" } : undefined}>
          {hover !== null && (
            <>
              <b>{hv} points</b>
              <em>{back === 0 ? "Aujourd’hui" : back === 1 ? "La semaine dernière" : `Il y a ${back} semaines`}</em>
              {hover > 0 && (
                <span>
                  <i style={{ background: hv - prev >= 0 ? "var(--lagon)" : "var(--corail)" }} />
                  {hv - prev >= 0 ? "+" : "−"}
                  {Math.abs(hv - prev)} par rapport à la semaine d’avant
                </span>
              )}
            </>
          )}
        </div>
      </div>
      <p className="scorefoot">
        {n ? `Parti de ${hist[0]}. ` : ""}
        {fixed} corrigé{fixed > 1 ? "s" : ""}, {open} ouvert{open > 1 ? "s" : ""}.
      </p>
    </section>
  );
}

function Heat({ assets, issues, evaluated }: { assets: AssetView[]; issues: Issue[]; evaluated: Map<string, Set<Cat>> }) {
  const { showSheet } = useUI();
  const [cur, setCur] = useState<{ asset: string; cat: Cat } | null>(null);
  const [tip, setTip] = useState<{ left: number; top: number; below: boolean } | null>(null);
  const tipRef = useRef<HTMLDivElement>(null);

  const anchor = useRef<HTMLElement | null>(null);
  const over = (asset: string, cat: Cat, el: HTMLElement) => {
    anchor.current = el;
    setCur({ asset, cat });
  };
  const out = () => {
    anchor.current = null;
    setCur(null);
    setTip(null);
  };
  // Placed once the tooltip holds the cell's content, before paint.
  const curKey = cur ? cur.asset + "/" + cur.cat : "";
  useLayoutEffect(() => {
    const t = tipRef.current;
    const host = t?.parentElement?.getBoundingClientRect();
    const r = anchor.current?.getBoundingClientRect();
    if (!curKey || !t || !host || !r) return;
    const half = Math.min(120, host.width / 2 - 8);
    const below = r.top - t.offsetHeight - 14 < 84;
    setTip({ left: Math.max(half + 8, Math.min(host.width - half - 8, r.left - host.left + r.width / 2)), top: (below ? r.bottom : r.top) - host.top, below });
  }, [curKey]);

  const curAsset = cur ? assets.find((a) => a.n === cur.asset) : undefined;
  const curState: CellState | null = curAsset && cur ? catState(curAsset, cur.cat, issues, evaluated) : null;
  const curList = cur ? issues.filter((i) => !i.fixed && i.host === cur.asset && i.cat === cur.cat) : [];

  return (
    <section className="card2 heat" aria-label="Carte de chaleur des risques" onMouseLeave={out}>
      <div ref={tipRef} className={"hmtip" + (tip ? " on" : "") + (tip?.below ? " below" : "")} id="hmtip" role="tooltip" style={tip ? { left: tip.left + "px", top: tip.top + "px" } : undefined}>
        {cur && (
          <>
            <b>{cur.asset}</b>
            <em>{CATNAME[cur.cat]}</em>
            {curState === "na" ? (
              <em>{cur.cat === "fuites" ? "Bientôt : la surveillance des fuites arrive." : "Non concerné : ce contrôle ne s’applique pas à cet actif."}</em>
            ) : !curList.length ? (
              <span>
                <i style={{ background: "var(--lagon)" }} />
                Vérifié, rien à signaler.
              </span>
            ) : (
              <>
                {curList.map((i) => (
                  <span key={i.targetId + i.id}>
                    <i style={{ background: COLOR[i.sev] }} />
                    {i.title}
                  </span>
                ))}
                <em>Cliquez pour ouvrir l’actif</em>
              </>
            )}
          </>
        )}
      </div>
      <div className={"hmgrid" + (cur ? " hot" : "")} style={{ gridTemplateColumns: `minmax(84px,1.3fr) repeat(${CATS.length},minmax(38px,1fr))` }}>
        <span className="hmcol" style={{ textAlign: "left", fontWeight: 600, color: "var(--ink)" }}>
          Où est le risque
        </span>
        {CATS.map(([c, l]) => (
          <span key={c} className={"hmcol" + (cur?.cat === c ? " on" : "")} data-col={c}>
            {l}
          </span>
        ))}
        {assets.map((a, r) => (
          <HeatRow key={a.n} a={a} r={r} issues={issues} evaluated={evaluated} cur={cur} over={over} open={(n) => showSheet(<AssetSheet n={n} />)} />
        ))}
      </div>
      <div className="key" style={{ justifyContent: "flex-start", marginTop: 10, gap: "6px 12px", fontSize: 12 }}>
        <span>
          <i style={{ background: "var(--lagon)" }} />
          Rien
        </span>
        <span>
          <i style={{ background: "var(--ciel)" }} />
          Moyen
        </span>
        <span>
          <i style={{ background: "var(--ambre)" }} />
          Élevé
        </span>
        <span>
          <i style={{ background: "var(--corail)" }} />
          Critique
        </span>
        <span>
          <i style={{ background: "var(--ring)" }} />
          Non concerné
        </span>
      </div>
    </section>
  );
}

function HeatRow({
  a,
  r,
  issues,
  evaluated,
  cur,
  over,
  open,
}: {
  a: AssetView;
  r: number;
  issues: Issue[];
  evaluated: Map<string, Set<Cat>>;
  cur: { asset: string; cat: Cat } | null;
  over: (asset: string, cat: Cat, el: HTMLElement) => void;
  open: (n: string) => void;
}) {
  return (
    <>
      <span className={"hmrow" + (cur?.asset === a.n ? " on" : "")} data-row={a.n}>
        {a.n}
      </span>
      {CATS.map(([c], k) => {
        const s = catState(a, c, issues, evaluated);
        const isCur = cur?.asset === a.n && cur.cat === c;
        const delay = { animationDelay: ((r + k) * 0.03).toFixed(2) + "s" };
        if (s === "na") {
          return (
            <span
              key={c}
              style={delay}
              className={"hm na" + (isCur ? " cur" : "")}
              aria-label={`${a.n}, ${c} : non concerné`}
              onMouseEnter={(e) => over(a.n, c, e.currentTarget)}
            >
              <i />
            </span>
          );
        }
        const n = issues.filter((i) => !i.fixed && i.host === a.n && i.cat === c).length;
        const label = n ? `${n} problème${n > 1 ? "s" : ""}, niveau ${SEV[s === "ok" ? "ok" : s][0].toLowerCase()}` : "aucun problème";
        return (
          <button
            key={c}
            type="button"
            style={delay}
            className={"hm " + s + (isCur ? " cur" : "")}
            aria-label={`${a.n}, ${c} : ${label}`}
            onMouseEnter={(e) => over(a.n, c, e.currentTarget)}
            onFocus={(e) => over(a.n, c, e.currentTarget)}
            onClick={() => open(a.n)}
          >
            {n ? n : <Tick size={14} width={3} />}
          </button>
        );
      })}
    </>
  );
}

function Seg({ name, pass, total }: { name: string; pass: number; total: number }) {
  return (
    <div className="chk">
      <span>{name}</span>
      <span className="dots" role="img" aria-label={`${name} : ${pass} contrôles réussis sur ${total}`}>
        {Array.from({ length: total }, (_, i) => (
          <i key={i} className={i < pass ? "on" : ""} />
        ))}
      </span>
      <span className="num">
        {pass}
        <small> / {total}</small>
      </span>
    </div>
  );
}

function Paper({ kind }: { kind: "dir" | "tech" }) {
  return (
    <div className="paper" aria-hidden="true">
      <b />
      <i style={{ width: "70%" }} />
      <i style={{ width: "46%" }} />
      {kind === "dir" ? (
        <svg viewBox="0 0 80 34">
          <path d="M2 30 L20 24 L38 26 L56 14 L78 6" fill="none" stroke="var(--azur)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      ) : (
        <>
          <u />
          <u />
          <u />
          <u />
        </>
      )}
      <i style={{ width: "82%" }} />
      <i style={{ width: "58%" }} />
    </div>
  );
}

export function RapportsPage() {
  const { data, issues, assets, org } = useOrg();
  const { toast } = useUI();
  const [period, setPeriod] = useState<4 | 12>(12);
  if (!data) return null;
  const now = new Date();
  const hist = weekly(data.overview.trend, period, now);
  const open = issues.filter((i) => !i.fixed).length;
  const fixed = issues.length - open;
  const evaluated = evaluatedCats(data.checks);
  const tally = (modules: string[]) => {
    const cs = data.checks.filter((c) => modules.includes(c.module) && c.status !== "not_applicable");
    return [cs.filter((c) => c.status === "passed").length, cs.length] as const;
  };
  const segs: [string, readonly [number, number]][] = [
    ["Emails", tally(["email"])],
    ["Chiffrement", tally(["tls", "web"])],
    ["Ports et services", tally(["ports"])],
  ];
  const pass = segs.reduce((s, [, [p]]) => s + p, 0);
  const total = segs.reduce((s, [, [, t]]) => s + t, 0);
  const reports = data.subscription.plan.reports;
  const pdf = (kind: "executive" | "technical", label: string, ghost: boolean) =>
    reports ? (
      <a className={"btn" + (ghost ? " ghost" : "")} href={reportURL(org.org_id, kind, "fr")} download>
        Générer le PDF
      </a>
    ) : (
      <button className={"btn" + (ghost ? " ghost" : "")} type="button" aria-disabled="true" onClick={() => toast(`${label} : inclus à partir de l’offre Essentiel`)}>
        Générer le PDF
      </button>
    );

  return (
    <>
      <div className="rtop">
        <h1 className="hello" style={{ margin: 0, fontFamily: "inherit", fontWeight: 400, letterSpacing: 0 }}>
          Rapports
        </h1>
        <div className="seg2" role="group" aria-label="Période">
          {(
            [
              [4, "4 sem."],
              [12, "12 sem."],
            ] as const
          ).map(([k, l]) => (
            <button key={k} type="button" aria-pressed={period === k} onClick={() => setPeriod(k)}>
              {l}
            </button>
          ))}
        </div>
      </div>
      <div className="duo">
        <ScoreCard key={period} hist={hist} score={data.overview.score} fixed={fixed} open={open} />
        <Heat assets={assets} issues={issues} evaluated={evaluated} />
      </div>

      <div className="section checks">
        <div className="rhead">
          <h2 style={{ fontSize: 18 }}>Contrôles automatisés</h2>
          <p style={{ fontSize: 14, color: "var(--ink2)" }}>
            {pass} réussis sur {total}
          </p>
        </div>
        {segs.map(([name, [p, t]]) => (
          <Seg key={name} name={name} pass={p} total={t} />
        ))}
      </div>

      <div className="section">
        <h2>À partager</h2>
        <div className="docs">
          <div className="doc">
            <Paper kind="dir" />
            <div>
              <h3>Rapport Direction</h3>
              <p>Deux pages, sans jargon : le score, ce qui a été corrigé, ce qui reste à décider.</p>
              {pdf("executive", "Rapport Direction", false)}
            </div>
          </div>
          <div className="doc">
            <Paper kind="tech" />
            <div>
              <h3>Rapport Technique</h3>
              <p>Pour votre informaticien : chaque problème, sa preuve, sa CVE et les étapes de correction.</p>
              {pdf("technical", "Rapport Technique", true)}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
