import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Activity } from "../../api/types";
import { Tick } from "../icons";
import { COLOR, DIST, byPriority, feedDay, worst, type AssetView, type Issue } from "../model";
import { useOrg } from "../OrgData";
import { AssetSheet, FindingSheet, useFix } from "../sheets";
import { useUI } from "../ui";

/** countTo animates a number from one value to another (the mockup's countTo). */
function useCount(to: number): number {
  const [v, setV] = useState(to);
  const from = useRef(to);
  useEffect(() => {
    const start = from.current;
    if (start === to) return;
    const t0 = performance.now();
    let raf = 0;
    const step = (t: number) => {
      const k = Math.min(1, (t - t0) / 700);
      setV(Math.round(start + (to - start) * (1 - Math.pow(1 - k, 3))));
      if (k < 1) raf = requestAnimationFrame(step);
      else from.current = to;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [to]);
  return v;
}

export function Radar({ assets, issues, score }: { assets: AssetView[]; issues: Issue[]; score: number | null }) {
  const { showSheet } = useUI();
  const [hot, setHot] = useState<string | null>(null);
  const [tip, setTip] = useState<{ left: number; top: number; below: boolean } | null>(null);
  const host = useRef<HTMLDivElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const shown = useCount(score ?? 0);
  const openOf = (n: string) => issues.filter((i) => !i.fixed && i.host === n);
  const pos = (a: AssetView) => {
    const r = DIST[worst(openOf(a.n))];
    const rad = (a.a * Math.PI) / 180;
    return [150 + r * Math.cos(rad), 150 + r * Math.sin(rad)] as const;
  };

  const anchor = useRef<SVGGElement | null>(null);
  const over = (a: AssetView, el: SVGGElement) => {
    anchor.current = el;
    setHot(a.n);
  };
  const out = () => {
    anchor.current = null;
    setHot(null);
    setTip(null);
  };
  // Placed once the tooltip holds the hovered asset's content, before the
  // browser paints (the mockup fills it, then measures): above the dot,
  // or below it when the top would hide under the header.
  useLayoutEffect(() => {
    const h = host.current?.getBoundingClientRect();
    const dot = anchor.current?.querySelectorAll("circle")[1]?.getBoundingClientRect();
    const t = tipRef.current;
    if (!hot || !h || !dot || !t) return;
    const below = dot.top - t.offsetHeight - 14 < 84;
    setTip({
      left: Math.max(126, Math.min(h.width - 126, dot.left - h.left + dot.width / 2)),
      top: (below ? dot.bottom : dot.top) - h.top,
      below,
    });
  }, [hot]);
  const open = (n: string) => {
    out();
    showSheet(<AssetSheet n={n} />);
  };
  const ringLabel = (r: number, txt: string) => (
    <text className="rlabel" x="150" y={150 - r + 3.5} textAnchor="middle">
      {txt}
    </text>
  );
  const cur = hot ? assets.find((a) => a.n === hot) : undefined;
  const curPos = cur ? pos(cur) : null;
  const curOpen = cur ? openOf(cur.n) : [];

  return (
    <div className="radar" ref={host}>
      <svg id="radar" className={hot ? "hot" : ""} viewBox="0 0 300 300" role="group" aria-label="Carte de votre périmètre : plus un point est loin du centre, plus l'actif est exposé">
        <circle cx="150" cy="150" r="128" fill="none" stroke="var(--ring)" strokeWidth="1.8" strokeDasharray="3 6" strokeLinecap="round" />
        <circle cx="150" cy="150" r="100" fill="none" stroke="var(--ring)" strokeWidth="1.8" />
        <circle cx="150" cy="150" r="74" fill="none" stroke="var(--ring)" strokeWidth="1.8" />
        <line x1="22" x2="278" y1="150" y2="150" stroke="var(--ring)" strokeWidth="1" strokeDasharray="1 5" />
        <line x1="150" x2="150" y1="22" y2="278" stroke="var(--ring)" strokeWidth="1" strokeDasharray="1 5" />
        {ringLabel(128, "En danger")}
        {ringLabel(100, "Exposé")}
        {ringLabel(74, "À surveiller")}
        <line
          id="rd-line"
          x1="150"
          y1="150"
          x2={curPos ? curPos[0].toFixed(1) : 150}
          y2={curPos ? curPos[1].toFixed(1) : 150}
          stroke="var(--ink)"
          strokeWidth="1.4"
          strokeDasharray="3 4"
          opacity={curPos ? 1 : 0}
        />
        <circle cx="150" cy="150" r="44" fill="var(--surface)" stroke="var(--ring)" strokeWidth="1.8" />
        <text className="core" x="150" y="156" textAnchor="middle" fontSize="30" id="score-num">
          {score === null ? "–" : shown}
        </text>
        <text x="150" y="172" textAnchor="middle" fontSize="10" fill="var(--ink2)">
          sur 100
        </text>
        {assets.map((a) => {
          const o = openOf(a.n);
          const w = worst(o);
          const [x, y] = pos(a);
          return (
            <g
              key={a.n}
              className={"dot" + (w === "crit" ? " hot" : "") + (hot === a.n ? " cur" : "")}
              data-asset={a.n}
              style={{ transform: `translate(${x.toFixed(1)}px,${y.toFixed(1)}px)` }}
              tabIndex={0}
              role="button"
              aria-label={`${a.n} : ${o.length} problème(s) ouvert(s)`}
              onMouseEnter={(e) => over(a, e.currentTarget)}
              onMouseLeave={out}
              onFocus={(e) => over(a, e.currentTarget)}
              onBlur={out}
              onClick={() => open(a.n)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  open(a.n);
                }
              }}
            >
              <circle className="halo" r="7" fill={COLOR[w]} opacity="0" />
              <circle r={w === "ok" ? 6 : 8} fill={COLOR[w]} stroke="var(--bg)" strokeWidth="3" />
              <circle r="22" fill="transparent" />
            </g>
          );
        })}
      </svg>
      <div
        ref={tipRef}
        className={"hmtip" + (tip ? " on" : "") + (tip?.below ? " below" : "")}
        id="rdtip"
        role="tooltip"
        style={tip ? { left: tip.left + "px", top: tip.top + "px" } : undefined}
      >
        {cur && (
          <>
            <b>{cur.n}</b>
            <em>{cur.k}</em>
            {curOpen.length ? (
              curOpen.map((i) => (
                <span key={i.targetId + i.id}>
                  <i style={{ background: COLOR[i.sev] }} />
                  {i.title}
                </span>
              ))
            ) : (
              <span>
                <i style={{ background: "var(--lagon)" }} />
                Protégé, aucun problème ouvert.
              </span>
            )}
            <em>Cliquez pour ouvrir l’actif</em>
          </>
        )}
      </div>
    </div>
  );
}

function FeedLine({ a, now }: { a: Activity; now: Date }) {
  let cls = "";
  let text;
  if (a.kind === "scan") {
    text = (
      <span>
        Scan terminé sur <b>{a.domain}</b> : {a.assets ?? 0} actif{(a.assets ?? 0) > 1 ? "s" : ""} vérifié{(a.assets ?? 0) > 1 ? "s" : ""}.
      </span>
    );
  } else if (a.to === "fixed") {
    cls = "f-ok";
    text = (
      <span>
        Corrigé sur <b>{a.asset}</b> : {a.title}.
      </span>
    );
  } else if (a.to === "accepted_risk") {
    text = (
      <span>
        Risque accepté sur <b>{a.asset}</b> : {a.title}.
      </span>
    );
  } else {
    if (a.severity === "critical" || a.severity === "high") cls = "f-crit";
    text = (
      <span>
        {a.from === "fixed" ? "Revenu" : "Nouveau problème"} sur <b>{a.asset}</b> : {a.title}.
      </span>
    );
  }
  return (
    <li className={cls}>
      <time dateTime={a.at}>{feedDay(a.at, now)}</time>
      {text}
    </li>
  );
}

export function AujourdhuiPage() {
  const { me, data, issues, assets } = useOrg();
  const { showSheet } = useUI();
  const fix = useFix();
  // The three actions of the day are chosen once, when the screen opens
  // (the open problems that protect the most): ticking one keeps it in
  // place with its green check, as in the mockup.
  const chosen = useRef<string[] | null>(null);
  if (!data) return null;
  const now = new Date();
  const keyOf = (i: { targetId: string; id: string }) => i.targetId + "/" + i.id;
  if (!chosen.current || chosen.current.some((k) => !issues.some((i) => keyOf(i) === k))) {
    chosen.current = issues
      .filter((i) => !i.fixed)
      .sort(byPriority)
      .slice(0, 3)
      .map(keyOf);
  }
  const ids = chosen.current;
  const top = ids.map((k) => issues.find((i) => keyOf(i) === k)).filter((i): i is Issue => i !== undefined);
  const left = top.filter((i) => !i.fixed).length;
  const head =
    top.length === 0
      ? "Rien à corriger pour l’instant."
      : left === 0
        ? "Tout est fait pour aujourd’hui."
        : left === 1
          ? "Plus qu’une action pour aujourd’hui."
          : `${left} actions vous séparent d’un périmètre plus sûr.`;
  const first = me.name.split(/\s+/)[0];
  const score = data.overview.score;

  return (
    <>
      <div className="today">
        <div>
          <p className="hello">{first ? `Bonjour ${first}` : "Bonjour"}</p>
          <h1 className="lead">{head}</h1>
          <div className="section">
            <div className="rhead">
              <h2>À faire aujourd’hui</h2>
              <span className="dots big3" id="todo-prog" role="img" aria-label={`${top.length - left} actions faites sur ${top.length}`}>
                {top.map((i) => (
                  <i key={i.targetId + i.id} className={i.fixed ? "on" : ""} />
                ))}
              </span>
            </div>
            <p className="hint">Classé par ce qui vous protège le plus, le plus vite.</p>
            <ul className="todo">
              {top.map((i) => (
                <li key={i.targetId + i.id} className={i.fixed ? "done" : ""}>
                  <button className="check" type="button" aria-pressed={i.fixed} aria-label={`Marquer « ${i.title} » comme fait`} onClick={() => void fix(i)}>
                    <Tick size={20} width={3} />
                  </button>
                  <div>
                    <p className="t">{i.title}</p>
                    <p className="m">
                      {i.host}, environ {i.mins} min ·{" "}
                      <button className="link" type="button" style={{ minHeight: 0 }} onClick={() => showSheet(<FindingSheet id={i.id} targetId={i.targetId} />)}>
                        Comment faire
                      </button>
                    </p>
                  </div>
                  <span className="gain">+{i.gain} pts</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
        <div>
          <Radar assets={assets} issues={issues} score={score} />
        </div>
      </div>
      <div className="section">
        <h2>Depuis votre dernière visite</h2>
        {data.activity.length ? (
          <ul className="feed">
            {data.activity.slice(0, 5).map((a, k) => (
              <FeedLine key={k} a={a} now={now} />
            ))}
          </ul>
        ) : (
          <p className="hint">Rien de nouveau ces sept derniers jours.</p>
        )}
      </div>
    </>
  );
}
