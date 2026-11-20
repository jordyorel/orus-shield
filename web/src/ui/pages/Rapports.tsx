import { useRef, useState, type CSSProperties } from "react";
import { Tick } from "../icons";
import { G, Ico } from "../glyphs";
import { reportURL } from "../../api/client";
import { Link } from "../../router";
import { settingsPath } from "../AppShell";
import { getLang, tr } from "../../i18n";
import { CATNAME, CATS, SEV, families, catState, evaluatedCats, weeklySlots, type AssetView, type Cat, type CellState, type Issue } from "../model";
import { useOrg } from "../OrgData";
import { AssetSheet, FindingSheet } from "../sheets";
import { useLinger } from "../linger";
import { useUI } from "../ui";

/** isoWeek is the ISO 8601 week number of d. */
function isoWeek(d: Date): number {
  const t = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const day = t.getUTCDay() || 7;
  t.setUTCDate(t.getUTCDate() + 4 - day);
  const y0 = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  return Math.ceil(((t.getTime() - y0.getTime()) / 86_400_000 + 1) / 7);
}

/** WeekBars draws the score of each week of the period as a bar, the
 * latest one solid with its value above; a week before any scan is an empty
 * dashed slot. The pointer (or the arrow keys) picks a week: its bar lights
 * up and a tooltip gives its score and the change from the week before. */
function WeekBars({ slots, now }: { slots: (number | null)[]; now: Date }) {
  const n = slots.length;
  // The tooltip lingers so the pointer can reach and read it (useLinger).
  const tip = useLinger<number>();
  const hover = tip.value;
  const setHover = tip.show;
  const known = slots.filter((v): v is number => v !== null);
  if (!known.length) return <p className="panelnote">{tr("Le graphique apparaît après le premier scan.", "The chart appears after the first scan.")}</p>;
  const W = 640;
  const H = 200;
  const L = 34;
  const top = 22;
  const bottom = 170;
  const lo = Math.max(0, Math.floor((Math.min(...known) - 10) / 20) * 20);
  const y = (v: number) => bottom - ((v - lo) / (100 - lo)) * (bottom - top);
  const ticks = [lo, Math.round((lo + 100) / 2), 100];
  const slot = (W - L - 6) / n;
  const bw = Math.min(44, slot * 0.6);
  const weekOf = (i: number) => isoWeek(new Date(now.getTime() - (n - 1 - i) * 7 * 86_400_000));
  const lastIdx = slots.reduce<number>((m, v, i) => (v !== null ? i : m), -1);
  const pick = (e: { clientX: number; currentTarget: Element }) => {
    const r = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width) * W;
    setHover(Math.max(0, Math.min(n - 1, Math.floor((x - L) / slot))));
  };
  const v = hover !== null ? slots[hover]! : null;
  const prevKnown = hover !== null ? slots.slice(0, hover).filter((x): x is number => x !== null).pop() ?? null : null;
  const back = hover !== null ? n - 1 - hover : 0;
  const cx = hover !== null ? L + hover * slot + slot / 2 : 0;
  const tipY = v !== null ? y(v) : bottom - 10;
  return (
    <div
      className="wbars"
      tabIndex={0}
      role="group"
      aria-label={tr("Score par semaine : flèches gauche et droite pour parcourir", "Score by week: left and right arrows to browse")}
      onKeyDown={(e) => {
        if (e.key === "ArrowLeft") setHover(Math.max(0, (hover ?? n - 1) - 1));
        if (e.key === "ArrowRight") setHover(Math.min(n - 1, (hover ?? n - 2) + 1));
      }}
      onBlur={tip.leave}
    >
      <svg
        className="trend"
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-label={tr(`Score par semaine, ${known.length} semaine${known.length > 1 ? "s" : ""} de scans`, `Score by week, ${known.length} week${known.length > 1 ? "s" : ""} of scans`)}
        onPointerMove={pick}
        onPointerDown={pick}
        onPointerLeave={tip.leave}
      >
        {ticks.map((t) => (
          <g key={t}>
            <line x1={L} x2={W - 6} y1={y(t)} y2={y(t)} stroke="var(--line2)" />
            <text x="0" y={y(t) + 4}>
              {t}
            </text>
          </g>
        ))}
        {slots.map((val, i) => {
          const x = L + i * slot + (slot - bw) / 2;
          const on = i === hover || (hover === null && i === lastIdx);
          return (
            <g key={i} className={"wbar" + (on ? " on" : "") + (hover !== null && i !== hover ? " dim" : "")}>
              {val === null ? (
                <rect className="wempty" x={x} y={bottom - 26} width={bw} height={26} rx="4" />
              ) : (
                <rect className="wbarfill" x={x} y={y(val)} width={bw} height={bottom - y(val)} rx="4" />
              )}
              {(n <= 8 || i % 2 === (n - 1) % 2) && (
                <text x={x + bw / 2} y={H - 8} textAnchor="middle" className={on ? "wlab on" : "wlab"}>
                  {tr(`S${weekOf(i)}`, `W${weekOf(i)}`)}
                </text>
              )}
              {hover === null && i === lastIdx && val !== null && (
                <text x={x + bw / 2} y={y(val) - 8} textAnchor="middle" className="barval">
                  {val}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      {hover !== null && (
        <div
          className="wtip"
          role="status"
          onPointerEnter={tip.hold}
          onPointerLeave={tip.leave}
          style={
            {
              left: `${(cx / W) * 100}%`,
              top: `${(tipY / H) * 100}%`,
              "--shift": cx / W > 0.75 ? "-88%" : cx / W < 0.2 ? "-12%" : "-50%",
              "--arrow": cx / W > 0.75 ? "88%" : cx / W < 0.2 ? "12%" : "50%",
            } as CSSProperties
          }
        >
          {v !== null ? (
            <>
              <b>
                {v} <small>/100</small>
              </b>
              <span>{back === 0 ? tr("Cette semaine", "This week") : back === 1 ? tr("La semaine dernière", "Last week") : tr(`Semaine ${weekOf(hover)}`, `Week ${weekOf(hover)}`)}</span>
              {prevKnown !== null && (
                <em className={v - prevKnown > 0 ? "up" : v - prevKnown < 0 ? "dn" : ""}>
                  {v - prevKnown > 0 ? "+" : v - prevKnown < 0 ? "−" : "±"}
                  {Math.abs(v - prevKnown)} {tr("par rapport à la semaine d’avant", "from the week before")}
                </em>
              )}
            </>
          ) : (
            <>
              <b>{tr(`Semaine ${weekOf(hover)}`, `Week ${weekOf(hover)}`)}</b>
              <span>{tr("Pas encore de scan cette semaine", "No scan yet that week")}</span>
            </>
          )}
        </div>
      )}
    </div>
  );
}

/** HeatTable: each asset, each family of checks, its open problems. A cell
 * is a button: hovering shows its problems in a tooltip and lights up its
 * row and column; a click opens the asset. */
function HeatTable({ assets, issues, evaluated }: { assets: AssetView[]; issues: Issue[]; evaluated: Map<string, Set<Cat>> }) {
  const { showSheet } = useUI();
  // The tooltip lingers so the pointer can reach it, read it and click a
  // problem in it (useLinger).
  const tip = useLinger<{ a: string; c: Cat; x: number; y: number; below: boolean }>();
  const cur = tip.value;
  const host = useRef<HTMLDivElement>(null);
  const point = (a: string, c: Cat, el: HTMLElement) => {
    const h = host.current?.getBoundingClientRect();
    const r = el.getBoundingClientRect();
    // Below the cell when the space above is short: the sticky top bar
    // (52 px) would hide the tooltip.
    const below = r.top < 52 + 170;
    if (h) tip.show({ a, c, x: r.left - h.left + r.width / 2, y: (below ? r.bottom : r.top) - h.top, below });
  };
  const curAsset = cur ? assets.find((x) => x.n === cur.a) : undefined;
  const curState: CellState | null = curAsset && cur ? catState(curAsset, cur.c, issues, evaluated) : null;
  const curList = cur ? issues.filter((i) => !i.fixed && i.host === cur.a && i.cat === cur.c) : [];
  return (
    <div className="hm3wrap" ref={host} onMouseLeave={tip.leave} onKeyDown={(e) => e.key === "Escape" && tip.close()}>
      <div className="tw">
      <table className="hm3">
        <thead>
          <tr>
            <th scope="col">{tr("Actif", "Asset")}</th>
            {CATS.map(([c, short]) => (
              <th key={c} scope="col" title={CATNAME[c]} className={cur?.c === c ? "on" : ""}>
                {short}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {assets.map((a) => (
            <tr key={a.n} className={cur?.a === a.n ? "on" : ""}>
              <th scope="row">
                <button type="button" className="hmhost" onClick={() => showSheet(<AssetSheet n={a.n} />)}>
                  {a.n}
                </button>
              </th>
              {CATS.map(([c]) => {
                const st = catState(a, c, issues, evaluated);
                const nOpen = issues.filter((i) => !i.fixed && i.host === a.n && i.cat === c).length;
                const label =
                  st === "na"
                      ? tr("non concerné", "not applicable")
                      : nOpen
                        ? tr(`${nOpen} problème${nOpen > 1 ? "s" : ""}, niveau ${SEV[st === "ok" ? "ok" : st][0].toLowerCase()}`, `${nOpen} problem${nOpen > 1 ? "s" : ""}, ${SEV[st === "ok" ? "ok" : st][0].toLowerCase()} level`)
                        : tr("aucun problème", "no problem");
                const isCur = cur?.a === a.n && cur?.c === c;
                return (
                  <td key={c}>
                    <button
                      type="button"
                      className={"hcell s-" + st + (isCur ? " cur" : "") + (cur && !isCur ? " dim" : "")}
                      aria-label={`${a.n}, ${CATNAME[c]} : ${label}`}
                      onMouseEnter={(e) => point(a.n, c, e.currentTarget)}
                      onFocus={(e) => point(a.n, c, e.currentTarget)}
                      onBlur={tip.leave}
                      onClick={() => showSheet(<AssetSheet n={a.n} />)}
                    >
                      {st === "na" ? "" : nOpen ? nOpen : <Tick size={12} width={3.2} />}
                    </button>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      </div>
      {cur && (
        <div className={"htip" + (cur.below ? " below" : "")} role="tooltip" style={{ left: cur.x, top: cur.y }} onMouseEnter={tip.hold} onMouseLeave={tip.leave} onFocus={tip.hold} onBlur={tip.leave}>
          <b className="mono">{cur.a}</b>
          <em>{CATNAME[cur.c]}</em>
          {curState === "na" ? (
            <span>{tr("Non concerné : ce contrôle ne s’applique pas à cet actif.", "Not applicable: this check does not apply to this asset.")}</span>
          ) : curList.length ? (
            <>
              {curList.slice(0, 4).map((i) => (
                <button
                  key={i.targetId + i.id}
                  type="button"
                  className="htipline htiplink"
                  onClick={() => {
                    tip.close();
                    showSheet(<FindingSheet id={i.id} targetId={i.targetId} />);
                  }}
                >
                  <i className={"sevdot d-" + i.sev} />
                  {i.title}
                </button>
              ))}
              <button
                type="button"
                className="htipmore"
                onClick={() => {
                  tip.close();
                  showSheet(<AssetSheet n={cur.a} />);
                }}
              >
                {curList.length > 4 ? tr(`et ${curList.length - 4} autre(s) : ouvrir l’actif →`, `and ${curList.length - 4} more: open the asset →`) : tr("Ouvrir l’actif →", "Open the asset →")}
              </button>
            </>
          ) : (
            <span className="htipline">
              <i className="sevdot d-ok" />
              {tr("Vérifié, rien à signaler", "Checked, all clear")}
            </span>
          )}
        </div>
      )}
      <ul className="hlegend" aria-label={tr("Légende", "Legend")}>
        <li><i className="hcell s-ok" /> {tr("Rien à signaler", "All clear")}</li>
        <li><i className="hcell s-med" /> {tr("Moyen", "Medium")}</li>
        <li><i className="hcell s-high" /> {tr("Élevé", "High")}</li>
        <li><i className="hcell s-crit" /> {tr("Critique", "Critical")}</li>
        <li><i className="hcell s-na" /> {tr("Non concerné", "Not applicable")}</li>
      </ul>
    </div>
  );
}

export function RapportsPage() {
  const { data, issues, assets, org } = useOrg();
  const { toast } = useUI();
  const [period, setPeriod] = useState<4 | 12>(12);
  const [langs, setLangs] = useState<Record<"executive" | "technical", "fr" | "en">>(() => ({ executive: getLang(), technical: getLang() }));
  if (!data) return null;
  const now = new Date();
  const slots = weeklySlots(data.overview.trend, period, now);
  const hist = slots.filter((x): x is number => x !== null);
  const open = issues.filter((i) => !i.fixed).length;
  const fixed = issues.length - open;
  const evaluated = evaluatedCats(data.checks);
  const segs: [string, readonly [number, number]][] = families(data.checks).map(([name, p, t]) => [name, [p, t]] as const);
  const pass = segs.reduce((s, [, [p]]) => s + p, 0);
  const total = segs.reduce((s, [, [, t]]) => s + t, 0);
  const reports = data.subscription.plan.reports;
  const pdf = (kind: "executive" | "technical", label: string, ghost: boolean, lang: "fr" | "en") =>
    reports ? (
      <a className={"btn sm" + (ghost ? " ghost" : "")} href={reportURL(org.org_id, kind, lang)} download>
        {tr("Générer le PDF", "Generate the PDF")}
      </a>
    ) : (
      <button className={"btn sm" + (ghost ? " ghost" : "")} type="button" aria-disabled="true" onClick={() => toast(tr(`${label} : inclus à partir de l’offre Essentiel`, `${label}: included from the Essential plan`))}>
        {tr("Générer le PDF", "Generate the PDF")}
      </button>
    );

  return (
    <>
      <div className="ph">
        <div>
          <h1>{tr("Rapports", "Reports")}</h1>
          <p>{tr("L’évolution de votre sécurité, et les rapports à partager.", "How your security is evolving, and the reports to share.")}</p>
        </div>
        <div className="phacts">
          <div className="cseg" role="group" aria-label={tr("Période", "Period")}>
            {(
              [
                [4, tr("4 sem.", "4 wk")],
                [12, tr("12 sem.", "12 wk")],
              ] as const
            ).map(([k, l]) => (
              <button key={k} type="button" aria-pressed={period === k} onClick={() => setPeriod(k)}>
                {l}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid2">
        <section className="panel">
          <header>
            <h2><Ico d={G.chart} />{tr("Score de sécurité", "Security score")}</h2>
            <span className="panelsub">
              <b className="scorenow">{data.overview.score ?? "–"}</b> / 100
              {hist.length > 1 && (
                <>
                  {" · "}
                  <em className={"delta " + (hist[hist.length - 1]! - hist[0]! >= 0 ? "up" : "dn")}>
                    {(hist[hist.length - 1]! - hist[0]! >= 0 ? "+" : "") + (hist[hist.length - 1]! - hist[0]!)}
                  </em>{" "}
                  {tr(`en ${hist.length} semaines`, `in ${hist.length} weeks`)}
                </>
              )}
            </span>
          </header>
          <div className="panelbody">
            <WeekBars slots={slots} now={now} />
          </div>
          <p className="panelfoot">{tr(`${fixed} corrigé${fixed > 1 ? "s" : ""}, ${open} ouvert${open > 1 ? "s" : ""}.`, `${fixed} fixed, ${open} open.`)}</p>
        </section>
        <section className="panel">
          <header>
            <h2><Ico d={G.shield} tone="green" />{tr("Contrôles automatisés", "Automated checks")}</h2>
            <span className="panelsub">{tr(`${pass} réussis sur ${total}`, `${pass} of ${total} passed`)}</span>
          </header>
          <div className="tw">
            <table className="ctable ctnarrow">
              <thead>
                <tr>
                  <th>{tr("Famille", "Family")}</th>
                  <th>{tr("Réussis", "Passed")}</th>
                  <th style={{ width: "42%" }}>
                    <span className="vh">{tr("Part réussie", "Share passed")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {segs.map(([name, [p, t]]) => (
                  <tr key={name}>
                    <td>{name}</td>
                    <td className="num">{t ? `${p} / ${t}` : "–"}</td>
                    <td>
                      {t > 0 && (
                        <div className="sevbar" role="img" aria-label={tr(`${name} : ${p} contrôles réussis sur ${t}`, `${name}: ${p} of ${t} checks passed`)}>
                          {p > 0 && <i style={{ flex: p, background: "var(--ok)" }} />}
                          {t - p > 0 && <i style={{ flex: t - p, background: p / t >= 0.5 ? "var(--high)" : "var(--crit)" }} />}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="panelfoot">
            {tr("Chaque scan réévalue ces contrôles. ", "Every scan evaluates these checks again. ")}
            <Link to={settingsPath(org.org_id, "scans")}>{tr("Ce que nous vérifions", "What we check")}</Link>
          </p>
        </section>
      </div>

      <div className="grid2">
        <section className="panel">
          <header>
            <h2><Ico d={G.grid} tone="amber" />{tr("Où est le risque", "Where the risk is")}</h2>
            <span className="panelsub">{tr("problèmes ouverts par actif", "open problems by asset")}</span>
          </header>
          <div className="panelbody">
            <HeatTable assets={assets} issues={issues} evaluated={evaluated} />
          </div>
        </section>
        <div className="repcol">
          {(
            [
              ["executive", tr("Rapport Direction", "Executive report"), tr("Dirigeants, clients, assureur", "Executives, customers, insurer"), tr("Deux pages sans jargon : le score, ce qui a été corrigé, ce qui reste à décider.", "Two pages, no jargon: the score, what was fixed, what remains to decide."), false],
              ["technical", tr("Rapport Technique", "Technical report"), tr("Informaticien, prestataire", "IT person, provider"), tr("Chaque problème, sa preuve, sa CVE et les étapes de correction.", "Every problem, its evidence, its CVE and the steps to fix it."), true],
            ] as const
          ).map(([kind, name, who, what, ghost]) => (
            <section key={kind} className="panel repcard">
              <div className="repbody">
                <span className="repicon" aria-hidden="true">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M6 3h9l4 4v14H6zM14 3v5h5M9 13h6M9 17h6" />
                  </svg>
                </span>
                <div>
                  <h2>{name}</h2>
                  <p className="repwho">{tr(`Pour : ${who}`, `For: ${who}`)}</p>
                  <p className="repwhat">{what}</p>
                </div>
              </div>
              <footer>
                <div className="cseg" role="group" aria-label={tr(`Langue du ${name}`, `${name} language`)}>
                  {(["fr", "en"] as const).map((l) => (
                    <button key={l} type="button" aria-pressed={langs[kind] === l} onClick={() => setLangs({ ...langs, [kind]: l })}>
                      {l.toUpperCase()}
                    </button>
                  ))}
                </div>
                {pdf(kind, name, ghost, langs[kind])}
              </footer>
            </section>
          ))}
        </div>
      </div>
    </>
  );
}
