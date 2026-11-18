import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Activity } from "../../api/types";
import { Link, navigate } from "../../router";
import { appPath } from "../AppShell";
import { Tick } from "../icons";
import { COLOR, DIST, byPriority, feedDay, groupIssues, groupVerdict, hostsText, verdictText, worst, type AssetView, type Issue, type IssueGroup } from "../model";
import { localTitle } from "../lang";
import { useOrg } from "../OrgData";
import { AssetSheet, FindingSheet, useFix } from "../sheets";
import { ScanLine } from "../ScanLine";
import { useUI } from "../ui";
import { AddPanel } from "./Actifs";

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
        Corrigé sur <b>{a.asset}</b> : {localTitle(a.title, a.title_fr)}.
      </span>
    );
  } else if (a.to === "accepted_risk") {
    text = (
      <span>
        Risque accepté sur <b>{a.asset}</b> : {localTitle(a.title, a.title_fr)}.
      </span>
    );
  } else {
    if (a.severity === "critical" || a.severity === "high") cls = "f-crit";
    text = (
      <span>
        {a.from === "fixed" ? "Revenu" : "Nouveau problème"} sur <b>{a.asset}</b> : {localTitle(a.title, a.title_fr)}.
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

type StepState = "done" | "cur" | "todo";

/** summaryOf words the first scan's figures for the closing screen. */
function summaryOf(score: number | null, open: number): string {
  const sc = score === null ? "" : `Score de sécurité : ${score}/100. `;
  const pb = open === 0 ? "Aucun problème à corriger pour le moment." : `${open} problème${open > 1 ? "s" : ""} à corriger, du plus urgent au moins urgent.`;
  return sc + pb;
}

/** firstScan says where a new organization's first scan stands, from its
 * domains' scans: running (queued or running), failed (every one failed),
 * or none yet. */
function firstScan(data: { targets: { id: string; internal?: boolean }[]; scans: { target_id: string; status: string }[] }) {
  const ids = new Set(data.targets.filter((t) => !t.internal).map((t) => t.id));
  const scans = data.scans.filter((s) => ids.has(s.target_id));
  const scanning = scans.some((s) => s.status === "queued" || s.status === "running");
  const failed = !scanning && scans.length > 0 && scans.every((s) => s.status === "failed");
  return { scanning, failed };
}

/** Onboarding is the Premiers pas card: what a new organization does before
 * its first results, ticked from real data (domains, verification, scans).
 * It replaces the actions of the day and the radar until a scan has
 * finished: before that, they would show an empty, misleading picture.
 * Nothing is scanned before verification; the API then queues a light
 * first scan. */
/** The Premiers pas card's state in this browser, per organization: "shown"
 * once it has been displayed, "closed" once the customer has moved on to the
 * results. Only a customer who saw the card gets its closing screen; a
 * missing or blocked storage simply skips it. */
const onboardKey = (orgId: string) => `orus.onboard.${orgId}`;
function readOnboard(orgId: string): string {
  try {
    return window.localStorage.getItem(onboardKey(orgId)) ?? "";
  } catch {
    return "";
  }
}
function writeOnboard(orgId: string, v: "shown" | "closed") {
  try {
    window.localStorage.setItem(onboardKey(orgId), v);
  } catch {
    // Private window or blocked storage: the closing screen is skipped.
  }
}

/** finished: the first scan is done; the card shows every step ticked, the
 * first figures and the way to the results (onDone). */
function Onboarding({ finished = false, onDone }: { finished?: boolean; onDone?: () => void }) {
  const { org, data, isAdmin, issues } = useOrg();
  // While a scan runs, OrgProvider reloads now and then: the screen fills by itself.
  const { scanning, failed } = data ? firstScan(data) : { scanning: false, failed: false };
  if (!data) return null;
  const domains = data.targets.filter((t) => !t.internal);
  const added = domains.length > 0;
  const verified = domains.some((t) => t.verified);
  const state = (done: boolean, before: boolean): StepState => (done ? "done" : before ? "cur" : "todo");
  const steps: { title: string; hint: string; s: StepState }[] = [
    { title: "Compte créé et protégé", hint: "Mot de passe et double authentification.", s: "done" },
    { title: "Ajoutez votre domaine", hint: "Celui de votre site ou de vos emails : nous trouvons ses sous-domaines et ses serveurs.", s: state(added, true) },
    { title: "Prouvez qu’il est à vous", hint: "Un enregistrement TXT à ajouter dans sa zone DNS. Nous n’analysons que ce qui vous appartient.", s: state(verified, added) },
    {
      title: "Premier scan",
      hint: finished
        ? "Terminé. Le résumé vous attend aussi par email."
        : scanning
          ? "En cours, volontairement léger : cet écran se remplit dès qu’il est terminé, et vous recevez un résumé par email."
          : failed
            ? "Le scan n’a pas abouti. Relancez-le depuis Actifs."
            : "Il démarre dès que le domaine est vérifié.",
      s: state(finished, verified),
    },
  ];
  const done = steps.filter((x) => x.s === "done").length;
  return (
    <div className="section onboard">
      <div className="rhead">
        <h2>Premiers pas</h2>
        <span className="dots big3" role="img" aria-label={`${done} étape${done > 1 ? "s" : ""} faite${done > 1 ? "s" : ""} sur ${steps.length}`}>
          {steps.map((x) => (
            <i key={x.title} className={x.s === "done" ? "on" : ""} />
          ))}
        </span>
      </div>
      <ol className="todo steps">
        {steps.map((x) => (
          <li key={x.title} className={x.s} aria-current={x.s === "cur" ? "step" : undefined}>
            <span className="check" aria-hidden="true">
              {x.s === "done" ? <Tick size={20} width={3} /> : null}
            </span>
            <div>
              <p className="t">{x.title}</p>
              <p className="m">{x.hint}</p>
            </div>
          </li>
        ))}
      </ol>
      {finished && (
        <>
          <p className="sub">
            {summaryOf(data.overview.score, issues.filter((i) => !i.fixed).length)}
          </p>
          <div className="actions">
            <button className="btn" type="button" onClick={onDone}>
              Voir mes résultats
            </button>
          </div>
        </>
      )}
      {!finished &&
        !verified &&
        (isAdmin ? (
          <div className="rpanel addpanel">
            <AddPanel resume />
          </div>
        ) : (
          <p className="hint">Un administrateur de l’organisation ajoute et vérifie le domaine.</p>
        ))}
      {failed && (
        <p className="hint">
          <Link className="link" to={appPath(org.org_id, "actifs")}>
            Ouvrir Actifs
          </Link>
        </p>
      )}
      <p className="hint">
        {finished ? "Et maintenant" : "Ensuite"} : qui reçoit les alertes, et votre équipe, dans{" "}
        <Link className="link" to={appPath(org.org_id, "reglages")}>
          Réglages
        </Link>
        .
      </p>
    </div>
  );
}

/** FreeBand reminds a free organization that its audit was a single one,
 * and offers the trial. */
function FreeBand() {
  const { org, data } = useOrg();
  if (!data) return null;
  const done = data.scans
    .filter((s) => s.status === "done" && s.finished_at)
    .map((s) => s.finished_at as string)
    .sort()[0];
  const when = done ? ` du ${new Date(done).toLocaleDateString("fr-FR", { day: "numeric", month: "long" })}` : "";
  const trial = data.subscription.trial_available;
  return (
    <div className="rpanel freeband" role="note">
      <p>
        <b>Offre Gratuit : audit unique{when}.</b> Plus rien n’est revérifié. {trial ? "Activez l’essai de 14 jours" : "Choisissez une offre"} pour un scan chaque
        semaine et la vérification de vos corrections.
      </p>
      <Link className="btn" to={appPath(org.org_id, "offre")}>
        {trial ? "Essayer 14 jours" : "Voir les offres"}
      </Link>
    </div>
  );
}

export function AujourdhuiPage() {
  const { me, org, data, issues, assets, verdicts } = useOrg();
  const { showSheet } = useUI();
  const fix = useFix();
  const [onboard, setOnboard] = useState(() => readOnboard(org.org_id));
  const beforeFirstScan = !!data && !data.scans.some((s) => s.status === "done") && data.assets.length === 0;
  useEffect(() => {
    if (beforeFirstScan && onboard === "") {
      writeOnboard(org.org_id, "shown");
      setOnboard("shown");
    }
  }, [beforeFirstScan, onboard, org.org_id]);
  // The three actions of the day are chosen once, when the screen opens
  // (the open problems that protect the most): ticking one keeps it in
  // place with its green check, as in the mockup.
  const chosen = useRef<string[] | null>(null);
  if (!data) return null;
  const now = new Date();
  // One action per problem: the same check on several names is one group.
  const groups = groupIssues(issues);
  if (!chosen.current || chosen.current.some((k) => !groups.some((g) => g.key === k))) {
    chosen.current = groups
      .filter((g) => !g.fixed)
      .sort((a, b) => byPriority(a.lead, b.lead))
      .slice(0, 3)
      .map((g) => g.key);
  }
  const ids = chosen.current;
  const top = ids.map((k) => groups.find((g) => g.key === k)).filter((g): g is IssueGroup => g !== undefined);
  const left = top.filter((g) => !g.fixed).length;
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
  // The first scan just finished under the customer's eyes: the card's
  // closing screen, until they move on to the results.
  if (!beforeFirstScan && onboard === "shown") {
    return (
      <>
        <p className="hello">{first ? `Bonjour ${first}` : "Bonjour"}</p>
        <h1 className="lead">Votre premier scan est terminé.</h1>
        <Onboarding
          finished
          onDone={() => {
            writeOnboard(org.org_id, "closed");
            setOnboard("closed");
            // After the free audit, its results lead to the trial offer first.
            if (!data.subscription.plan.monitoring) navigate(appPath(org.org_id, "offre"));
          }}
        />
      </>
    );
  }
  // Nothing scanned yet: the Premiers pas card instead of an empty picture.
  if (beforeFirstScan) {
    const domains = data.targets.filter((t) => !t.internal);
    const { scanning, failed } = firstScan(data);
    return (
      <>
        <p className="hello">{first ? `Bonjour ${first}` : "Bonjour"}</p>
        <h1 className="lead">
          {!domains.length
            ? "Bienvenue. Voyons ce que vous exposez sur internet."
            : scanning
              ? "Votre premier scan est lancé."
              : failed
                ? "Votre premier scan n’a pas abouti."
                : domains.some((t) => t.verified)
                  ? "Votre domaine est vérifié."
                  : "Plus qu’une étape avant votre premier scan."}
        </h1>
        <Onboarding />
      </>
    );
  }

  return (
    <>
      {!data.subscription.plan.monitoring && <FreeBand />}
      <div className="today">
        <div>
          <p className="hello">{first ? `Bonjour ${first}` : "Bonjour"}</p>
          <h1 className="lead">{head}</h1>
          <ScanLine targets={data.targets.filter((t) => !t.internal)} />
          <div className="section">
            <div className="rhead">
              <h2>À faire aujourd’hui</h2>
              <span className="dots big3" id="todo-prog" role="img" aria-label={`${top.length - left} actions faites sur ${top.length}`}>
                {top.map((g) => (
                  <i key={g.key} className={g.fixed ? "on" : ""} />
                ))}
              </span>
            </div>
            <p className="hint">Classé par ce qui vous protège le plus, le plus vite. Cochez quand c’est corrigé : nous vérifions aussitôt.</p>
            <ul className="todo">
              {top.map((g) => {
                const i = g.lead;
                const v = groupVerdict(g.members, verdicts);
                return (
                  <li key={g.key} className={g.fixed ? "done" : ""}>
                    <button className="check" type="button" aria-pressed={g.fixed} aria-label={`Marquer « ${i.title} » comme fait`} onClick={() => void fix(g.members)}>
                      <Tick size={20} width={3} />
                    </button>
                    <div>
                      <p className="t">{i.title}</p>
                      <p className="m">
                        {hostsText(g.hosts)}, environ {i.mins} min ·{" "}
                        <button className="link" type="button" style={{ minHeight: 0 }} onClick={() => showSheet(<FindingSheet id={i.id} targetId={i.targetId} />)}>
                          Comment faire
                        </button>
                      </p>
                      {v && <p className={"verdict v-" + v.state}>{verdictText(v)}</p>}
                    </div>
                    <span className="gain">+{g.gain} pts</span>
                  </li>
                );
              })}
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
