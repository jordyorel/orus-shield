import { useEffect, useRef, useState, type CSSProperties } from "react";
import type { Activity } from "../../api/types";
import { Link, navigate } from "../../router";
import { appPath, settingsPath } from "../AppShell";
import { Tick } from "../icons";
import { G, Ico } from "../glyphs";
import { PROGRESS_DAYS, SEV, byPriority, families, feedDay, groupIssues, groupVerdict, hostsText, progressOf, scoreLevel, verdictText, type IssueGroup } from "../model";
import { getLang, locale, tr } from "../../i18n";
import { localTitle } from "../lang";
import { useOrg } from "../OrgData";
import { FindingSheet, ScoreSheet, useFix } from "../sheets";
import { scanTimes, useScanNow, when } from "../ScanLine";
import { useLinger } from "../linger";
import { useUI } from "../ui";
import { AddPanel } from "./Actifs";

function shortDay(iso: string): string {
  const d = new Date(iso);
  return `${d.toLocaleDateString(locale(), { weekday: "short", day: "numeric", month: "short" })}, ${d.toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" })}`;
}

function FeedLine({ a, now }: { a: Activity; now: Date }) {
  let cls = "";
  let text;
  if (a.kind === "scan") {
    text = (
      <span>
        {tr("Scan terminé sur ", "Scan finished on ")}
        <b>{a.domain}</b>
        {tr(
          ` : ${a.assets ?? 0} actif${(a.assets ?? 0) > 1 ? "s" : ""} vérifié${(a.assets ?? 0) > 1 ? "s" : ""}.`,
          `: ${a.assets ?? 0} asset${(a.assets ?? 0) > 1 ? "s" : ""} checked.`,
        )}
      </span>
    );
  } else if (a.to === "fixed") {
    cls = "f-ok";
    text = (
      <span>
        {tr("Corrigé sur ", "Fixed on ")}
        <b>{a.asset}</b>
        {tr(" : ", ": ")}
        {localTitle(a.title, a.title_fr)}.
      </span>
    );
  } else if (a.to === "accepted_risk") {
    text = (
      <span>
        {tr("Risque accepté sur ", "Risk accepted on ")}
        <b>{a.asset}</b>
        {tr(" : ", ": ")}
        {localTitle(a.title, a.title_fr)}.
      </span>
    );
  } else {
    if (a.severity === "critical" || a.severity === "high") cls = "f-crit";
    text = (
      <span>
        {a.from === "fixed" ? tr("Revenu sur ", "Back on ") : tr("Nouveau problème sur ", "New problem on ")}
        <b>{a.asset}</b>
        {tr(" : ", ": ")}
        {localTitle(a.title, a.title_fr)}.
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
  const sc = score === null ? "" : tr(`Score de sécurité : ${score}/100. `, `Security score: ${score}/100. `);
  const pb =
    open === 0
      ? tr("Aucun problème à corriger pour le moment.", "Nothing to fix for now.")
      : tr(`${open} problème${open > 1 ? "s" : ""} à corriger, du plus urgent au moins urgent.`, `${open} problem${open > 1 ? "s" : ""} to fix, most urgent first.`);
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
    { title: tr("Compte créé et protégé", "Account created and protected"), hint: tr("Mot de passe et double authentification.", "Password and two-factor authentication."), s: "done" },
    {
      title: tr("Ajoutez votre domaine", "Add your domain"),
      hint: tr("Celui de votre site ou de vos emails : nous trouvons ses sous-domaines et ses serveurs.", "The one of your website or your email: we find its subdomains and servers."),
      s: state(added, true),
    },
    {
      title: tr("Prouvez qu’il est à vous", "Prove it is yours"),
      hint: tr("Un enregistrement TXT à ajouter dans sa zone DNS. Nous n’analysons que ce qui vous appartient.", "A TXT record to add to its DNS zone. We only analyse what belongs to you."),
      s: state(verified, added),
    },
    {
      title: tr("Premier scan", "First scan"),
      hint: finished
        ? tr("Terminé. Le résumé vous attend aussi par email.", "Done. The summary is also waiting in your inbox.")
        : scanning
          ? tr("En cours, volontairement léger : cet écran se remplit dès qu’il est terminé, et vous recevez un résumé par email.", "Running, deliberately light: this screen fills in as soon as it is done, and you get a summary by email.")
          : failed
            ? tr("Le scan n’a pas abouti. Relancez-le depuis Actifs.", "The scan did not complete. Start it again from Assets.")
            : tr("Il démarre dès que le domaine est vérifié.", "It starts as soon as the domain is verified."),
      s: state(finished, verified),
    },
  ];
  const done = steps.filter((x) => x.s === "done").length;
  return (
    <div className="section onboard">
      <div className="rhead">
        <h2>{tr("Premiers pas", "Getting started")}</h2>
        <span
          className="dots big3"
          role="img"
          aria-label={tr(`${done} étape${done > 1 ? "s" : ""} faite${done > 1 ? "s" : ""} sur ${steps.length}`, `${done} of ${steps.length} steps done`)}
        >
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
              {tr("Voir mes résultats", "See my results")}
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
          <p className="hint">{tr("Un administrateur de l’organisation ajoute et vérifie le domaine.", "An administrator of the organization adds and verifies the domain.")}</p>
        ))}
      {failed && (
        <p className="hint">
          <Link className="link" to={appPath(org.org_id, "actifs")}>
            {tr("Ouvrir Actifs", "Open Assets")}
          </Link>
        </p>
      )}
      <p className="hint">
        {finished ? tr("Et maintenant", "Now") : tr("Ensuite", "Next")}
        {tr(" : qui reçoit les alertes, et votre équipe, dans ", ": who receives the alerts, and your team, in ")}
        <Link className="link" to={settingsPath(org.org_id, "alertes")}>
          {tr("Réglages", "Settings")}
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
  const when = done
    ? tr(` du ${new Date(done).toLocaleDateString("fr-FR", { day: "numeric", month: "long" })}`, ` of ${new Date(done).toLocaleDateString("en-GB", { day: "numeric", month: "long" })}`)
    : "";
  const trial = data.subscription.trial_available;
  return (
    <div className="rpanel freeband" role="note">
      <p>
        <b>{tr(`Offre Gratuit : audit unique${when}.`, `Free plan: single audit${when}.`)}</b>{" "}
        {tr("Plus rien n’est revérifié. ", "Nothing is checked again. ")}
        {trial ? tr("Activez l’essai de 14 jours", "Start the 14-day trial") : tr("Choisissez une offre", "Choose a plan")}
        {tr(" pour un scan chaque semaine et la vérification de vos corrections.", " for a scan every week and every fix verified.")}
      </p>
      <Link className="btn" to={appPath(org.org_id, "offre")}>
        {trial ? tr("Essayer 14 jours", "Try 14 days") : tr("Voir les offres", "See the plans")}
      </Link>
    </div>
  );
}

export function AujourdhuiPage() {
  const { me, org, data, issues, verdicts } = useOrg();
  const { showSheet } = useUI();
  const fix = useFix();
  const scanNow = useScanNow();
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
      ? tr("Rien à corriger pour l’instant.", "Nothing to fix for now.")
      : left === 0
        ? tr("Tout est fait pour aujourd’hui.", "All done for today.")
        : left === 1
          ? tr("Plus qu’une action pour aujourd’hui.", "Just one action left for today.")
          : tr(`${left} actions vous séparent d’un périmètre plus sûr.`, `${left} actions stand between you and a safer perimeter.`);
  const first = me.name.split(/\s+/)[0];
  const score = data.overview.score;
  const progress = progressOf(issues, data.overview.trend, score, now);
  // The first scan just finished under the customer's eyes: the card's
  // closing screen, until they move on to the results.
  if (!beforeFirstScan && onboard === "shown") {
    return (
      <>
        <p className="hello">{first ? tr(`Bonjour ${first}`, `Hello ${first}`) : tr("Bonjour", "Hello")}</p>
        <h1 className="lead">{tr("Votre premier scan est terminé.", "Your first scan is done.")}</h1>
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
        <p className="hello">{first ? tr(`Bonjour ${first}`, `Hello ${first}`) : tr("Bonjour", "Hello")}</p>
        <h1 className="lead">
          {!domains.length
            ? tr("Bienvenue. Voyons ce que vous exposez sur internet.", "Welcome. Let us see what you expose on the internet.")
            : scanning
              ? tr("Votre premier scan est lancé.", "Your first scan has started.")
              : failed
                ? tr("Votre premier scan n’a pas abouti.", "Your first scan did not complete.")
                : domains.some((t) => t.verified)
                  ? tr("Votre domaine est vérifié.", "Your domain is verified.")
                  : tr("Plus qu’une étape avant votre premier scan.", "One step left before your first scan.")}
        </h1>
        <Onboarding />
      </>
    );
  }

  const domains = data.targets.filter((t) => !t.internal);
  const openGroups = groups.filter((g) => !g.fixed);
  const bySev = (["crit", "high", "med", "low"] as const).map((k) => [k, openGroups.filter((g) => g.lead.sev === k).length] as const);
  const times = scanTimes(data.scans, domains);
  const fams = families(data.checks);
  const delta = progress && progress.from !== null && score !== null ? score - progress.from : 0;
  return (
    <>
      {!data.subscription.plan.monitoring && <FreeBand />}
      <div className="ph">
        <div>
          <h1>{first ? tr(`Bonjour ${first}`, `Hello ${first}`) : tr("Bonjour", "Hello")}</h1>
          <p>{head}</p>
        </div>
        <div className="phacts">
          <Link className="btn ghost sm" to={appPath(org.org_id, "rapports")}>
            {tr("Rapports PDF", "PDF reports")}
          </Link>
          <button className="btn sm" type="button" disabled={times.running} onClick={() => void scanNow(domains)}>
            {times.running ? tr("Scan en cours", "Scan running") : tr("Scanner maintenant", "Scan now")}
          </button>
        </div>
      </div>

      {/* The four answers to "where do I stand?", in one strip. */}
      <div className="statstrip">
        <div className="stat">
          <small><Ico d={G.shield} />{tr("Score de sécurité", "Security score")}</small>
          <p className="statv">
            <b>{score ?? "–"}</b>
            {score !== null && <span>/100</span>}
            {delta !== 0 && <em className={"delta " + (delta > 0 ? "up" : "dn")}>{(delta > 0 ? "+" : "") + delta}</em>}
            <Spark points={data.overview.trend} />
          </p>
          <p className="statfoot">
            <span>{scoreLevel(score)}</span>
            <button className="link" type="button" onClick={() => showSheet(<ScoreSheet />)}>
              {tr("Comprendre mon score", "Understand my score")}
            </button>
          </p>
        </div>
        <div className="stat">
          <small><Ico d={G.bug} tone="red" />{tr("Problèmes ouverts", "Open problems")}</small>
          <p className="statv">
            <b>{openGroups.length}</b>
            <span>
              {bySev
                .filter(([, n]) => n)
                .map(([k, n]) => `${n} ${SEV[k][0].toLowerCase()}${n > 1 && getLang() === "fr" ? "s" : ""}`)
                .join(" · ") || tr("rien à corriger", "nothing to fix")}
            </span>
          </p>
          <div className="sevbar" role="img" aria-label={bySev.map(([k, n]) => `${SEV[k][0]} : ${n}`).join(", ")}>
            {bySev.map(([k, n]) => (n ? <i key={k} style={{ flex: n, background: SEVVAR[k] }} /> : null))}
            {!openGroups.length && <i style={{ flex: 1, background: "var(--ok)" }} />}
          </div>
        </div>
        <div className="stat">
          <small><Ico d={G.check} tone="green" />{tr(`Corrigés sur ${PROGRESS_DAYS} jours`, `Fixed in ${PROGRESS_DAYS} days`)}</small>
          <p className="statv">
            <b>{progress?.fixed ?? 0}</b>
          </p>
          <p className="statfoot">
            <span>
              {progress && progress.from !== null && progress.from !== progress.to
                ? tr(`Score ${progress.from} → ${progress.to}`, `Score ${progress.from} → ${progress.to}`)
                : tr("Score stable", "Steady score")}
            </span>
          </p>
        </div>
        <div className="stat">
          <small><Ico d={G.clock} tone="violet" />{tr("Prochain scan", "Next scan")}</small>
          <p className="statv">
            <b className="statdate">{times.running ? tr("En cours", "Running") : times.next ? shortDay(times.next) : "–"}</b>
          </p>
          <p className="statfoot">
            <span>
              {times.running
                ? tr("Les résultats arrivent ici.", "Results will appear here.")
                : times.last
                  ? tr(`Dernier : ${when(times.last)}`, `Last: ${when(times.last)}`)
                  : tr("Pas encore scanné", "Not scanned yet")}
            </span>
          </p>
        </div>
      </div>

      <div className="grid2">
        <section className="panel">
          <header>
            <h2><Ico d={G.list} />{tr("À faire aujourd’hui", "To do today")}</h2>
            <span className="countchip" id="todo-prog">
              {tr(`${top.length - left} sur ${top.length}`, `${top.length - left} of ${top.length}`)}
            </span>
            <Link className="phlink" to={appPath(org.org_id, "problemes")}>
              {tr("Tous les problèmes →", "All problems →")}
            </Link>
          </header>
          <p className="panelnote">
            {tr(
              "Classé par ce qui vous protège le plus, le plus vite. Cochez quand c’est corrigé : nous vérifions aussitôt.",
              "Ranked by what protects you most, fastest. Tick when it is fixed: we check at once.",
            )}
          </p>
          {top.length ? (
            <ul className="todo prio">
              {top.map((g) => {
                const i = g.lead;
                const v = groupVerdict(g.members, verdicts);
                return (
                  <li key={g.key} className={g.fixed ? "done" : ""}>
                    <button className="check" type="button" aria-pressed={g.fixed} aria-label={tr(`Marquer « ${i.title} » comme fait`, `Mark “${i.title}” as done`)} onClick={() => void fix(g.members)}>
                      <Tick size={14} width={3} />
                    </button>
                    <div className="prioMain">
                      <p className="t">{i.title}</p>
                      <p className="m">
                        <span className="mono">{hostsText(g.hosts)}</span>
                        {" · "}
                        <button className="link" type="button" onClick={() => showSheet(<FindingSheet id={i.id} targetId={i.targetId} />)}>
                          {tr("Comment faire", "How to")}
                        </button>
                      </p>
                      {v && <p className={"verdict v-" + v.state}>{verdictText(v)}</p>}
                    </div>
                    <span className={"sevpill p-" + i.sev}>{SEV[i.sev][0]}</span>
                    <span className="priomins">{tr(`${i.mins} min`, `${i.mins} min`)}</span>
                    <span className="gain">+{g.gain} pts</span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="panelnote">{tr("Rien à corriger : nous continuons de surveiller.", "Nothing to fix: we keep watching.")}</p>
          )}
          <p className="panelfoot">
            {openGroups.length
              ? tr(
                  `${openGroups.length} problème${openGroups.length > 1 ? "s" : ""} ouvert${openGroups.length > 1 ? "s" : ""} en tout, environ ${openGroups.reduce((m, g) => m + g.lead.mins, 0)} minutes pour tout corriger.`,
                  `${openGroups.length} open problem${openGroups.length > 1 ? "s" : ""} in all, about ${openGroups.reduce((m, g) => m + g.lead.mins, 0)} minutes to fix everything.`,
                )
              : tr("Aucun problème ouvert.", "No open problem.")}
          </p>
        </section>

        <section className="panel">
          <header>
            <h2><Ico d={G.target} tone="green" />{tr("Posture par famille de contrôles", "Posture by family of checks")}</h2>
            <Link className="phlink" to={appPath(org.org_id, "rapports")}>
              {tr("Détail →", "Detail →")}
            </Link>
          </header>
          <div className="panelbody">
            <div className="gauge">
              <svg width="64" height="64" viewBox="0 0 64 64" role="img" aria-label={tr(`Score ${score ?? "inconnu"} sur 100`, `Score ${score ?? "unknown"} out of 100`)}>
                <circle cx="32" cy="32" r="27" fill="none" stroke="var(--line2)" strokeWidth="7" />
                {score !== null && (
                  <circle cx="32" cy="32" r="27" fill="none" stroke="var(--azur)" strokeWidth="7" strokeLinecap="round" strokeDasharray={`${(score / 100) * 169.6} 170`} transform="rotate(-90 32 32)" />
                )}
                <text id="score-num" x="32" y="37.5" textAnchor="middle" className="gaugenum">
                  {score ?? "–"}
                </text>
              </svg>
              <div>
                <b>{tr("Sur 100", "Out of 100")}</b>
                <p>
                  {(() => {
                    const weak = fams.filter(([, p, t]) => t > 0 && p < t).map(([name]) => name);
                    return weak.length
                      ? tr(`À renforcer : ${weak.join(", ")}.`, `To strengthen: ${weak.join(", ")}.`)
                      : tr("Toutes les familles évaluées sont au vert.", "Every evaluated family is green.");
                  })()}
                </p>
              </div>
            </div>
            {fams.map(([name, pass, total]) => {
              const pct = total ? pass / total : 0;
              return (
                <div className="famrow" key={name}>
                  <b>{name}</b>
                  <span className="track" role="img" aria-label={tr(`${name} : ${pass} réussis sur ${total}`, `${name}: ${pass} of ${total} passed`)}>
                    {total > 0 && <i style={{ width: `${Math.max(pct * 100, 4)}%`, background: pct === 1 ? "var(--ok)" : pct >= 0.5 ? "var(--high)" : "var(--crit)" }} />}
                  </span>
                  <span className="num">{total ? `${pass}/${total}` : "–"}</span>
                </div>
              );
            })}
          </div>
        </section>
      </div>

      <div className="grid2">
        <section className="panel">
          <header>
            <h2><Ico d={G.chart} />{tr("Évolution du score", "Score trend")}</h2>
            <Link className="phlink" to={appPath(org.org_id, "rapports")}>
              {tr("Rapports →", "Reports →")}
            </Link>
          </header>
          <div className="panelbody">
            <TrendChart points={data.overview.trend} />
          </div>
        </section>
        <section className="panel">
          <header>
            <h2><Ico d={G.pulse} tone="slate" />{tr("Depuis votre dernière visite", "Since your last visit")}</h2>
            <span className="panelsub">{tr("7 jours", "7 days")}</span>
          </header>
          {data.activity.length ? (
            <ul className="feed feed2">
              {data.activity.slice(0, 6).map((a, k) => (
                <FeedLine key={k} a={a} now={now} />
              ))}
            </ul>
          ) : (
            <p className="panelnote">{tr("Rien de nouveau ces sept derniers jours.", "Nothing new in the last seven days.")}</p>
          )}
          <p className="panelfoot">
            {tr("Un problème grave vous est aussi envoyé par email. ", "A serious problem is also sent to you by email. ")}
            <Link to={settingsPath(org.org_id, "alertes")}>{tr("Régler les alertes", "Set the alerts")}</Link>
          </p>
        </section>
      </div>
    </>
  );
}

/** SEVVAR are the console's severity colours. */
const SEVVAR: Record<"crit" | "high" | "med" | "low", string> = { crit: "var(--crit)", high: "var(--high)", med: "var(--med)", low: "var(--low)" };

/** TrendChart draws the daily score: an area under a line, one scale for
 * the line and its labels. The pointer (or the arrow keys) picks a day: a
 * guide line, its point and a tooltip with its score and change. */
function TrendChart({ points }: { points: { at: string; score: number | null }[] }) {
  // The tooltip lingers so the pointer can reach and read it (useLinger).
  const tip = useLinger<number>();
  const hover = tip.value;
  const setHover = tip.show;
  const pts = points.filter((p): p is { at: string; score: number } => p.score !== null);
  if (pts.length < 2) return <p className="panelnote">{tr("La courbe apparaît après deux scans.", "The curve appears after two scans.")}</p>;
  const W = 640;
  const H = 180;
  const L = 34;
  const top = 14;
  const bottom = 150;
  const n = pts.length;
  const lo = Math.max(0, Math.floor((Math.min(...pts.map((p) => p.score)) - 10) / 20) * 20);
  const y = (v: number) => bottom - ((v - lo) / (100 - lo)) * (bottom - top);
  const x = (k: number) => L + (k / (n - 1)) * (W - L - 6);
  const line = pts.map((p, k) => `${x(k).toFixed(1)},${y(p.score).toFixed(1)}`).join(" ");
  const ticks = [lo, lo + (100 - lo) / 2, 100].map((v) => Math.round(v));
  const day = (iso: string) => new Date(iso).toLocaleDateString(locale(), { day: "numeric", month: "short" });
  const last = pts[n - 1]!;
  const pick = (e: { clientX: number; currentTarget: Element }) => {
    const r = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * W;
    setHover(Math.max(0, Math.min(n - 1, Math.round(((px - L) / (W - L - 6)) * (n - 1)))));
  };
  const h = hover !== null ? pts[hover]! : null;
  const prev = hover !== null && hover > 0 ? pts[hover - 1]!.score : null;
  const hx = hover !== null ? x(hover) : 0;
  return (
    <div
      className="tchart"
      tabIndex={0}
      role="group"
      aria-label={tr("Score par jour : flèches gauche et droite pour parcourir", "Score by day: left and right arrows to browse")}
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
        aria-label={tr(`Score de ${pts[0]!.score} à ${last.score}`, `Score from ${pts[0]!.score} to ${last.score}`)}
        onPointerMove={pick}
        onPointerDown={pick}
        onPointerLeave={tip.leave}
      >
        <defs>
          <linearGradient id="trendfill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stopColor="var(--azur)" stopOpacity=".22" />
            <stop offset="1" stopColor="var(--azur)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {ticks.map((v) => (
          <g key={v}>
            <line x1={L} x2={W - 6} y1={y(v)} y2={y(v)} stroke="var(--line2)" />
            <text x="0" y={y(v) + 4}>
              {v}
            </text>
          </g>
        ))}
        <path d={`M${x(0)},${bottom} L${line.replaceAll(" ", " L")} L${x(n - 1)},${bottom}Z`} fill="url(#trendfill)" />
        <polyline fill="none" stroke="var(--azur)" strokeWidth="2.2" strokeLinejoin="round" points={line} />
        {h ? (
          <>
            <line className="guide" x1={hx} x2={hx} y1={top} y2={bottom} stroke="var(--ink3)" />
            <circle cx={hx} cy={y(h.score)} r="5" fill="var(--azur)" stroke="var(--surface)" strokeWidth="2.5" />
          </>
        ) : (
          <circle cx={x(n - 1)} cy={y(last.score)} r="4" fill="var(--azur)" stroke="var(--surface)" strokeWidth="2" />
        )}
        <rect x={L} y={top} width={W - L - 6} height={bottom - top} fill="transparent" />
        <text x={L} y={H - 6}>
          {day(pts[0]!.at)}
        </text>
        <text x={W - 6} y={H - 6} textAnchor="end">
          {tr("aujourd’hui", "today")}
        </text>
      </svg>
      {h && (
        <div
          className="wtip"
          role="status"
          onPointerEnter={tip.hold}
          onPointerLeave={tip.leave}
          style={
            {
              left: `${(hx / W) * 100}%`,
              top: `${(y(h.score) / H) * 100}%`,
              "--shift": hx / W > 0.75 ? "-88%" : hx / W < 0.2 ? "-12%" : "-50%",
              "--arrow": hx / W > 0.75 ? "88%" : hx / W < 0.2 ? "12%" : "50%",
            } as CSSProperties
          }
        >
          <b>
            {h.score} <small>/100</small>
          </b>
          <span>{hover === n - 1 ? tr("Aujourd’hui", "Today") : day(h.at)}</span>
          {prev !== null && h.score !== prev && (
            <em className={h.score > prev ? "up" : "dn"}>
              {h.score > prev ? "+" : "−"}
              {Math.abs(h.score - prev)} {tr("depuis la veille", "since the day before")}
            </em>
          )}
        </div>
      )}
    </div>
  );
}

/** Spark is the score's small curve in the strip, the last point marked. */
function Spark({ points }: { points: { score: number | null }[] }) {
  const v = points.map((p) => p.score).filter((x): x is number => x !== null);
  if (v.length < 2) return null;
  const lo = Math.min(...v) - 2;
  const hi = Math.max(...v) + 2;
  const xy = v.map((n, i) => [(i / (v.length - 1)) * 84 + 2, 22 - ((n - lo) / (hi - lo || 1)) * 18] as const);
  const line = xy.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const last = xy[xy.length - 1]!;
  return (
    <svg className="spark2" width="88" height="26" viewBox="0 0 88 26" aria-hidden="true">
      <polyline points={line} fill="none" stroke="var(--azur)" strokeWidth="1.8" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r="2.6" fill="var(--azur)" />
    </svg>
  );
}
