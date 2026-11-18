// The side sheets of the mockup: a problem (openSheet) and an asset
// (openAsset). They read the organization's data each render, so they
// follow changes (marked fixed, reopened, rescanned).

import { useState } from "react";
import { api, ApiError } from "../api/client";
import type { Scan } from "../api/types";
import { Close, Expand, NavIcon, Shrink, Tick } from "./icons";
import { CATS, RANK, SEV, STATE_LABEL, catState, evaluatedCats, groupIssues, scoreVerdict, sevOf, strongChecks, weakChecks, worst, type Issue, type SevOrOk } from "./model";
import { tr, useLang, type Lang } from "../i18n";
import { Link } from "../router";
import { useOrg } from "./OrgData";
import { mailtoLink, providerMessage, whatsappLink } from "./share";
import { useUI } from "./ui";

export function SevTag({ s, label }: { s: SevOrOk; label?: string | undefined }) {
  return (
    <span className={"sev " + SEV[s][1]}>
      <i />
      {label ?? SEV[s][0]}
    </span>
  );
}

/** isAuditUsed: the API refused because the free offer's single audit is
 * used (code audit_used). */
export function isAuditUsed(e: unknown): boolean {
  return e instanceof ApiError && e.code === "audit_used";
}

const UPSELL: Record<"fix" | "scan", () => [string, string]> = {
  fix: () => [
    tr("Faisons vérifier votre correction", "Let us verify your fix"),
    tr(
      "Votre audit gratuit est terminé. Pour qu’un nouveau scan confirme votre correction et que votre score remonte, activez l’essai de l’offre Essentiel.",
      "Your free audit is over. To have a new scan confirm your fix and raise your score, start the Essential trial.",
    ),
  ],
  scan: () => [
    tr("Relancez le scan avec l’essai", "Scan again with the trial"),
    tr(
      "Votre audit gratuit est terminé. Pour scanner à nouveau, chaque semaine, ports et vulnérabilités connues compris, activez l’essai de l’offre Essentiel.",
      "Your free audit is over. To scan again every week, ports and known vulnerabilities included, start the Essential trial.",
    ),
  ],
};

/** UpsellSheet answers an action the free offer's single audit does not
 * include (verify a fix, scan again) with the trial offer. */
export function UpsellSheet({ what }: { what: "fix" | "scan" }) {
  const { org, data } = useOrg();
  const { closeAll } = useUI();
  const [title, text] = UPSELL[what]();
  const trial = data?.subscription.trial_available ?? true;
  return (
    <>
      <div className="shead">
        <span />
        <CloseButton />
      </div>
      <h2 id="sheet-title">{title}</h2>
      <p className="sub">{text}</p>
      <ul className="upsell">
        <li>{tr("Un scan complet chaque semaine", "A full scan every week")}</li>
        <li>{tr("La vérification de chaque correction", "Every fix verified")}</li>
        <li>{tr("Les alertes par email et les rapports PDF", "Email alerts and PDF reports")}</li>
      </ul>
      {trial && (
        <p className="sub">
          {tr("14 jours d’essai : aucun prélèvement avant la fin, annulable en un clic.", "14-day trial: no charge before it ends, cancel in one click.")}
        </p>
      )}
      <div className="actions">
        <Link className="btn" to={`/orgs/${encodeURIComponent(org.org_id)}/offre`} onClick={closeAll}>
          {trial ? tr("Essayer 14 jours", "Try 14 days") : tr("Choisir une offre", "Choose a plan")}
        </Link>
      </div>
    </>
  );
}

/** CloseButton ends a sheet's header: the "see it large" toggle, then close. */
export function CloseButton() {
  const { closeAll, wide, toggleWide } = useUI();
  return (
    <span className="sheetbtns">
      <button className="iconbtn" type="button" aria-pressed={wide} aria-label={wide ? tr("Réduire", "Shrink") : tr("Agrandir", "Expand")} title={wide ? tr("Réduire", "Shrink") : tr("Agrandir", "Expand")} onClick={toggleWide}>
        {wide ? <Shrink /> : <Expand />}
      </button>
      <button className="iconbtn" type="button" data-close aria-label={tr("Fermer", "Close")} onClick={closeAll}>
        <Close />
      </button>
    </span>
  );
}

/** Steps ticked in a sheet, kept while the page is open (as in the mockup). */
const ticked = new Map<string, boolean[]>();

/** waitScan polls a scan until it ends, at most limitMs. null: still running. */
export async function waitScan(orgId: string, scanId: string, limitMs = 180_000): Promise<Scan | null> {
  const end = Date.now() + limitMs;
  while (Date.now() < end) {
    await new Promise((r) => setTimeout(r, 3000));
    const sc = await api.scan(orgId, scanId);
    if (sc.status === "done" || sc.status === "failed") return sc;
  }
  return null;
}

/** useFix marks a problem fixed or reopens it, with the mockup's toasts. A
 * group (the same problem on several names) is fixed in one gesture. Marked
 * fixed, it is followed until its verification scan says whether it is gone
 * (OrgProvider.watchFixes). */
export function useFix() {
  const { setStatus, isAdmin, data, watchFixes, forgetVerdicts } = useOrg();
  const { toast, showSheet } = useUI();
  return async (target: Issue | Issue[]) => {
    const all = Array.isArray(target) ? target : [target];
    if (!isAdmin) {
      toast(tr("Réservé aux administrateurs", "Administrators only"));
      return;
    }
    const fixing = !all.every((i) => i.fixed);
    // A fix is verified by a scan: after the free audit, that needs an offer.
    if (fixing && data && !data.subscription.plan.monitoring) {
      showSheet(<UpsellSheet what="fix" />);
      return;
    }
    // Fixing: the open ones. Reopening: those marked fixed (an accepted
    // risk stays the customer's decision, reopened from its own sheet).
    const list = all.filter((i) => (fixing ? !i.fixed : i.fixed && !i.accepted));
    const gain = list.reduce((s, i) => s + i.gain, 0);
    toast(fixing ? tr(`Marqué comme corrigé : +${gain} points, vérification en cours`, `Marked as fixed: +${gain} points, checking`) : tr("Rouvert", "Reopened"));
    try {
      for (const i of list) await setStatus(i, fixing ? "fixed" : "open");
      if (fixing) watchFixes(list);
      else forgetVerdicts(list);
    } catch (e) {
      if (isAuditUsed(e)) showSheet(<UpsellSheet what="fix" />);
      else toast(e instanceof ApiError && e.status === 403 ? tr("Réservé aux administrateurs", "Administrators only") : tr("Impossible pour le moment, réessayez", "Not possible right now, try again"));
    }
  };
}

/**
 * ShareBlock is "Envoyer à mon prestataire": the problem, ready to forward
 * to whoever fixes it (web agency, host, IT person), by email or WhatsApp,
 * or copied. The message's language is chosen here: the provider may not
 * speak the dashboard's.
 */
function ShareBlock({ i, copy }: { i: Issue; copy: (v: string) => void }) {
  const { issues, me } = useOrg();
  const { lang } = useLang();
  const [msgLang, setMsgLang] = useState<Lang>(lang);
  // Every name of its problem line (the same check failing on several).
  const hosts = [
    ...new Set(issues.filter((x) => x.targetId === i.targetId && x.finding.check_id === i.finding.check_id && x.title === i.title && x.fixed === i.fixed).map((x) => x.host)),
  ];
  const m = providerMessage(i, hosts, msgLang, me.name);
  return (
    <>
      <h3>{tr("Envoyer à mon prestataire", "Send to my provider")}</h3>
      <p className="why">
        {tr(
          "C’est votre agence web, votre hébergeur ou votre informaticien qui corrige ? Envoyez-lui ce problème, avec ses étapes et sa preuve technique.",
          "Is it your web agency, your host or your IT person who fixes things? Send them this problem, with its steps and technical evidence.",
        )}
      </p>
      <div className="sharerow">
        <div className="seg2 langsw" role="group" aria-label={tr("Langue du message", "Language of the message")}>
          {(
            [
              ["fr", "FR", "Français"],
              ["en", "EN", "English"],
            ] as const
          ).map(([k, short, name]) => (
            <button key={k} type="button" lang={k} aria-label={name} aria-pressed={msgLang === k} onClick={() => setMsgLang(k)}>
              {short}
            </button>
          ))}
        </div>
        <a className="btn ghost sm" href={mailtoLink(m)}>
          {tr("Email", "Email")}
        </a>
        <a className="btn ghost sm" href={whatsappLink(m)} target="_blank" rel="noopener noreferrer">
          WhatsApp
        </a>
        <button className="link" type="button" onClick={() => copy(m.subject + "\n\n" + m.body)}>
          {tr("Copier le message", "Copy the message")}
        </button>
      </div>
    </>
  );
}

export function FindingSheet({ id, targetId }: { id: string; targetId: string }) {
  const { issues, org, reload, isAdmin } = useOrg();
  const { toast, showSheet, closeAll } = useUI();
  const fix = useFix();
  const i = issues.find((x) => x.id === id && x.targetId === targetId);
  const key = targetId + "/" + id;
  const [st, setSt] = useState<boolean[]>(() => ticked.get(key) ?? (i ? i.steps.map(() => false) : []));
  const [checking, setChecking] = useState(false);
  if (!i) {
    return (
      <>
        <div className="shead">
          <span />
          <CloseButton />
        </div>
        <h2 id="sheet-title">{tr("Ce problème n’existe plus", "This problem no longer exists")}</h2>
      </>
    );
  }
  const done = st.filter(Boolean).length;
  const toggle = (k: number) => {
    const next = st.map((v, j) => (j === k ? !v : v));
    ticked.set(key, next);
    setSt(next);
  };
  const copy = (v: string) => {
    try {
      navigator.clipboard.writeText(v).then(
        () => toast(tr("Copié", "Copied")),
        () => toast(tr("Copie impossible ici", "Copying is not possible here")),
      );
    } catch {
      toast(tr("Copie impossible ici", "Copying is not possible here"));
    }
  };
  const recheck = async () => {
    if (!isAdmin) {
      toast(tr("Réservé aux administrateurs", "Administrators only"));
      return;
    }
    setChecking(true);
    try {
      const sc = await api.startScan(org.org_id, i.targetId, [i.moduleId]);
      const end = await waitScan(org.org_id, sc.id);
      await reload();
      if (!end) toast(tr("Vérification en cours : le résultat arrivera ici", "Checking: the result will appear here"));
      else if (end.status === "failed") toast(tr("La vérification a échoué, réessayez plus tard", "The check failed, try again later"));
      else {
        const f = await api.findings(org.org_id);
        const now = f.items.find((x) => x.id === i.id && x.target_id === i.targetId);
        toast(now && now.status === "open" ? tr("Toujours présent au dernier contrôle", "Still there at the latest check") : tr("Confirmé : le problème a disparu", "Confirmed: the problem is gone"));
      }
    } catch (e) {
      if (isAuditUsed(e)) showSheet(<UpsellSheet what="scan" />);
      else
        toast(
          e instanceof ApiError && e.code === "plan_limit"
            ? tr("Ce contrôle n’est pas inclus dans votre offre", "This check is not included in your plan")
            : tr("Impossible de vérifier pour le moment", "The check cannot run right now"),
        );
    } finally {
      setChecking(false);
    }
  };
  const cve = i.cve;
  return (
    <>
      <div className="shead">
        <SevTag s={i.fixed ? "ok" : i.sev} label={i.accepted ? tr("Risque accepté", "Risk accepted") : undefined} />
        <CloseButton />
      </div>
      <h2 id="sheet-title">{i.title}</h2>
      <button className="assetlink" type="button" onClick={() => showSheet(<AssetSheet n={i.host} />)}>
        <NavIcon name="actifs" size={16} width={2} />
        {i.host}
      </button>
      <div className="stats3">
        <div>
          <small>{tr("Gravité", "Severity")}</small>
          <b>{SEV[i.sev][0]}</b>
        </div>
        <div>
          <small>{tr("Temps", "Time")}</small>
          <b>{i.mins} min</b>
        </div>
        <div>
          <small>{tr("Gain", "Gain")}</small>
          <b>{tr(`+${i.gain} points`, `+${i.gain} points`)}</b>
        </div>
      </div>
      {cve && (
        <div className="cve">
          <div>
            <small>{tr("Référence", "Reference")}</small>
            <b>{cve.id ?? tr("Sans CVE", "No CVE")}</b>
            {cve.name && <small>{cve.name}</small>}
          </div>
          <div>
            <small>{tr("Gravité CVSS", "CVSS severity")}</small>
            <b>{cve.cvss !== undefined ? tr(`${cve.cvss.toLocaleString("fr-FR")} sur 10`, `${cve.cvss.toLocaleString("en-GB")} out of 10`) : tr("Non publiée", "Not published")}</b>
          </div>
          <div>
            <small>{tr("Probabilité EPSS", "EPSS probability")}</small>
            <b>
              {cve.epss !== undefined
                ? tr(`${(cve.epss * 100).toLocaleString("fr-FR", { maximumFractionDigits: 1 })} %`, `${(cve.epss * 100).toLocaleString("en-GB", { maximumFractionDigits: 1 })}%`)
                : tr("Non publiée", "Not published")}
            </b>
          </div>
          {cve.kev && <p className="kev">{tr("Exploitée activement par des attaquants", "Actively exploited by attackers")}</p>}
        </div>
      )}
      <h3>{tr("Pourquoi c’est important", "Why it matters")}</h3>
      <p className="why">{i.why}</p>
      <h3>
        {tr("Comment corriger", "How to fix it")}
        <span id="step-count">{tr(`${done} sur ${st.length}`, `${done} of ${st.length}`)}</span>
      </h3>
      <div className="stepline">
        <b id="step-bar" style={{ width: (st.length ? (done / st.length) * 100 : 0) + "%" }} />
      </div>
      <ul className="steps">
        {i.steps.map((s, k) => (
          <li key={k}>
            <button type="button" className={"stepbtn" + (st[k] ? " on" : "")} aria-pressed={!!st[k]} onClick={() => toggle(k)}>
              <i>
                <Tick />
              </i>
              <span>{s}</span>
            </button>
          </li>
        ))}
      </ul>
      <h3>{tr("Preuve technique", "Technical evidence")}</h3>
      <div className="proof">
        <pre>{i.proof}</pre>
        <button className="link" type="button" onClick={() => copy(i.proof)}>
          {tr("Copier", "Copy")}
        </button>
      </div>
      {!i.fixed && <ShareBlock i={i} copy={copy} />}
      {!i.fixed && (
        <p className="hint">
          {tr(
            "Une fois corrigé, dites-le-nous : un contrôle part aussitôt pour le confirmer, et votre score se met à jour.",
            "Once fixed, let us know: a check starts at once to confirm it, and your score is updated.",
          )}
        </p>
      )}
      <div className="actions sticky">
        <button
          className={"btn" + (st.length && done === st.length && !i.fixed ? " ready" : "")}
          id="fix-btn"
          type="button"
          onClick={() => {
            closeAll();
            void fix(i);
          }}
        >
          {i.fixed ? tr("Rouvrir", "Reopen") : tr("J’ai corrigé : vérifier", "I fixed it: check")}
        </button>
        <button className="btn ghost" type="button" disabled={checking} onClick={() => void recheck()}>
          {checking ? (
            <>
              <span className="spin" />
              {tr("Vérification", "Checking")}
            </>
          ) : (
            tr("Revérifier", "Check again")
          )}
        </button>
      </div>
    </>
  );
}

export function AssetSheet({ n }: { n: string }) {
  const { assets, issues, data, org, reload, isAdmin } = useOrg();
  const { toast, showSheet } = useUI();
  const [scanning, setScanning] = useState(false);
  const a = assets.find((x) => x.n === n);
  const open = issues.filter((i) => !i.fixed && i.host === n).sort((x, y) => RANK[x.sev] - RANK[y.sev]);
  const w = worst(open);
  const evaluated = data ? evaluatedCats(data.checks) : new Map();
  if (!a) {
    return (
      <>
        <div className="shead">
          <span />
          <CloseButton />
        </div>
        <h2 id="sheet-title">{n}</h2>
        <p className="why" style={{ color: "var(--ink2)" }}>
          {tr("Cet actif n’est plus dans l’inventaire.", "This asset is no longer in the inventory.")}
        </p>
      </>
    );
  }
  const scan = async () => {
    if (!isAdmin) {
      toast(tr("Réservé aux administrateurs", "Administrators only"));
      return;
    }
    setScanning(true);
    try {
      const sc = await api.startScan(org.org_id, a.targetId);
      const end = await waitScan(org.org_id, sc.id);
      await reload();
      if (!end) toast(tr("Scan en cours : les résultats arriveront ici", "Scan running: the results will appear here"));
      else if (end.status === "failed") toast(tr("Le scan a échoué, réessayez plus tard", "The scan failed, try again later"));
      else {
        const done = (await api.scans(org.org_id)).items.find((x) => x.id === sc.id);
        const fresh = done?.new_findings ?? 0;
        toast(
          fresh
            ? tr(`Scan terminé : ${fresh} nouveau${fresh > 1 ? "x" : ""} problème${fresh > 1 ? "s" : ""}`, `Scan finished: ${fresh} new problem${fresh > 1 ? "s" : ""}`)
            : tr("Scan terminé : rien de nouveau", "Scan finished: nothing new"),
        );
      }
    } catch (e) {
      if (isAuditUsed(e)) showSheet(<UpsellSheet what="scan" />);
      else toast(tr("Impossible de lancer le scan pour le moment", "The scan cannot start right now"));
    } finally {
      setScanning(false);
    }
  };
  return (
    <>
      <div className="shead">
        <SevTag s={w} label={w === "ok" ? tr("Protégé", "Protected") : undefined} />
        <CloseButton />
      </div>
      <h2 id="sheet-title">{n}</h2>
      <p className="why" style={{ color: "var(--ink2)" }}>
        {a.k}
      </p>
      <h3>{tr("État par contrôle", "Status by check")}</h3>
      <div className="cats">
        {CATS.map(([c, l]) => {
          const s = catState(a, c, issues, evaluated);
          return (
            <div key={c}>
              <i className={"hm " + s} />
              <b>{l}</b>
              <small>{STATE_LABEL[s]}</small>
            </div>
          );
        })}
      </div>
      <h3>{tr("Technologies détectées", "Detected technologies")}</h3>
      {a.tech.length ? (
        <div className="tags">
          {a.tech.map((x) => (
            <span key={x}>{x}</span>
          ))}
        </div>
      ) : (
        <p className="why" style={{ color: "var(--ink2)" }}>
          {tr("Aucune technologie détectée pour l’instant.", "No technology detected yet.")}
        </p>
      )}
      <h3>{tr("Services exposés", "Exposed services")}</h3>
      {a.svc.length ? (
        <ul className="svc">
          {a.svc.map((s) => (
            <li key={s[0]}>
              <b>{s[0]}</b>
              <span>{s[1]}</span>
              <small>{s[2]}</small>
            </li>
          ))}
        </ul>
      ) : (
        <p className="why" style={{ color: "var(--ink2)" }}>
          {tr("Aucun service réseau détecté sur cet actif.", "No network service detected on this asset.")}
        </p>
      )}
      <h3>
        {tr("Problèmes ouverts", "Open problems")}<span>{open.length}</span>
      </h3>
      {open.length ? (
        <ul className="rows2 insheet">
          {open.map((i) => (
            <li key={i.targetId + i.id}>
              <button className="rowmain" type="button" onClick={() => showSheet(<FindingSheet id={i.id} targetId={i.targetId} />)}>
                <span className="t">{i.title}</span>
                <span className="m">
                  <SevTag s={i.sev} />
                  <span>{i.mins} min</span>
                </span>
              </button>
              <span className="gain">+{i.gain}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="why" style={{ color: "var(--ink2)" }}>
          {tr("Aucun problème ouvert.", "No open problem.")}
        </p>
      )}
      <div className="scanbar" id="asset-scan" hidden={!scanning}>
        <b />
      </div>
      <div className="actions sticky">
        <button className="btn" type="button" disabled={scanning} onClick={() => void scan()}>
          {scanning ? tr("Scan en cours", "Scan running") : tr("Lancer un scan", "Start a scan")}
        </button>
      </div>
    </>
  );
}


/**
 * ScoreSheet explains the score: what it means, how it is computed, what
 * lowers it (each failed check, with the points its fix wins) and what is
 * fine (the passed checks, by category): the proof of what the customer
 * pays for. Every figure comes from the engine's check statuses.
 */
export function ScoreSheet() {
  const { data, issues } = useOrg();
  const { showSheet } = useUI();
  if (!data) return null;
  const score = data.overview.score;
  const weak = weakChecks(data.checks, issues, data.targets);
  const strong = strongChecks(data.checks);
  const several = new Set(weak.map((w) => w.domain)).size > 1;
  return (
    <>
      <div className="shead">
        <span />
        <CloseButton />
      </div>
      <h2 id="sheet-title">{score === null ? tr("Votre score", "Your score") : tr(`Votre score : ${score} sur 100`, `Your score: ${score} out of 100`)}</h2>
      <p className="why">{scoreVerdict(score, groupIssues(issues).filter((g) => !g.fixed).length)}</p>
      <h3>{tr("Comment il est calculé", "How it is computed")}</h3>
      <p className="why">
        {tr(
          "Chaque scan passe vos domaines au crible de contrôles. Le score est la part des contrôles réussis, chacun compté selon sa gravité : un contrôle critique pèse dix fois plus qu’un contrôle faible. Corriger un problème grave fait donc remonter le score bien plus vite.",
          "Every scan runs a set of checks on your domains. The score is the share of checks passed, each counted by its severity: a critical check weighs ten times more than a low one. Fixing a serious problem therefore raises the score much faster.",
        )}
      </p>
      <h3>
        {tr("Ce qui fait baisser votre score", "What lowers your score")}
        <span>{weak.length}</span>
      </h3>
      {weak.length ? (
        <ul className="rows2 insheet">
          {weak.map((w) => (
            <li key={w.key}>
              {w.issue ? (
                <button className="rowmain" type="button" onClick={() => w.issue && showSheet(<FindingSheet id={w.issue.id} targetId={w.issue.targetId} />)}>
                  <span className="t">{w.title}</span>
                  <span className="m">
                    <SevTag s={sevOf(w.severity)} />
                    {several && <span>{w.domain}</span>}
                  </span>
                </button>
              ) : (
                <div className="rowmain">
                  <span className="t">{w.title}</span>
                  <span className="m">
                    <SevTag s={sevOf(w.severity)} />
                    {several && <span>{w.domain}</span>}
                  </span>
                </div>
              )}
              {w.gain > 0 && <span className="gain">+{w.gain}</span>}
            </li>
          ))}
        </ul>
      ) : (
        <p className="why" style={{ color: "var(--ink2)" }}>
          {tr("Aucun contrôle en échec : rien ne fait baisser votre score.", "No failed check: nothing lowers your score.")}
        </p>
      )}
      <h3>
        {tr("Ce qui va bien", "What is fine")}
        <span>{strong.total}</span>
      </h3>
      {strong.groups.length ? (
        <>
          <p className="why">
            {tr(
              `${strong.total} contrôle${strong.total > 1 ? "s" : ""} réussi${strong.total > 1 ? "s" : ""} au dernier scan. Nous les revérifions à chaque scan : vous serez prévenu si l’un d’eux échoue.`,
              `${strong.total} check${strong.total > 1 ? "s" : ""} passed at the latest scan. We check them again at every scan: you will be told if one fails.`,
            )}
          </p>
          <ul className="wellgroups">
            {strong.groups.map((g) => (
              <li key={g.category}>
                <b>{g.label}</b>
                <ul>
                  {g.titles.map((t) => (
                    <li key={t}>
                      <i aria-hidden="true">
                        <Tick size={14} width={3} />
                      </i>
                      {t}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p className="why" style={{ color: "var(--ink2)" }}>
          {tr("Rien n’a encore été contrôlé avec succès : les résultats arrivent après le premier scan.", "Nothing has passed a check yet: results arrive after the first scan.")}
        </p>
      )}
    </>
  );
}
