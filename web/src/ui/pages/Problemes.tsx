// Problèmes: every problem line of the organization, as a console table
// (2026-11-19): status tabs, a filter bar (text, severity, type), dense rows.
// A row opens the problem's side sheet; ticking it starts a verification.

import { useEffect, useState } from "react";
import { tr } from "../../i18n";
import { useLocation } from "../../router";
import { Search, Soon, Tick } from "../icons";
import { CATNAME, groupIssues, groupVerdict, hostsText, RANK, SEV, verdictText, type IssueType, type Sev } from "../model";
import { useOrg } from "../OrgData";
import { FindingSheet, useFix } from "../sheets";
import { useUI } from "../ui";

type Tab = "open" | "fixed" | "accepted";

/** useWide: a screen wide enough for the table and the problem side by
 * side. Without matchMedia (tests, old browsers), the side sheet is used. */
function useWide(): boolean {
  const q = "(min-width: 1200px)";
  const [wide, setWide] = useState(() => typeof window.matchMedia === "function" && window.matchMedia(q).matches);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const m = window.matchMedia(q);
    const on = () => setWide(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return wide;
}

/** since words how long ago iso was, briefly: "aujourd'hui", "3 j", "7 sem.". */
function since(iso: string, now: Date): string {
  const d = Math.floor((now.getTime() - new Date(iso).getTime()) / 86_400_000);
  if (!iso || Number.isNaN(d)) return "–";
  if (d < 1) return tr("aujourd’hui", "today");
  if (d < 14) return tr(`${d} j`, `${d} d`);
  if (d < 60) return tr(`${Math.floor(d / 7)} sem.`, `${Math.floor(d / 7)} wk`);
  return tr(`${Math.floor(d / 30)} mois`, `${Math.floor(d / 30)} mo`);
}
type SevF = "crit" | "high" | "med";

export function ProblemesPage() {
  const { issues, verdicts } = useOrg();
  const { showSheet } = useUI();
  const fix = useFix();
  const [tab, setTab] = useState<Tab>("open");
  const [sevs, setSevs] = useState<SevF[]>([]);
  const [type, setType] = useState<IssueType | "all">("all");
  const [q, setQ] = useState("");
  const wide = useWide();
  const [sel, setSel] = useState<string | null>(null);
  const now = new Date();

  // A link to one problem (alert emails: ?id=<finding>) opens its sheet.
  const { search } = useLocation();
  const linked = search.get("id");
  const target = linked ? issues.find((i) => i.id === linked) : undefined;
  useEffect(() => {
    if (target) showSheet(<FindingSheet id={target.id} targetId={target.targetId} />);
    // Once, when the linked problem is known.
  }, [target?.id]);

  // One line per problem: the same check on several names is one group.
  const pool = groupIssues(issues).map((g) => ({ ...g.lead, group: g, fixed: g.fixed, gain: g.gain }));
  // A line ticked here stays in "Ouverts" while its verification is followed,
  // so its verdict shows where the customer ticked it.
  const tabOf = (i: (typeof pool)[number]): Tab =>
    !i.fixed || (!i.accepted && groupVerdict(i.group.members, verdicts)) ? "open" : i.accepted ? "accepted" : "fixed";
  // "Moyen" holds medium and low problems.
  const bucket = (s: Sev): SevF => (s === "low" ? "med" : s);
  const needle = q.trim().toLowerCase();
  const matches = (i: (typeof pool)[number]) =>
    !needle || [i.title, ...i.group.hosts, i.module, i.cve?.id ?? ""].some((x) => x.toLowerCase().includes(needle));
  const inTab = pool.filter((i) => tabOf(i) === tab);
  const list = inTab
    .filter((i) => (type === "all" || i.type === type) && (!sevs.length || sevs.includes(bucket(i.sev))) && matches(i))
    .sort((a, b) => RANK[a.sev] - RANK[b.sev] || b.gain - a.gain);
  // The problem shown beside the table: the one chosen, else the first.
  const current = list.find((i) => i.group.key === sel) ?? list[0];
  const openRow = (i: (typeof list)[number]) => {
    if (wide) setSel(i.group.key);
    else showSheet(<FindingSheet id={i.id} targetId={i.targetId} />);
  };
  const open = pool.filter((i) => !i.fixed);
  const mins = open.reduce((s, i) => s + i.mins, 0);
  const sevCount = (k: SevF) => inTab.filter((i) => bucket(i.sev) === k).length;
  const tabs: [Tab, string][] = [
    ["open", tr("Ouverts", "Open")],
    ["fixed", tr("Corrigés", "Fixed")],
    ["accepted", tr("Risque accepté", "Risk accepted")],
  ];
  const sevLabels: [SevF, string][] = [
    ["crit", tr("Critique", "Critical")],
    ["high", tr("Élevé", "High")],
    ["med", tr("Moyen", "Medium")],
  ];
  const types: [IssueType | "all", string][] = [
    ["all", tr("Tous les types", "All types")],
    ["vuln", tr("Vulnérabilités", "Vulnerabilities")],
    ["menace", tr("Menaces émergentes", "Emerging threats")],
  ];
  const filtered = sevs.length > 0 || type !== "all" || needle !== "";

  return (
    <>
      <div className="ph">
        <div>
          <h1>{tr("Problèmes", "Problems")}</h1>
          <p>
            {open.length
              ? tr(
                  `${open.length} ouvert${open.length > 1 ? "s" : ""}, environ ${mins} minutes pour tout corriger.`,
                  `${open.length} open, about ${mins} minutes to fix everything.`,
                )
              : tr("Aucun problème ouvert.", "No open problem.")}
          </p>
        </div>
      </div>

      <nav className="ctabs" aria-label={tr("Statut", "Status")}>
        {tabs.map(([k, l]) => (
          <button key={k} type="button" aria-pressed={tab === k} onClick={() => setTab(k)}>
            {l}
            <span className="ctabn">{pool.filter((i) => tabOf(i) === k).length}</span>
          </button>
        ))}
        <span className="ctabsoon">
          {tr("Fuites de données", "Data leaks")} <Soon />
        </span>
      </nav>

      <div className={"psplit" + (wide && current ? " on" : "")}>
      <section className="panel plist">
        <div className="fbar">
          <label className="fin">
            <Search />
            <span className="vh">{tr("Filtrer les problèmes", "Filter the problems")}</span>
            <input type="search" placeholder={tr("Filtrer par titre, actif, CVE…", "Filter by title, asset, CVE…")} value={q} onChange={(e) => setQ(e.target.value)} />
          </label>
          <div className="fchips" role="group" aria-label={tr("Filtrer par gravité", "Filter by severity")}>
            {sevLabels.map(([k, l]) => (
              <button
                key={k}
                type="button"
                className={"fchip c-" + k}
                title={k === "med" ? tr("Moyen ou faible", "Medium or low") : undefined}
                aria-pressed={sevs.includes(k)}
                onClick={() => setSevs(sevs.includes(k) ? sevs.filter((x) => x !== k) : [...sevs, k])}
              >
                <i aria-hidden="true" />
                {l}
                <b>{sevCount(k)}</b>
              </button>
            ))}
          </div>
          <label className="fselect">
            <span className="vh">{tr("Type de problème", "Problem type")}</span>
            <select value={type} onChange={(e) => setType(e.target.value as IssueType | "all")}>
              {types.map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </select>
          </label>
          <span className="fcount">
            {tr(`${list.length} résultat${list.length > 1 ? "s" : ""}`, `${list.length} result${list.length !== 1 ? "s" : ""}`)}
            {filtered && (
              <button
                className="link"
                type="button"
                onClick={() => {
                  setSevs([]);
                  setType("all");
                  setQ("");
                }}
              >
                {tr("Effacer", "Clear")}
              </button>
            )}
          </span>
        </div>
        {tab === "open" && (
          <p className="panelnote">
            {tr(
              "Cochez un problème quand vous l’avez corrigé : nous relançons aussitôt un contrôle pour le confirmer.",
              "Tick a problem once you have fixed it: we run a check at once to confirm it.",
            )}
          </p>
        )}
        <div className="ptable">
          <div className="ptabhead" aria-hidden="true">
            <span />
            <span>{tr("Problème", "Problem")}</span>
            <span>{tr("Gravité", "Severity")}</span>
            <span>{tr("Actif", "Asset")}</span>
            <span className="pcatcol">{tr("Catégorie", "Category")}</span>
            <span>{tr("Vu depuis", "Seen since")}</span>
            <span className="r">{tr("Gain", "Gain")}</span>
          </div>
          <ul className="rows2 prow">
            {list.length ? (
              list.map((i) => {
                const v = groupVerdict(i.group.members, verdicts);
                return (
                  <li key={i.group.key} className={(i.fixed ? "done" : "") + (wide && current?.group.key === i.group.key ? " sel" : "")}>
                    <button className="check" type="button" aria-pressed={i.fixed} aria-label={tr(`Marquer « ${i.title} » comme corrigé`, `Mark “${i.title}” as fixed`)} onClick={() => void fix(i.group.members)}>
                      <Tick size={13} width={3.2} />
                    </button>
                    <button className="rowmain" type="button" aria-current={wide && current?.group.key === i.group.key ? "true" : undefined} onClick={() => openRow(i)}>
                      <span className="t">{i.title}</span>
                      <span className="m">
                        <span className="mono">{i.finding.check_id}</span>
                        {i.cve?.id && <span className="mono"> · {i.cve.id}</span>}
                        {i.cve?.kev && <span className="kevtag">{tr("exploitée activement", "actively exploited")}</span>}
                      </span>
                      {v && <span className={"verdict v-" + v.state}>{verdictText(v)}</span>}
                    </button>
                    <span className={"sevpill p-" + (i.fixed ? "ok" : i.sev)}>{i.accepted ? tr("Risque accepté", "Risk accepted") : i.fixed ? SEV.ok[0] : SEV[i.sev][0]}</span>
                    <span className="mono phost">{hostsText(i.group.hosts)}</span>
                    <span className="pcat pcatcol">{i.cat ? CATNAME[i.cat] : i.module}</span>
                    <span className="priomins">{since(i.finding.first_seen, now)}</span>
                    <span className="gain r">+{i.gain}</span>
                  </li>
                );
              })
            ) : (
              <li className="empty">
                {filtered
                  ? tr("Aucun problème ne correspond à ces filtres.", "No problem matches these filters.")
                  : tab === "open"
                    ? tr("Rien à corriger : nous continuons de surveiller.", "Nothing to fix: we keep watching.")
                    : tr("Rien ici pour le moment.", "Nothing here for now.")}
              </li>
            )}
          </ul>
        </div>
      </section>
      {wide && current && (
        <aside className="panel pdetail" aria-labelledby="detail-title">
          <FindingSheet key={current.group.key} id={current.id} targetId={current.targetId} inline />
        </aside>
      )}
      </div>
    </>
  );
}
