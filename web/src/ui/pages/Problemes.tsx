import { useEffect, useState } from "react";
import { useLocation } from "../../router";
import { Tick } from "../icons";
import { groupIssues, groupVerdict, hostsText, RANK, verdictText, type IssueType, type SevOrOk } from "../model";
import { useOrg } from "../OrgData";
import { FindingSheet, SevTag, useFix } from "../sheets";
import { useUI } from "../ui";

const TYPES: [IssueType | "all", string][] = [
  ["all", "Tout"],
  ["vuln", "Vulnérabilités"],
  ["fuite", "Fuites de données"],
  ["menace", "Menaces émergentes"],
];

type Filter = "all" | "crit" | "high" | "med" | "ok";

export function ProblemesPage() {
  const { issues, verdicts } = useOrg();
  const { showSheet } = useUI();
  const fix = useFix();
  const [f, setF] = useState<Filter>("all");
  const [type, setType] = useState<IssueType | "all">("all");

  // A link to one problem (alert emails: ?id=<finding>) opens its sheet.
  const { search } = useLocation();
  const linked = search.get("id");
  const target = linked ? issues.find((i) => i.id === linked) : undefined;
  useEffect(() => {
    if (target) showSheet(<FindingSheet id={target.id} targetId={target.targetId} />);
    // Once, when the linked problem is known.
  }, [target?.id]);

  // One line per problem: the same check on several names is one group.
  const pool = groupIssues(issues.filter((i) => type === "all" || i.type === type)).map((g) => ({
    ...g.lead,
    group: g,
    fixed: g.fixed,
    gain: g.gain,
  }));
  // "Moyens" holds medium and low problems (the mockup has no low).
  const bucket = (s: string): Filter => (s === "low" ? "med" : (s as Filter));
  const cnt = (k: Filter) => pool.filter((i) => (k === "ok" ? i.fixed : !i.fixed && bucket(i.sev) === k)).length;
  const list = pool
    .filter((i) => (f === "all" ? true : f === "ok" ? i.fixed : !i.fixed && bucket(i.sev) === f))
    .sort((a, b) => Number(a.fixed) - Number(b.fixed) || RANK[a.sev] - RANK[b.sev] || b.gain - a.gain);
  const openList = pool.filter((i) => !i.fixed);
  const openN = openList.length;
  const mins = openList.reduce((s, i) => s + i.mins, 0);
  const bar: [Filter, string][] = [
    ["crit", "Critiques"],
    ["high", "Élevés"],
    ["med", "Moyens"],
    ["ok", "Corrigés"],
  ];

  return (
    <>
      <div className="rtop">
        <h1 className="hello" style={{ margin: 0, fontFamily: "inherit", fontWeight: 400, letterSpacing: 0 }}>
          Problèmes
        </h1>
      </div>
      <p className="pagehead">
        <b>{openN}</b> ouvert{openN > 1 ? "s" : ""}
        <span>environ {mins} minutes pour tout corriger</span>
      </p>
      <div className="sevbar" role="group" aria-label="Filtrer par gravité">
        {bar.map(([k, l]) =>
          cnt(k) ? (
            <button
              key={k}
              type="button"
              className={`sb ${k}${f === k ? " sel" : ""}${f !== "all" && f !== k ? " dimmed" : ""}`}
              style={{ flex: cnt(k) }}
              aria-pressed={f === k}
              aria-label={`${l} : ${cnt(k)}`}
              onClick={() => setF(f === k ? "all" : k)}
            />
          ) : null,
        )}
      </div>
      <div className="sevkey">
        {bar.map(([k, l]) => (
          <button key={k} type="button" aria-pressed={f === k} onClick={() => setF(f === k ? "all" : k)}>
            <i className={"sb " + k} />
            {l}
            <b>{cnt(k)}</b>
          </button>
        ))}
      </div>
      <div className="filters" role="group" aria-label="Type de problème">
        {TYPES.map(([k, l]) => (
          <button key={k} className="pill" type="button" aria-pressed={type === k} onClick={() => setType(k)}>
            {l}
            {k === "fuite" && <span className="soon">Bientôt</span>}
          </button>
        ))}
      </div>
      <p className="hint">Cochez un problème quand vous l’avez corrigé : nous relançons aussitôt un contrôle pour le confirmer.</p>
      <ul className="rows2">
        {list.length ? (
          list.map((i, k) => {
            const s: SevOrOk = i.fixed ? "ok" : i.sev;
            const v = groupVerdict(i.group.members, verdicts);
            return (
              <li key={i.group.key} className={i.fixed ? "done" : ""} style={{ animationDelay: (k * 0.04).toFixed(2) + "s" }}>
                <button className="check" type="button" aria-pressed={i.fixed} aria-label={`Marquer « ${i.title} » comme corrigé`} onClick={() => void fix(i.group.members)}>
                  <Tick size={18} width={3} />
                </button>
                <button className="rowmain" type="button" onClick={() => showSheet(<FindingSheet id={i.id} targetId={i.targetId} />)}>
                  <span className="t">{i.title}</span>
                  <span className="m">
                    <SevTag s={s} label={i.accepted ? "Risque accepté" : undefined} />
                    <span>{hostsText(i.group.hosts)}</span>
                    <span>{i.module}</span>
                    <span>{i.mins} min</span>
                    {i.cve?.kev && <span className="kevtag">exploitée activement</span>}
                  </span>
                  {v && <span className={"verdict v-" + v.state}>{verdictText(v)}</span>}
                </button>
                <span className="gain">+{i.gain}</span>
              </li>
            );
          })
        ) : (
          <li className="empty">
            {type === "fuite" ? "La surveillance des fuites de données arrive bientôt." : "Rien dans cette catégorie. Choisissez un autre filtre."}
          </li>
        )}
      </ul>
    </>
  );
}
