// The side sheets of the mockup: a problem (openSheet) and an asset
// (openAsset). They read the organization's data each render, so they
// follow changes (marked fixed, reopened, rescanned).

import { useState } from "react";
import { api, ApiError } from "../api/client";
import type { Scan } from "../api/types";
import { Close, NavIcon, Tick } from "./icons";
import { CATS, RANK, SEV, STATE_LABEL, catState, evaluatedCats, worst, type Issue, type SevOrOk } from "./model";
import { useOrg } from "./OrgData";
import { useUI } from "./ui";

export function SevTag({ s, label }: { s: SevOrOk; label?: string | undefined }) {
  return (
    <span className={"sev " + SEV[s][1]}>
      <i />
      {label ?? SEV[s][0]}
    </span>
  );
}

export function CloseButton() {
  const { closeAll } = useUI();
  return (
    <button className="iconbtn" type="button" data-close aria-label="Fermer" onClick={closeAll}>
      <Close />
    </button>
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

/** useFix marks a problem fixed or reopens it, with the mockup's toasts. */
export function useFix() {
  const { setStatus, isAdmin } = useOrg();
  const { toast } = useUI();
  return async (i: Issue) => {
    if (!isAdmin) {
      toast("Réservé aux administrateurs");
      return;
    }
    const fixing = !i.fixed;
    toast(fixing ? `Marqué comme corrigé : +${i.gain} points` : "Rouvert");
    try {
      await setStatus(i, fixing ? "fixed" : "open");
    } catch (e) {
      toast(e instanceof ApiError && e.status === 403 ? "Réservé aux administrateurs" : "Impossible pour le moment, réessayez");
    }
  };
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
        <h2 id="sheet-title">Ce problème n’existe plus</h2>
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
        () => toast("Copié"),
        () => toast("Copie impossible ici"),
      );
    } catch {
      toast("Copie impossible ici");
    }
  };
  const recheck = async () => {
    if (!isAdmin) {
      toast("Réservé aux administrateurs");
      return;
    }
    setChecking(true);
    try {
      const sc = await api.startScan(org.org_id, i.targetId, [i.moduleId]);
      const end = await waitScan(org.org_id, sc.id);
      await reload();
      if (!end) toast("Vérification en cours : le résultat arrivera ici");
      else if (end.status === "failed") toast("La vérification a échoué, réessayez plus tard");
      else {
        const f = await api.findings(org.org_id);
        const now = f.items.find((x) => x.id === i.id && x.target_id === i.targetId);
        toast(now && now.status === "open" ? "Toujours présent au dernier contrôle" : "Confirmé : le problème a disparu");
      }
    } catch (e) {
      toast(e instanceof ApiError && e.code === "plan_limit" ? "Ce contrôle n’est pas inclus dans votre offre" : "Impossible de vérifier pour le moment");
    } finally {
      setChecking(false);
    }
  };
  const cve = i.cve;
  return (
    <>
      <div className="shead">
        <SevTag s={i.fixed ? "ok" : i.sev} label={i.accepted ? "Risque accepté" : undefined} />
        <CloseButton />
      </div>
      <h2 id="sheet-title">{i.title}</h2>
      <button className="assetlink" type="button" onClick={() => showSheet(<AssetSheet n={i.host} />)}>
        <NavIcon name="actifs" size={16} width={2} />
        {i.host}
      </button>
      <div className="stats3">
        <div>
          <small>Gravité</small>
          <b>{SEV[i.sev][0]}</b>
        </div>
        <div>
          <small>Temps</small>
          <b>{i.mins} min</b>
        </div>
        <div>
          <small>Gain</small>
          <b>+{i.gain} points</b>
        </div>
      </div>
      {cve && (
        <div className="cve">
          <div>
            <small>Référence</small>
            <b>{cve.id ?? "Sans CVE"}</b>
            {cve.name && <small>{cve.name}</small>}
          </div>
          <div>
            <small>Gravité CVSS</small>
            <b>{cve.cvss !== undefined ? `${cve.cvss.toLocaleString("fr-FR")} sur 10` : "Non publiée"}</b>
          </div>
          <div>
            <small>Probabilité EPSS</small>
            <b>{cve.epss !== undefined ? `${(cve.epss * 100).toLocaleString("fr-FR", { maximumFractionDigits: 1 })} %` : "Non publiée"}</b>
          </div>
          {cve.kev && <p className="kev">Exploitée activement par des attaquants</p>}
        </div>
      )}
      <h3>Pourquoi c’est important</h3>
      <p className="why">{i.why}</p>
      <h3>
        Comment corriger
        <span id="step-count">
          {done} sur {st.length}
        </span>
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
      <h3>Preuve technique</h3>
      <div className="proof">
        <pre>{i.proof}</pre>
        <button className="link" type="button" onClick={() => copy(i.proof)}>
          Copier
        </button>
      </div>
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
          {i.fixed ? "Rouvrir" : "Marquer comme corrigé"}
        </button>
        <button className="btn ghost" type="button" disabled={checking} onClick={() => void recheck()}>
          {checking ? (
            <>
              <span className="spin" />
              Vérification
            </>
          ) : (
            "Revérifier"
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
          Cet actif n’est plus dans l’inventaire.
        </p>
      </>
    );
  }
  const scan = async () => {
    if (!isAdmin) {
      toast("Réservé aux administrateurs");
      return;
    }
    setScanning(true);
    try {
      const sc = await api.startScan(org.org_id, a.targetId);
      const end = await waitScan(org.org_id, sc.id);
      await reload();
      if (!end) toast("Scan en cours : les résultats arriveront ici");
      else if (end.status === "failed") toast("Le scan a échoué, réessayez plus tard");
      else {
        const done = (await api.scans(org.org_id)).items.find((x) => x.id === sc.id);
        const fresh = done?.new_findings ?? 0;
        toast(fresh ? `Scan terminé : ${fresh} nouveau${fresh > 1 ? "x" : ""} problème${fresh > 1 ? "s" : ""}` : "Scan terminé : rien de nouveau");
      }
    } catch {
      toast("Impossible de lancer le scan pour le moment");
    } finally {
      setScanning(false);
    }
  };
  return (
    <>
      <div className="shead">
        <SevTag s={w} label={w === "ok" ? "Protégé" : undefined} />
        <CloseButton />
      </div>
      <h2 id="sheet-title">{n}</h2>
      <p className="why" style={{ color: "var(--ink2)" }}>
        {a.k}
      </p>
      <h3>État par contrôle</h3>
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
      <h3>Technologies détectées</h3>
      {a.tech.length ? (
        <div className="tags">
          {a.tech.map((x) => (
            <span key={x}>{x}</span>
          ))}
        </div>
      ) : (
        <p className="why" style={{ color: "var(--ink2)" }}>
          Aucune technologie détectée pour l’instant.
        </p>
      )}
      <h3>Services exposés</h3>
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
          Aucun service réseau détecté sur cet actif.
        </p>
      )}
      <h3>
        Problèmes ouverts<span>{open.length}</span>
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
          Aucun problème ouvert.
        </p>
      )}
      <div className="scanbar" id="asset-scan" hidden={!scanning}>
        <b />
      </div>
      <div className="actions sticky">
        <button className="btn" type="button" disabled={scanning} onClick={() => void scan()}>
          {scanning ? "Scan en cours" : "Lancer un scan"}
        </button>
      </div>
    </>
  );
}

