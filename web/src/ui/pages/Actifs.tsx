import { useEffect, useState } from "react";
import { api, ApiError } from "../../api/client";
import type { Agent, Instructions, Target } from "../../api/types";
import { Tick } from "../icons";
import { CATS, DOMAIN_RE, RANK, catState, evaluatedCats, worst } from "../model";
import { useOrg } from "../OrgData";
import { AssetSheet, SevTag } from "../sheets";
import { useUI } from "../ui";

type Add =
  | { step: 0; domain: string; err: string }
  | { step: 1 | 2; domain: string; err: string; target: Target; rec: Instructions }
  | { step: 3; domain: string; err: string };

function AddPanel() {
  const { org, data, reload, isAdmin } = useOrg();
  const { toast } = useUI();
  // A domain added earlier and not verified yet resumes at its record.
  const pending = data?.targets.find((t) => !t.verified && !t.internal);
  const [ad, setAd] = useState<Add>({ step: 0, domain: "", err: "" });
  const [busy, setBusy] = useState(false);

  const showRecord = async (target: Target) => {
    const rec = await api.verificationInstructions(org.org_id, target.id);
    setAd({ step: 1, domain: target.domain, err: "", target, rec });
  };

  const next = async () => {
    const v = ad.domain.trim().toLowerCase();
    if (!DOMAIN_RE.test(v)) {
      setAd({ step: 0, domain: v, err: v ? "Ce nom de domaine n’est pas valide. Exemple : votre-entreprise.cg" : "Saisissez un nom de domaine." });
      return;
    }
    if (!isAdmin) {
      setAd({ step: 0, domain: v, err: "Seul un administrateur peut ajouter un domaine." });
      return;
    }
    setBusy(true);
    try {
      const t = await api.createTarget(org.org_id, v);
      await showRecord(t);
      void reload();
    } catch (e) {
      const err =
        e instanceof ApiError && e.status === 409
          ? "Ce domaine est déjà dans votre espace."
          : e instanceof ApiError && e.code === "plan_limit"
            ? "Votre offre ne permet pas d’ajouter un autre domaine. Changez d’offre dans Réglages."
            : "Impossible d’ajouter ce domaine pour le moment.";
      setAd({ step: 0, domain: v, err });
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    if (ad.step !== 1) return;
    const { target, rec } = ad;
    setAd({ ...ad, step: 2 });
    try {
      await api.verifyTarget(org.org_id, target.id);
      try {
        await api.startScan(org.org_id, target.id);
      } catch {
        // Verified anyway: the scan can be started from the asset.
      }
      setAd({ step: 3, domain: target.domain, err: "" });
      void reload();
    } catch (e) {
      const err =
        e instanceof ApiError && e.status === 422
          ? "L’enregistrement n’est pas encore visible. Les changements DNS peuvent prendre quelques minutes."
          : "Vérification impossible pour le moment.";
      setAd({ step: 1, domain: target.domain, err, target, rec });
    }
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

  if (ad.step === 0) {
    return (
      <>
        <h2>Ajouter un domaine</h2>
        <p className="sub">Vous prouvez qu’il vous appartient, puis le premier scan démarre.</p>
        <div className="addrow">
          <label className="vh" htmlFor="add-in">
            Nom de domaine
          </label>
          <input
            id="add-in"
            type="text"
            inputMode="url"
            autoComplete="off"
            placeholder="votre-entreprise.cg"
            value={ad.domain}
            onChange={(e) => setAd({ ...ad, domain: e.target.value })}
            onKeyDown={(e) => {
              if (e.key === "Enter") void next();
            }}
          />
          <button className="btn" type="button" disabled={busy} onClick={() => void next()}>
            Ajouter
          </button>
        </div>
        <p className="err" role="alert">
          {ad.err}
        </p>
        {pending && isAdmin && (
          <p className="sub">
            {pending.domain} attend sa vérification.{" "}
            <button className="link" type="button" style={{ minHeight: 0 }} onClick={() => void showRecord(pending)}>
              Reprendre
            </button>
          </p>
        )}
      </>
    );
  }
  if (ad.step === 1) {
    return (
      <>
        <h2>Prouvez que {ad.domain} est à vous</h2>
        <p className="sub">Ajoutez cet enregistrement dans la zone DNS du domaine.</p>
        <div className="record">
          <div>
            <small>Type</small>
            <b>TXT</b>
          </div>
          <div>
            <small>Nom</small>
            <b>{ad.rec.record_name}</b>
          </div>
          <div>
            <small>Valeur</small>
            <b>{ad.rec.record_value}</b>
          </div>
        </div>
        <p className="err" role="alert">
          {ad.err}
        </p>
        <div className="actions">
          <button className="btn" type="button" onClick={() => void verify()}>
            Vérifier maintenant
          </button>
          <button className="btn ghost" type="button" onClick={() => copy(ad.rec.record_value)}>
            Copier la valeur
          </button>
          <button className="btn ghost" type="button" onClick={() => setAd({ step: 0, domain: "", err: "" })}>
            Annuler
          </button>
        </div>
      </>
    );
  }
  if (ad.step === 2) {
    return (
      <>
        <h2>Vérification en cours</h2>
        <p className="sub">Lecture de la zone DNS de {ad.domain}.</p>
        <div className="scanbar">
          <b />
        </div>
      </>
    );
  }
  return (
    <>
      <div className="okmark" aria-hidden="true">
        <Tick size={28} width={3} />
      </div>
      <h2>{ad.domain} est vérifié</h2>
      <p className="sub">Le premier scan vient de démarrer.</p>
      <div className="actions">
        <button className="btn ghost" type="button" onClick={() => setAd({ step: 0, domain: "", err: "" })}>
          Ajouter un autre domaine
        </button>
      </div>
    </>
  );
}

export function ActifsPage() {
  const { data, assets, issues } = useOrg();
  const { showSheet } = useUI();
  const [af, setAf] = useState<"all" | "pb" | "ok">("all");
  if (!data) return null;
  const evaluated = evaluatedCats(data.checks);
  const openOf = (n: string) => issues.filter((i) => !i.fixed && i.host === n);
  const sorted = assets.slice().sort((a, b) => RANK[worst(openOf(a.n))] - RANK[worst(openOf(b.n))]);
  const list = sorted.filter((a) => (af === "all" ? true : af === "pb" ? openOf(a.n).length > 0 : openOf(a.n).length === 0));
  const nPb = assets.filter((a) => openOf(a.n).length).length;
  // The offer covers hosts_per_scan names per domain.
  const p = data.subscription.plan;
  const cap = p.hosts_per_scan ? p.hosts_per_scan * Math.max(1, data.targets.length) : Math.max(1, assets.length);

  return (
    <>
      <div className="rtop">
        <h1 className="hello" style={{ margin: 0, fontFamily: "inherit", fontWeight: 400, letterSpacing: 0 }}>
          Actifs
        </h1>
      </div>
      <p className="pagehead">
        <b>{assets.length}</b> actifs surveillés<span>{nPb} avec un problème ouvert</span>
      </p>
      <div className="meter" role="img" aria-label={`${assets.length} actifs sur ${cap} inclus dans l'offre ${p.name}`}>
        <div>
          <b style={{ width: Math.min(100, (assets.length / cap) * 100) + "%" }} />
        </div>
        <span>
          {assets.length} sur {cap} inclus dans l’offre {p.name}
        </span>
      </div>
      <div className="filters" role="group" aria-label="Filtrer les actifs">
        {(
          [
            ["all", "Tous"],
            ["pb", "Avec un problème"],
            ["ok", "Protégés"],
          ] as const
        ).map(([k, l]) => (
          <button key={k} className="pill" type="button" aria-pressed={af === k} onClick={() => setAf(k)}>
            {l}
          </button>
        ))}
      </div>
      <div className="agrid">
        {list.map((a, k) => {
          const o = openOf(a.n);
          const w = worst(o);
          return (
            <button key={a.n} className="acard" type="button" style={{ animationDelay: (k * 0.04).toFixed(2) + "s" }} onClick={() => showSheet(<AssetSheet n={a.n} />)}>
              <span className="atop">
                <span className="n">{a.n}</span>
                <SevTag s={w} label={w === "ok" ? "Protégé" : undefined} />
              </span>
              <span className="k">
                {a.k}
                {o.length ? `, ${o.length} problème${o.length > 1 ? "s" : ""}` : ""}
              </span>
              <span className="strip" aria-hidden="true">
                {CATS.map(([c]) => (
                  <i key={c} className={"hm " + catState(a, c, issues, evaluated)} />
                ))}
              </span>
              <span className="tags">
                {a.tech.slice(0, 2).map((x) => (
                  <span key={x}>{x}</span>
                ))}
              </span>
            </button>
          );
        })}
      </div>
      <p className="striphelp">Les cinq cases de chaque carte : Emails, TLS, Ports, Fuites, Menaces.</p>
      <div className="rpanel addpanel">
        <AddPanel />
      </div>
      <InternalNetworks />
    </>
  );
}

/** online: an agent seen in the last few minutes (it polls every 30 s). */
function agentState(a: Agent, now: Date): [string, "ok" | "high" | "med" | "crit"] {
  if (a.revoked_at) return ["Révoqué", "crit"];
  if (!a.enrolled_at) return ["En attente d’installation", "med"];
  if (a.last_seen_at && now.getTime() - new Date(a.last_seen_at).getTime() < 5 * 60_000) return ["En ligne", "ok"];
  return ["Hors ligne", "high"];
}

/** InternalNetworks manages the agents of the organization (step J). */
function InternalNetworks() {
  const { org, data, issues, isAdmin, reload } = useOrg();
  const { toast } = useUI();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [ranges, setRanges] = useState("");
  const [err, setErr] = useState("");
  const [code, setCode] = useState<{ name: string; code: string } | null>(null);
  const included = data?.subscription.plan.agents ?? false;

  const load = () =>
    api.agents(org.org_id).then(
      (r) => setAgents(r.items),
      () => setAgents([]),
    );
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [org.org_id]);

  const create = async () => {
    setErr("");
    const list = ranges
      .split(/[\s,]+/)
      .map((r) => r.trim())
      .filter(Boolean);
    try {
      const res = await api.createAgent(org.org_id, name.trim(), list);
      setCode({ name: res.agent.name, code: res.enrolment_code });
      setAdding(false);
      setName("");
      setRanges("");
      void load();
      void reload();
    } catch (e) {
      setErr(
        e instanceof ApiError && e.code === "plan_limit"
          ? "Les réseaux internes sont inclus dans l’offre sur devis."
          : e instanceof ApiError && e.status === 400
            ? "Vérifiez les plages : des réseaux privés (10.x, 172.16-31.x, 192.168.x), au plus un /20, par exemple 192.168.1.0/24."
            : "Agent non créé, réessayez.",
      );
    }
  };
  const newCode = async (a: Agent) => {
    try {
      const r = await api.newAgentCode(org.org_id, a.id);
      setCode({ name: a.name, code: r.enrolment_code });
      void load();
    } catch {
      toast("Code impossible pour le moment");
    }
  };
  const revoke = async (a: Agent) => {
    if (!window.confirm(`Révoquer l’agent ${a.name} ? Il ne pourra plus rien scanner ni envoyer.`)) return;
    try {
      await api.revokeAgent(org.org_id, a.id);
      toast("Agent révoqué");
      void load();
    } catch {
      toast("Révocation impossible pour le moment");
    }
  };
  const scan = async (a: Agent) => {
    try {
      await api.startScan(org.org_id, a.target_id, ["ports"]);
      toast("Scan demandé : l’agent le lancera à son prochain passage (30 secondes au plus)");
      void reload();
    } catch {
      toast("Scan impossible pour le moment");
    }
  };
  const now = new Date();
  const field = { height: 44, borderRadius: 14, border: "1px solid var(--line)", background: "var(--bg)", color: "var(--ink)", font: "inherit", padding: "0 14px" };
  const origin = window.location.origin;

  return (
    <div className="rpanel addpanel">
      <h2>
        Réseaux internes
        {!included && <span className="soon">Offre sur devis</span>}
      </h2>
      <p className="sub">Un petit agent, installé sur une machine de votre réseau, analyse vos adresses privées. Il ne fait que des appels sortants : aucun port à ouvrir chez vous.</p>
      {agents.length > 0 && (
        <ul className="sess">
          {agents.map((a) => {
            const [label, sev] = agentState(a, now);
            const open = issues.filter((i) => i.targetId === a.target_id && !i.fixed).length;
            return (
              <li key={a.id}>
                <span className="mico" aria-hidden="true">
                  {a.os?.startsWith("windows") ? "W" : "L"}
                </span>
                <div>
                  <p className="mt">
                    {a.name} · {a.ranges.join(", ")}
                  </p>
                  <p className="md">
                    <span className={"sev s-" + sev}>
                      <i />
                      {label}
                    </span>
                    {a.hostname ? ` · ${a.hostname}` : ""}
                    {a.version ? ` · version ${a.version}` : ""}
                    {` · ${open} problème${open > 1 ? "s" : ""} ouvert${open > 1 ? "s" : ""}`}
                  </p>
                </div>
                {isAdmin && !a.revoked_at ? (
                  <span style={{ display: "flex", gap: 12 }}>
                    {a.enrolled_at && (
                      <button className="link" type="button" onClick={() => void scan(a)}>
                        Scanner
                      </button>
                    )}
                    <button className="link" type="button" onClick={() => void newCode(a)}>
                      Nouveau code
                    </button>
                    <button className="link" type="button" onClick={() => void revoke(a)}>
                      Révoquer
                    </button>
                  </span>
                ) : (
                  <span />
                )}
              </li>
            );
          })}
        </ul>
      )}
      {code && (
        <div className="record" style={{ marginTop: 14 }}>
          <div>
            <small>Code d’installation de {code.name}, valable 24 heures, affiché une seule fois</small>
            <b>{code.code}</b>
          </div>
          <div>
            <small>Linux (en root)</small>
            <b>orus-agent enroll -api {origin} -code {code.code} &amp;&amp; systemctl enable --now orus-agent</b>
          </div>
          <div>
            <small>Windows (PowerShell en administrateur)</small>
            <b>.\orus-agent.exe enroll -api {origin} -code {code.code}</b>
          </div>
        </div>
      )}
      {isAdmin && included && !adding && (
        <div className="actions">
          <button className="btn ghost" type="button" onClick={() => setAdding(true)}>
            Ajouter un réseau interne
          </button>
        </div>
      )}
      {adding && (
        <div className="pwbox">
          <label className="md" htmlFor="agent-name">
            Nom (le site ou le bureau)
          </label>
          <input id="agent-name" style={field} value={name} placeholder="Siège, Brazzaville" onChange={(e) => setName(e.target.value)} />
          <label className="md" htmlFor="agent-ranges">
            Plages d’adresses privées, séparées par des espaces
          </label>
          <input id="agent-ranges" style={field} value={ranges} placeholder="192.168.1.0/24 10.0.0.0/24" onChange={(e) => setRanges(e.target.value)} />
          <p className="err" role="alert">
            {err}
          </p>
          <div className="actions" style={{ marginTop: 0 }}>
            <button className="btn" type="button" onClick={() => void create()}>
              Créer et obtenir le code
            </button>
            <button className="btn ghost" type="button" onClick={() => setAdding(false)}>
              Annuler
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
