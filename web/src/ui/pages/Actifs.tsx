import { useEffect, useState } from "react";
import { api, ApiError } from "../../api/client";
import type { Agent, Instructions, Target } from "../../api/types";
import { Tick } from "../icons";
import { CATS, DOMAIN_RE, RANK, catState, evaluatedCats, worst } from "../model";
import { useOrg } from "../OrgData";
import { AssetSheet, SevTag } from "../sheets";
import { tr } from "../../i18n";
import { ScanLine } from "../ScanLine";
import { useUI } from "../ui";

const RETRY_MS = 30_000;
const RETRY_MAX = 20; // 10 minutes

/** hostPart is the record's name without its domain, what most DNS
 * providers' "Host" field expects (they append the domain themselves). */
export function hostPart(name: string, domain: string): string {
  const suffix = "." + domain;
  return name.endsWith(suffix) ? name.slice(0, -suffix.length) : name;
}

type Add =
  | { step: 0; domain: string; err: string }
  | { step: 1 | 2; domain: string; err: string; target: Target; rec: Instructions }
  | { step: 3; domain: string; err: string };

/** AddPanel adds a domain, shows its TXT record and verifies it; the API
 * then queues its first, light scan (nothing is scanned before). resume: open a domain still waiting
 * for verification at its record straight away (the Premiers pas card of
 * Aujourd'hui). */
export function AddPanel({ resume = false }: { resume?: boolean }) {
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
  const pendingId = resume && isAdmin ? pending?.id : undefined;
  useEffect(() => {
    const t = data?.targets.find((x) => x.id === pendingId);
    if (t) void showRecord(t).catch(() => undefined); // the panel stays at its first step
    // Only when the pending domain changes, not on every reload.
  }, [pendingId]);

  const next = async () => {
    const v = ad.domain.trim().toLowerCase();
    if (!DOMAIN_RE.test(v)) {
      setAd({
        step: 0,
        domain: v,
        err: v ? tr("Ce nom de domaine n’est pas valide. Exemple : votre-entreprise.cg", "This domain name is not valid. Example: your-company.com") : tr("Saisissez un nom de domaine.", "Enter a domain name."),
      });
      return;
    }
    if (!isAdmin) {
      setAd({ step: 0, domain: v, err: tr("Seul un administrateur peut ajouter un domaine.", "Only an administrator can add a domain.") });
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
          ? tr("Ce domaine est déjà dans votre espace.", "This domain is already in your workspace.")
          : e instanceof ApiError && e.code === "plan_limit"
            ? tr("Votre offre ne permet pas d’ajouter un autre domaine. Changez d’offre dans Réglages.", "Your plan does not allow another domain. Change plans in Settings.")
            : tr("Impossible d’ajouter ce domaine pour le moment.", "This domain cannot be added right now.");
      setAd({ step: 0, domain: v, err });
    } finally {
      setBusy(false);
    }
  };

  // After a failed check (record not visible yet), the panel checks again
  // by itself every RETRY_MS, RETRY_MAX times: DNS changes take minutes to
  // appear, and the customer should not have to click in a loop.
  const [retries, setRetries] = useState(0);
  const verify = async (auto = false) => {
    if (ad.step !== 1) return;
    const { target, rec } = ad;
    if (!auto) {
      setAd({ ...ad, step: 2 });
      setRetries(0);
    }
    try {
      // The API reads the record itself, then queues the first scan.
      await api.verifyTarget(org.org_id, target.id);
      setAd({ step: 3, domain: target.domain, err: "" });
      void reload();
    } catch (e) {
      const missing = e instanceof ApiError && e.status === 422;
      const err = missing
        ? tr("L’enregistrement n’est pas encore visible. Les changements DNS peuvent prendre quelques minutes.", "The record is not visible yet. DNS changes can take a few minutes.")
        : tr("Vérification impossible pour le moment.", "Verification is not possible right now.");
      setAd({ step: 1, domain: target.domain, err, target, rec });
      setRetries((n) => (missing ? n + 1 : RETRY_MAX + 1));
    }
  };
  const waiting = ad.step === 1 && ad.err !== "" && retries > 0 && retries <= RETRY_MAX;
  useEffect(() => {
    if (!waiting) return;
    const t = setTimeout(() => void verify(true), RETRY_MS);
    return () => clearTimeout(t);
    // verify reads the current panel; a new attempt is planned after each result.
  }, [waiting, retries]);

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

  if (ad.step === 0) {
    return (
      <>
        <h2>{tr("Ajouter un domaine", "Add a domain")}</h2>
        <p className="sub">{tr("Vous prouvez qu’il vous appartient, puis un premier scan léger démarre.", "You prove it is yours, then a light first scan starts.")}</p>
        <div className="addrow">
          <label className="vh" htmlFor="add-in">
            {tr("Nom de domaine", "Domain name")}
          </label>
          <input
            id="add-in"
            type="text"
            inputMode="url"
            autoComplete="off"
            placeholder={tr("votre-entreprise.cg", "your-company.com")}
            value={ad.domain}
            onChange={(e) => setAd({ ...ad, domain: e.target.value })}
            onKeyDown={(e) => {
              if (e.key === "Enter") void next();
            }}
          />
          <button className="btn" type="button" disabled={busy} onClick={() => void next()}>
            {tr("Ajouter", "Add")}
          </button>
        </div>
        <p className="err" role="alert">
          {ad.err}
        </p>
        {pending && isAdmin && (
          <p className="sub">
            {tr(`${pending.domain} attend sa vérification.`, `${pending.domain} is waiting for its verification.`)}{" "}
            <button className="link" type="button" style={{ minHeight: 0 }} onClick={() => void showRecord(pending)}>
              {tr("Reprendre", "Resume")}
            </button>
          </p>
        )}
      </>
    );
  }
  if (ad.step === 1) {
    return (
      <>
        <h2>{tr(`Prouvez que ${ad.domain} est à vous`, `Prove that ${ad.domain} is yours`)}</h2>
        <p className="sub">{tr("Ajoutez cet enregistrement dans la zone DNS du domaine.", "Add this record to the domain's DNS zone.")}</p>
        <div className="record">
          <div>
            <small>Type</small>
            <b>TXT</b>
          </div>
          <div>
            <small>{tr("Nom", "Name")}</small>
            <b>{ad.rec.record_name}</b>
          </div>
          <div>
            <small>{tr("Valeur", "Value")}</small>
            <b>{ad.rec.record_value}</b>
          </div>
        </div>
        <p className="sub">
          {tr("Chez la plupart des hébergeurs, le champ Nom (ou Host) attend seulement ", "Most DNS providers expect only ")}
          <b>{hostPart(ad.rec.record_name, ad.domain)}</b>
          {tr(` : ils ajoutent eux-mêmes .${ad.domain}.`, ` in the Name (or Host) field: they add .${ad.domain} themselves.`)}
        </p>
        <p className="err" role="alert">
          {ad.err}
        </p>
        {waiting && <p className="sub">{tr("Nous réessayons automatiquement toutes les 30 secondes.", "We try again automatically every 30 seconds.")}</p>}
        <div className="actions">
          <button className="btn" type="button" onClick={() => void verify()}>
            {tr("Vérifier maintenant", "Verify now")}
          </button>
          <button className="btn ghost" type="button" onClick={() => copy(ad.rec.record_value)}>
            {tr("Copier la valeur", "Copy the value")}
          </button>
          <button className="btn ghost" type="button" onClick={() => setAd({ step: 0, domain: "", err: "" })}>
            {tr("Annuler", "Cancel")}
          </button>
        </div>
      </>
    );
  }
  if (ad.step === 2) {
    return (
      <>
        <h2>{tr("Vérification en cours", "Verifying")}</h2>
        <p className="sub">{tr(`Lecture de la zone DNS de ${ad.domain}.`, `Reading the DNS zone of ${ad.domain}.`)}</p>
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
      <h2>{tr(`${ad.domain} est vérifié`, `${ad.domain} is verified`)}</h2>
      <p className="sub">{tr("Le premier scan vient de démarrer.", "The first scan has just started.")}</p>
      <div className="actions">
        <button className="btn ghost" type="button" onClick={() => setAd({ step: 0, domain: "", err: "" })}>
          {tr("Ajouter un autre domaine", "Add another domain")}
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
          {tr("Actifs", "Assets")}
        </h1>
      </div>
      <p className="pagehead">
        <b>{assets.length}</b> {tr("actifs surveillés", "monitored assets")}
        <span>{tr(`${nPb} avec un problème ouvert`, `${nPb} with an open problem`)}</span>
      </p>
      <div className="meter" role="img" aria-label={tr(`${assets.length} actifs sur ${cap} inclus dans l'offre ${p.name}`, `${assets.length} of ${cap} assets included in the ${p.name} plan`)}>
        <div>
          <b style={{ width: Math.min(100, (assets.length / cap) * 100) + "%" }} />
        </div>
        <span>
          {tr(`${assets.length} sur ${cap} inclus dans l’offre ${p.name}`, `${assets.length} of ${cap} included in the ${p.name} plan`)}
        </span>
      </div>
      <ul className="domlines" aria-label={tr("Vos domaines", "Your domains")}>
        {data.targets
          .filter((t) => !t.internal)
          .map((t) => (
            <li key={t.id}>
              <b>{t.domain}</b>
              {t.verified ? <ScanLine targets={[t]} /> : <span className="hint">{tr("À vérifier : ajoutez son enregistrement TXT plus bas.", "To verify: add its TXT record below.")}</span>}
            </li>
          ))}
      </ul>
      <div className="filters" role="group" aria-label={tr("Filtrer les actifs", "Filter the assets")}>
        {(
          [
            ["all", tr("Tous", "All")],
            ["pb", tr("Avec un problème", "With a problem")],
            ["ok", tr("Protégés", "Protected")],
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
                <SevTag s={w} label={w === "ok" ? tr("Protégé", "Protected") : undefined} />
              </span>
              <span className="k">
                {a.k}
                {o.length ? tr(`, ${o.length} problème${o.length > 1 ? "s" : ""}`, `, ${o.length} problem${o.length > 1 ? "s" : ""}`) : ""}
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
      <p className="striphelp">{tr("Les cinq cases de chaque carte : Emails, TLS, Ports, Fuites, Menaces.", "The five boxes of each card: Email, TLS, Ports, Leaks, Threats.")}</p>
      <div className="rpanel addpanel">
        <AddPanel />
      </div>
      <InternalNetworks />
    </>
  );
}

/** online: an agent seen in the last few minutes (it polls every 30 s). */
function agentState(a: Agent, now: Date): [string, "ok" | "high" | "med" | "crit"] {
  if (a.revoked_at) return [tr("Révoqué", "Revoked"), "crit"];
  if (!a.enrolled_at) return [tr("En attente d’installation", "Waiting for installation"), "med"];
  if (a.last_seen_at && now.getTime() - new Date(a.last_seen_at).getTime() < 5 * 60_000) return [tr("En ligne", "Online"), "ok"];
  return [tr("Hors ligne", "Offline"), "high"];
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
          ? tr("Les réseaux internes sont inclus dans l’offre sur devis.", "Internal networks are included in the custom plan.")
          : e instanceof ApiError && e.status === 400
            ? tr(
                "Vérifiez les plages : des réseaux privés (10.x, 172.16-31.x, 192.168.x), au plus un /20, par exemple 192.168.1.0/24.",
                "Check the ranges: private networks (10.x, 172.16-31.x, 192.168.x), at most a /20, for example 192.168.1.0/24.",
              )
            : tr("Agent non créé, réessayez.", "Agent not created, try again."),
      );
    }
  };
  const newCode = async (a: Agent) => {
    try {
      const r = await api.newAgentCode(org.org_id, a.id);
      setCode({ name: a.name, code: r.enrolment_code });
      void load();
    } catch {
      toast(tr("Code impossible pour le moment", "No code can be issued right now"));
    }
  };
  const revoke = async (a: Agent) => {
    if (!window.confirm(tr(`Révoquer l’agent ${a.name} ? Il ne pourra plus rien scanner ni envoyer.`, `Revoke the agent ${a.name}? It will no longer scan or send anything.`))) return;
    try {
      await api.revokeAgent(org.org_id, a.id);
      toast(tr("Agent révoqué", "Agent revoked"));
      void load();
    } catch {
      toast(tr("Révocation impossible pour le moment", "Revocation is not possible right now"));
    }
  };
  const scan = async (a: Agent) => {
    try {
      await api.startScan(org.org_id, a.target_id, ["ports"]);
      toast(tr("Scan demandé : l’agent le lancera à son prochain passage (30 secondes au plus)", "Scan requested: the agent starts it at its next check-in (30 seconds at most)"));
      void reload();
    } catch {
      toast(tr("Scan impossible pour le moment", "The scan is not possible right now"));
    }
  };
  const now = new Date();
  const field = { height: 44, borderRadius: 14, border: "1px solid var(--line)", background: "var(--bg)", color: "var(--ink)", font: "inherit", padding: "0 14px" };
  const origin = window.location.origin;

  return (
    <div className="rpanel addpanel">
      <h2>
        {tr("Réseaux internes", "Internal networks")}
        {!included && <span className="soon">{tr("Offre sur devis", "Custom plan")}</span>}
      </h2>
      <p className="sub">
        {tr(
          "Un petit agent, installé sur une machine de votre réseau, analyse vos adresses privées. Il ne fait que des appels sortants : aucun port à ouvrir chez vous.",
          "A small agent, installed on a machine of your network, analyses your private addresses. It only makes outgoing calls: no port to open on your side.",
        )}
      </p>
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
                    {tr(` · ${open} problème${open > 1 ? "s" : ""} ouvert${open > 1 ? "s" : ""}`, ` · ${open} open problem${open > 1 ? "s" : ""}`)}
                  </p>
                </div>
                {isAdmin && !a.revoked_at ? (
                  <span style={{ display: "flex", gap: 12 }}>
                    {a.enrolled_at && (
                      <button className="link" type="button" onClick={() => void scan(a)}>
                        {tr("Scanner", "Scan")}
                      </button>
                    )}
                    <button className="link" type="button" onClick={() => void newCode(a)}>
                      {tr("Nouveau code", "New code")}
                    </button>
                    <button className="link" type="button" onClick={() => void revoke(a)}>
                      {tr("Révoquer", "Revoke")}
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
            <small>{tr(`Code d’installation de ${code.name}, valable 24 heures, affiché une seule fois`, `Installation code for ${code.name}, valid 24 hours, shown only once`)}</small>
            <b>{code.code}</b>
          </div>
          <div>
            <small>{tr("Linux (en root)", "Linux (as root)")}</small>
            <b>orus-agent enroll -api {origin} -code {code.code} &amp;&amp; systemctl enable --now orus-agent</b>
          </div>
          <div>
            <small>{tr("Windows (PowerShell en administrateur)", "Windows (PowerShell as administrator)")}</small>
            <b>.\orus-agent.exe enroll -api {origin} -code {code.code}</b>
          </div>
        </div>
      )}
      {isAdmin && included && !adding && (
        <div className="actions">
          <button className="btn ghost" type="button" onClick={() => setAdding(true)}>
            {tr("Ajouter un réseau interne", "Add an internal network")}
          </button>
        </div>
      )}
      {adding && (
        <div className="pwbox">
          <label className="md" htmlFor="agent-name">
            {tr("Nom (le site ou le bureau)", "Name (the site or office)")}
          </label>
          <input id="agent-name" style={field} value={name} placeholder={tr("Siège, Brazzaville", "Head office, Nairobi")} onChange={(e) => setName(e.target.value)} />
          <label className="md" htmlFor="agent-ranges">
            {tr("Plages d’adresses privées, séparées par des espaces", "Private address ranges, separated by spaces")}
          </label>
          <input id="agent-ranges" style={field} value={ranges} placeholder="192.168.1.0/24 10.0.0.0/24" onChange={(e) => setRanges(e.target.value)} />
          <p className="err" role="alert">
            {err}
          </p>
          <div className="actions" style={{ marginTop: 0 }}>
            <button className="btn" type="button" onClick={() => void create()}>
              {tr("Créer et obtenir le code", "Create and get the code")}
            </button>
            <button className="btn ghost" type="button" onClick={() => setAdding(false)}>
              {tr("Annuler", "Cancel")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
