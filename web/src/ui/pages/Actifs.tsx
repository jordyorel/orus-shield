import { useEffect, useState } from "react";
import { api, ApiError } from "../../api/client";
import type { Agent, Instructions, Target } from "../../api/types";
import { Search, Tick } from "../icons";
import { G, Ico } from "../glyphs";
import { CATS, DOMAIN_RE, RANK, SEV, catState, evaluatedCats, serviceIP, servicePort, worst } from "../model";
import { useOrg } from "../OrgData";
import { AssetSheet } from "../sheets";
import { locale, tr } from "../../i18n";
import { ScanLine } from "../ScanLine";
import { takeDomain } from "../prefill";
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
  // A domain tested on the public test page before signing up comes ready.
  const [ad, setAd] = useState<Add>(() => ({ step: 0, domain: takeDomain(), err: "" }));
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

/**
 * AddDomainRow ends a list of domains: "+ Ajouter un domaine", which opens
 * the add and verify flow in place. It starts open while a domain waits for
 * its verification, so its TXT record stays in view.
 */
export function AddDomainRow() {
  const { data } = useOrg();
  const pending = !!data?.targets.some((t) => !t.verified && !t.internal);
  const [open, setOpen] = useState(pending);
  if (!open) {
    return (
      <button className="addrowbtn" type="button" onClick={() => setOpen(true)}>
        <span aria-hidden="true">+</span>
        {tr("Ajouter un domaine", "Add a domain")}
      </button>
    );
  }
  return (
    <div className="rpanel addpanel addopen">
      {!pending && (
        <button className="link addclose" type="button" onClick={() => setOpen(false)}>
          {tr("Fermer", "Close")}
        </button>
      )}
      <AddPanel resume={pending} />
    </div>
  );
}

/** daysTo counts whole days from now to iso (negative once past). */
function daysTo(iso: string, now: Date): number {
  return Math.floor((new Date(iso).getTime() - now.getTime()) / 86_400_000);
}

/** CertCell words a certificate's expiry: expired, soon, or valid. */
function CertCell({ notAfter, now }: { notAfter: string; now: Date }) {
  const d = daysTo(notAfter, now);
  if (d < 0) return <span className="sevpill p-crit">{tr(`Expiré il y a ${-d} j`, `Expired ${-d} d ago`)}</span>;
  if (d <= 14) return <span className="sevpill p-high">{tr(`Expire dans ${d} j`, `Expires in ${d} d`)}</span>;
  return <span className="num">{tr(`Valide · ${d} j`, `Valid · ${d} d`)}</span>;
}

type ATab = "hosts" | "services" | "certs" | "domains";

export function ActifsPage() {
  const { data, assets, issues, isAdmin } = useOrg();
  const { showSheet } = useUI();
  const [af, setAf] = useState<"all" | "pb" | "ok">("all");
  const [tab, setTab] = useState<ATab>("hosts");
  const [q, setQ] = useState("");
  const pending = !!data?.targets.some((t) => !t.verified && !t.internal);
  const [adding, setAdding] = useState(pending);
  if (!data) return null;
  const now = new Date();
  const evaluated = evaluatedCats(data.checks);
  const openOf = (n: string) => issues.filter((i) => !i.fixed && i.host === n);
  const needle = q.trim().toLowerCase();
  const sorted = assets.slice().sort((a, b) => RANK[worst(openOf(a.n))] - RANK[worst(openOf(b.n))]);
  const list = sorted.filter(
    (a) =>
      (af === "all" ? true : af === "pb" ? openOf(a.n).length > 0 : openOf(a.n).length === 0) &&
      (!needle || [a.n, ...a.ips, ...a.tech].some((x) => x.toLowerCase().includes(needle))),
  );
  const nPb = assets.filter((a) => openOf(a.n).length).length;
  // The offer covers hosts_per_scan names per domain.
  const p = data.subscription.plan;
  const cap = p.hosts_per_scan ? p.hosts_per_scan * Math.max(1, data.targets.length) : Math.max(1, assets.length);
  const nOk = assets.length - nPb;
  const domains = data.targets.filter((t) => !t.internal);
  const count = { all: assets.length, pb: nPb, ok: nOk };
  const current = data.assets.filter((x) => !x.gone_at);
  const services = current.filter((x) => x.kind === "service").sort((x, y) => Number(servicePort(x.value)) - Number(servicePort(y.value)));
  const certs = current.filter((x) => x.kind === "certificate").sort((x, y) => (x.details.not_after ?? "").localeCompare(y.details.not_after ?? ""));
  const expired = certs.filter((c) => c.details.not_after && daysTo(c.details.not_after, now) < 0).length;
  const nextCert = certs.find((c) => c.details.not_after && daysTo(c.details.not_after, now) >= 0);
  const ports = new Map<string, number>();
  for (const sv of services) ports.set(servicePort(sv.value), (ports.get(servicePort(sv.value)) ?? 0) + 1);
  const topPorts = [...ports.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3);
  const sevs = (["crit", "high", "med", "low"] as const).map((k) => [k, assets.filter((x) => worst(openOf(x.n)) === k).length] as const);
  const tabs: [ATab, string, number][] = [
    ["hosts", tr("Noms d’hôte", "Hostnames"), assets.length],
    ["services", tr("Services", "Services"), services.length],
    ["certs", tr("Certificats", "Certificates"), certs.length],
    ["domains", tr("Domaines", "Domains"), domains.length],
  ];

  return (
    <>
      <div className="ph">
        <div>
          <h1>{tr("Actifs", "Assets")}</h1>
          <p>{tr("Tout ce que vous exposez sur internet, découvert par les journaux de certificats et le DNS.", "Everything you expose on the internet, discovered through certificate logs and DNS.")}</p>
        </div>
        {isAdmin && !adding && (
          <div className="phacts">
            <button className="btn sm" type="button" onClick={() => setAdding(true)}>
              <span aria-hidden="true">+ </span>
              {tr("Ajouter un domaine", "Add a domain")}
            </button>
          </div>
        )}
      </div>

      {adding && (
        <div className="rpanel addpanel addopen">
          {!pending && (
            <button className="link addclose" type="button" onClick={() => setAdding(false)}>
              {tr("Fermer", "Close")}
            </button>
          )}
          <AddPanel resume={pending} />
        </div>
      )}

      <div className="statstrip">
        <div className="stat">
          <small><Ico d={G.globe} />{tr("Actifs surveillés", "Monitored assets")}</small>
          <p className="statv">
            <b>{assets.length}</b>
            <span>{tr(`sur ${cap} inclus dans l’offre ${p.name}`, `of ${cap} included in the ${p.name} plan`)}</span>
          </p>
          <div className="sevbar" role="img" aria-label={tr(`${assets.length} actifs sur ${cap}`, `${assets.length} of ${cap} assets`)}>
            <i style={{ width: Math.min(100, (assets.length / cap) * 100) + "%", background: "var(--azur)" }} />
          </div>
        </div>
        <div className="stat">
          <small><Ico d={G.bug} tone="red" />{tr("Avec un problème", "With a problem")}</small>
          <p className="statv">
            <b>{nPb}</b>
            <span>{tr(`${nOk} protégé${nOk > 1 ? "s" : ""}`, `${nOk} protected`)}</span>
          </p>
          <div className="sevbar" aria-hidden="true">
            {sevs.map(([k, n]) => (n ? <i key={k} style={{ flex: n, background: `var(--${k})` }} /> : null))}
            {nOk > 0 && <i style={{ flex: nOk, background: "var(--ok)" }} />}
          </div>
        </div>
        <div className="stat">
          <small><Ico d={G.server} tone="violet" />{tr("Services exposés", "Exposed services")}</small>
          <p className="statv">
            <b>{services.length}</b>
            <span>{tr("ports ouverts", "open ports")}</span>
          </p>
          <p className="statfoot">
            <span className="mono">{topPorts.map(([pt, n]) => `${pt} ×${n}`).join(" · ") || "–"}</span>
          </p>
        </div>
        <div className="stat">
          <small><Ico d={G.lock} tone="green" />{tr("Certificats", "Certificates")}</small>
          <p className="statv">
            <b>{certs.length - expired}</b>
            <span>{tr("valides", "valid")}</span>
            {expired > 0 && <em className="delta dn">{tr(`${expired} expiré${expired > 1 ? "s" : ""}`, `${expired} expired`)}</em>}
          </p>
          <p className="statfoot">
            <span>{nextCert?.details.not_after ? tr(`prochain à expirer : ${daysTo(nextCert.details.not_after, now)} j`, `next to expire: ${daysTo(nextCert.details.not_after, now)} d`) : "–"}</span>
          </p>
        </div>
      </div>

      <nav className="ctabs" aria-label={tr("Inventaire", "Inventory")}>
        {tabs.map(([k, l, n]) => (
          <button key={k} type="button" aria-pressed={tab === k} onClick={() => setTab(k)}>
            {l}
            <span className="ctabn">{n}</span>
          </button>
        ))}
      </nav>

      {tab === "hosts" && (
        <section className="panel">
          <div className="fbar">
            <label className="fin">
              <Search />
              <span className="vh">{tr("Filtrer les actifs", "Filter the assets")}</span>
              <input type="search" placeholder={tr("Filtrer par nom, IP, technologie…", "Filter by name, IP, technology…")} value={q} onChange={(e) => setQ(e.target.value)} />
            </label>
            <div className="cseg" role="group" aria-label={tr("Filtrer les actifs", "Filter the assets")}>
              {(
                [
                  ["all", tr("Tous", "All")],
                  ["pb", tr("Avec un problème", "With a problem")],
                  ["ok", tr("Protégés", "Protected")],
                ] as const
              ).map(([k, l]) => (
                <button key={k} type="button" aria-pressed={af === k} onClick={() => setAf(k)}>
                  {l} <b>{count[k]}</b>
                </button>
              ))}
            </div>
          </div>
          <div className="tw">
            <table className="ctable">
              <thead>
                <tr>
                  <th>{tr("Nom d’hôte", "Hostname")}</th>
                  <th>{tr("Adresse IP", "IP address")}</th>
                  <th>{tr("Ports", "Ports")}</th>
                  <th>{tr("Technologies", "Technologies")}</th>
                  <th>{tr("Certificat", "Certificate")}</th>
                  <th>{tr("Contrôles", "Checks")}</th>
                  <th>{tr("Risque", "Risk")}</th>
                </tr>
              </thead>
              <tbody>
                {list.length ? (
                  list.map((a) => {
                    const o = openOf(a.n);
                    const w = worst(o);
                    return (
                      <tr key={a.n}>
                        <td>
                          <button className={"arow sev-" + w} type="button" title={a.n} onClick={() => showSheet(<AssetSheet n={a.n} />)}>
                            <b className="mono">{a.n}</b>
                            <small>
                              {a.k}
                              {o.length ? tr(` · ${o.length} problème${o.length > 1 ? "s" : ""}`, ` · ${o.length} problem${o.length > 1 ? "s" : ""}`) : ""}
                            </small>
                          </button>
                        </td>
                        <td className="mono">{a.ips.join(", ") || "–"}</td>
                        <td>
                          <span className="chips">
                            {a.svc.length
                              ? a.svc.slice(0, 4).map(([pt]) => (
                                  <span key={pt} className="chip mono">
                                    {pt}
                                  </span>
                                ))
                              : "–"}
                          </span>
                        </td>
                        <td>
                          <span className="chips">
                            {a.tech.length
                              ? a.tech.slice(0, 3).map((x) => (
                                  <span key={x} className="tag">
                                    {x}
                                  </span>
                                ))
                              : "–"}
                          </span>
                        </td>
                        <td>{a.cert ? <CertCell notAfter={a.cert.notAfter} now={now} /> : "–"}</td>
                        <td>
                          <span className="acats" aria-hidden="true">
                            {CATS.map(([c, l]) => (
                              <span key={c} title={l}>
                                <i className={"hm " + catState(a, c, issues, evaluated)} />
                              </span>
                            ))}
                          </span>
                        </td>
                        <td>
                          <span className={"sevpill p-" + w}>{w === "ok" ? tr("Protégé", "Protected") : SEV[w][0]}</span>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={7} className="ctempty">
                      {assets.length
                        ? tr("Aucun actif ne correspond à ces filtres.", "No asset matches these filters.")
                        : tr("Aucun actif trouvé pour l’instant : il apparaîtra après le premier scan.", "No asset found yet: they appear after the first scan.")}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {tab === "services" && (
        <section className="panel">
          <div className="tw">
            <table className="ctable">
              <thead>
                <tr>
                  <th>{tr("Adresse", "Address")}</th>
                  <th>{tr("Port", "Port")}</th>
                  <th>{tr("Nom d’hôte", "Hostname")}</th>
                  <th>{tr("Service", "Service")}</th>
                  <th>{tr("Produit et version", "Product and version")}</th>
                  <th>{tr("Vu depuis", "Seen since")}</th>
                </tr>
              </thead>
              <tbody>
                {services.length ? (
                  services.map((sv) => (
                    <tr key={sv.id}>
                      <td className="mono">{serviceIP(sv.value)}</td>
                      <td>
                        <span className="chip mono">{servicePort(sv.value)}</span>
                      </td>
                      <td className="mono">{sv.details.host ?? "–"}</td>
                      <td>{sv.details.service ?? sv.details.expected ?? "–"}</td>
                      <td>{[sv.details.product, sv.details.version].filter(Boolean).join(" ") || "–"}</td>
                      <td className="num">{new Date(sv.first_seen).toLocaleDateString(locale(), { day: "numeric", month: "short", year: "numeric" })}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="ctempty">
                      {tr("Aucun service exposé trouvé pour l’instant.", "No exposed service found yet.")}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {tab === "certs" && (
        <section className="panel">
          <div className="tw">
            <table className="ctable">
              <thead>
                <tr>
                  <th>{tr("Sujet", "Subject")}</th>
                  <th>{tr("Noms couverts", "Names covered")}</th>
                  <th>{tr("Émetteur", "Issuer")}</th>
                  <th>{tr("Expiration", "Expiry")}</th>
                </tr>
              </thead>
              <tbody>
                {certs.length ? (
                  certs.map((c) => (
                    <tr key={c.id}>
                      <td className="mono">{c.details.subject || "–"}</td>
                      <td className="mono ctnames">{(c.details.names ?? "").split(" ").filter(Boolean).slice(0, 4).join(", ") || "–"}</td>
                      <td>{c.details.issuer || "–"}</td>
                      <td>{c.details.not_after ? <CertCell notAfter={c.details.not_after} now={now} /> : "–"}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="ctempty">
                      {tr("Aucun certificat vu pour l’instant.", "No certificate seen yet.")}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {tab === "domains" && (
        <section className="panel">
          {domains.map((t) => (
            <div key={t.id} className="domrow">
              <div className="domtop">
                <b className="mono">{t.domain}</b>
                <span className={"stchip " + (t.verified ? "st-ok" : "st-warn")}>{t.verified ? tr("Vérifié", "Verified") : tr("À vérifier", "To verify")}</span>
                <span className="domn">{tr(`${assets.filter((x) => x.targetId === t.id).length} actifs`, `${assets.filter((x) => x.targetId === t.id).length} assets`)}</span>
              </div>
              {t.verified ? <ScanLine targets={[t]} /> : <span className="hint">{tr("Publiez son enregistrement TXT pour le scanner.", "Publish its TXT record to scan it.")}</span>}
            </div>
          ))}
          {!domains.length && <p className="ctempty">{tr("Aucun domaine pour l’instant.", "No domain yet.")}</p>}
        </section>
      )}

      <div className="section">
        <InternalNetworks />
      </div>
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
