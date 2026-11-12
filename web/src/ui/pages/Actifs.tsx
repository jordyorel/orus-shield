import { useState } from "react";
import { api, ApiError } from "../../api/client";
import type { Instructions, Target } from "../../api/types";
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
  const pending = data?.targets.find((t) => !t.verified);
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
    </>
  );
}
