import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import type { Instructions, Me, Membership, OverviewTarget } from "../api/types";
import { AppShell } from "../components/AppShell";
import { Alert } from "../components/AuthLayout";
import { plural, scoreBand } from "../format";
import { navigate } from "../router";
import { fallback } from "./messages";

const OPEN = ["critical", "high", "medium", "low"] as const;
const openCount = (t: OverviewTarget) => OPEN.reduce((n, s) => n + (t.open_findings[s] ?? 0), 0);

/** Types of the mockup: only domains exist in the engine today. */
const TYPES = ["Domaine", "Adresse IP ou plage", "Application web", "Microsoft 365", "Google Workspace", "Compte cloud (AWS, Azure)"];

type Pending =
  | { kind: "instructions"; targetId: string; instructions: Instructions; message?: { kind: "error" | "warning"; text: string } }
  | { kind: "verified"; domain: string; scanStarted: boolean };

export function AssetsPage({ me, org }: { me: Me; org: Membership }) {
  const isAdmin = org.role === "admin";
  const [targets, setTargets] = useState<OverviewTarget[] | null>(null);
  const [error, setError] = useState("");
  const [formError, setFormError] = useState("");
  const [pending, setPending] = useState<Pending | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  // The overview already joins each target with its score and open findings.
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const ov = await api.overview(org.org_id, 30, signal);
        setTargets([...ov.per_target].sort((a, b) => a.domain.localeCompare(b.domain)));
      } catch (err) {
        if (signal?.aborted) return;
        if (err instanceof ApiError && err.code === "mfa_required") navigate("/mfa/setup?reason=admin", { replace: true });
        else setError(fallback(err));
      }
    },
    [org.org_id],
  );

  useEffect(() => {
    const ctrl = new AbortController();
    void load(ctrl.signal);
    return () => ctrl.abort();
  }, [load]);

  const showInstructions = async (targetId: string) => {
    const instructions = await api.verificationInstructions(org.org_id, targetId);
    setCopied(false);
    setPending({ kind: "instructions", targetId, instructions });
  };

  const add = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const domain = String(new FormData(form).get("domain")).trim();
    setBusy(true);
    setFormError("");
    try {
      const t = await api.createTarget(org.org_id, domain);
      form.reset();
      await load();
      await showInstructions(t.id);
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) setFormError("Ce nom de domaine n’est pas valide. Exemple : exemple.com");
      else if (err instanceof ApiError && err.status === 409) setFormError("Ce domaine est déjà surveillé.");
      else setFormError(fallback(err));
    } finally {
      setBusy(false);
    }
  };

  const verify = async (p: Extract<Pending, { kind: "instructions" }>) => {
    setBusy(true);
    try {
      await api.verifyTarget(org.org_id, p.targetId);
      // Ownership proven: the first full scan, active modules included.
      let scanStarted = true;
      try {
        await api.startScan(org.org_id, p.targetId);
      } catch {
        scanStarted = false;
      }
      setPending({ kind: "verified", domain: p.instructions.domain, scanStarted });
      await load();
    } catch (err) {
      if (err instanceof ApiError && err.status === 422) {
        setPending({ ...p, message: { kind: "warning", text: "Enregistrement introuvable pour l’instant. Une modification DNS peut prendre quelques minutes à se propager : réessayez ensuite." } });
      } else if (err instanceof ApiError && err.status === 409) {
        await showInstructions(p.targetId); // the token expired: a new one
      } else {
        setPending({ ...p, message: { kind: "error", text: fallback(err) } });
      }
    } finally {
      setBusy(false);
    }
  };

  const record = (i: Instructions) => `${i.record_name}  ${i.record_type}  "${i.record_value}"`;

  return (
    <AppShell me={me} org={org} section="actifs" title="Actifs">
      {error && <Alert kind="error">{error}</Alert>}

      <section className="card">
        <h2>Ajouter un actif</h2>
        <p className="card-sub">Les scans actifs ne démarrent qu’après vérification de la propriété.</p>
        {isAdmin ? (
          <form className="add-form" onSubmit={(e) => void add(e)}>
            <div className="field type">
              <label htmlFor="atype">Type</label>
              <select id="atype" defaultValue="Domaine">
                {TYPES.map((t) => (
                  <option key={t} value={t} disabled={t !== "Domaine"}>
                    {t === "Domaine" ? t : `${t} (bientôt)`}
                  </option>
                ))}
              </select>
            </div>
            <div className="field name">
              <label htmlFor="aname">Adresse</label>
              <input id="aname" name="domain" type="text" placeholder="exemple.com" autoComplete="off" spellCheck={false} required />
            </div>
            <div className="field crit">
              <label htmlFor="acrit">Criticité métier</label>
              <select id="acrit" disabled title="Bientôt disponible">
                <option>Bientôt disponible</option>
              </select>
            </div>
            <button className="btn btn-primary" type="submit" disabled={busy}>
              Ajouter
            </button>
          </form>
        ) : (
          <p className="small muted card-note">L’ajout d’actifs est réservé aux administrateurs.</p>
        )}
        {formError && <p className="form-error" role="alert">{formError}</p>}

        {pending?.kind === "instructions" && (
          <div className="verify-box">
            <p className="strong">Vérifiez la propriété de {pending.instructions.domain}</p>
            <p className="verify-text">Ajoutez cet enregistrement TXT dans la zone DNS du domaine, puis lancez la vérification.</p>
            <pre className="record">{record(pending.instructions)}</pre>
            {pending.instructions.expires_at && (
              <p className="small muted verify-text">
                Ce code est valable jusqu’au {new Date(pending.instructions.expires_at).toLocaleString("fr-FR", { dateStyle: "long", timeStyle: "short" })}. Laissez
                l’enregistrement en place : il est revérifié avant les scans actifs.
              </p>
            )}
            {pending.message && <Alert kind={pending.message.kind}>{pending.message.text}</Alert>}
            <div className="button-row verify-actions">
              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void verify(pending)}>
                Vérifier maintenant
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => void navigator.clipboard.writeText(record(pending.instructions)).then(() => setCopied(true))}
              >
                {copied ? "Copié" : "Copier l’enregistrement"}
              </button>
            </div>
          </div>
        )}
        {pending?.kind === "verified" && (
          <p className="alert alert-notice verify-done" role="status">
            Propriété vérifiée pour {pending.domain}.{" "}
            {pending.scanStarted ? "Le premier scan complet démarre maintenant." : "Lancez un scan depuis l’écran Scans."}
          </p>
        )}
      </section>

      <section className="card row-single">
        <div className="card-head">
          <h2>Actifs surveillés</h2>
          {targets && (
            <p className="small muted">
              {targets.length} {plural(targets.length, "actif", "actifs")}
            </p>
          )}
        </div>
        {targets && targets.length === 0 && (
          <p className="muted card-note">Aucun actif pour l’instant. Ajoutez le domaine de votre entreprise ci-dessus.</p>
        )}
        {targets && targets.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Actif</th>
                  <th scope="col">Type</th>
                  <th scope="col">Criticité</th>
                  <th scope="col">Propriété</th>
                  <th scope="col">Score</th>
                  <th scope="col">Ouvertes</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => (
                  <tr key={t.id}>
                    <td className="name">{t.domain}</td>
                    <td className="muted">Domaine</td>
                    <td className="muted">—</td>
                    <td>
                      {t.verified ? (
                        <span className="tag ok">Vérifiée</span>
                      ) : isAdmin ? (
                        <button type="button" className="tag warn tag-button" onClick={() => void showInstructions(t.id).catch((err: unknown) => setError(fallback(err)))}>
                          À vérifier
                        </button>
                      ) : (
                        <span className="tag warn">À vérifier</span>
                      )}
                    </td>
                    <td>{t.posture_score !== null ? <span className={`score ${scoreBand(t.posture_score)}`}>{t.posture_score}</span> : <span className="muted">—</span>}</td>
                    <td>{openCount(t)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card row-single">
        <h2>Découverts automatiquement</h2>
        <p className="card-sub">Ces éléments sembleront vous appartenir mais ne seront pas encore surveillés.</p>
        <p className="small muted card-note">
          <span className="soon">Bientôt disponible</span> — la découverte des sous-domaines (certificats publics) est en préparation. Un élément découvert n’est jamais
          scanné activement avant que vous l’ajoutiez et vérifiiez sa propriété.
        </p>
      </section>
    </AppShell>
  );
}
