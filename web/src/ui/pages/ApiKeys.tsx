// Réglages > API: the organization's API keys, for its own tools (offers
// with plan.public_api), laid out like the key pages of the usual
// developer tools: the keys first, a button to create one (in a side
// sheet), the new key shown once in a callout, then a quick start. Only a
// signed-in admin manages keys; a key itself can never create or revoke
// one (the API refuses).

import { useEffect, useState } from "react";
import { api, ApiError } from "../../api/client";
import type { APIKey } from "../../api/types";
import { locale, tr } from "../../i18n";
import { Link } from "../../router";
import { settingsPath } from "../AppShell";
import { KeyIcon, Tick } from "../icons";
import { sinceText } from "../model";
import { useOrg } from "../OrgData";
import { CloseButton } from "../sheets";
import { useUI } from "../ui";
import { WebhooksBlock } from "./Webhooks";

const EXPIRY: [number, () => string][] = [
  [0, () => tr("Jamais", "Never")],
  [30, () => tr("30 jours", "30 days")],
  [90, () => tr("90 jours", "90 days")],
  [365, () => tr("1 an", "1 year")],
];

function day(iso: string): string {
  return new Date(iso).toLocaleDateString(locale(), { day: "numeric", month: "short", year: "numeric" });
}

const expired = (k: APIKey) => !!k.expires_at && new Date(k.expires_at) < new Date();

/** CreateKeySheet is the creation form, in the side sheet. */
function CreateKeySheet({ orgId, onCreated }: { orgId: string; onCreated: (name: string, secret: string) => void }) {
  const { closeAll } = useUI();
  const [name, setName] = useState("");
  const [scope, setScope] = useState<"read" | "write">("read");
  const [expiry, setExpiry] = useState(0);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const create = async () => {
    if (!name.trim()) {
      setErr(tr("Donnez un nom à la clé, par exemple « Intégration CI ».", "Give the key a name, such as “CI integration”."));
      return;
    }
    setBusy(true);
    setErr("");
    try {
      const r = await api.createApiKey(orgId, name.trim(), scope, expiry);
      closeAll();
      onCreated(r.key.name, r.secret);
    } catch (e) {
      setErr(
        e instanceof ApiError && e.code === "too_many_keys"
          ? tr("Vous avez déjà 20 clés actives : révoquez-en une d’abord.", "You already have 20 active keys: revoke one first.")
          : tr("La clé n’a pas pu être créée. Réessayez.", "The key could not be created. Try again."),
      );
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <div className="shead">
        <span />
        <CloseButton />
      </div>
      <h2 id="sheet-title">{tr("Créer une clé d’API", "Create an API key")}</h2>
      <p className="why">{tr("Elle donnera accès à cette organisation seulement.", "It will give access to this organization only.")}</p>
      <div className="aform">
        <div className="field">
          <label htmlFor="key-name">{tr("Nom", "Name")}</label>
          <input id="key-name" type="text" maxLength={80} autoFocus placeholder={tr("Intégration CI", "CI integration")} value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <fieldset className="keychoice">
          <legend>{tr("Droits", "Access")}</legend>
          {(
            [
              ["read", tr("Lecture", "Read"), tr("Lire les résultats : problèmes, actifs, score, rapports.", "Read results: problems, assets, score, reports.")],
              ["write", tr("Lecture et écriture", "Read and write"), tr("Aussi lancer un scan et changer le statut d’un problème.", "Also start a scan and change a problem’s status.")],
            ] as const
          ).map(([k, l, d]) => (
            <label key={k} className={"keyopt" + (scope === k ? " on" : "")}>
              <input type="radio" name="key-scope" checked={scope === k} onChange={() => setScope(k)} />
              <span>
                <b>{l}</b>
                <small>{d}</small>
              </span>
            </label>
          ))}
        </fieldset>
        <div className="field">
          <span className="flabel">{tr("Expiration", "Expiry")}</span>
          <div className="seg2" role="group" aria-label={tr("Expiration", "Expiry")}>
            {EXPIRY.map(([d, l]) => (
              <button key={d} type="button" aria-pressed={expiry === d} onClick={() => setExpiry(d)}>
                {l()}
              </button>
            ))}
          </div>
          <p className="md">{tr("Une clé qui expire limite les dégâts si elle fuit.", "A key that expires limits the damage if it leaks.")}</p>
        </div>
        <p className="err" role="alert">
          {err}
        </p>
      </div>
      <div className="actions sticky">
        <button className="btn" type="button" disabled={busy} onClick={() => void create()}>
          {busy ? <span className="spin" /> : null}
          {tr("Créer la clé", "Create the key")}
        </button>
      </div>
    </>
  );
}

/** QuickStart shows how to call the API, in three languages. */
function QuickStart({ orgId }: { orgId: string }) {
  const { toast } = useUI();
  const [lang, setLang] = useState<"curl" | "python" | "js">("curl");
  const url = `${typeof window !== "undefined" ? window.location.origin : ""}/api/v1/orgs/${orgId}/findings`;
  const code = {
    curl: `curl -H "Authorization: Bearer $ORUS_API_KEY" \\\n  ${url}`,
    python: `import os, requests\n\nr = requests.get(\n    "${url}",\n    headers={"Authorization": f"Bearer {os.environ['ORUS_API_KEY']}"},\n)\nprint(r.json()["items"])`,
    js: `const r = await fetch("${url}", {\n  headers: { Authorization: \`Bearer \${process.env.ORUS_API_KEY}\` },\n});\nconsole.log((await r.json()).items);`,
  }[lang];
  const routes: [string, string, string][] = [
    ["GET", "/overview", tr("Score, problèmes ouverts, tendance", "Score, open problems, trend")],
    ["GET", "/findings", tr("Tous les problèmes", "All problems")],
    ["GET", "/assets", tr("L’inventaire des actifs", "The asset inventory")],
    ["GET", "/targets", tr("Vos domaines", "Your domains")],
    ["GET", "/report?kind=executive", tr("Le rapport PDF", "The PDF report")],
    ["POST", "/targets/{id}/scans", tr("Lancer un scan (écriture)", "Start a scan (write)")],
    ["PUT", "/targets/{id}/findings/{id}/status", tr("Changer le statut d’un problème (écriture)", "Change a problem’s status (write)")],
  ];
  return (
    <div className="rpanel apistart">
      <div className="rhead">
        <h3>{tr("Démarrage rapide", "Quick start")}</h3>
        <div className="seg2" role="group" aria-label={tr("Langage", "Language")}>
          {(
            [
              ["curl", "curl"],
              ["python", "Python"],
              ["js", "JavaScript"],
            ] as const
          ).map(([k, l]) => (
            <button key={k} type="button" aria-pressed={lang === k} onClick={() => setLang(k)}>
              {l}
            </button>
          ))}
        </div>
      </div>
      <div className="codebox">
        <pre>{code}</pre>
        <button
          className="btn ghost sm"
          type="button"
          onClick={() =>
            navigator.clipboard?.writeText(code).then(
              () => toast(tr("Copié", "Copied")),
              () => toast(tr("Copie impossible ici", "Copying is not possible here")),
            )
          }
        >
          {tr("Copier", "Copy")}
        </button>
      </div>
      <ul className="routes">
        {routes.map(([m, p, d]) => (
          <li key={m + p}>
            <span className={"verb v-" + m.toLowerCase()}>{m}</span>
            <code>{p}</code>
            <small>{d}</small>
          </li>
        ))}
      </ul>
      <p className="md">
        {tr(
          "Toutes les routes commencent par /api/v1/orgs/{organisation}. 120 requêtes par minute et par clé ; au-delà, la réponse est 429.",
          "Every route starts with /api/v1/orgs/{organization}. 120 requests per minute per key; beyond that, the answer is 429.",
        )}{" "}
        <a href="/docs/api" target="_blank" rel="noopener">
          {tr("Documentation complète", "Full documentation")}
        </a>
      </p>
    </div>
  );
}

export function ApiKeysSection() {
  const { org, data, isAdmin } = useOrg();
  const { toast, showSheet } = useUI();
  const [keys, setKeys] = useState<APIKey[] | null>(null);
  const [secret, setSecret] = useState<{ name: string; value: string } | null>(null);
  const allowed = !!data?.subscription.plan.public_api;

  const load = () =>
    api.apiKeys(org.org_id).then(
      (r) => setKeys(r.items),
      () => setKeys([]),
    );
  useEffect(() => {
    if (allowed && isAdmin) void load();
  }, [allowed, isAdmin, org.org_id]);

  if (!allowed) {
    return (
      <div className="rpanel apiempty">
        <span className="keybadge" aria-hidden="true">
          <KeyIcon size={26} />
        </span>
        <h2>{tr("Connectez vos propres outils", "Connect your own tools")}</h2>
        <p className="why">
          {tr(
            "Lisez vos résultats, lancez un scan ou marquez un problème corrigé depuis un script, votre CI ou votre outil de suivi.",
            "Read your results, start a scan or mark a problem fixed from a script, your CI or your tracking tool.",
          )}
        </p>
        <p className="md">{tr("Inclus dans les offres Pro et Sur devis.", "Included in the Pro and custom plans.")}</p>
        <Link className="btn" to={settingsPath(org.org_id, "abonnement")}>
          {tr("Voir les offres", "See the plans")}
        </Link>
      </div>
    );
  }
  if (!isAdmin) {
    return <p className="hint">{tr("Seuls les administrateurs gèrent les clés d’API.", "Only administrators manage API keys.")}</p>;
  }

  const openCreate = () =>
    showSheet(
      <CreateKeySheet
        orgId={org.org_id}
        onCreated={(name, value) => {
          setSecret({ name, value });
          void load();
        }}
      />,
    );
  const revoke = async (k: APIKey) => {
    if (!window.confirm(tr(`Révoquer « ${k.name} » ? Les outils qui l’utilisent perdront l’accès aussitôt.`, `Revoke “${k.name}”? The tools using it lose access at once.`))) return;
    try {
      await api.revokeApiKey(org.org_id, k.id);
      toast(tr("Clé révoquée", "Key revoked"));
      await load();
    } catch {
      toast(tr("Impossible de révoquer la clé pour le moment", "The key cannot be revoked right now"));
    }
  };
  const copy = (v: string) =>
    navigator.clipboard?.writeText(v).then(
      () => toast(tr("Copié", "Copied")),
      () => toast(tr("Copie impossible ici", "Copying is not possible here")),
    );

  return (
    <>
      <div className="apihead">
        <p className="why" style={{ margin: 0 }}>
          {tr(
            "Une clé donne accès à cette organisation seulement, jamais à l’équipe, à la facturation ni aux comptes de test.",
            "A key reaches this organization only, never the team, billing or test accounts.",
          )}
        </p>
        <button className="btn" type="button" onClick={openCreate}>
          + {tr("Créer une clé", "Create a key")}
        </button>
      </div>

      {secret && (
        <div className="keysecret" role="status">
          <span className="okmark" aria-hidden="true">
            <Tick size={16} width={3} />
          </span>
          <div>
            <p className="mt">{tr(`Clé « ${secret.name} » créée`, `Key “${secret.name}” created`)}</p>
            <p className="md">{tr("Copiez-la maintenant : elle ne sera plus jamais affichée.", "Copy it now: it will never be shown again.")}</p>
            <div className="codebox">
              <pre>{secret.value}</pre>
              <button className="btn sm" type="button" onClick={() => void copy(secret.value)}>
                {tr("Copier", "Copy")}
              </button>
            </div>
            <button className="link" type="button" onClick={() => setSecret(null)}>
              {tr("J’ai copié la clé", "I have copied the key")}
            </button>
          </div>
        </div>
      )}

      {keys === null ? (
        <p className="hint">{tr("Chargement…", "Loading…")}</p>
      ) : keys.length === 0 ? (
        <div className="rpanel apiempty">
          <span className="keybadge" aria-hidden="true">
            <KeyIcon size={26} />
          </span>
          <h2>{tr("Aucune clé pour l’instant.", "No key yet.")}</h2>
          <p className="why">{tr("Créez une clé pour chaque outil : vous pourrez la révoquer seule si elle fuit.", "Create one key per tool: you can revoke it alone if it leaks.")}</p>
        </div>
      ) : (
        <ul className="keylist">
          {keys.map((k) => {
            const gone = !!k.revoked_at || expired(k);
            return (
              <li key={k.id} className={gone ? "gone" : ""}>
                <span className="keybadge" aria-hidden="true">
                  <KeyIcon />
                </span>
                <div className="keymain">
                  <p>
                    <b>{k.name}</b>
                    <code>{k.prefix}…</code>
                  </p>
                  <small>
                    {tr(`Créée le ${day(k.created_at)}`, `Created ${day(k.created_at)}`)}
                    {" · "}
                    {k.revoked_at
                      ? tr("révoquée", "revoked")
                      : expired(k)
                        ? tr("expirée", "expired")
                        : k.last_used_at
                          ? tr(`utilisée ${sinceText(k.last_used_at, new Date())}`, `used ${sinceText(k.last_used_at, new Date())}`)
                          : tr("jamais utilisée", "never used")}
                    {!gone && k.expires_at ? tr(` · expire le ${day(k.expires_at)}`, ` · expires ${day(k.expires_at)}`) : ""}
                  </small>
                </div>
                <span className={"scopechip" + (k.scope === "write" ? " w" : "")}>{k.scope === "write" ? tr("Lecture et écriture", "Read and write") : tr("Lecture", "Read")}</span>
                {gone ? (
                  <span className="keystate">{k.revoked_at ? tr("Révoquée", "Revoked") : tr("Expirée", "Expired")}</span>
                ) : (
                  <button className="btn ghost sm keyrevoke" type="button" onClick={() => void revoke(k)}>
                    {tr("Révoquer", "Revoke")}
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      )}

      <QuickStart orgId={org.org_id} />
      <WebhooksBlock />
    </>
  );
}
