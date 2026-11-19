// Réglages > API > Webhooks: HTTPS endpoints that receive the
// organization's events as signed JSON POSTs (the worker delivers them,
// package webhook). Same layout as the keys: the list, a button that opens
// a side sheet, the signing secret shown once.

import { useEffect, useState } from "react";
import { api, ApiError } from "../../api/client";
import type { Webhook } from "../../api/types";
import { tr } from "../../i18n";
import { Tick } from "../icons";
import { sinceText } from "../model";
import { useOrg } from "../OrgData";
import { CloseButton } from "../sheets";
import { useUI } from "../ui";

/** EVENTS are the events an endpoint may receive, worded. */
const EVENTS: [string, () => string, () => string][] = [
  ["finding.opened", () => tr("Nouveau problème", "New problem"), () => tr("Un problème apparaît, ou revient après une correction.", "A problem appears, or comes back after a fix.")],
  ["finding.fixed", () => tr("Problème corrigé", "Problem fixed"), () => tr("Un scan ne voit plus le problème.", "A scan no longer sees the problem.")],
  ["scan.finished", () => tr("Scan terminé", "Scan finished"), () => tr("Le résumé d’un scan : score, problèmes ouverts et corrigés.", "A scan’s summary: score, problems opened and fixed.")],
];
const eventName = (e: string) => EVENTS.find(([k]) => k === e)?.[1]() ?? e;

function CreateWebhookSheet({ orgId, onCreated }: { orgId: string; onCreated: (url: string, secret: string) => void }) {
  const { closeAll } = useUI();
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<string[]>(["finding.opened"]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const toggle = (e: string) => setEvents(events.includes(e) ? events.filter((x) => x !== e) : [...events, e]);
  const create = async () => {
    if (!url.trim().startsWith("https://")) {
      setErr(tr("L’adresse doit commencer par https://", "The address must start with https://"));
      return;
    }
    if (!events.length) {
      setErr(tr("Choisissez au moins un événement.", "Choose at least one event."));
      return;
    }
    setBusy(true);
    setErr("");
    try {
      const r = await api.createWebhook(orgId, url.trim(), events);
      closeAll();
      onCreated(r.webhook.url, r.secret);
    } catch (e) {
      setErr(
        e instanceof ApiError && e.code === "bad_url"
          ? tr("Adresse refusée : https, sur un nom ou une adresse publique, sans identifiants.", "Address refused: https, on a public name or address, without credentials.")
          : e instanceof ApiError && e.code === "too_many_webhooks"
            ? tr("10 webhooks au plus : supprimez-en un d’abord.", "10 webhooks at most: remove one first.")
            : e instanceof ApiError && e.status === 503
              ? tr("Les webhooks ne sont pas encore activés sur ce serveur.", "Webhooks are not enabled on this server yet.")
              : tr("Le webhook n’a pas pu être ajouté. Réessayez.", "The webhook could not be added. Try again."),
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
      <h2 id="sheet-title">{tr("Ajouter un webhook", "Add a webhook")}</h2>
      <p className="why">{tr("Nous enverrons un POST JSON signé à cette adresse à chaque événement choisi.", "We will send a signed JSON POST to this address for every chosen event.")}</p>
      <div className="aform">
        <div className="field">
          <label htmlFor="hook-url">{tr("Adresse de réception", "Endpoint URL")}</label>
          <input id="hook-url" type="url" inputMode="url" autoFocus placeholder="https://hooks.example.com/orus" value={url} onChange={(e) => setUrl(e.target.value)} />
        </div>
        <fieldset className="keychoice">
          <legend>{tr("Événements", "Events")}</legend>
          {EVENTS.map(([k, l, d]) => (
            <label key={k} className={"keyopt" + (events.includes(k) ? " on" : "")}>
              <input type="checkbox" checked={events.includes(k)} onChange={() => toggle(k)} />
              <span>
                <b>
                  {l()} <code>{k}</code>
                </b>
                <small>{d()}</small>
              </span>
            </label>
          ))}
        </fieldset>
        <p className="err" role="alert">
          {err}
        </p>
      </div>
      <div className="actions sticky">
        <button className="btn" type="button" disabled={busy} onClick={() => void create()}>
          {busy ? <span className="spin" /> : null}
          {tr("Ajouter le webhook", "Add the webhook")}
        </button>
      </div>
    </>
  );
}

/** deliveryState words an endpoint's last delivery. */
function deliveryState(h: Webhook): [string, string] {
  if (!h.last_delivery_at) return [tr("Jamais appelé", "Never called"), "st-mute"];
  const when = sinceText(h.last_delivery_at, new Date());
  if (h.last_status && h.last_status >= 200 && h.last_status < 300) return [tr(`OK ${h.last_status} · ${when}`, `OK ${h.last_status} · ${when}`), "st-ok"];
  return [tr(`Échec${h.last_status ? " " + h.last_status : ""} · ${when}`, `Failed${h.last_status ? " " + h.last_status : ""} · ${when}`), "st-bad"];
}

export function WebhooksBlock() {
  const { org } = useOrg();
  const { toast, showSheet } = useUI();
  const [hooks, setHooks] = useState<Webhook[] | null>(null);
  const [secret, setSecret] = useState<{ url: string; value: string } | null>(null);
  const load = () =>
    api.webhooks(org.org_id).then(
      (r) => setHooks(r.items),
      () => setHooks([]),
    );
  useEffect(() => {
    void load();
  }, [org.org_id]);

  const add = () =>
    showSheet(
      <CreateWebhookSheet
        orgId={org.org_id}
        onCreated={(url, value) => {
          setSecret({ url, value });
          void load();
        }}
      />,
    );
  const test = async (h: Webhook) => {
    try {
      await api.testWebhook(org.org_id, h.id);
      toast(tr("Test envoyé : son résultat s’affiche ici dans quelques secondes", "Test sent: its result shows here in a few seconds"));
      setTimeout(() => void load(), 12000);
    } catch {
      toast(tr("Impossible d’envoyer le test pour le moment", "The test cannot be sent right now"));
    }
  };
  const remove = async (h: Webhook) => {
    if (!window.confirm(tr(`Supprimer le webhook vers ${h.url} ?`, `Remove the webhook to ${h.url}?`))) return;
    try {
      await api.deleteWebhook(org.org_id, h.id);
      toast(tr("Webhook supprimé", "Webhook removed"));
      await load();
    } catch {
      toast(tr("Impossible de supprimer le webhook pour le moment", "The webhook cannot be removed right now"));
    }
  };

  return (
    <div className="section">
      <div className="apihead">
        <div style={{ flex: "1 1 320px" }}>
          <h2 style={{ margin: 0 }}>{tr("Webhooks", "Webhooks")}</h2>
          <p className="why" style={{ margin: "4px 0 0" }}>
            {tr(
              "Recevez nos événements dans vos outils, à chaque scan : SIEM, ticketing, automatisations (Zapier, Make, n8n).",
              "Receive our events in your tools, at every scan: SIEM, ticketing, automations (Zapier, Make, n8n).",
            )}
          </p>
        </div>
        <button className="btn ghost" type="button" onClick={add}>
          + {tr("Ajouter un webhook", "Add a webhook")}
        </button>
      </div>

      {secret && (
        <div className="keysecret" role="status">
          <span className="okmark" aria-hidden="true">
            <Tick size={16} width={3} />
          </span>
          <div>
            <p className="mt">{tr("Webhook ajouté : son secret de signature", "Webhook added: its signing secret")}</p>
            <p className="md">
              {tr(
                "Gardez-le dans votre outil pour vérifier l’en-tête Orus-Signature. Il ne sera plus jamais affiché.",
                "Keep it in your tool to check the Orus-Signature header. It will never be shown again.",
              )}
            </p>
            <div className="codebox">
              <pre>{secret.value}</pre>
              <button
                className="btn sm"
                type="button"
                onClick={() =>
                  navigator.clipboard?.writeText(secret.value).then(
                    () => toast(tr("Copié", "Copied")),
                    () => toast(tr("Copie impossible ici", "Copying is not possible here")),
                  )
                }
              >
                {tr("Copier", "Copy")}
              </button>
            </div>
            <button className="link" type="button" onClick={() => setSecret(null)}>
              {tr("J’ai copié le secret", "I have copied the secret")}
            </button>
          </div>
        </div>
      )}

      {hooks && hooks.length > 0 && (
        <ul className="keylist hooklist">
          {hooks.map((h) => {
            const [state, cls] = deliveryState(h);
            return (
              <li key={h.id}>
                <span className="keybadge" aria-hidden="true">
                  ↗
                </span>
                <div className="keymain">
                  <p>
                    <code className="hookurl">{h.url}</code>
                  </p>
                  <small>{h.events.map(eventName).join(" · ")}</small>
                </div>
                <span className={"stchip " + cls} title={h.last_error ?? undefined}>
                  {state}
                </span>
                <span className="hookacts">
                  <button className="btn ghost sm" type="button" onClick={() => void test(h)}>
                    {tr("Envoyer un test", "Send a test")}
                  </button>
                  <button className="btn ghost sm keyrevoke" type="button" onClick={() => void remove(h)}>
                    {tr("Supprimer", "Remove")}
                  </button>
                </span>
              </li>
            );
          })}
        </ul>
      )}
      {hooks && hooks.length === 0 && <p className="hint">{tr("Aucun webhook pour l’instant.", "No webhook yet.")}</p>}
      <p className="md" style={{ marginTop: 10 }}>
        <a href="/docs/api#webhooks" target="_blank" rel="noopener">
          {tr("Format des événements et vérification de la signature", "Event format and signature check")}
        </a>
      </p>
    </div>
  );
}
