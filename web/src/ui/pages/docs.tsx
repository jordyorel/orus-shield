// The public API's documentation (/docs/api), rendered from the OpenAPI
// document the server serves (GET /api/v1/openapi.json): the page cannot
// drift from the API it describes. French texts come from the document's
// x-*-fr extensions; English from its standard fields.

import { Fragment, useEffect, useState, type ReactNode } from "react";
import { api } from "../../api/client";
import type { OpenAPIDoc, OpenAPIOperation, OpenAPISchema } from "../../api/types";
import { tr, useLang } from "../../i18n";
import { Link } from "../../router";
import { useBodyClass } from "../ui";
import { PubFoot, PubHead } from "./public";

/** inline renders `code` and **bold** of the document's descriptions. */
function inline(text: string): ReactNode[] {
  return text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).map((part, i) =>
    part.startsWith("`") ? <code key={i}>{part.slice(1, -1)}</code> : part.startsWith("**") ? <b key={i}>{part.slice(2, -2)}</b> : <Fragment key={i}>{part}</Fragment>,
  );
}

function paragraphs(text: string | undefined): ReactNode {
  return (text ?? "").split(/\n\n+/).map((p, i) => <p key={i}>{inline(p)}</p>);
}

const refName = (s?: OpenAPISchema) => (s?.$ref ? s.$ref.split("/").at(-1) : undefined);

/** typeOf words a schema briefly: "string", "Finding", "list of Finding". */
function typeOf(s: OpenAPISchema | undefined): ReactNode {
  if (!s) return "";
  const r = refName(s);
  if (r) return <a href={"#schema-" + r}>{r}</a>;
  if (s.properties?.items?.type === "array") {
    const inner = refName(s.properties.items.items);
    return <>{tr("liste de ", "list of ")}{inner ? <a href={"#schema-" + inner}>{inner}</a> : "objets"}</>;
  }
  if (s.type === "array") return <>{tr("liste de ", "list of ")}{typeOf(s.items)}</>;
  const t = Array.isArray(s.type) ? s.type.filter((x) => x !== "null").join(" | ") + (s.type.includes("null") ? " | null" : "") : (s.type ?? "object");
  return s.enum ? `${t} (${s.enum.join(", ")})` : s.format ? `${t}, ${s.format}` : t;
}

function opId(path: string, method: string) {
  return (method + path).replace(/[^a-z0-9]+/gi, "-").toLowerCase();
}

function Operation({ path, method, op, fr }: { path: string; method: string; op: OpenAPIOperation; fr: boolean }) {
  const params = op.parameters ?? [];
  const body = op.requestBody?.content["application/json"];
  const query = params.filter((p) => p.in === "query" && p.name === "kind").length ? "?kind=executive&lang=fr" : "";
  const curl =
    `curl ${method === "get" ? "" : `-X ${method.toUpperCase()} `}-H "Authorization: Bearer $ORUS_API_KEY" \\\n` +
    (body?.example ? `  -H "Content-Type: application/json" -d '${JSON.stringify(body.example)}' \\\n` : "") +
    `  "${typeof window !== "undefined" ? window.location.origin : ""}/api/v1${path}${query}"`;
  return (
    <section className="rpanel docop" id={opId(path, method)}>
      <div className="docophead">
        <span className={"verb v-" + method}>{method.toUpperCase()}</span>
        <code>{path}</code>
        <span className={"scopechip" + (op["x-scope"] === "write" ? " w" : "")}>{op["x-scope"] === "write" ? tr("Clé écriture", "Write key") : tr("Clé lecture", "Read key")}</span>
      </div>
      <h3>{fr ? op["x-summary-fr"] : op.summary}</h3>
      <div className="docdesc">{paragraphs(fr ? op["x-description-fr"] : op.description)}</div>
      {params.length > 0 && (
        <>
          <h4>{tr("Paramètres", "Parameters")}</h4>
          <table className="doctable">
            <tbody>
              {params.map((p) => (
                <tr key={p.in + p.name}>
                  <th scope="row">
                    <code>{p.name}</code>
                    <small>{p.in === "path" ? tr("chemin", "path") : tr("requête", "query")}{p.required ? tr(", requis", ", required") : ""}</small>
                  </th>
                  <td>{typeOf(p.schema)}</td>
                  <td>{fr ? p["x-description-fr"] : p.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {body && (
        <>
          <h4>{tr("Corps de la requête", "Request body")}</h4>
          <pre className="guidecode">{JSON.stringify(body.example ?? {}, null, 2)}</pre>
        </>
      )}
      <h4>{tr("Réponses", "Responses")}</h4>
      <ul className="docresp">
        {Object.entries(op.responses).map(([code, r]) => {
          const schema = r.content?.["application/json"]?.schema;
          return (
            <li key={code}>
              <span className={"rcode c" + code[0]}>{code}</span>
              <span>
                {r.description}
                {schema && code.startsWith("2") ? <> · {typeOf(schema)}</> : null}
              </span>
            </li>
          );
        })}
      </ul>
      <h4>{tr("Exemple", "Example")}</h4>
      <div className="codebox">
        <pre>{curl}</pre>
      </div>
    </section>
  );
}

export function ApiDocsPage() {
  useBodyClass(["public"]);
  const { lang } = useLang();
  const fr = lang === "fr";
  const [doc, setDoc] = useState<OpenAPIDoc | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const ac = new AbortController();
    // A request cancelled on purpose (page left, or React's double effect
    // in development) is not a failure.
    api.openapi(ac.signal).then(setDoc, () => {
      if (!ac.signal.aborted) setFailed(true);
    });
    return () => ac.abort();
  }, []);
  useEffect(() => {
    const prev = document.title;
    document.title = tr("Documentation de l’API · Orus Shield", "API documentation · Orus Shield");
    return () => {
      document.title = prev;
    };
  }, [lang]);

  const ops = doc
    ? Object.entries(doc.paths).flatMap(([path, methods]) => Object.entries(methods).map(([method, op]) => ({ path, method, op })))
    : [];
  const tags = doc?.tags ?? [];

  return (
    <main>
      <div className="view">
        <PubHead cur="docs" />
        <section className="phead">
          <h1>{tr("Documentation de l’API", "API documentation")}</h1>
          <p className="herosub">
            {tr("Pour connecter vos outils à Orus Shield. Le document OpenAPI complet : ", "To connect your tools to Orus Shield. The full OpenAPI document: ")}
            <a href="/api/v1/openapi.json">openapi.json</a>.
          </p>
        </section>
        {failed && <p className="err">{tr("La documentation n’a pas pu être chargée.", "The documentation could not be loaded.")}</p>}
        {doc && (
          <div className="doclayout">
            <nav className="docnav" aria-label={tr("Opérations", "Operations")}>
              <a href="#intro">{tr("Introduction", "Introduction")}</a>
              {tags.map((t) => (
                <Fragment key={t.name}>
                  <p>{fr ? t["x-name-fr"] : t.name}</p>
                  {ops
                    .filter((o) => o.op.tags?.includes(t.name))
                    .map((o) => (
                      <a key={o.method + o.path} href={"#" + opId(o.path, o.method)}>
                        <span className={"verb v-" + o.method}>{o.method.toUpperCase()}</span>
                        {fr ? o.op["x-summary-fr"] : o.op.summary}
                      </a>
                    ))}
                </Fragment>
              ))}
              <a href="#schemas">{tr("Objets", "Objects")}</a>
            </nav>
            <div className="docmain">
              <section className="docintro" id="intro">
                {paragraphs(fr ? doc.info["x-description-fr"] : doc.info.description)}
                <p>
                  {tr("Créez une clé dans ", "Create a key in ")}
                  <Link to="/app">{tr("Réglages > API", "Settings > API")}</Link>
                  {tr(" de votre tableau de bord.", " of your dashboard.")}
                </p>
              </section>
              {tags.map((t) => (
                <Fragment key={t.name}>
                  <h2>{fr ? t["x-name-fr"] : t.name}</h2>
                  {ops
                    .filter((o) => o.op.tags?.includes(t.name))
                    .map((o) => (
                      <Operation key={o.method + o.path} path={o.path} method={o.method} op={o.op} fr={fr} />
                    ))}
                </Fragment>
              ))}
              <h2 id="schemas">{tr("Objets", "Objects")}</h2>
              {Object.entries(doc.components?.schemas ?? {}).map(([name, s]) => (
                <section key={name} className="rpanel docop" id={"schema-" + name}>
                  <h3>
                    <code>{name}</code>
                  </h3>
                  {s.description && <div className="docdesc">{paragraphs(s.description)}</div>}
                  {s.properties ? (
                    <table className="doctable">
                      <tbody>
                        {Object.entries(s.properties).map(([p, ps]) => (
                          <tr key={p}>
                            <th scope="row">
                              <code>{p}</code>
                            </th>
                            <td>{typeOf(ps)}</td>
                            <td>{ps.description ? inline(ps.description) : ""}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p className="md">{typeOf(s)}</p>
                  )}
                </section>
              ))}
            </div>
          </div>
        )}
        <PubFoot />
      </div>
    </main>
  );
}
