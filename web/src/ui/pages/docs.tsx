// The public API's documentation (/docs/api): the OpenAPI document the
// server serves (GET /api/v1/openapi.json), drawn by Scalar (scalar.tsx,
// loaded on this page only). The page cannot drift from the API: the
// document is the server's, checked by TestOpenAPIMatchesTheServer. Its
// guides (authentication, errors, limits, webhooks, changelog) are the
// document's description; French texts come from its x-*-fr extensions.

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { api } from "../../api/client";
import type { OpenAPIDoc } from "../../api/types";
import { tr, useLang } from "../../i18n";
import { useBodyClass, useUI } from "../ui";
import { PubFoot, PubHead } from "./public";

const ScalarReference = lazy(() => import("./scalar"));

/** localize returns the document in French: every summary, description
 * and tag name replaced by its x-*-fr text where one exists. English is
 * the document as served. */
export function localize(doc: OpenAPIDoc, fr: boolean): OpenAPIDoc {
  if (!fr) return doc;
  const names = new Map((doc.tags ?? []).map((t) => [t.name, t["x-name-fr"] ?? t.name]));
  const walk = (v: unknown, key = ""): unknown => {
    if (Array.isArray(v)) return key === "tags" ? v.map((t) => (typeof t === "string" ? (names.get(t) ?? t) : walk(t))) : v.map((x) => walk(x));
    if (!v || typeof v !== "object") return v;
    const o = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(o)) out[k] = walk(x, k);
    if (typeof o["x-summary-fr"] === "string") out.summary = o["x-summary-fr"];
    if (typeof o["x-description-fr"] === "string") out.description = o["x-description-fr"];
    if (typeof o["x-name-fr"] === "string") out.name = o["x-name-fr"];
    return out;
  };
  return walk(doc) as OpenAPIDoc;
}

export function ApiDocsPage() {
  useBodyClass(["public", "docsbody"]);
  const { lang } = useLang();
  const { theme } = useUI();
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
  const shown = useMemo(() => (doc ? localize(doc, lang === "fr") : null), [doc, lang]);
  const loading = (
    <p className="docloading" role="status">
      <span className="spin" /> {tr("Chargement de la documentation…", "Loading the documentation…")}
    </p>
  );

  return (
    <main>
      <div className="view">
        <PubHead cur="docs" />
      </div>
      {failed && (
        <div className="view">
          <p className="err">{tr("La documentation n’a pas pu être chargée.", "The documentation could not be loaded.")}</p>
        </div>
      )}
      {shown ? (
        <Suspense fallback={loading}>
          {/* key: Scalar reads its document once; a language change draws it again. */}
          <ScalarReference key={lang} doc={shown} dark={theme === "dark"} lang={lang === "fr" ? "fr" : "en"} />
        </Suspense>
      ) : (
        !failed && loading
      )}
      <div className="view">
        <PubFoot />
      </div>
    </main>
  );
}
