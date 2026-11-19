// The API reference drawn by Scalar (MIT, @scalar/api-reference-react),
// loaded on /docs/api only (React.lazy in docs.tsx): it is a large bundle
// that the rest of the site never downloads.
//
// Why a dependency: a good API reference is search, a sidebar that follows
// the reading, request and response examples in several languages, schema
// trees, and a "try it" console. Writing that by hand is weeks of work that
// Scalar does well; it runs entirely on our origin, from our own build.
//
// Everything that would reach a third party is switched off: no telemetry,
// no fonts from fonts.scalar.com (our own fonts apply), no proxy (a request
// tried from the console goes straight to our API, same origin), no MCP or
// agent features, no developer tools. Its look follows our tokens
// (styles.css, .docscalar).

import { ApiReferenceReact } from "@scalar/api-reference-react";
import "@scalar/api-reference-react/style.css";
import { useMemo } from "react";
import type { OpenAPIDoc } from "../../api/types";

export default function ScalarReference({ doc, dark, lang }: { doc: OpenAPIDoc; dark: boolean; lang: "fr" | "en" }) {
  const configuration = useMemo(
    () => ({
      content: doc,
      theme: "none" as const,
      layout: "modern" as const,
      forceDarkModeState: dark ? ("dark" as const) : ("light" as const),
      hideDarkModeToggle: true,
      withDefaultFonts: false,
      telemetry: false,
      showDeveloperTools: "never" as const,
      mcp: { disabled: true },
      agent: { disabled: true },
      persistAuth: false,
      documentDownloadType: "json" as const,
      defaultOpenAllTags: true,
      hideClientButton: false,
      // Scalar's own labels (Headers, Body, required…) in the page's language.
      localization: { locale: lang },
      authentication: { preferredSecurityScheme: "apiKey" },
    }),
    [doc, dark, lang],
  );
  return (
    <div className="docscalar">
      <ApiReferenceReact configuration={configuration} />
    </div>
  );
}
