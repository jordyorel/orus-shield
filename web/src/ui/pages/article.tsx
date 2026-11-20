// Long reading pages (guides, legal texts): a reading column beside a
// sticky "On this page" table of contents that follows the reading, as
// documentation and legal sites do.

import { useEffect, useState } from "react";
import { tr } from "../../i18n";

/** slug turns a heading into an anchor: "1. Qui fournit le service" ->
 * "1-qui-fournit-le-service". */
export function slug(s: string): string {
  return s
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

/** Toc lists the page's sections; the one being read is marked. */
export function Toc({ titles }: { titles: string[] }) {
  const [cur, setCur] = useState(titles[0] ? slug(titles[0]) : "");
  useEffect(() => {
    // jsdom and old browsers have no IntersectionObserver: the list still works.
    if (typeof IntersectionObserver === "undefined") return;
    const seen = new Map<string, boolean>();
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) seen.set(e.target.id, e.isIntersecting);
        const first = titles.map(slug).find((id) => seen.get(id));
        if (first) setCur(first);
      },
      { rootMargin: "-80px 0px -60% 0px" },
    );
    for (const t of titles) {
      const el = document.getElementById(slug(t));
      if (el) io.observe(el);
    }
    return () => io.disconnect();
  }, [titles.join("|")]);
  if (titles.length < 2) return null;
  return (
    <nav className="toc" aria-label={tr("Sur cette page", "On this page")}>
      <p>{tr("Sur cette page", "On this page")}</p>
      {titles.map((t) => (
        <a key={t} href={"#" + slug(t)} aria-current={cur === slug(t) ? "location" : undefined}>
          {t}
        </a>
      ))}
    </nav>
  );
}
