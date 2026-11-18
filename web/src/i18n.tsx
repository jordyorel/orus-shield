// The dashboard speaks French and English. Every text is written in both,
// side by side, with tr("Problèmes", "Problems"): no key files to keep in
// step, and a text cannot exist in one language only.
//
// The language is the user's choice (Profil, or the switch of the public
// site), kept on their account once signed in; before that, the choice
// made in this browser, else the browser's language (French unless it is
// English: the product is French-first). Changing it re-renders the whole
// interface in the other language.

import { createContext, Fragment, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

export type Lang = "fr" | "en";

const KEY = "orus.lang";

function initial(): Lang {
  try {
    const v = window.localStorage.getItem(KEY);
    if (v === "fr" || v === "en") return v;
  } catch {
    // Private window or blocked storage: the browser's language decides.
  }
  return typeof navigator !== "undefined" && navigator.language?.toLowerCase().startsWith("en") ? "en" : "fr";
}

let current: Lang = initial();

/** tr picks the text in the current language. */
export function tr(fr: string, en: string): string {
  return current === "en" ? en : fr;
}

/** getLang is the current language, for code outside components. */
export function getLang(): Lang {
  return current;
}

/** locale is the current language's locale, for dates and numbers. */
export function locale(): string {
  return current === "en" ? "en-GB" : "fr-FR";
}

interface LangCtx {
  lang: Lang;
  setLang: (l: Lang) => void;
}

const Ctx = createContext<LangCtx>({ lang: current, setLang: () => undefined });

export function useLang(): LangCtx {
  return useContext(Ctx);
}

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, set] = useState<Lang>(current);
  const setLang = useCallback((l: Lang) => {
    if (l === current) return;
    current = l;
    try {
      window.localStorage.setItem(KEY, l);
    } catch {
      // Kept for this page only.
    }
    document.documentElement.lang = l;
    set(l);
  }, []);
  const value = useMemo(() => ({ lang, setLang }), [lang, setLang]);
  document.documentElement.lang = lang;
  return <Ctx value={value}>{children}</Ctx>;
}

/** Relang re-renders its subtree from scratch when the language changes,
 * so every text, including those computed once, is in the new language. */
export function Relang({ children }: { children: ReactNode }) {
  return <Fragment key={useLang().lang}>{children}</Fragment>;
}

/** setLangForTests switches the language outside React (tests). */
export function setLangForTests(l: Lang) {
  current = l;
}

/** labeled is a [key, label] pair whose label follows the current language,
 * for lists of options defined once (tabs, filters). */
export function labeled<K>(k: K, fr: string, en: string): [K, string] {
  const t: [K, string] = [k, ""];
  Object.defineProperty(t, 1, { get: () => tr(fr, en), enumerable: true });
  return t;
}
