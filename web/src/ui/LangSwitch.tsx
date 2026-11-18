// The FR / EN switch at the top of the public site and the sign-in pages.
//
// Signed out, the choice is kept in this browser (package i18n). Signed in,
// it is saved on the account first, as in Profil: the app applies the
// account's language on every load, so a choice kept only in the browser
// would be undone at once.

import { api } from "../api/client";
import { useAuth } from "../auth";
import { tr, useLang, type Lang } from "../i18n";
import { useUI } from "./ui";

/** useChooseLang switches the language, saving it on the account when
 * signed in. It rejects when the account could not be updated. */
export function useChooseLang(): (l: Lang) => Promise<void> {
  const { lang, setLang } = useLang();
  const { state, refresh } = useAuth();
  return async (l: Lang) => {
    if (l === lang) return;
    if (state.status === "signed-in") {
      await api.setLang(l);
      await refresh();
    }
    setLang(l);
  };
}

const LANGS: [Lang, string, string][] = [
  ["fr", "FR", "Français"],
  ["en", "EN", "English"],
];

export function LangSwitch() {
  const { lang } = useLang();
  const choose = useChooseLang();
  const { toast } = useUI();
  return (
    <div className="seg2 langsw" role="group" aria-label={tr("Langue", "Language")}>
      {LANGS.map(([k, short, name]) => (
        <button
          key={k}
          type="button"
          lang={k}
          aria-label={name}
          aria-pressed={lang === k}
          onClick={() => choose(k).catch(() => toast(tr("Langue non enregistrée, réessayez", "Language not saved, try again")))}
        >
          {short}
        </button>
      ))}
    </div>
  );
}
