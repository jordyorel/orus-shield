// What every screen shares: the toast, the side sheet, the search palette
// and the theme (the mockup's toast(), showSheet(), closeAll(), openPal()).

import { createContext, Fragment, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Arrow } from "./icons";

interface UI {
  toast: (msg: string) => void;
  showSheet: (content: ReactNode) => void;
  closeAll: () => void;
  sheetOpen: boolean;
  palOpen: boolean;
  openPal: () => void;
  theme: "light" | "dark";
  setTheme: (t: "light" | "dark") => void;
}

const Ctx = createContext<UI | null>(null);

export function useUI(): UI {
  const v = useContext(Ctx);
  if (!v) throw new Error("useUI outside UIProvider");
  return v;
}

const THEME_KEY = "orus.theme";

function storedTheme(): "light" | "dark" {
  try {
    return window.localStorage.getItem(THEME_KEY) === "dark" ? "dark" : "light";
  } catch {
    return "light";
  }
}

export function UIProvider({ children }: { children: ReactNode }) {
  const [toastMsg, setToastMsg] = useState("");
  const [toastOn, setToastOn] = useState(false);
  // The sheet keeps a history: a sheet opened from another one (a problem
  // from its asset) can go back to it.
  const [stack, setStack] = useState<ReactNode[]>([]);
  const [sheetOpen, setSheetOpen] = useState(false);
  const [palOpen, setPalOpen] = useState(false);
  const [theme, setThemeState] = useState<"light" | "dark">(storedTheme);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const lastFocus = useRef<HTMLElement | null>(null);
  const sheetRef = useRef<HTMLElement>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const toast = useCallback((msg: string) => {
    setToastMsg(msg);
    setToastOn(true);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setToastOn(false), 2200);
  }, []);

  const showSheet = useCallback((content: ReactNode) => {
    const open = sheetRef.current?.classList.contains("on") ?? false;
    if (!open) lastFocus.current = document.activeElement as HTMLElement | null;
    setStack((st) => (open ? [...st, content] : [content]));
    setSheetOpen(true);
    if (sheetRef.current) sheetRef.current.scrollTop = 0;
    requestAnimationFrame(() => sheetRef.current?.querySelector<HTMLElement>("[data-close]")?.focus());
  }, []);

  const back = useCallback(() => {
    setStack((st) => (st.length > 1 ? st.slice(0, -1) : st));
    if (sheetRef.current) sheetRef.current.scrollTop = 0;
  }, []);

  const closeAll = useCallback(() => {
    setSheetOpen(false);
    setPalOpen(false);
    const f = lastFocus.current;
    if (f && document.contains(f)) f.focus();
  }, []);

  const openPal = useCallback(() => {
    lastFocus.current = document.activeElement as HTMLElement | null;
    setPalOpen(true);
  }, []);

  const setTheme = useCallback((t: "light" | "dark") => {
    setThemeState(t);
    try {
      window.localStorage.setItem(THEME_KEY, t);
    } catch {
      // Private window: the theme lasts for this page only.
    }
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeAll();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [closeAll]);

  const value = useMemo<UI>(
    () => ({ toast, showSheet, closeAll, sheetOpen, palOpen, openPal, theme, setTheme }),
    [toast, showSheet, closeAll, sheetOpen, palOpen, openPal, theme, setTheme],
  );

  return (
    <Ctx value={value}>
      {children}
      <div className={"scrim" + (sheetOpen || palOpen ? " on" : "")} onClick={closeAll} />
      <aside ref={sheetRef} className={"sheet" + (sheetOpen ? " on" : "")} role="dialog" aria-modal="true" aria-labelledby="sheet-title" aria-hidden={!sheetOpen}>
        {stack.length > 1 && (
          <button className="back" type="button" onClick={back}>
            <Arrow />
            Retour
          </button>
        )}
        <Fragment key={stack.length}>{stack[stack.length - 1]}</Fragment>
      </aside>
      <div className={"toast" + (toastOn ? " on" : "")} role="status">
        {toastMsg}
      </div>
    </Ctx>
  );
}

/** useBodyClass sets the mockup's body classes (public, focus, pay). */
export function useBodyClass(classes: string[]) {
  const key = classes.join(" ");
  useEffect(() => {
    const list = key.split(" ").filter(Boolean);
    for (const c of list) document.body.classList.add(c);
    return () => {
      for (const c of list) document.body.classList.remove(c);
    };
  }, [key]);
}

/** shake replays the mockup's error shake on a form. */
export function shake(el: HTMLElement | null) {
  if (!el) return;
  el.classList.remove("shake");
  void el.offsetWidth;
  el.classList.add("shake");
}
