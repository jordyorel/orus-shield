// A small router on the History API: about ten screens do not need a
// routing library. Paths are matched with :name segments.

import { useEffect, useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent } from "react";

const listeners = new Set<() => void>();

function subscribe(onChange: () => void): () => void {
  listeners.add(onChange);
  window.addEventListener("popstate", onChange);
  return () => {
    listeners.delete(onChange);
    window.removeEventListener("popstate", onChange);
  };
}

/** navigate changes the URL without reloading and re-renders the app. */
export function navigate(to: string, options: { replace?: boolean } = {}): void {
  if (options.replace) window.history.replaceState(null, "", to);
  else window.history.pushState(null, "", to);
  document.documentElement.scrollTop = 0;
  for (const l of listeners) l();
}

const currentPath = () => window.location.pathname;
const currentSearch = () => window.location.search;

/** useLocation re-renders on every navigation. */
export function useLocation(): { path: string; search: URLSearchParams } {
  const path = useSyncExternalStore(subscribe, currentPath);
  const search = useSyncExternalStore(subscribe, currentSearch);
  return { path, search: new URLSearchParams(search) };
}

/**
 * match returns the parameters of path for pattern ("/orgs/:org"), or null.
 * Parameters are decoded; a malformed escape does not match.
 */
export function match(pattern: string, path: string): Record<string, string> | null {
  const want = pattern.split("/");
  const got = path.replace(/\/+$/, "").split("/");
  if (path === "/") got.splice(1, 1, "");
  if (want.length !== got.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < want.length; i++) {
    const w = want[i] ?? "";
    const g = got[i] ?? "";
    if (w.startsWith(":")) {
      if (g === "") return null;
      try {
        params[w.slice(1)] = decodeURIComponent(g);
      } catch {
        return null;
      }
    } else if (w !== g) {
      return null;
    }
  }
  return params;
}

type LinkProps = AnchorHTMLAttributes<HTMLAnchorElement> & { to: string };

/** Link is an <a> that navigates without reloading on a plain left click. */
export function Link({ to, onClick, ...rest }: LinkProps) {
  const click = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e);
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    navigate(to);
  };
  return <a href={to} onClick={click} {...rest} />;
}

/** Redirect replaces the current URL once rendered. */
export function Redirect({ to }: { to: string }) {
  useEffect(() => navigate(to, { replace: true }), [to]);
  return null;
}
