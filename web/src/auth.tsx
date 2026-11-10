// The signed-in user, loaded once from GET /auth/me and shared by every
// screen. The session itself is an HttpOnly cookie: JavaScript never sees
// it, so a script injected in the page could not steal it.

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, ApiError } from "./api/client";
import type { Me } from "./api/types";

export type AuthState = { status: "loading" } | { status: "signed-out" } | { status: "signed-in"; me: Me };

interface AuthContextValue {
  state: AuthState;
  /** signedIn records the user returned by a login. */
  signedIn: (me: Me) => void;
  /** refresh reloads the user (after MFA enrolment upgraded the session). */
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: "loading" });

  const refresh = useCallback(async () => {
    try {
      setState({ status: "signed-in", me: await api.me() });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setState({ status: "signed-out" });
      else throw e;
    }
  }, []);

  useEffect(() => {
    refresh().catch(() => setState({ status: "signed-out" }));
  }, [refresh]);

  const value = useMemo<AuthContextValue>(
    () => ({
      state,
      signedIn: (me) => setState({ status: "signed-in", me }),
      refresh,
      signOut: async () => {
        try {
          await api.logout();
        } finally {
          setState({ status: "signed-out" });
        }
      },
    }),
    [state, refresh],
  );
  return <AuthContext value={value}>{children}</AuthContext>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}

/**
 * needsMfa: an admin whose session has no second factor. The API refuses
 * them every organization route (403 mfa_required); the app sends them to
 * enrolment first.
 */
export function needsMfa(me: Me): boolean {
  return !me.mfa_session && me.orgs.some((o) => o.role === "admin");
}
