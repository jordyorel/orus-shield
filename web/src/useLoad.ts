import { useEffect, useState } from "react";
import { ApiError } from "./api/client";
import { fallback } from "./pages/messages";
import { navigate } from "./router";

/**
 * useLoad runs load once per key and returns its data or a French error
 * message. An admin without a second factor is sent to enrolment.
 */
export function useLoad<T>(load: (signal: AbortSignal) => Promise<T>, key: string): { data: T | null; error: string } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const ctrl = new AbortController();
    load(ctrl.signal)
      .then((d) => {
        setData(d);
        setError("");
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        if (err instanceof ApiError && err.code === "mfa_required") navigate("/mfa/setup?reason=admin", { replace: true });
        else setError(fallback(err));
      });
    return () => ctrl.abort();
    // load changes identity on every render; key says when to reload.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return { data, error };
}
