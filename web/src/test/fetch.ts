import { vi } from "vitest";

/** A route answers a request: status and JSON body (undefined for 204). */
export type Route = (body: unknown) => { status: number; json?: unknown };

/**
 * mockApi replaces fetch with routes keyed by "METHOD /path" (without the
 * /api/v1 prefix). Unknown routes fail the test loudly. Returns the list of
 * calls, to assert what was sent.
 */
export function mockApi(routes: Record<string, Route>) {
  const calls: { key: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const key = `${init?.method ?? "GET"} ${input.replace(/^\/api\/v1/, "")}`;
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ key, body });
      const route = routes[key];
      if (!route) throw new Error("unexpected request " + key);
      const { status, json } = route(body);
      return new Response(status === 204 ? null : JSON.stringify(json ?? {}), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  return calls;
}

export const ok = (json: unknown): Route => () => ({ status: 200, json });
export const fail = (status: number, error = "error", code?: string): Route => () => ({ status, json: { error, code } });
