import type { Me, MfaChallenge, MfaSetup, Overview, RecoveryCodes } from "./types";

/**
 * An error answered by the API. message is the API's English text, for
 * logs only: pages show their own French wording, chosen from status and
 * code.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(status: number, code: string | undefined, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const init: RequestInit = { method, credentials: "same-origin" };
  if (signal) init.signal = signal;
  if (body !== undefined) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const res = await fetch("/api/v1" + path, init);
  if (res.status === 204) return undefined as T;
  const isJSON = (res.headers.get("Content-Type") ?? "").startsWith("application/json");
  const data: unknown = isJSON ? await res.json() : null;
  if (!res.ok) {
    const e = (data ?? {}) as { error?: string; code?: string };
    throw new ApiError(res.status, e.code, e.error ?? `HTTP ${res.status}`);
  }
  return data as T;
}

/** Login answers either the user (session opened) or an MFA challenge. */
export function isMfaChallenge(r: Me | MfaChallenge): r is MfaChallenge {
  return "mfa_required" in r && r.mfa_required;
}

const org = (id: string) => "/orgs/" + encodeURIComponent(id);

export const api = {
  me: (signal?: AbortSignal) => request<Me>("GET", "/auth/me", undefined, signal),
  login: (email: string, password: string) => request<Me | MfaChallenge>("POST", "/auth/login", { email, password }),
  loginMfa: (mfa_token: string, code: string) => request<Me>("POST", "/auth/login/mfa", { mfa_token, code }),
  logout: () => request<void>("POST", "/auth/logout"),
  setupPassword: (token: string, password: string) => request<void>("POST", "/auth/setup-password", { token, password }),
  mfaSetup: (password: string) => request<MfaSetup>("POST", "/auth/mfa/setup", { password }),
  mfaConfirm: (code: string) => request<RecoveryCodes>("POST", "/auth/mfa/confirm", { code }),
  overview: (orgId: string, days: number, signal?: AbortSignal) =>
    request<Overview>("GET", `${org(orgId)}/overview?days=${days}`, undefined, signal),
};
