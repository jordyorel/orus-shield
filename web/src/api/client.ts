import type { Finding, FindingStatus, Instructions, Invitation, List, Me, Member, MfaChallenge, MfaSetup, ModuleInfo, Overview, RecoveryCodes, Role, Scan, Target } from "./types";
import type { Exclusions } from "../exclusions";

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
  changePassword: (current_password: string, new_password: string) =>
    request<void>("POST", "/auth/password", { current_password, new_password }),
  mfaDisable: (password: string, code: string) => request<void>("POST", "/auth/mfa/disable", { password, code }),
  members: (orgId: string, signal?: AbortSignal) => request<List<Member>>("GET", `${org(orgId)}/members`, undefined, signal),
  invite: (orgId: string, email: string, role: Role) => request<Invitation>("POST", `${org(orgId)}/members`, { email, role }),
  setMemberRole: (orgId: string, userId: string, role: Role) =>
    request<void>("PUT", `${org(orgId)}/members/${encodeURIComponent(userId)}/role`, { role }),
  removeMember: (orgId: string, userId: string) => request<void>("DELETE", `${org(orgId)}/members/${encodeURIComponent(userId)}`),
  newSetupToken: (orgId: string, userId: string) =>
    request<{ setup_token: string }>("POST", `${org(orgId)}/members/${encodeURIComponent(userId)}/setup-token`),
  overview: (orgId: string, days: number, signal?: AbortSignal) =>
    request<Overview>("GET", `${org(orgId)}/overview?days=${days}`, undefined, signal),
  findings: (orgId: string, signal?: AbortSignal) => request<List<Finding>>("GET", `${org(orgId)}/findings`, undefined, signal),
  /** setFindingStatus: accepted_risk, or open to withdraw it. "fixed" is decided by scans only. */
  setFindingStatus: (orgId: string, targetId: string, findingId: string, status: Exclude<FindingStatus, "fixed">) =>
    request<void>(
      "PUT",
      `${org(orgId)}/targets/${encodeURIComponent(targetId)}/findings/${encodeURIComponent(findingId)}/status`,
      { status },
    ),
  startScan: (orgId: string, targetId: string, modules?: string[]) =>
    request<Scan>("POST", `${org(orgId)}/targets/${encodeURIComponent(targetId)}/scans`, modules ? { modules } : {}),
  targets: (orgId: string, signal?: AbortSignal) => request<List<Target>>("GET", `${org(orgId)}/targets`, undefined, signal),
  updateTarget: (orgId: string, targetId: string, settings: { rate_per_sec?: number; exclusions?: Exclusions }) =>
    request<Target>("PATCH", `${org(orgId)}/targets/${encodeURIComponent(targetId)}`, settings),
  modules: (orgId: string, signal?: AbortSignal) => request<List<ModuleInfo>>("GET", `${org(orgId)}/modules`, undefined, signal),
  scans: (orgId: string, signal?: AbortSignal) => request<List<Scan>>("GET", `${org(orgId)}/scans?limit=20`, undefined, signal),
  createTarget: (orgId: string, domain: string) => request<Target>("POST", `${org(orgId)}/targets`, { domain }),
  /** verificationInstructions issues a token if needed: it is a POST. */
  verificationInstructions: (orgId: string, targetId: string) =>
    request<Instructions>("POST", `${org(orgId)}/targets/${encodeURIComponent(targetId)}/verification`),
  verifyTarget: (orgId: string, targetId: string) =>
    request<Target>("POST", `${org(orgId)}/targets/${encodeURIComponent(targetId)}/verify`),
  scan: (orgId: string, scanId: string, signal?: AbortSignal) =>
    request<Scan>("GET", `${org(orgId)}/scans/${encodeURIComponent(scanId)}`, undefined, signal),
};
