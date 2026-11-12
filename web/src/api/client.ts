import type { Activity, DeclaredAPI, TestAccount, AuthActivity, Check, DeviceSession, Finding, FindingStatus, Instructions, Invitation, List, Me, Member, MfaChallenge, MfaSetup, ModuleInfo, Month, OrgAsset, OrgSettings, Overview, Plan, RecoveryCodes, Role, Scan, ScheduleInput, Subscription, Target } from "./types";
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
  forgotPassword: (email: string) => request<void>("POST", "/auth/forgot-password", { email }),
  signup: (email: string, organization: string) => request<void>("POST", "/auth/signup", { email, organization }),
  completeSignup: (token: string, password: string) => request<void>("POST", "/auth/signup/complete", { token, password }),
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
    request<{ setup_token: string; emailed: boolean }>("POST", `${org(orgId)}/members/${encodeURIComponent(userId)}/setup-token`),
  orgAssets: (orgId: string, signal?: AbortSignal) => request<List<OrgAsset>>("GET", `${org(orgId)}/assets`, undefined, signal),
  checks: (orgId: string, signal?: AbortSignal) => request<List<Check>>("GET", `${org(orgId)}/checks`, undefined, signal),
  trends: (orgId: string, months: number, signal?: AbortSignal) =>
    request<List<Month>>("GET", `${org(orgId)}/trends?months=${months}`, undefined, signal),
  overview: (orgId: string, days: number, signal?: AbortSignal) =>
    request<Overview>("GET", `${org(orgId)}/overview?days=${days}`, undefined, signal),
  findings: (orgId: string, signal?: AbortSignal) => request<List<Finding>>("GET", `${org(orgId)}/findings`, undefined, signal),
  /** setFindingStatus: fixed (the API queues a verification scan), accepted_risk, or open to withdraw either. */
  setFindingStatus: (orgId: string, targetId: string, findingId: string, status: FindingStatus) =>
    request<void>(
      "PUT",
      `${org(orgId)}/targets/${encodeURIComponent(targetId)}/findings/${encodeURIComponent(findingId)}/status`,
      { status },
    ),
  startScan: (orgId: string, targetId: string, modules?: string[]) =>
    request<Scan>("POST", `${org(orgId)}/targets/${encodeURIComponent(targetId)}/scans`, modules ? { modules } : {}),
  targets: (orgId: string, signal?: AbortSignal) => request<List<Target>>("GET", `${org(orgId)}/targets`, undefined, signal),
  updateTarget: (orgId: string, targetId: string, settings: { rate_per_sec?: number; exclusions?: Exclusions; schedule?: ScheduleInput | null }) =>
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
  plans: (signal?: AbortSignal) => request<List<Plan>>("GET", "/plans", undefined, signal),
  subscription: (orgId: string, signal?: AbortSignal) => request<Subscription>("GET", `${org(orgId)}/subscription`, undefined, signal),
  settings: (orgId: string, signal?: AbortSignal) => request<OrgSettings>("GET", `${org(orgId)}/settings`, undefined, signal),
  saveSettings: (orgId: string, s: OrgSettings) => request<OrgSettings>("PUT", `${org(orgId)}/settings`, s),
  activity: (orgId: string, signal?: AbortSignal) => request<List<Activity>>("GET", `${org(orgId)}/activity?days=7&limit=10`, undefined, signal),
  updateMe: (name: string) => request<Me>("PATCH", "/auth/me", { name }),
  sessions: (signal?: AbortSignal) => request<List<DeviceSession>>("GET", "/auth/sessions", undefined, signal),
  endSession: (id: string) => request<void>("DELETE", `/auth/sessions/${encodeURIComponent(id)}`),
  authActivity: (signal?: AbortSignal) => request<List<AuthActivity>>("GET", "/auth/activity", undefined, signal),
  apis: (orgId: string, targetId: string, signal?: AbortSignal) =>
    request<List<DeclaredAPI>>("GET", `${org(orgId)}/targets/${encodeURIComponent(targetId)}/apis`, undefined, signal),
  createAPI: (orgId: string, targetId: string, a: { name: string; kind: string; base_url: string; spec_url?: string; spec?: string }) =>
    request<DeclaredAPI>("POST", `${org(orgId)}/targets/${encodeURIComponent(targetId)}/apis`, a),
  testAccount: (orgId: string, targetId: string, signal?: AbortSignal) =>
    request<TestAccount>("GET", `${org(orgId)}/targets/${encodeURIComponent(targetId)}/credential`, undefined, signal),
  setTestAccount: (
    orgId: string,
    targetId: string,
    a: { kind: "header" | "form"; header_name?: string; header_value?: string; login_url?: string; username?: string; password?: string; username_field?: string; password_field?: string; consent: boolean },
  ) => request<TestAccount>("PUT", `${org(orgId)}/targets/${encodeURIComponent(targetId)}/credential`, a),
  deleteTestAccount: (orgId: string, targetId: string) =>
    request<void>("DELETE", `${org(orgId)}/targets/${encodeURIComponent(targetId)}/credential`),
  deleteAPI: (orgId: string, targetId: string, id: string) =>
    request<void>("DELETE", `${org(orgId)}/targets/${encodeURIComponent(targetId)}/apis/${encodeURIComponent(id)}`),
};

/** The URL of an organization's PDF report: the API builds it on demand, the browser downloads it. */
export function reportURL(orgId: string, kind: "executive" | "technical", lang: "fr" | "en"): string {
  return `/api/v1/orgs/${encodeURIComponent(orgId)}/report?kind=${kind}&lang=${lang}`;
}
