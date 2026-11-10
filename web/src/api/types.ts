// Shapes of the engine's JSON API (engine/internal/api). Keep in sync with
// the Go structs named in each comment.

export type Role = "admin" | "viewer";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** membershipJSON */
export interface Membership {
  org_id: string;
  org_name: string;
  role: Role;
}

/** meResponse: the signed-in user. */
export interface Me {
  user_id: string;
  email: string;
  /** The user has a confirmed second factor. */
  mfa_enabled: boolean;
  /** This session was opened with it. Admins need it for their organizations. */
  mfa_session: boolean;
  orgs: Membership[];
}

/** mfaChallengeResponse: correct password, a code is expected next. */
export interface MfaChallenge {
  mfa_required: true;
  mfa_token: string;
}

/** mfaSetupResponse */
export interface MfaSetup {
  secret: string;
  otpauth_uri: string;
}

/** recoveryCodesResponse */
export interface RecoveryCodes {
  recovery_codes: string[];
}

/** overviewTarget */
export interface OverviewTarget {
  id: string;
  domain: string;
  verified: boolean;
  last_scan_at: string | null;
  stale: boolean;
  open_findings: Partial<Record<Severity, number>>;
  posture_score: number | null;
  current_assets: number;
}

/** trendPoint */
export interface TrendPoint {
  at: string;
  score: number | null;
}

/** remediationJSON: means in seconds, null without fixes. */
export interface Remediation {
  fixed: number;
  mean_seconds: number | null;
  previous_fixed: number;
  previous_mean_seconds: number | null;
}

/** priorityJSON: which rule produced it, and the facts to write it. */
export type Priority =
  | {
      kind: "finding";
      target_id: string;
      domain: string;
      finding_id: string;
      severity: Severity;
      title: string;
      asset: string;
      first_seen: string;
    }
  | { kind: "verify_target"; target_id: string; domain: string }
  | { kind: "scan_target"; target_id: string; domain: string; last_scan_at?: string };

/** overviewJSON */
export interface Overview {
  days: number;
  targets: number;
  verified_targets: number;
  open_findings: Partial<Record<Severity, number>>;
  assets: number;
  new_assets: number;
  score: number | null;
  score_change: number | null;
  trend: TrendPoint[];
  remediation: Remediation;
  priorities: Priority[];
  per_target: OverviewTarget[];
}
