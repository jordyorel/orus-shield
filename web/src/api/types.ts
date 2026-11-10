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

export type FindingStatus = "open" | "fixed" | "accepted_risk";

/** orgFinding: a finding in the standard schema (engine/internal/finding) with its target's ID. */
export interface Finding {
  target_id: string;
  schema_version: string;
  id: string;
  module_id: string;
  check_id: string;
  /** The registered domain, e.g. "example.com". */
  target: string;
  /** What was checked, e.g. "_dmarc.example.com". */
  asset: string;
  severity: Severity;
  title: string;
  description: string;
  /** Raw technical proof. */
  evidence: string;
  /** Ordered remediation steps. */
  remediation: string[] | null;
  references: string[] | null;
  first_seen: string;
  last_seen: string;
  status: FindingStatus;
  fixed_at?: string;
}

export interface List<T> {
  items: T[];
}

export type ScanStatus = "queued" | "running" | "done" | "failed";

/** scanJSON */
export interface Scan {
  id: string;
  target_id: string;
  domain: string;
  modules: string[];
  requested_by: string;
  status: ScanStatus;
  attempts: number;
  error?: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  /** Findings this scan opened and fixed (finished scans, in lists only). */
  new_findings?: number;
  fixed_findings?: number;
}

/** moduleJSON */
export interface ModuleInfo {
  id: string;
  name: string;
  /** active modules run on verified targets only. */
  kind: "passive" | "active" | "";
  checks: number;
}

/** targetJSON */
export interface Target {
  id: string;
  domain: string;
  verified: boolean;
  verified_at: string | null;
  verify_checked_at: string | null;
  rate_per_sec: number;
  exclusions: unknown;
  created_at: string;
}

/** instructionsJSON: the DNS record that proves ownership. */
export interface Instructions {
  domain: string;
  record_name: string;
  record_type: "TXT";
  record_value: string;
  expires_at: string | null;
  verified: boolean;
}

/** memberJSON */
export interface Member {
  user_id: string;
  email: string;
  role: Role;
  /** A password is set. */
  activated: boolean;
  mfa_enabled: boolean;
}

/** invitationJSON: setup_token is shown once, absent for an activated account. */
export interface Invitation {
  member: Member;
  setup_token?: string;
}

/** orgAssetJSON */
export interface OrgAsset {
  target_id: string;
  domain: string;
  id: string;
  kind: "hostname" | "ip" | "service" | "certificate";
  value: string;
  details: Record<string, string>;
  sources: string[];
  first_seen: string;
  last_seen: string;
  gone_at: string | null;
}

export type Category = "email" | "web" | "tls" | "dns" | "network" | "identity" | "cloud" | "leaks";

/** checkJSON */
export interface Check {
  target_id?: string;
  id: string;
  title: string;
  module: string;
  category: Category;
  severity: Severity;
  status: "passed" | "failed" | "not_applicable";
  findings: number;
  evaluated_at: string;
}

/** monthJSON */
export interface Month {
  month: string;
  opened: number;
  fixed: number;
}
