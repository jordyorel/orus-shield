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
  /** Display name, "" until the user sets one in Profil. */
  name: string;
  password_changed_at: string | null;
  recovery_codes_left: number;
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
  /** Computed by the API for the dashboard (findingExtras). */
  category?: Category;
  /** Estimated minutes to fix. */
  minutes: number;
  /** Points the target's score wins once fixed (open findings only). */
  gain: number;
  /** From a recent CVE template matched to a detected technology. */
  emerging: boolean;
  cve?: CVE;
}

/** cveJSON */
export interface CVE {
  id?: string;
  name?: string;
  cvss?: number;
  epss?: number;
  kev: boolean;
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
  /** null: scanned on demand only. */
  schedule: Schedule | null;
  /** An agent's internal network, not a domain. */
  internal?: boolean;
}

export type Frequency = "daily" | "weekly" | "monthly";

/** scheduleJSON: when a target is scanned. weekday: 0 is Sunday. */
export interface Schedule {
  frequency: Frequency;
  weekday: number;
  hour: number;
  timezone: string;
  modules: string[];
  next_scan_at: string;
}

/** What PATCH /targets/{id} accepts: the server computes next_scan_at. */
export type ScheduleInput = Omit<Schedule, "next_scan_at">;

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
  /** An email was sent to the invitee (false: mail is not configured). */
  emailed: boolean;
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

/** planJSON: limits, 0 is unlimited. Prices per month. */
export interface Plan {
  id: "discovery" | "sme" | "pro" | "enterprise";
  name: string;
  domains: number;
  hosts_per_scan: number;
  members: number;
  active_modules: boolean;
  max_frequency: Frequency;
  alerts: boolean;
  reports: boolean;
  threats: boolean;
  /** The deep profile ("Approfondi"). */
  deep_scans: boolean;
  /** Deep scans per calendar month, 0 unlimited. */
  deep_scans_per_month: number;
  /** Declared APIs are scanned (step H). */
  api_scans: boolean;
  /** Scans can log in with a test account (step I). */
  auth_scans: boolean;
  /** Internal networks scanned by agents (step J). */
  agents: boolean;
  usd_monthly: number;
  usd_yearly: number;
  xaf_monthly: number;
  xaf_yearly: number;
  on_quote: boolean;
}

/** subscriptionJSON */
export interface Subscription {
  plan: Plan;
  status: "trialing" | "active" | "canceled" | "none";
  until: string | null;
  in_grace: boolean;
  lapsed: boolean;
  /** deep_scans: run this calendar month (UTC). */
  usage: { domains: number; members: number; deep_scans: number };
  plans: Plan[];
}

export type AlertLevel = "critical" | "high" | "all";

/** orgSettingsJSON: Réglages. weekday 0 is Sunday; frequency "" until chosen. */
export interface OrgSettings {
  alert_level: AlertLevel;
  email_alerts: boolean;
  profile: "quick" | "standard" | "deep";
  disabled_modules: string[];
  frequency: Frequency | "";
  weekday: number;
  hour: number;
  timezone: string;
  rate_per_sec: number;
  /** Request only: the customer confirms being allowed to have the servers tested deeply. */
  deep_consent?: boolean;
  /** When that consent was given, null without one. */
  deep_consent_at: string | null;
}

/** activityJSON */
export interface Activity {
  kind: "finding" | "scan";
  at: string;
  target_id: string;
  domain: string;
  finding_id?: string;
  title?: string;
  asset?: string;
  severity?: Severity;
  /** Absent: first seen. */
  from?: FindingStatus;
  to?: FindingStatus;
  scan_id?: string;
  requested_by?: string;
  assets?: number;
}

/** sessionJSON */
export interface DeviceSession {
  id: string;
  created_at: string;
  last_seen_at: string;
  ip: string;
  user_agent: string;
  current: boolean;
}

/** authActivityJSON */
export interface AuthActivity {
  at: string;
  action: string;
  ip: string;
}

/** apiJSON: an API declared on a target. */
export interface DeclaredAPI {
  id: string;
  target_id: string;
  name: string;
  kind: "openapi" | "graphql";
  base_url: string;
  spec_url?: string;
  /** Size of the uploaded description, bytes. */
  spec_size?: number;
  created_at: string;
  created_by: string;
}

/** credentialJSON: a target's test account, never its secret. */
export interface TestAccount {
  kind: "header" | "form";
  header_name?: string;
  login_url?: string;
  username?: string;
  username_field?: string;
  password_field?: string;
  created_at: string;
  created_by: string;
}

/** agentJSON */
export interface Agent {
  id: string;
  /** Its internal network (a target). */
  target_id: string;
  name: string;
  ranges: string[];
  enroll_expires_at: string | null;
  enrolled_at: string | null;
  last_seen_at: string | null;
  hostname?: string;
  os?: string;
  version?: string;
  revoked_at: string | null;
  created_at: string;
  created_by: string;
}
