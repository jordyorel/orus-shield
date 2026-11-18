// The data of one organization, loaded once for every tab (Aujourd'hui,
// Problèmes, Actifs, Rapports, Réglages) and reloaded after a change.

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, ApiError } from "../api/client";
import type { Activity, Check, Finding, FindingStatus, Me, Membership, OrgAsset, OrgSettings, Overview, Scan, Subscription, Target } from "../api/types";
import { useAuth } from "../auth";
import { fallback } from "../messages";
import { navigate } from "../router";
import { toAssets, toIssues, type AssetView, type Issue, type Verdict } from "./model";

export interface OrgData {
  overview: Overview;
  findings: Finding[];
  assets: OrgAsset[];
  checks: Check[];
  targets: Target[];
  subscription: Subscription;
  settings: OrgSettings;
  activity: Activity[];
  scans: Scan[];
}

interface OrgCtx {
  me: Me;
  org: Membership;
  isAdmin: boolean;
  data: OrgData | null;
  error: string;
  issues: Issue[];
  assets: AssetView[];
  reload: () => Promise<void>;
  /** setStatus changes a finding's status and updates the lists in place. */
  setStatus: (issue: Issue, status: FindingStatus) => Promise<void>;
  setSettings: (s: OrgSettings) => void;
  /** verdicts: what the verification scans said, by "targetId/findingId". */
  verdicts: Record<string, Verdict>;
  /** watchFixes follows the verification scans of problems just marked
   * fixed, then records their verdict (confirmed, or still there). */
  watchFixes: (list: Issue[]) => void;
  /** forgetVerdicts drops the verdicts of problems reopened by hand. */
  forgetVerdicts: (list: Issue[]) => void;
  /** scanning: a scan of one of the domains is queued or running. */
  scanning: boolean;
}

/** How long a verification is followed, and how often. */
const WATCH_MS = 5 * 60_000;
const WATCH_EVERY = 4000;

const Ctx = createContext<OrgCtx | null>(null);

export function useOrg(): OrgCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useOrg outside OrgProvider");
  return v;
}

async function load(orgId: string, signal?: AbortSignal): Promise<OrgData> {
  const [overview, findings, assets, checks, targets, subscription, settings, activity, scans] = await Promise.all([
    api.overview(orgId, 84, signal),
    api.findings(orgId, signal),
    api.orgAssets(orgId, signal),
    api.checks(orgId, signal),
    api.targets(orgId, signal),
    api.subscription(orgId, signal),
    api.settings(orgId, signal),
    api.activity(orgId, signal),
    api.scans(orgId, signal),
  ]);
  return {
    overview,
    findings: findings.items,
    assets: assets.items,
    checks: checks.items,
    targets: targets.items,
    subscription,
    settings,
    activity: activity.items,
    scans: scans.items,
  };
}

export function OrgProvider({ me, org, children }: { me: Me; org: Membership; children: ReactNode }) {
  const [data, setData] = useState<OrgData | null>(null);
  const [error, setError] = useState("");

  const { refresh } = useAuth();
  const handle = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.code === "mfa_required") navigate("/mfa/setup?reason=admin", { replace: true });
      else if (err instanceof ApiError && err.status === 401) {
        // The session ended (expired, signed out elsewhere, or a cookie the
        // browser did not keep): back to the sign-in page, said plainly.
        navigate("/connexion?ok=expired", { replace: true });
        void refresh().catch(() => undefined);
      } else setError(fallback(err));
    },
    [refresh],
  );

  useEffect(() => {
    const ctrl = new AbortController();
    load(org.org_id, ctrl.signal)
      .then(setData)
      .catch((e: unknown) => {
        if (!ctrl.signal.aborted) handle(e);
      });
    return () => ctrl.abort();
  }, [org.org_id, handle]);

  const reload = useCallback(async () => {
    try {
      setData(await load(org.org_id));
    } catch (e) {
      handle(e);
    }
  }, [org.org_id, handle]);

  const setStatus = useCallback(
    async (issue: Issue, status: FindingStatus) => {
      // Optimistic, as in the mockup: the check turns green at once, and
      // goes back if the API refuses.
      const set = (s: FindingStatus) =>
        setData((d) =>
          d ? { ...d, findings: d.findings.map((f) => (f.id === issue.id && f.target_id === issue.targetId ? { ...f, status: s } : f)) } : d,
        );
      const before = issue.finding.status;
      set(status);
      try {
        await api.setFindingStatus(org.org_id, issue.targetId, issue.id, status);
      } catch (e) {
        set(before);
        throw e;
      }
    },
    [org.org_id],
  );

  const setSettings = useCallback((s: OrgSettings) => setData((d) => (d ? { ...d, settings: s } : d)), []);

  const [verdicts, setVerdicts] = useState<Record<string, Verdict>>({});
  const keyOf = (i: Issue) => i.targetId + "/" + i.id;
  const watchFixes = useCallback(
    (list: Issue[]) => {
      if (!list.length) return;
      setVerdicts((v) => ({ ...v, ...Object.fromEntries(list.map((i) => [keyOf(i), { state: "checking" } as Verdict])) }));
      const targets = new Set(list.map((i) => i.targetId));
      const modules = new Set(list.map((i) => i.moduleId));
      const end = Date.now() + WATCH_MS;
      // The API queues the verification scan before answering: it is in the
      // list at the first look, and the verdict comes once it is done.
      const look = async () => {
        let busy = true;
        try {
          const sc = await api.scans(org.org_id);
          busy = sc.items.some((s) => targets.has(s.target_id) && (s.status === "queued" || s.status === "running") && s.modules.some((m) => modules.has(m)));
        } catch {
          // A missed look: try again.
        }
        if (busy && Date.now() < end) {
          setTimeout(() => void look(), WATCH_EVERY);
          return;
        }
        let fresh: OrgData;
        try {
          fresh = await load(org.org_id);
        } catch {
          setVerdicts((v) => ({ ...v, ...Object.fromEntries(list.map((i) => [keyOf(i), { state: "late" } as Verdict])) }));
          return;
        }
        setData(fresh);
        const at = new Date().toISOString();
        setVerdicts((v) => {
          const next = { ...v };
          for (const i of list) {
            const f = fresh.findings.find((x) => x.id === i.id && x.target_id === i.targetId);
            next[keyOf(i)] = busy ? { state: "late" } : f && f.status === "open" ? { state: "still", at } : { state: "confirmed" };
          }
          return next;
        });
      };
      setTimeout(() => void look(), 1500);
    },
    [org.org_id],
  );
  const forgetVerdicts = useCallback((list: Issue[]) => {
    setVerdicts((v) => {
      const next = { ...v };
      for (const i of list) delete next[keyOf(i)];
      return next;
    });
  }, []);
  const scanning = !!data?.scans.some((s) => s.status === "queued" || s.status === "running");
  // A scan under way: reload now and then, so results appear by themselves.
  useEffect(() => {
    if (!scanning) return;
    const t = setInterval(() => void reload(), 15000);
    return () => clearInterval(t);
  }, [scanning, reload]);

  const value = useMemo<OrgCtx>(() => {
    const issues = data ? toIssues(data.findings, data.assets) : [];
    return {
      me,
      org,
      isAdmin: org.role === "admin",
      data,
      error,
      issues,
      assets: data ? toAssets(data.assets) : [],
      reload,
      setStatus,
      setSettings,
      verdicts,
      watchFixes,
      forgetVerdicts,
      scanning,
    };
  }, [me, org, data, error, reload, setStatus, setSettings, verdicts, watchFixes, forgetVerdicts, scanning]);

  return <Ctx value={value}>{children}</Ctx>;
}
