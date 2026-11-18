// ScanLine says when the domains were last scanned and will be next, and
// starts a scan now: the scans the customer pays for, in plain sight
// (Aujourd'hui for every domain, Actifs for each one).

import { api } from "../api/client";
import { locale, tr } from "../i18n";
import type { Scan, Target } from "../api/types";
import { useOrg } from "./OrgData";
import { isAuditUsed, UpsellSheet } from "./sheets";
import { useUI } from "./ui";

/** when words a date for the scan line: "aujourd’hui à 9:30", "hier à 2:00",
 * "samedi 22 novembre à 2:00". */
export function when(iso: string, now = new Date()): string {
  const d = new Date(iso);
  const time = d.toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" });
  const day = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(d) - day(now)) / 86_400_000);
  if (diff === 0) return tr(`aujourd’hui à ${time}`, `today at ${time}`);
  if (diff === -1) return tr(`hier à ${time}`, `yesterday at ${time}`);
  if (diff === 1) return tr(`demain à ${time}`, `tomorrow at ${time}`);
  return tr(`${d.toLocaleDateString("fr-FR", { weekday: "long", day: "numeric", month: "long" })} à ${time}`, `${d.toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long" })} at ${time}`);
}

/** useScanNow starts a full scan (the offer's modules) of verified domains. */
export function useScanNow() {
  const { org, data, isAdmin, reload } = useOrg();
  const { toast, showSheet } = useUI();
  return async (targets: Target[]) => {
    if (!isAdmin) {
      toast(tr("Réservé aux administrateurs", "Administrators only"));
      return;
    }
    if (data && !data.subscription.plan.monitoring) {
      showSheet(<UpsellSheet what="scan" />);
      return;
    }
    const verified = targets.filter((t) => t.verified && !t.internal);
    if (!verified.length) {
      toast(tr("Vérifiez d’abord votre domaine dans Actifs", "Verify your domain in Assets first"));
      return;
    }
    try {
      for (const t of verified) await api.startScan(org.org_id, t.id);
      toast(
        verified.length > 1
          ? tr(`Scan lancé sur ${verified.length} domaines`, `Scan started on ${verified.length} domains`)
          : tr(`Scan lancé sur ${verified[0]!.domain}`, `Scan started on ${verified[0]!.domain}`),
      );
      await reload();
    } catch (e) {
      if (isAuditUsed(e)) showSheet(<UpsellSheet what="scan" />);
      else toast(tr("Impossible de lancer le scan pour le moment", "The scan cannot start right now"));
    }
  };
}

/** scanTimes tells, for targets, whether a scan runs, the last one
 * finished and the next one scheduled. */
export function scanTimes(scans: Scan[], targets: Target[]): { running: boolean; last: string | undefined; next: string | undefined } {
  const ids = new Set(targets.map((t) => t.id));
  const mine = scans.filter((s) => ids.has(s.target_id));
  return {
    running: mine.some((s) => s.status === "queued" || s.status === "running"),
    last: mine
      .filter((s) => s.status === "done" && s.finished_at)
      .map((s) => s.finished_at as string)
      .sort()
      .at(-1),
    next: targets
      .map((t) => t.schedule?.next_scan_at)
      .filter((x): x is string => !!x)
      .sort()[0],
  };
}

export function ScanLine({ targets }: { targets: Target[] }) {
  const { data } = useOrg();
  const scanNow = useScanNow();
  if (!data) return null;
  const { running, last, next } = scanTimes(data.scans, targets);
  return (
    <div className="scanline" role="status">
      <span>
        {running ? tr("Scan en cours…", "Scan running…") : last ? tr(`Dernier scan : ${when(last)}`, `Last scan: ${when(last)}`) : tr("Pas encore scanné", "Not scanned yet")}
        {" · "}
        {next ? tr(`Prochain : ${when(next)}`, `Next: ${when(next)}`) : tr("Aucun scan planifié", "No scan scheduled")}
      </span>
      <button className="link" type="button" disabled={running} onClick={() => void scanNow(targets)}>
        {running ? tr("Scan en cours", "Scan running") : tr("Scanner maintenant", "Scan now")}
      </button>
    </div>
  );
}
