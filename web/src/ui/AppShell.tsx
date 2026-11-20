// The application layout of the mockup: the rail (desktop), the top bar,
// the bottom tabs (phone) and the search palette (Ctrl K).

import { Fragment, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { labeled, tr } from "../i18n";
import { Link, navigate } from "../router";
import { Fold, Logo, Moon, NavIcon, Search } from "./icons";
import { groupIssues, initials } from "./model";
import { useOrg } from "./OrgData";
import { FindingSheet } from "./sheets";
import { useUI } from "./ui";

export const NAV: [string, string][] = [
  labeled("aujourdhui", "Aujourd’hui", "Today"),
  labeled("problemes", "Problèmes", "Problems"),
  labeled("actifs", "Actifs", "Assets"),
  labeled("rapports", "Rapports", "Reports"),
  labeled("reglages", "Réglages", "Settings"),
];

export const appPath = (orgId: string, view: string) => `/orgs/${encodeURIComponent(orgId)}/${view}`;

/** The sections of Réglages (?s=), "scans" being the default. */
export type SettingsSection = "scans" | "domaines" | "alertes" | "equipe" | "api" | "abonnement" | "apparence";

/** settingsPath is the address of one section of Réglages. */
export function settingsPath(orgId: string, s: SettingsSection): string {
  return appPath(orgId, "reglages") + (s === "scans" ? "" : "?s=" + s);
}

/** NavLinks are the tabs. folded: the rail shows icons only, so each name
 * moves to a tooltip (the link keeps it as its accessible name). counts:
 * the badges of the rail (open problem lines, assets). */
function NavLinks({ orgId, current, folded = false, counts }: { orgId: string; current: string; folded?: boolean; counts?: Record<string, [number, boolean]> }) {
  return (
    <>
      {NAV.map(([k, l]) => (
        <Fragment key={k}>
          {counts && k === "reglages" && (
            <span className="navlbl" aria-hidden="true">
              {tr("Organisation", "Organization")}
            </span>
          )}
          <Link to={appPath(orgId, k)} data-nav={k} aria-current={k === current ? "page" : undefined} title={folded ? l : undefined}>
            <NavIcon name={k} />
            <span className="navl">{l}</span>
            {counts?.[k] && counts[k][0] > 0 && (
              <span className={"navcnt" + (counts[k][1] ? " hot" : "")} aria-label={tr(`${counts[k][0]} ouverts`, `${counts[k][0]} open`)}>
                {counts[k][0]}
              </span>
            )}
          </Link>
        </Fragment>
      ))}
    </>
  );
}

// The rail folds to its icons (desktop). The choice is this browser's
// convenience only: kept in localStorage, and the rail opens unfolded
// when storage is unavailable.
const RAIL_KEY = "orus.rail";

function readFolded(): boolean {
  try {
    return window.localStorage.getItem(RAIL_KEY) === "folded";
  } catch {
    return false;
  }
}

function writeFolded(folded: boolean) {
  try {
    if (folded) window.localStorage.setItem(RAIL_KEY, "folded");
    else window.localStorage.removeItem(RAIL_KEY);
  } catch {
    // Private window: kept for this page only.
  }
}

/** daysLeft counts the whole days until iso, at least 0. */
function daysLeft(iso: string, now = Date.now()): number {
  return Math.max(0, Math.ceil((new Date(iso).getTime() - now) / 86_400_000));
}

/** OfferCard is the offer at the foot of the rail: a running trial and
 * its days left, or Gratuit and the way to the trial. Nothing for a paid
 * offer: the organization block names it. */
function OfferCard() {
  const { org, data } = useOrg();
  if (!data) return null;
  const sub = data.subscription;
  if (!sub.plan.monitoring) {
    return (
      <Link className="railoffer" to={appPath(org.org_id, "offre")}>
        <b>{tr("Offre Gratuite", "Free plan")}</b>
        <span>{tr("Un audit. La surveillance continue commence avec l’essai.", "One audit. Continuous monitoring starts with the trial.")}</span>
        <em>{tr("Essayer 14 jours", "Try 14 days")}</em>
      </Link>
    );
  }
  if (sub.status === "trialing" && sub.until) {
    const n = daysLeft(sub.until);
    return (
      <Link className="railoffer" to={settingsPath(org.org_id, "abonnement")}>
        <b>{tr(`Essai ${sub.plan.name}`, `${sub.plan.name} trial`)}</b>
        <span>{tr(`${n} jour${n > 1 ? "s" : ""} restant${n > 1 ? "s" : ""} sur 14`, `${n} day${n !== 1 ? "s" : ""} left of 14`)}</span>
        <i className="railbar" aria-hidden="true">
          <i style={{ width: `${Math.round((Math.min(14, 14 - n) / 14) * 100)}%` }} />
        </i>
        <em>{tr("Choisir mon offre", "Choose my plan")}</em>
      </Link>
    );
  }
  return null;
}

/** OfferChip shows the offer in force in the top bar: a running trial and
 * its days left, or Gratuit and the way to the trial. */
function OfferChip() {
  const { org, data } = useOrg();
  if (!data) return null;
  const sub = data.subscription;
  if (!sub.plan.monitoring) {
    return (
      <Link className="topchip free" to={appPath(org.org_id, "offre")}>
        {tr("Gratuit · Essayer 14 jours", "Free · Try 14 days")}
      </Link>
    );
  }
  if (sub.status === "trialing" && sub.until) {
    const n = daysLeft(sub.until);
    return (
      <Link className="topchip" to={settingsPath(org.org_id, "abonnement")}>
        {tr(`Essai ${sub.plan.name} : ${n} jour${n > 1 ? "s" : ""} restant${n > 1 ? "s" : ""}`, `${sub.plan.name} trial: ${n} day${n !== 1 ? "s" : ""} left`)}
      </Link>
    );
  }
  return null;
}

export function AppShell({ view, children }: { view: string; children: ReactNode }) {
  const { me, org, scanning, issues, assets, data } = useOrg();
  const { openPal, theme, setTheme } = useUI();
  const [folded, setFolded] = useState(readFolded);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openPal();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [openPal]);

  // Braces: an effect must return nothing or a clean-up function, and
  // scrollTo returns a Promise in recent Chromium.
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [view]);

  const lines = groupIssues(issues).filter((g) => !g.fixed);
  const counts: Record<string, [number, boolean]> = {
    problemes: [lines.length, lines.some((g) => g.lead.sev === "crit")],
    actifs: [assets.length, false],
  };
  const here = view === "profil" ? tr("Mon profil", "My profile") : view === "offre" ? tr("Offre", "Plan") : (NAV.find(([k]) => k === view)?.[1] ?? "");
  const plan = data?.subscription.plan.name;

  return (
    <>
      <div className={"shell" + (folded ? " railmin" : "")}>
        <nav className="rail" aria-label="Navigation" id="rail">
          <Link className="logo" to="/" aria-label={tr("Orus Shield, aller à l’accueil", "Orus Shield, go to the home page")}>
            <Logo size={28} />
            <span className="railname" aria-hidden="true">
              Orus Shield
            </span>
          </Link>
          <div className="railorg" title={folded ? org.org_name : undefined}>
            <span className="orgav" aria-hidden="true">
              {initials(org.org_name, org.org_name)}
            </span>
            <span className="railwho">
              <b>{org.org_name}</b>
              <small>
                {plan ? plan + " · " : ""}
                {org.role === "admin" ? tr("Administrateur", "Administrator") : tr("Lecteur", "Viewer")}
              </small>
            </span>
          </div>
          <NavLinks orgId={org.org_id} current={view} folded={folded} counts={counts} />
          <div className="railfoot">
            {!folded && <OfferCard />}
            <Link
              className="railprofile"
              to={appPath(org.org_id, "profil")}
              aria-current={view === "profil" ? "page" : undefined}
              aria-label={tr("Mon profil", "My profile")}
              title={folded ? me.name || me.email : undefined}
            >
              <span className="avatar" aria-hidden="true">
                {initials(me.name, me.email)}
              </span>
              <span className="railwho" aria-hidden="true">
                <b>{me.name || tr("Mon profil", "My profile")}</b>
                <small>{me.email}</small>
              </span>
            </Link>
            <button
              className="railtoggle"
              type="button"
              aria-controls="rail"
              aria-expanded={!folded}
              title={folded ? tr("Déplier le menu", "Expand the menu") : undefined}
              onClick={() => {
                writeFolded(!folded);
                setFolded(!folded);
              }}
            >
              <Fold />
              <span>{folded ? tr("Déplier le menu", "Expand the menu") : tr("Réduire le menu", "Collapse the menu")}</span>
            </button>
          </div>
        </nav>
        <div className="shellmain">
          <header className="top">
            <Link className="brand" to="/" aria-label={tr("Orus Shield, aller à l’accueil", "Orus Shield, go to the home page")}>
              <Logo />
              <span>Orus Shield</span>
            </Link>
            <p className="crumb">
              <span>{org.org_name}</span>
              <span aria-hidden="true">/</span>
              <b>{here}</b>
            </p>
            <button className="search" id="open-pal" type="button" onClick={openPal}>
              <Search />
              <span className="searchl">{tr("Rechercher un actif, un problème…", "Search an asset, a problem…")}</span>
              <kbd>Ctrl K</kbd>
            </button>
            {scanning && (
              <span className="topchip scanning" role="status">
                <span className="live" aria-hidden="true" />
                {tr("Scan en cours", "Scan running")}
              </span>
            )}
            <OfferChip />
            <Link className="iconbtn avatar topavatar" to={appPath(org.org_id, "profil")} aria-label={tr("Mon profil", "My profile")}>
              {initials(me.name, me.email)}
            </Link>
            <button className="iconbtn" id="theme" type="button" aria-label={tr("Changer de thème", "Change theme")} onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
              <Moon />
            </button>
          </header>
          <main id="main" tabIndex={-1}>
            <div className="view" key={view}>
              {children}
            </div>
          </main>
        </div>
      </div>
      <nav className="tabs" aria-label="Navigation" id="tabs">
        <NavLinks orgId={org.org_id} current={view} />
      </nav>
      <Palette />
    </>
  );
}

interface PalItem {
  label: string;
  kind: string;
  go: () => void;
}

function Palette() {
  const { org, issues } = useOrg();
  const { palOpen, closeAll, showSheet } = useUI();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (palOpen) {
      setQ("");
      setSel(0);
      requestAnimationFrame(() => input.current?.focus());
    }
  }, [palOpen]);

  const all = useMemo<PalItem[]>(() => {
    const screens: [string, string, string][] = [
      ...NAV.map(([k, l]): [string, string, string] => [appPath(org.org_id, k), l, tr("Écran", "Screen")]),
      [appPath(org.org_id, "profil"), tr("Mon profil", "My profile"), tr("Écran", "Screen")],
      ["/", tr("Site public", "Public site"), tr("Écran", "Screen")],
      ["/tarifs", tr("Tarifs", "Pricing"), tr("Écran", "Screen")],
    ];
    return [
      ...screens.map(([to, label, kind]) => ({ label, kind, go: () => navigate(to) })),
      ...issues.map((i) => ({ label: i.title, kind: i.host, go: () => showSheet(<FindingSheet id={i.id} targetId={i.targetId} />) })),
    ];
  }, [org.org_id, issues, showSheet]);

  const needle = q.trim().toLowerCase();
  const list = needle ? all.filter((x) => (x.label + " " + x.kind).toLowerCase().includes(needle)) : all;
  const cur = Math.min(sel, Math.max(0, list.length - 1));

  const run = (i: number) => {
    const it = list[i];
    if (!it) return;
    closeAll();
    it.go();
  };

  return (
    <div className={"pal" + (palOpen ? " on" : "")} id="pal" role="dialog" aria-modal="true" aria-label={tr("Recherche", "Search")} aria-hidden={!palOpen}>
      <input
        ref={input}
        id="pal-in"
        type="text"
        placeholder={tr("Aller à un écran ou chercher un problème", "Go to a screen or search for a problem")}
        autoComplete="off"
        aria-label={tr("Rechercher", "Search")}
        value={q}
        onChange={(e) => {
          setQ(e.target.value);
          setSel(0);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setSel(Math.min(list.length - 1, cur + 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setSel(Math.max(0, cur - 1));
          } else if (e.key === "Enter") {
            e.preventDefault();
            run(cur);
          }
        }}
      />
      <ul id="pal-list">
        {list.length ? (
          list.map((x, i) => (
            <li key={i}>
              <button type="button" className={i === cur ? "sel" : ""} onClick={() => run(i)}>
                <span>{x.label}</span>
                <small>{x.kind}</small>
              </button>
            </li>
          ))
        ) : (
          <li style={{ padding: 14, color: "var(--ink2)" }}>{tr("Aucun résultat. Essayez « emails » ou « actifs ».", "No results. Try “email” or “assets”.")}</li>
        )}
      </ul>
    </div>
  );
}
