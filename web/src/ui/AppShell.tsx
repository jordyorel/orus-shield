// The application layout of the mockup: the rail (desktop), the top bar,
// the bottom tabs (phone) and the search palette (Ctrl K).

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { labeled, tr } from "../i18n";
import { Link, navigate } from "../router";
import { Fold, Logo, Moon, NavIcon, Search } from "./icons";
import { initials } from "./model";
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
export type SettingsSection = "scans" | "domaines" | "alertes" | "equipe" | "abonnement" | "apparence";

/** settingsPath is the address of one section of Réglages. */
export function settingsPath(orgId: string, s: SettingsSection): string {
  return appPath(orgId, "reglages") + (s === "scans" ? "" : "?s=" + s);
}

/** NavLinks are the tabs. folded: the rail shows icons only, so each name
 * moves to a tooltip (the link keeps it as its accessible name). */
function NavLinks({ orgId, current, folded = false }: { orgId: string; current: string; folded?: boolean }) {
  return (
    <>
      {NAV.map(([k, l]) => (
        <Link key={k} to={appPath(orgId, k)} data-nav={k} aria-current={k === current ? "page" : undefined} title={folded ? l : undefined}>
          <NavIcon name={k} />
          <span className="navl">{l}</span>
        </Link>
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
  const { me, org, scanning } = useOrg();
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

  return (
    <>
      <div className={"shell" + (folded ? " railmin" : "")}>
        <nav className="rail" aria-label="Navigation" id="rail">
          <Link className="logo" to="/" aria-label={tr("Orus Shield, aller à l’accueil", "Orus Shield, go to the home page")}>
            <Logo size={30} />
            <span className="railname" aria-hidden="true">
              Orus Shield
            </span>
          </Link>
          <NavLinks orgId={org.org_id} current={view} folded={folded} />
          {/* The profile at the foot of the rail, above the fold toggle
              (desktop; on a phone it stays in the top bar). */}
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
        </nav>
        <div>
          <header className="top">
            <Link className="brand" to="/" aria-label={tr("Orus Shield, aller à l’accueil", "Orus Shield, go to the home page")}>
              <Logo />
              <span>Orus Shield</span>
            </Link>
            {scanning && (
              <span className="topchip scanning" role="status">
                <span className="spin" aria-hidden="true" />
                {tr("Scan en cours", "Scan running")}
              </span>
            )}
            <OfferChip />
            <button className="search" id="open-pal" type="button" onClick={openPal}>
              <Search />
              {tr("Rechercher", "Search")} <kbd>Ctrl K</kbd>
            </button>
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
