// The application layout of the mockup: the rail (desktop), the top bar,
// the bottom tabs (phone) and the search palette (Ctrl K).

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, navigate } from "../router";
import { Logo, Moon, NavIcon, Search } from "./icons";
import { initials } from "./model";
import { useOrg } from "./OrgData";
import { FindingSheet } from "./sheets";
import { useUI } from "./ui";

export const NAV: [string, string][] = [
  ["aujourdhui", "Aujourd’hui"],
  ["problemes", "Problèmes"],
  ["actifs", "Actifs"],
  ["rapports", "Rapports"],
  ["reglages", "Réglages"],
];

export const appPath = (orgId: string, view: string) => `/orgs/${encodeURIComponent(orgId)}/${view}`;

function NavLinks({ orgId, current }: { orgId: string; current: string }) {
  return (
    <>
      {NAV.map(([k, l]) => (
        <Link key={k} to={appPath(orgId, k)} data-nav={k} aria-current={k === current ? "page" : undefined}>
          <NavIcon name={k} />
          {l}
        </Link>
      ))}
    </>
  );
}

export function AppShell({ view, children }: { view: string; children: ReactNode }) {
  const { me, org } = useOrg();
  const { openPal, theme, setTheme } = useUI();

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
      <div className="shell">
        <nav className="rail" aria-label="Navigation" id="rail">
          <Link className="logo" to="/" aria-label="Orus Shield, aller à l’accueil">
            <Logo size={30} />
          </Link>
          <NavLinks orgId={org.org_id} current={view} />
        </nav>
        <div>
          <header className="top">
            <Link className="brand" to="/" aria-label="Orus Shield, aller à l’accueil">
              <Logo />
              <span>Orus Shield</span>
            </Link>
            <button className="search" id="open-pal" type="button" onClick={openPal}>
              <Search />
              Rechercher <kbd>Ctrl K</kbd>
            </button>
            <Link className="iconbtn avatar" to={appPath(org.org_id, "profil")} aria-label="Mon profil">
              {initials(me.name, me.email)}
            </Link>
            <button className="iconbtn" id="theme" type="button" aria-label="Changer de thème" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
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
      ...NAV.map(([k, l]): [string, string, string] => [appPath(org.org_id, k), l, "Écran"]),
      [appPath(org.org_id, "profil"), "Mon profil", "Écran"],
      ["/", "Site public", "Écran"],
      ["/tarifs", "Tarifs", "Écran"],
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
    <div className={"pal" + (palOpen ? " on" : "")} id="pal" role="dialog" aria-modal="true" aria-label="Recherche" aria-hidden={!palOpen}>
      <input
        ref={input}
        id="pal-in"
        type="text"
        placeholder="Aller à un écran ou chercher un problème"
        autoComplete="off"
        aria-label="Rechercher"
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
          <li style={{ padding: 14, color: "var(--ink2)" }}>Aucun résultat. Essayez « emails » ou « actifs ».</li>
        )}
      </ul>
    </div>
  );
}
