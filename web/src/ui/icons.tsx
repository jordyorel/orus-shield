// The mockup's inline SVG icons, as components. The shield of the mockup
// is replaced by the project's falcon logo (public/logo-mark.png).

import { tr } from "../i18n";
import type { ReactNode } from "react";

// The tabs' icons (redrawn 2026-11-20 in the even-stroke style of modern
// consoles): a dashboard, a shield with an alert, stacked servers, a column
// chart on its axes, a cog.
const paths: Record<string, ReactNode> = {
  aujourdhui: (
    <>
      <rect x="3.5" y="3.5" width="7" height="8" rx="1.6" />
      <rect x="13.5" y="3.5" width="7" height="5" rx="1.6" />
      <rect x="13.5" y="11.5" width="7" height="9" rx="1.6" />
      <rect x="3.5" y="14.5" width="7" height="6" rx="1.6" />
    </>
  ),
  problemes: (
    <>
      <path d="M12 3.2 19 6v5.2c0 4.3-2.9 7.8-7 9.6-4.1-1.8-7-5.3-7-9.6V6z" />
      <path d="M12 8.2v4.6M12 15.8h.01" />
    </>
  ),
  actifs: (
    <>
      <rect x="3.5" y="4" width="17" height="7" rx="2" />
      <rect x="3.5" y="13" width="17" height="7" rx="2" />
      <path d="M7.5 7.5h.01M7.5 16.5h.01M11 7.5h5M11 16.5h5" />
    </>
  ),
  rapports: <path d="M3.5 3.5v17h17M8 16.5v-4M12.5 16.5V8M17 16.5v-6.5" />,
  reglages: (
    <>
      <path d="M10.4 3.6a1.6 1.6 0 0 1 3.2 0l.2 1.1a7 7 0 0 1 1.7 1l1.1-.4a1.6 1.6 0 0 1 1.6 2.8l-.9.7a7 7 0 0 1 0 2l.9.7a1.6 1.6 0 0 1-1.6 2.8l-1.1-.4a7 7 0 0 1-1.7 1l-.2 1.1a1.6 1.6 0 0 1-3.2 0l-.2-1.1a7 7 0 0 1-1.7-1l-1.1.4a1.6 1.6 0 0 1-1.6-2.8l.9-.7a7 7 0 0 1 0-2l-.9-.7a1.6 1.6 0 0 1 1.6-2.8l1.1.4a7 7 0 0 1 1.7-1z" transform="translate(0 2)" />
      <circle cx="12" cy="12" r="2.6" />
    </>
  ),
};

export function NavIcon({ name, size = 22, width = 1.75 }: { name: string; size?: number; width?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={width} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {paths[name]}
    </svg>
  );
}

/** Logo is the falcon mark, at the size of the mockup's shield. */
export function Logo({ size = 26 }: { size?: number }) {
  return <img className="brandmark" src="/logo-mark.png" width={size} height={Math.round((size * 117) / 128)} alt="" aria-hidden="true" />;
}

export const Moon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
    <path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z" />
  </svg>
);

export const Search = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
    <circle cx="11" cy="11" r="7" />
    <path d="M20 20l-4-4" />
  </svg>
);

export const Arrow = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M15 6l-6 6 6 6" />
  </svg>
);

export const Eye = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

export function Tick({ size = 14, width = 3.2 }: { size?: number; width?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth={width} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M5 12l5 5 9-10" />
    </svg>
  );
}

export const Close = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" aria-hidden="true">
    <path d="M6 6l12 12M18 6L6 18" />
  </svg>
);

/** Expand and Shrink: the side sheet's "see it large" toggle. */
export const Expand = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M14 4h6v6M10 20H4v-6M20 4l-7 7M4 20l7-7" />
  </svg>
);

export const Shrink = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M20 10h-6V4M4 14h6v6M14 10l7-7M10 14l-7 7" />
  </svg>
);

/** Fold: the rail's "fold to icons" toggle (it turns over once folded). */
export const Fold = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M11 17l-5-5 5-5M18 17l-5-5 5-5" />
  </svg>
);

/** KeyIcon: an API key. */
export const KeyIcon = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="8" cy="15" r="4" />
    <path d="M10.85 12.15 19 4M15 8l3 3M17 6l2 2" />
  </svg>
);

export const Lock = ({ size = 16 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
    <rect x="5" y="11" width="14" height="9" rx="2" />
    <path d="M8 11V8a4 4 0 0 1 8 0v3" />
  </svg>
);

export const Device = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" aria-hidden="true">
    <rect x="4" y="5" width="16" height="11" rx="2" />
    <path d="M2 19h20" />
  </svg>
);

export const Envelope = () => (
  <div className="envelope" aria-hidden="true">
    <svg viewBox="0 0 120 90">
      <rect x="6" y="14" width="108" height="70" rx="12" fill="var(--surface)" stroke="var(--ring)" strokeWidth="2" />
      <path className="flap" d="M8 20 L60 56 L112 20" fill="none" stroke="var(--azur)" strokeWidth="3" strokeLinejoin="round" />
    </svg>
  </div>
);

/** The mockup's MODS: the five checks of Réglages and of the home page. */
export const MODS: { key: "emails" | "tls" | "ports" | "fuites" | "menaces"; module: string | null; title: string; desc: string; icon: ReactNode }[] = [
  {
    key: "emails",
    module: "email",
    get title() {
      return tr("Emails", "Email");
    },
    desc: "SPF, DKIM, DMARC",
    icon: (
      <>
        <path d="M3 6h18v12H3z" />
        <path d="M3 7l9 6 9-6" />
      </>
    ),
  },
  {
    key: "tls",
    module: "tls",
    get title() {
      return tr("Chiffrement", "Encryption");
    },
    get desc() {
      return tr("Certificats et versions de TLS", "Certificates and TLS versions");
    },
    icon: (
      <>
        <rect x="5" y="11" width="14" height="9" rx="2" />
        <path d="M8 11V8a4 4 0 0 1 8 0v3" />
      </>
    ),
  },
  {
    key: "ports",
    module: "ports",
    get title() {
      return tr("Ports et services", "Ports and services");
    },
    get desc() {
      return tr("Sur les serveurs dont la propriété est prouvée", "On servers whose ownership is proven");
    },
    icon: (
      <>
        <circle cx="12" cy="12" r="9" />
        <circle cx="12" cy="12" r="4" />
      </>
    ),
  },
  {
    key: "fuites",
    module: "leaks",
    get title() {
      return tr("Fuites de données", "Data leaks");
    },
    get desc() {
      return tr("Vos adresses dans les fuites connues", "Your addresses in known leaks");
    },
    icon: <path d="M12 3c4 5 6 8 6 11a6 6 0 0 1-12 0c0-3 2-6 6-11z" />,
  },
  {
    key: "menaces",
    module: "vulns",
    get title() {
      return tr("Menaces émergentes", "Emerging threats");
    },
    get desc() {
      return tr("Failles en cours d’exploitation qui vous concernent", "Flaws being exploited that concern you");
    },
    icon: (
      <>
        <path d="M12 3l9 16H3L12 3z" />
        <path d="M12 10v4M12 17v.5" />
      </>
    ),
  },
];

export function ModIcon({ children }: { children: ReactNode }) {
  return (
    <span className="mico">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {children}
      </svg>
    </span>
  );
}

/** Soon is the "Bientôt" badge of an element without a real source yet. */
export const Soon = () => <span className="soon">{tr("Bientôt", "Soon")}</span>;
