// The mockup's inline SVG icons, as components. The shield of the mockup
// is replaced by the project's falcon logo (public/logo-mark.png).

import type { ReactNode } from "react";

const paths: Record<string, ReactNode> = {
  aujourdhui: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2" />
    </>
  ),
  problemes: <path d="M4 6h16M4 12h16M4 18h10" />,
  actifs: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" />
    </>
  ),
  rapports: <path d="M5 20V10M12 20V4M19 20v-7" />,
  reglages: (
    <>
      <path d="M4 7h10M18 7h2M4 17h2M10 17h10" />
      <circle cx="16" cy="7" r="2" />
      <circle cx="8" cy="17" r="2" />
    </>
  ),
};

export function NavIcon({ name, size = 22, width = 1.9 }: { name: string; size?: number; width?: number }) {
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
    title: "Emails",
    desc: "SPF, DKIM et DMARC",
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
    title: "Chiffrement",
    desc: "Certificats et versions de TLS",
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
    title: "Ports et services",
    desc: "Sur les serveurs dont la propriété est prouvée",
    icon: (
      <>
        <circle cx="12" cy="12" r="9" />
        <circle cx="12" cy="12" r="4" />
      </>
    ),
  },
  {
    key: "fuites",
    module: null,
    title: "Fuites de données",
    desc: "Vos adresses dans les fuites connues",
    icon: <path d="M12 3c4 5 6 8 6 11a6 6 0 0 1-12 0c0-3 2-6 6-11z" />,
  },
  {
    key: "menaces",
    module: "vulns",
    title: "Menaces émergentes",
    desc: "Failles en cours d’exploitation qui vous concernent",
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
export const Soon = () => <span className="soon">Bientôt</span>;
