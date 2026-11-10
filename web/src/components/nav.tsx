// The application menu, as in the mockups: every screen is listed, even
// those not built yet (they open a "Bientôt disponible" page).

import type { ReactNode } from "react";

export interface Section {
  /** URL segment after /orgs/{org}; "" for the overview. */
  path: string;
  label: string;
  icon: ReactNode;
}

const icon = (children: ReactNode) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
    {children}
  </svg>
);

export const sections: Section[] = [
  {
    path: "",
    label: "Vue d'ensemble",
    icon: icon(
      <>
        <rect x="3" y="3" width="7" height="9" rx="1.5" />
        <rect x="14" y="3" width="7" height="5" rx="1.5" />
        <rect x="14" y="12" width="7" height="9" rx="1.5" />
        <rect x="3" y="16" width="7" height="5" rx="1.5" />
      </>,
    ),
  },
  {
    path: "surface",
    label: "Surface d'attaque",
    icon: icon(
      <>
        <circle cx="12" cy="12" r="9" />
        <circle cx="12" cy="12" r="5" />
        <circle cx="12" cy="12" r="1" />
      </>,
    ),
  },
  { path: "priorisation", label: "Priorisation", icon: icon(<path d="M4 6h16M4 12h10M4 18h5" />) },
  {
    path: "vulnerabilites",
    label: "Vulnérabilités",
    icon: icon(
      <>
        <path d="M12 3l9 16H3L12 3z" />
        <path d="M12 10v4M12 17v.5" />
      </>,
    ),
  },
  {
    path: "posture",
    label: "Posture et conformité",
    icon: icon(
      <>
        <path d="M4 17a8 8 0 1 1 16 0" />
        <path d="M12 17l4-5" />
      </>,
    ),
  },
  {
    path: "gouvernance",
    label: "Gouvernance",
    icon: icon(
      <>
        <rect x="5" y="4" width="14" height="17" rx="2" />
        <path d="M9 4V3h6v1M9 13l2 2 4-4" />
      </>,
    ),
  },
  {
    path: "actifs",
    label: "Actifs",
    icon: icon(
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M3 12h18M12 3c2.5 3 2.5 15 0 18M12 3c-2.5 3-2.5 15 0 18" />
      </>,
    ),
  },
  {
    path: "scans",
    label: "Scans",
    icon: icon(
      <>
        <circle cx="11" cy="11" r="7" />
        <path d="M20 20l-4-4" />
      </>,
    ),
  },
  {
    path: "parametres",
    label: "Paramètres",
    icon: icon(
      <>
        <circle cx="12" cy="12" r="3" />
        <path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1" />
      </>,
    ),
  },
];

export function orgPath(orgId: string, section = ""): string {
  const base = "/orgs/" + encodeURIComponent(orgId);
  return section ? `${base}/${section}` : base;
}
