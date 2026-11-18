// The domain a visitor tested on the public test page, carried to the
// dashboard: once they sign up, Premiers pas offers it ready to add. Kept
// in this browser only, as a convenience; without storage the visitor
// types it again.

const KEY = "orus.domain";

/** rememberDomain keeps the tested domain until the dashboard takes it. */
export function rememberDomain(domain: string) {
  try {
    if (domain) window.localStorage.setItem(KEY, domain);
  } catch {
    // Private window: typed again later.
  }
}

/** takeDomain returns the remembered domain once. */
export function takeDomain(): string {
  try {
    const d = window.localStorage.getItem(KEY) ?? "";
    window.localStorage.removeItem(KEY);
    return /^[a-z0-9.-]{3,253}$/.test(d) ? d : "";
  } catch {
    return "";
  }
}

/** cleanDomain keeps the name of what a visitor pasted: a URL, an email
 * address, a name with a path. */
export function cleanDomain(v: string): string {
  let d = v.trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, "").replace(/^[^@/]*@/, "");
  d = d.split(/[/?#:]/)[0] ?? "";
  return d.replace(/\.$/, "");
}
