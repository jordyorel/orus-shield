// Exclusions are edited as text, one per line, as in the mockup, and sent
// in the engine's format (gate.Exclusions). The engine validates them again.

export interface Exclusions {
  ips?: string[];
  ports?: number[];
  paths?: string[];
  hosts?: string[];
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/;
const IPV6 = /^[0-9a-f:]+(\/\d{1,3})?$/i;

/**
 * parseExclusions sorts lines into the engine's kinds: "/admin" is a path,
 * "3389" a port, "192.0.2.10" or "192.0.2.0/24" an address, anything else
 * a host name. Empty lines are ignored.
 */
export function parseExclusions(text: string): { value: Exclusions; errors: string[] } {
  const value: Required<Exclusions> = { ips: [], ports: [], paths: [], hosts: [] };
  const errors: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith("/")) value.paths.push(line);
    else if (/^\d+$/.test(line)) {
      const port = Number(line);
      if (port >= 1 && port <= 65535) value.ports.push(port);
      else errors.push(line);
    } else if (IPV4.test(line) || (line.includes(":") && IPV6.test(line))) value.ips.push(line);
    else if (/^[a-z0-9.-]+$/i.test(line) && line.includes(".")) value.hosts.push(line.toLowerCase());
    else errors.push(line);
  }
  return { value, errors };
}

/** formatExclusions writes the engine's exclusions back as lines. */
export function formatExclusions(ex: unknown): string {
  const e = (ex ?? {}) as Exclusions;
  return [...(e.paths ?? []), ...(e.ips ?? []), ...(e.ports ?? []).map(String), ...(e.hosts ?? [])].join("\n");
}
