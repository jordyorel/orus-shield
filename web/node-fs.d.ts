// The two functions of node:fs that vite.config.ts uses (local HTTPS
// certificates), declared here instead of adding @types/node.
declare module "node:fs" {
  export function existsSync(path: string): boolean;
  export function readFileSync(path: string, encoding: "utf8"): string;
}
