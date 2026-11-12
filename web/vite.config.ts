import react from "@vitejs/plugin-react";
import { existsSync, readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";

// The dashboard and the API share one origin: in development Vite relays
// /api to the Go server, so the session cookie (Secure, SameSite=Lax,
// __Host- prefix) and the API's cross-origin protection work unchanged.
// The Host header is kept (no changeOrigin): the API sees a same-origin
// request from the browser, as it will in production.
// Node's process, declared here instead of adding @types/node for one line.
declare const process: { env: Record<string, string | undefined> };
const api = process.env.ORUS_API_URL ?? "http://127.0.0.1:8080";

// Local HTTPS, when a certificate exists in web/.certs (git-ignored; made
// by deploy/dev-https.sh with mkcert). Safari refuses Secure cookies on
// http://localhost, so the session only holds over HTTPS there; the other
// browsers accept both.
const cert = ".certs/localhost.pem";
const key = ".certs/localhost-key.pem";
const https = existsSync(cert) && existsSync(key) ? { cert: readFileSync(cert, "utf8"), key: readFileSync(key, "utf8") } : undefined;

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    ...(https ? { https } : {}),
    proxy: { "/api": { target: api } },
  },
  build: {
    // No inline scripts or styles in index.html: the production CSP has no
    // 'unsafe-inline'.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
  },
});
