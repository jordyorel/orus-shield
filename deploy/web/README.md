# Security headers of the site and the dashboard (production)

The API sets its own headers (`engine/internal/api/server.go`: JSON only,
`default-src 'none'`). The site and the dashboard are static files built by
Vite (`web/dist`), served by the reverse proxy, which must add the headers
below. `Caddyfile` is a ready example; any proxy works with the same values.

## Content-Security-Policy

```
default-src 'self';
script-src 'self' https://cdn.paddle.com;
style-src 'self';
img-src 'self' data:;
font-src 'self';
connect-src 'self' https://*.paddle.com;
frame-src https://*.paddle.com;
worker-src 'self' blob:;
object-src 'none';
base-uri 'none';
form-action 'self';
frame-ancestors 'none';
upgrade-insecure-requests
```

Why each source:

- `script-src 'self'`: our bundle only; no inline script anywhere (the
  build inlines nothing, `assetsInlineLimit: 0`). `https://cdn.paddle.com`:
  Paddle.js, loaded on the payment page only (`web/src/ui/paddle.ts`).
- `style-src 'self'`: our stylesheets. React sets `style={...}` through the
  DOM, which CSP allows. Scalar (`/docs/api`) inserts two `<style>` elements
  (its default theme and its toasts) that this refuses, harmlessly: our
  variables replace its theme.
- `img-src data:`: small SVG icons inlined by CSS.
- `connect-src` and `frame-src https://*.paddle.com`: Paddle's checkout
  (card fields in Paddle's iframe; card numbers never reach us).
- `worker-src blob:`: Scalar's search may start a worker from a blob.
- `frame-ancestors 'none'`: no one may frame the dashboard (clickjacking).
- `form-action 'self'`, `base-uri 'none'`, `object-src 'none'`: classic
  injection footholds closed.

No Google Fonts, analytics or third-party script: the privacy policy
promises none, and this CSP enforces it.

## Other headers

```
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(self "https://*.paddle.com")
Cross-Origin-Opener-Policy: same-origin-allow-popups
```

Add `preload` to HSTS once the product domain and every subdomain serve
HTTPS for good. `same-origin-allow-popups`: "Factures et paiement" opens
Paddle's portal in a new tab.

## The API behind the proxy

Set `ORUS_TRUSTED_PROXIES` to the proxy's address on the API: the per-address
limits (logins, signups, the public test) then count clients, not the proxy.
The proxy must set `X-Forwarded-For` itself (Caddy does by default).
