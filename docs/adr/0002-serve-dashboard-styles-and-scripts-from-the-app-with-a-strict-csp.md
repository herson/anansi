# ADR-0002: Serve dashboard styles and scripts from the app with a strict CSP

## Status

Accepted

## Date

2026-11-17

## Context

`web/templates/index.html` loads `https://cdn.tailwindcss.com`, Tailwind's "Play CDN". The script is unversioned and has no Subresource Integrity (SRI) hash. It generates CSS in the browser at runtime, and Tailwind documents it as unsuitable for production.

Any script on the page can read the dashboard's data and send authenticated requests. That includes scan results, which show the network's weak points, and the start-scan action. A compromise of the CDN or of the domain would therefore give an attacker control of the dashboard.

The page also uses an inline `<script>` block and an `onclick=` attribute. These rule out a Content Security Policy (CSP) that blocks injected scripts.

The dashboard is small: one page (plus the login page from ADR-0001), two tables, a form and a progress bar. The project is Python-only and has no Node toolchain.

## Decision Drivers

- No third-party code runs in a page that can start scans.
- Allow a CSP of `script-src 'self'`, so an injected script cannot run even if template escaping is ever bypassed.
- Do not add a Node toolchain or a generated artifact to a Python project.
- Keep the current look.

## Options Considered

### Option 1: Pin a versioned Tailwind browser build with SRI

Load a versioned file (for example from jsDelivr) with an `integrity` hash.

- **Good:** smallest change.
- **Bad:** it is still third-party code running in the page, and still a runtime CSS generator that Tailwind says not to use in production. Its injected styles need `style-src 'unsafe-inline'`, which weakens the CSP.

### Option 2: Build Tailwind CSS with the Tailwind CLI

Compile only the classes the templates use into a static CSS file, either in a multi-stage Docker build or as a committed file.

- **Good:** keeps the utility-class workflow, and no third-party code runs at runtime.
- **Bad:** adds a Node (or standalone-binary) toolchain to CI, Docker and contributor setup. The alternative, a committed generated file, breaks the "no generated files in git" rule.

### Option 3: A small hand-written stylesheet and script served from `/static`

Move the styles to `web/templates/static/app.css`, using a handful of semantic classes, and the script to `static/app.js`, wired up with `addEventListener` instead of `onclick=`. Send `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` on every response.

- **Good:** no third-party code, no build step and no toolchain. Allows the strictest useful CSP. The CSS is roughly 100 lines, small enough to review.
- **Bad:** we lose Tailwind's utility classes, so future styling means writing CSS by hand.

## Decision

We will use **Option 3**. For a page this size, a short stylesheet is less to maintain than either a pinned runtime generator or a build toolchain. It is also the only option that both removes third-party code and allows a CSP without `'unsafe-inline'`. If the dashboard grows into a real frontend (the roadmap mentions React), the frontend's own build step should replace this, and that will be a new ADR.

## Consequences

### Positive

- The dashboard runs only code served by Anansi. A CDN outage or compromise can't affect it.
- Injected markup can't execute scripts, even if a template escaping bug slips in. This is defence in depth on top of Jinja2 autoescaping, which matters because nmap banners come from the scanned hosts.
- Clickjacking is blocked by `frame-ancestors 'none'`.

### Negative / Trade-offs

- New styling needs hand-written CSS rather than utility classes.
- Every page must follow the CSP: no inline scripts, styles or event-handler attributes.

### Risks

- A missed inline style or handler fails silently in the browser, because the CSP blocks it. Tests assert that the CSP header is sent and that templates contain no inline `<script>` bodies or `on*=` attributes.

## Links

- Roadmap item S5 (`ROADMAP.md`, Audit Remediation, Phase 2)
- Related: [ADR-0001](0001-require-a-session-backed-api-key-for-every-dashboard-and-api-route.md)
