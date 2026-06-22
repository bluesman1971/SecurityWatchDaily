# Security Review Report - 2026-06-22

## Scope

Reviewed SecurityWatchDaily as a red-team code review of the local web UI, CLI entry points, SQLite persistence, external collectors, connector setup, CSV import, and browser-rendered output.

Selected profile: Strict, because the app handles untrusted external vulnerability feeds, untrusted CSV/connector inventory data, local operational data, and a browser-facing control surface.

## Executive Summary

The codebase has good foundations: SQL writes are parameterized, user-facing HTML uses escaping in the reviewed render paths, connector secrets are represented as environment variable names rather than stored secret values, generated local databases are ignored by Git, and the current test suite passes.

The primary risk is that the app is designed as local-only but does not enforce local-only assumptions strongly enough. If a user starts it on `0.0.0.0`, or if a malicious website can reach the local browser session, the app has no authentication, no CSRF protection, and POST routes that can mutate configuration and trigger outbound network calls. That creates a realistic chain into blind SSRF, local data modification, unwanted connector actions, and denial of service.

## Findings

### Critical: No authentication or authorization if the server is bound to a network interface

Evidence:
- The project explicitly says there are "No stored credentials, user accounts, or cloud deployment" in `README.md:15`.
- The CLI accepts arbitrary `--host` input in `securitywatchdaily/cli.py:30-32`.
- `main()` passes that host directly into `serve()` in `securitywatchdaily/cli.py:41-44`.
- `serve()` binds the HTTP server to the provided host in `securitywatchdaily/web/server.py:666-675`.
- POST routes perform state-changing actions without identity checks in `securitywatchdaily/web/server.py:118-147`.

Impact:
Anyone who can reach the bound port can view local platforms, sources, findings, connectors, asset inventory, and connector settings metadata. They can also add sources, toggle platforms/sources/connectors, trigger live runs, import assets, and change Intune connector settings.

Exploit sketch:
1. Operator runs `python3 -m securitywatchdaily serve --host 0.0.0.0`.
2. Attacker on the same network browses to `http://host:8765`.
3. Attacker POSTs to `/sources`, `/run-now`, `/assets/import`, or `/connectors/intune/settings`.

Recommended fix:
- Enforce loopback-only binding by default. Reject non-loopback hosts unless an explicit unsafe flag is provided.
- If non-loopback serving is ever supported, require authentication, authorization, CSRF protection, secure deployment settings, and logging before enabling it.
- Add tests that `serve` or CLI validation rejects `0.0.0.0`, `::`, and non-loopback LAN addresses unless the explicit unsafe mode is present.

### High: Missing CSRF protection on all state-changing POST routes

Evidence:
- All POST routes are dispatched without a CSRF token or Origin/Referer validation in `securitywatchdaily/web/server.py:118-147`.
- The affected actions include running live checks, importing assets, toggling connectors, and saving Intune settings in `securitywatchdaily/web/server.py:130-143`.
- The route methods mutate state or trigger work in `securitywatchdaily/web/server.py:560-663`.

Impact:
Even when bound to `127.0.0.1`, a malicious website visited by the user can submit HTML forms to `http://127.0.0.1:8765`. Same-origin policy prevents reading responses, but it does not prevent blind POSTs. That allows drive-by modification of the local SQLite database and can trigger outbound network requests from the user's machine.

Exploit sketch:
```html
<form method="post" action="http://127.0.0.1:8765/sources">
  <input name="id" value="evil_cisa">
  <input name="name" value="Evil CISA">
  <input name="source_type" value="cisa">
  <input name="url" value="http://127.0.0.1:1/probe">
</form>
<script>document.forms[0].submit()</script>
```

Recommended fix:
- Add per-session CSRF tokens for every POST form and reject missing/invalid tokens.
- Add an Origin check that only accepts same-origin loopback requests.
- Consider setting a local session cookie with `SameSite=Strict` once sessions exist.
- Add negative tests for each high-risk POST route: `/sources`, `/run-now`, `/assets/import`, `/connectors/toggle`, `/connectors/test`, `/connectors/sync`, and `/connectors/intune/settings`.

### High: User-configured source URLs enable blind SSRF

Evidence:
- Source URL validation only checks that the scheme is `http` or `https` and that a netloc exists in `securitywatchdaily/validation.py:47-51`.
- Collectors fetch the configured URL directly in `securitywatchdaily/collectors/http.py:16-21`.
- The source registry allows collectors such as `cisa`, `ubuntu`, `paloalto`, and `hn` to use configured URLs in `securitywatchdaily/collectors/__init__.py:13-23`.
- The run path executes enabled sources in `securitywatchdaily/services/run_service.py:57-65`.
- Freshservice endpoint testing similarly builds and requests a configured URL in `securitywatchdaily/services/connector_service.py:490-504`.

Impact:
An attacker who can write source configuration, either through network exposure or CSRF, can cause the app to request internal services from the user's machine or network. This can be used for blind port probing, hitting localhost-only admin endpoints, cloud metadata access in hosted environments, or interacting with internal HTTP services.

Recommended fix:
- For built-in source types, prefer known source defaults or explicit allowlists.
- Block private, loopback, link-local, multicast, and metadata IP ranges after DNS resolution.
- Re-check the resolved target after redirects or disable redirects for untrusted source URLs.
- Consider separating "trusted built-in source URL" from "custom source URL" and require a local confirmation for custom URLs.
- Add SSRF tests for `127.0.0.1`, `localhost`, `[::1]`, RFC1918 addresses, link-local addresses, and DNS names resolving to blocked ranges.

### Medium: External feed reads are unbounded and can exhaust memory or CPU

Evidence:
- `fetch_text()` reads the entire response body into memory with `response.read()` in `securitywatchdaily/collectors/http.py:20-21`.
- JSON parsing then loads the entire body in `securitywatchdaily/collectors/http.py:39-48`.
- CSV and XML collectors parse the fetched body after the full read.
- CSV upload has a 2 MB POST limit in `securitywatchdaily/web/server.py:149-152`, but external collector responses do not have an equivalent limit.

Impact:
A malicious or compromised feed can return a very large response or slow response that consumes memory, CPU, and worker threads. This is especially risky when combined with attacker-controlled source URLs.

Recommended fix:
- Enforce a maximum response size for all collector HTTP reads.
- Read in chunks and abort once the cap is exceeded.
- Use lower per-source timeouts and possibly a total run deadline.
- Add tests for oversized feed bodies and slow/erroring feeds.

### Medium: Error handling leaks implementation details and can produce unstable responses

Evidence:
- Generic GET exceptions render exception type and message into the page in `securitywatchdaily/web/server.py:115-116`.
- `/assets/<id>` and `/findings/<id>` cast path fragments with `int(...)` before validation in `securitywatchdaily/web/server.py:514` and `securitywatchdaily/web/server.py:539`.
- `minimum_cve_year` is cast directly with `int(...)` in `securitywatchdaily/web/server.py:568`.
- Collector unexpected errors store exception type and message in run source status in `securitywatchdaily/services/run_service.py:64-65`.

Impact:
Malformed paths and malformed form values can expose internal exception details, create noisy terminal logs, and return inconsistent 500 behavior. The current output is escaped, so this is not XSS, but it does make probing and support triage easier for attackers and harder for operators.

Recommended fix:
- Validate route IDs before conversion and return a normal 404 or 400.
- Convert numeric form fields through validation helpers that raise `AppError` with safe messages.
- Render generic user-safe errors while logging detailed exceptions only to local logs.
- Add regression tests for `/assets/not-an-int`, `/findings/not-an-int`, and invalid `minimum_cve_year`.

### Medium: Browser security headers are incomplete for a local control UI

Evidence:
- Responses set `Content-Type`, `X-Content-Type-Options`, and `Referrer-Policy` in `securitywatchdaily/web/server.py:182-187`.
- There is no `Content-Security-Policy`, `frame-ancestors`, `Cache-Control`, or equivalent clickjacking/cache hardening.

Impact:
Escaping is currently doing the heavy lifting. If a future rendering path misses escaping, the absence of CSP makes exploitation easier. Missing frame protection also leaves the UI more exposed to clickjacking-style local attacks if a browser can frame the app.

Recommended fix:
- Add a restrictive CSP, for example default self-only resources and `frame-ancestors 'none'`.
- Add `Cache-Control: no-store` for pages that may render local asset inventory or connector details.
- Add tests that core routes include the expected security headers.

### Low: Custom multipart parsing is brittle

Evidence:
- Multipart parsing is implemented manually in `securitywatchdaily/web/server.py:161-180`.

Impact:
The current upload size cap limits blast radius, but hand-rolled multipart parsing is easy to get wrong with quoted boundaries, unusual encodings, repeated fields, or crafted payloads. This is more reliability/security-hardening debt than an immediate exploit.

Recommended fix:
- Use a standard multipart parser or tightly constrain accepted uploads to one field and document those constraints.
- Add tests for repeated fields, empty file plus pasted CSV, unusual filenames, and malformed multipart boundaries.

## Positive Security Notes

- HTML output consistently uses `esc()` in reviewed dynamic render paths.
- SQL queries use parameters for user-controlled values. Dynamic placeholder lists are derived from integer sets, not direct raw input.
- Connector settings are designed to store environment variable names, not secret values.
- Runtime databases and report/output directories are ignored by `.gitignore`.
- Existing tests cover validation, storage, matching, connector non-secret behavior, HTTP errors, and practical web flows.

## Verification Performed

- `python3 -m compileall -q securitywatchdaily tests` passed.
- `python3 -m unittest discover -s tests -v` initially hit sandbox socket restrictions after 24 tests passed and 6 localhost web tests errored.
- Reran `python3 -m unittest discover -s tests -v` with localhost binding allowed: 30 tests passed.
- Lightweight secret-pattern search found placeholders, documentation examples, env-var names, and test sentinel values. No obvious committed live secret was identified from that search.
- Reviewed `.gitignore`; generated SQLite databases, reports, runs, traces, caches, and virtualenvs are ignored.

## Suggested Fix Order

1. Enforce loopback-only serving and add explicit guardrails around `--host`.
2. Add CSRF protection and Origin checks to every POST route.
3. Add SSRF protections and response-size caps to collector HTTP fetches.
4. Normalize route/form validation and safe error rendering.
5. Add CSP, frame protection, and no-store cache headers.
6. Replace or harden multipart parsing.
