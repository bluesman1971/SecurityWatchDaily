# Security Roadmap

## Purpose

SecurityWatchDaily is currently designed as a local-first web tool. If it will run on a non-loopback address, even on a trusted local network, the trust boundary changes. The app becomes a shared control surface for vulnerability findings, asset inventory, connector metadata, local configuration, and outbound network activity.

This roadmap defines the work required before non-loopback use is considered secure enough to support.

## Security Goal

Enable shared local-network use without exposing unauthenticated control paths, cross-site request forgery, server-side request forgery, secret leakage, unsafe error output, or avoidable browser-side attack surface.

## Acceptance Criteria

Shared mode is ready only when all of the following are true:

- Non-loopback binding is blocked unless an explicit shared mode is enabled.
- Shared mode fails closed unless authentication is configured.
- All protected routes require a valid authenticated server-side session.
- All state-changing POST routes require CSRF validation.
- POST requests validate same-origin requests with an Origin check.
- Session cookies are hardened.
- External HTTP fetches block loopback, private, link-local, multicast, and metadata addresses.
- External HTTP fetches enforce response size and timeout limits.
- Error pages do not expose internal exception details.
- Browser security headers are present on HTML responses.
- Upload parsing is bounded and tested.
- Security-sensitive actions produce local audit events without logging secrets.
- Tests cover allow and deny paths for auth, CSRF, SSRF, sessions, and unsafe shared-mode configuration.

## Phase 1: Shared-Mode Gate

Goal: make unsafe network binding impossible by accident.

Implementation:

- Keep `127.0.0.1` as the default host.
- Reject `0.0.0.0`, `::`, and non-loopback LAN addresses unless an explicit `--shared` flag is passed.
- Require authentication configuration before `--shared` can start.
- Require HTTPS or an explicitly documented reverse-proxy mode before shared mode can start.
- Print a clear startup warning in shared mode that names the bind address and expected URL.

Example target command:

```bash
python3 -m securitywatchdaily serve --host 0.0.0.0 --shared
```

Tests:

- Non-loopback bind is rejected without `--shared`.
- Shared mode is rejected when auth is not configured.
- Loopback mode still works without shared-mode configuration.

## Phase 2: Authentication

Goal: require real identity before users can view or modify local security data.

Implementation:

- Add a `users` table with username, password hash, role, timestamps, and last login time.
- Add a bootstrap command such as `python3 -m securitywatchdaily create-admin`.
- Store only password hashes, never plaintext passwords.
- Prefer Argon2id through a vetted package such as `argon2-cffi`; verify the package before adding it.
- Add `/login` and `/logout`.
- Protect every route except `/login`, static CSS, and a minimal health endpoint if needed.
- Start with one role, `admin`, unless a read-only role is explicitly needed.

Tests:

- Valid admin login succeeds.
- Invalid password fails.
- Unknown username fails.
- Protected GET routes reject unauthenticated users.
- Protected POST routes reject unauthenticated users.
- Logout invalidates access.

## Phase 3: Server-Side Sessions

Goal: avoid client-side trust and keep session revocation simple.

Implementation:

- Add a `sessions` table.
- Generate cryptographically random session tokens.
- Store only a hash of each session token.
- Regenerate the session token on login.
- Invalidate sessions on logout.
- Enforce idle and absolute timeouts.
- Reject session IDs in URLs.
- Use hardened cookies:
  - `HttpOnly`
  - `SameSite=Strict`
  - `Secure` in HTTPS or shared mode
  - path scoped to the app

Suggested initial timeouts:

- Idle timeout: 8 hours.
- Absolute timeout: 24 hours.

Tests:

- Session cookie is issued on login.
- Session token is not accepted after logout.
- Expired sessions are rejected.
- Session token is rotated on login.
- Cookie flags are present.

## Phase 4: CSRF Protection

Goal: prevent drive-by websites from submitting forms to a user's local or shared SecurityWatchDaily instance.

Implementation:

- Generate a CSRF token per authenticated session.
- Render the token as a hidden input in every POST form.
- Validate the token before dispatching any POST action.
- Validate the `Origin` header for POST requests.
- Accept only the configured same-origin app URL.
- Return `403` for missing, invalid, or cross-origin POSTs.

Routes that require CSRF coverage:

- `/platforms`
- `/platforms/toggle`
- `/sources`
- `/sources/toggle`
- `/run-now`
- `/run-sample`
- `/assets/import`
- `/connectors/toggle`
- `/connectors/test`
- `/connectors/sync`
- `/connectors/intune/settings`
- `/admin/users`
- `/admin/users/delete`
- `/logout`

Tests:

- Each protected POST rejects missing CSRF.
- Each protected POST rejects invalid CSRF.
- Each protected POST rejects bad Origin.
- Valid authenticated same-origin POST succeeds.
- Login remains available without CSRF until a pre-auth token flow is designed.

## Phase 5: SSRF-Safe HTTP Client

Goal: prevent configured sources and connector checks from reaching internal services unintentionally.

Implementation:

- Create one safe HTTP client wrapper for collectors and connector checks.
- Allow only `https` by default for external sources.
- Resolve hostnames before connecting.
- Block:
  - loopback addresses
  - RFC1918 private ranges
  - link-local ranges
  - multicast ranges
  - IPv6 unique-local and link-local ranges
  - cloud metadata endpoints such as `169.254.169.254`
- Disable redirects or revalidate every redirect target.
- Enforce connection and read timeouts.
- Enforce a maximum response size.
- Return safe, actionable fetch errors.
- Prefer known built-in source defaults over arbitrary custom URLs.

Tests:

- `127.0.0.1`, `localhost`, and `[::1]` are blocked.
- RFC1918 addresses are blocked.
- Link-local and metadata addresses are blocked.
- DNS names resolving to blocked ranges are blocked.
- Redirects to blocked ranges are blocked.
- Oversized responses fail safely.
- Valid public HTTPS sources still work.

## Phase 6: Response Size and Runtime Limits

Status: external HTTP response size and timeout limits are implemented. CSV upload row-count hardening remains deferred
to the upload and multipart hardening phase.

Goal: prevent malicious or broken feeds from exhausting memory, CPU, or worker threads.

Implementation:

- Replace full-body `response.read()` calls with capped chunked reads.
- Set per-source response size limits.
- Set per-source timeouts.
- Consider a total run deadline for live checks.
- Keep CSV upload size limits and add row-count limits.

Suggested initial limits:

- External feed response size: 5 MB.
- External request timeout: 10-20 seconds.
- CSV upload size: keep the current 2 MB cap unless real imports require more.
- CSV row count: choose a documented limit based on expected local inventory size.

Tests:

- Oversized HTTP response is rejected.
- Slow or timing-out source fails without stopping the full run.
- Oversized CSV import is rejected.
- Excessive row count is rejected with an actionable message.

## Phase 7: Safer Error Handling

Status: implemented. Malformed asset and finding route IDs fail with safe client errors, invalid numeric platform form
fields return actionable validation messages, and unexpected web handler failures render a generic 500 page without
exception details.

Goal: keep implementation details out of browser responses.

Implementation:

- Validate route IDs before converting them to integers.
- Return safe `400` or `404` pages for malformed route IDs.
- Validate numeric form fields through helpers that raise safe app errors.
- Render generic `500` pages for unexpected failures.
- Log detailed exceptions only locally.
- Never log secrets, session tokens, CSRF tokens, API keys, bearer tokens, or client secrets.

Tests:

- `/assets/not-an-int` returns safe `404` or `400`.
- `/findings/not-an-int` returns safe `404` or `400`.
- Invalid `minimum_cve_year` returns a validation error.
- Unexpected errors do not render exception type or stack details.

## Phase 8: Browser Security Headers

Status: implemented. HTML responses include a strict self-only CSP, `no-store` caching, `nosniff`, and no-referrer
headers. Static CSS keeps its content type and `nosniff` behavior.

Goal: reduce browser-side exploitability if a rendering bug is introduced later.

Implementation:

- Add security headers to HTML responses:

```text
Content-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store
```

- Keep CSP strict. Avoid adding inline scripts unless the CSP is updated deliberately and tested.

Tests:

- Core HTML routes include the required headers.
- Static assets keep appropriate content type and nosniff behavior.

## Phase 9: Upload and Multipart Hardening

Goal: remove brittle upload parsing behavior before shared use.

Implementation:

- Replace custom multipart parsing with a standard parser, or strictly constrain accepted multipart input.
- Keep upload size limits.
- Add row-count limits.
- Add max field length checks consistently for all asset fields.
- Validate repeated fields deterministically.

Tests:

- Empty file plus pasted CSV behaves predictably.
- Repeated fields do not bypass validation.
- Malformed multipart boundaries are rejected safely.
- Unusual filenames do not affect parsing or storage.

## Phase 10: Audit Logging

Goal: give operators a local trail of security-sensitive actions without collecting secrets.

Implementation:

- Add local audit events for:
  - login success
  - login failure
  - logout
  - source create and toggle
  - platform create and toggle
  - connector enable, test, sync, and settings changes
  - asset import
  - live run trigger
- Include timestamp, action, username, result, and safe request context.
- Exclude passwords, password hashes, session IDs, CSRF tokens, API keys, bearer tokens, client secrets, and full connector credentials.

Tests:

- Security-sensitive actions write audit events.
- Failed auth attempts write audit events without sensitive data.
- Audit logs do not contain session or CSRF token values.

## Documentation Work

Required docs:

- Update `README.md` with shared-mode setup and warnings.
- Update `docs/operations.md` with secure shared deployment steps.
- Update `docs/architecture.md` with the new trust boundary, auth/session flow, and SSRF-safe fetch boundary.
- Add an ADR under `docs/decisions/` for shared local-network mode and authentication.
- Update `CHANGELOG.md` under `Security` when implementation lands.

## Suggested Delivery Order

1. Shared-mode gate.
2. Authentication and server-side sessions.
3. CSRF and Origin checks.
4. SSRF-safe HTTP client and response caps.
5. Safer route/form validation and error handling.
6. Security headers.
7. Multipart/upload hardening.
8. Audit logging.
9. Documentation and ADR.
10. Full security regression test pass.

## Release Gate

Do not document non-loopback serving as supported until the release includes:

- passing auth/session tests,
- passing CSRF tests,
- passing SSRF tests,
- passing full unit and web tests,
- updated operations documentation,
- an ADR for the shared-mode trust boundary,
- and a final security review confirming no known high or critical issues remain for shared local-network use.
