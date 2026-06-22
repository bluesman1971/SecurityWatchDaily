# 0002 Local Admin Authentication

## Status

Accepted

## Date

2026-06-22

## Context

SecurityWatchDaily needs real authentication before shared network use can be considered. Phase 2 requires an admin user table, password hashes instead of plaintext passwords, login/logout routes, and protection for existing web routes.

The project currently has no dependency lock file and primarily uses the Python standard library. `argon2-cffi` was checked locally and is not installed in the current environment.

## Decision

Add a `users` table with username, password hash, role, timestamps, and last login time. Start with one role: `admin`.

Use `python3 -m securitywatchdaily create-admin` to bootstrap a local admin. The command prompts for a password by default and supports `--password-stdin` for scripted local setup.

Store password hashes as encoded PBKDF2-SHA256 records with per-user random salts and iteration metadata. Store no plaintext passwords.

Use process-local server-side session tokens for Phase 2 login/logout. The token value is placed in an `HttpOnly`, `SameSite=Lax` cookie and validated against server memory on protected requests.

Phase 3 update: replace process-local sessions with a SQLite `sessions` table. Generate a cryptographically random cookie token on login, store only its SHA-256 hash, delete prior admin sessions when issuing a new login session, validate the token hash on every protected request, delete the active session on logout, enforce an 8-hour idle timeout and 24-hour absolute timeout, and reject session identifiers in URLs. Session cookies are now `HttpOnly`, `SameSite=Strict`, scoped to `/`, and omit `Secure` while the supported deployment remains localhost HTTP.

Phase 4 update: generate one CSRF token per authenticated session and store it with the server-side session record. Render that token as a hidden input in authenticated POST forms, including logout and admin user actions. Validate same-origin local `Origin` headers and CSRF tokens before dispatching authenticated POST actions. Keep `/login` outside CSRF enforcement until a pre-authentication CSRF flow is designed.

Admin-management update: keep the single `admin` role, but allow authenticated admins to add and delete other local admin users from `/admin/users`. Deleting a user removes that user's active sessions. The web UI prevents deleting the currently authenticated account so an operator cannot accidentally remove their own active access.

Phase 10 update: write local SQLite audit events for authentication, admin-user changes, platform and source changes, asset imports, connector actions, and run triggers. Audit events include timestamp, action, username, result, and safe request context. They exclude passwords, password hashes, session IDs, CSRF tokens, API keys, bearer tokens, client secrets, and connector credential values.

Keep shared mode disabled until later roadmap controls are complete.

## Options Considered

- Add `argon2-cffi` now: best password-hashing algorithm choice, but would introduce a new dependency without an existing lockfile and is not installed in the current environment.
- Use standard-library PBKDF2-SHA256 now: less ideal than Argon2id, but vetted, available, testable, and avoids dependency drift during this focused phase.
- Add persistent session records now: aligns with the future session roadmap, but expands Phase 2 beyond the minimal mechanism needed for safe login/logout.
- Keep process-local sessions after Phase 3: simpler, but fails the roadmap goal for durable server-side session revocation, timeout policy, and hardened cookie behavior.
- Keep user creation CLI-only: simpler, but makes routine local admin turnover awkward after the first bootstrap account exists.
- Require CSRF on `/login` in Phase 4: stronger consistency, but needs a clean pre-auth token design. The current Phase 4 keeps login working without CSRF and protects authenticated state-changing routes first.

## Rationale

PBKDF2-SHA256 is a vetted standard-library password hashing primitive and lets the project implement real authentication without making package installation part of this security patch.

Process-local sessions were server-side, revocable on logout, and sufficient for the initial localhost authentication phase. Phase 3 moves the session policy into SQLite so revocation, rotation, and timeout behavior are durable and testable without trusting client-side session state.

The CSRF token is separate from the session cookie token. The session cookie token is never rendered into HTML or stored raw in SQLite. The CSRF token is intentionally renderable because the server needs to place it in authenticated forms and compare it on POST.

## Consequences and Risks

- Existing databases gain a `users` table during initialization.
- Operators must create an admin before using the web UI.
- Sessions survive process restarts until logout, idle expiry, absolute expiry, user deletion, or replacement by a later login.
- The `sessions` table stores token hashes, CSRF tokens, timestamps, and user references; raw session tokens remain browser-only.
- Admin user deletion invalidates that user's active sessions.
- Password hashing should be revisited when dependency and lockfile management are in place, with Argon2id as the preferred upgrade path.
- Authenticated POSTs without a same-origin local `Origin` header and valid CSRF token now fail with `403`.
- Security-sensitive web actions now leave a local audit trail without storing authentication tokens or connector secrets.
- Shared mode remains unavailable until later roadmap prerequisites and secure deployment settings are complete.
