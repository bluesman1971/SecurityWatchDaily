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

Keep shared mode disabled until later roadmap controls are complete.

## Options Considered

- Add `argon2-cffi` now: best password-hashing algorithm choice, but would introduce a new dependency without an existing lockfile and is not installed in the current environment.
- Use standard-library PBKDF2-SHA256 now: less ideal than Argon2id, but vetted, available, testable, and avoids dependency drift during this focused phase.
- Add persistent session records now: aligns with the future session roadmap, but expands Phase 2 beyond the minimal mechanism needed for safe login/logout.

## Rationale

PBKDF2-SHA256 is a vetted standard-library password hashing primitive and lets the project implement real authentication without making package installation part of this security patch.

Process-local sessions are server-side, revocable on logout, and sufficient for localhost operation. Durable session storage, timeout policy, rotation policy, and stricter cookie behavior are intentionally left to the dedicated server-side session phase.

## Consequences and Risks

- Existing databases gain a `users` table during initialization.
- Operators must create an admin before using the web UI.
- Sessions do not survive process restarts.
- Password hashing should be revisited when dependency and lockfile management are in place, with Argon2id as the preferred upgrade path.
- Shared mode remains unavailable until CSRF protection, hardened persistent sessions, and deployment settings are complete.
