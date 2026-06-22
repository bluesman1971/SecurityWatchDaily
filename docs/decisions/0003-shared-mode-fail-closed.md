# 0003 Shared Mode Requires Explicit Public Origin

## Status

Accepted

## Date

2026-06-22

## Context

SecurityWatchDaily is local-first, but the CLI exposes an explicit `--shared` flag for non-loopback use. The security roadmap has now added authentication, server-side sessions, CSRF and Origin checks, SSRF-safe fetches, response limits, safe error handling, browser security headers, upload hardening, and local audit events.

Shared network use changes the trust boundary. The app needs an explicit browser-facing origin so it can validate POST `Origin` headers and set secure cookie behavior predictably.

## Decision

Keep non-loopback local mode rejected unless `--shared` is provided. Shared mode requires `--public-url` with the exact browser origin.

Require HTTPS public URLs by default. In HTTPS shared mode, session cookies include the `Secure` attribute, and authenticated POST `Origin` headers must exactly match `--public-url`.

Allow a temporary insecure testing override only when an admin explicitly passes `--allow-insecure-shared-testing` with an HTTP loopback public URL. Do not allow plain HTTP public URLs for LAN addresses.

## Options Considered

- Allow any HTTP public URL with `--shared`: rejected because it makes insecure LAN exposure too easy.
- Require HTTPS public URLs only: safest default, but awkward for temporary local proxy testing.
- Allow HTTP only with an explicit loopback testing override: accepted as a narrow escape hatch that cannot be used for LAN shared mode.

## Rationale

Authentication and request hardening reduce application-layer risk, but non-loopback serving also needs a clear transport and origin model. Requiring a configured public URL prevents ambiguous Origin checks. Keeping HTTP override loopback-only lets operators test reverse-proxy wiring locally without normalizing insecure shared-network deployments.

## Consequences and Risks

- Local loopback use remains supported.
- `python3 -m securitywatchdaily serve --host 0.0.0.0 --shared` fails unless `--public-url` is provided.
- HTTPS shared mode sets `Secure` on session cookies.
- Plain HTTP shared testing is available only for loopback public URLs with an explicit testing flag.
- Operators still need to configure their reverse proxy, certificates, and network access controls correctly.
