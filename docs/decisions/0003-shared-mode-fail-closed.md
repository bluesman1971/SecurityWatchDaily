# 0003 Shared Mode Fails Closed Until Secure Deployment

## Status

Accepted

## Date

2026-06-22

## Context

SecurityWatchDaily is local-first, but the CLI exposes an explicit `--shared` flag for future non-loopback use. The security roadmap has now added authentication, server-side sessions, CSRF and Origin checks, SSRF-safe fetches, response limits, safe error handling, browser security headers, upload hardening, and local audit events.

Shared network use still changes the trust boundary. The remaining unresolved deployment question is how operators should provide HTTPS directly or through a reviewed reverse proxy, including cookie `Secure` behavior and the expected public URL/origin.

## Decision

Keep non-loopback local mode rejected unless `--shared` is provided, and keep `--shared` itself fail-closed until HTTPS or reverse-proxy deployment settings are designed, documented, and tested.

Do not document shared local-network serving as supported yet. Documentation may describe that the flag exists and intentionally fails closed.

## Options Considered

- Enable shared mode now after the app hardening phases: rejected because secure deployment settings are still not designed.
- Support only reverse-proxy deployments: promising, but needs explicit trusted-origin, HTTPS, cookie, and operator setup documentation.
- Keep shared mode fail-closed: conservative and reversible while preserving the CLI shape for future work.

## Rationale

Authentication and request hardening reduce application-layer risk, but non-loopback serving also needs a clear transport and origin model. Failing closed prevents operators from accidentally relying on an incomplete shared-mode configuration.

## Consequences and Risks

- Local loopback use remains supported.
- `python3 -m securitywatchdaily serve --host 0.0.0.0 --shared` continues to fail with an actionable message.
- A future shared-mode slice must define HTTPS or reverse-proxy setup, cookie `Secure` behavior, expected origin handling, operator warnings, and tests before enabling non-loopback serving.
