# Changelog

## 0.1.0 - 2026-06-22

### Added

- Local SQLite-backed platform, source, run, finding, and trace storage.
- Local web UI for dashboard, platforms, sources, runs, and findings.
- Local admin authentication with `create-admin`, `/login`, `/logout`, and protected web routes.
- CSV-backed asset inventory import with row and field-level validation errors.
- Asset list, asset detail, finding impacted-asset, and asset related-finding views.
- Product aliases, normalization, version-aware matching, and match confidence labels for asset impact review.
- CLI commands for initialization, validation, sample runs, live runs, summaries, and serving.
- Modular collectors and source-level error reporting.
- Connector Catalog with read-only connector framework, sync health, import-error persistence, Sample Inventory sync, and Freshservice/Jamf/Intune connector shells.
- Microsoft Intune setup UI for non-secret Graph tenant/client metadata, local environment variable names, and test-before-enable guidance.
- Design-system aligned local web UI with paper/ink/red styling, sticky header, hairline rules, flatter panels, and pill actions.
- Pinned Ruff, Semgrep, and pip-audit dev tooling plus CI checks for Ruff, Semgrep, pip-audit, and Gitleaks.
- Tests for matching, validation, normalization, CSV import, version handling, trace suppression, storage, and web flows.

### Security

- Added SQLite-backed admin users with salted password hashes. Plaintext passwords are not stored.
- Added SQLite-backed server-side sessions, CSRF-protected POST forms, same-origin Origin checks, and URL session-ID rejection.
- Kept shared mode disabled by default and fail-closed for `--shared` until secure HTTPS or reverse-proxy deployment settings are designed.
- Added SSRF-safe external HTTP fetches with blocked internal address ranges, redirect blocking, response-size caps, and request timeouts.
- Added safe web error handling so unexpected failures do not render exception details, internal paths, credentialed URLs, or token-like values.
- Added restrictive browser security headers on HTML responses.
- Hardened CSV asset imports with row-count limits, consistent field-length limits, malformed multipart rejection, and repeated-field rejection.
- Added local SQLite audit events for security-sensitive web actions without logging passwords, session tokens, CSRF tokens, API keys, bearer tokens, client secrets, or connector credential values.
