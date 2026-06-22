# Changelog

## 0.1.0 - 2026-06-22

### Added

- Local SQLite-backed platform, source, run, finding, and trace storage.
- Local web UI for dashboard, platforms, sources, runs, and findings.
- CSV-backed asset inventory import with row and field-level validation errors.
- Asset list, asset detail, finding impacted-asset, and asset related-finding views.
- Product aliases, normalization, version-aware matching, and match confidence labels for asset impact review.
- CLI commands for initialization, validation, sample runs, live runs, summaries, and serving.
- Modular collectors and source-level error reporting.
- Connector Catalog with read-only connector framework, sync health, import-error persistence, Sample Inventory sync, and Freshservice/Jamf/Intune connector shells.
- Microsoft Intune setup UI for non-secret Graph tenant/client metadata, local environment variable names, and test-before-enable guidance.
- Design-system aligned local web UI with paper/ink/red styling, sticky header, hairline rules, flatter panels, and pill actions.
- Tests for matching, validation, normalization, CSV import, version handling, trace suppression, storage, and web flows.
