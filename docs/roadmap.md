# Roadmap

SecurityWatchDaily should grow in phases so each step is useful on its own and does not require teams to adopt a full CMDB or integration stack before they get value.

## Phase 1: Local Vulnerability Watch

Status: in progress in the first PR.

Goal: help IT teams see new or changed security advisories for the platforms they manage.

Included:

- Local web UI for dashboard, platforms, sources, runs, and findings.
- SQLite-backed platforms, sources, run history, findings, and trace state.
- Source collectors for MSRC, CISA KEV, Ubuntu USN, Palo Alto advisories, and Hacker News CVE signals.
- Trace suppression so unchanged findings do not repeat every day.
- Source-level error handling so one broken feed does not stop a run.
- CLI commands for setup, scheduled runs, validation, summaries, and serving the local UI.

Next refinements:

- Improve MSRC endpoint handling and source health detail.
- Add editable source test buttons in the UI.
- Add filtering and search on findings.
- Add explicit false-positive and reviewed states.

## Phase 2: CSV-Based Asset Impact Matching

Goal: let IT teams upload or maintain a list of assets and quickly see which findings might affect their organization.

Decision: start with CSV import instead of direct integrations. CSV is the lowest-friction path for proving the workflow across many teams and inventory sources.

Core capabilities:

- Add an Assets section with CSV import, asset list, and asset detail pages.
- Support a documented CSV template with fields such as hostname, owner/team, location, asset type, vendor, product, version, and last seen date.
- Store imported assets and installed software/hardware details in SQLite.
- Normalize vendor, product, and version values so messy inventory names can map to watched platforms.
- Add product aliases for common naming variants such as `PANOS`, `PAN-OS`, `Windows 11 Pro`, and `Microsoft Windows 11`.
- Enrich findings with affected product and version-range data where sources provide it.
- Allow manual affected-version enrichment when a source advisory is vague or unstructured.
- Match findings to assets by vendor, product, version, and platform rules.
- Show match confidence labels: confirmed affected, likely affected, needs review, not affected, and unknown.
- Add impacted asset views from both directions: finding to assets and asset to findings.
- Add inventory quality checks for missing versions, stale assets, unknown products, and unmatched watched platforms.

Suggested Phase 2 data model:

- `assets`: one row per managed device or service.
- `asset_components`: software, hardware, firmware, operating systems, packages, or services installed on an asset.
- `product_aliases`: raw inventory names mapped to normalized vendor/product names.
- `finding_products`: products believed to be affected by a finding.
- `finding_version_ranges`: affected and fixed version ranges when known.
- `finding_asset_matches`: materialized match results with confidence and review state.

Phase 2 acceptance criteria:

- A team can import a CSV, run the daily watch, and see potentially impacted assets.
- Version-aware matching is available when affected-version data exists.
- Unknown or missing version data is visible rather than silently treated as safe.
- The UI explains why each asset matched a finding.
- CSV import errors are actionable and identify the row/field that needs attention.

## Phase 3: Source-Of-Truth Connectors

Status: started with a local connector framework, catalog UI, health model, sample inventory connector, and read-only Freshservice/Jamf/Intune connector shells.

Goal: let teams choose the inventory systems they actually use and keep asset data refreshed without manual CSV exports.

Decision: connectors come after CSV impact matching. The matching model should be proven with CSV before adding vendor-specific auth, API limits, schemas, and permissions.

Candidate connectors:

- Freshservice for ITSM/ITAM assets and software inventory.
- Jamf for macOS and iOS devices, installed applications, and OS versions.
- Microsoft Intune for managed endpoints, operating system versions, and detected applications.
- Additional sources of truth such as Lansweeper, ServiceNow, Defender, Tenable, Qualys, Rapid7, Meraki, or custom CSV/SFTP drops.

Core capabilities:

- Add a Connector Catalog where teams select the systems they use.
- Keep connectors disabled until explicitly configured.
- Store connector settings separately from secrets.
- Use environment variables or a local secret store for credentials.
- Add connector test buttons with clear permission and endpoint errors.
- Track last successful sync, last failed sync, and sync counts.
- Normalize imported assets through the same Phase 2 product alias and matching pipeline.
- Preserve CSV import as a fallback and troubleshooting path.

Connector design rules:

- Connectors are read-only by default.
- Connector failures must not break vulnerability collection.
- Each connector maps external data into the same internal asset/component model.
- Tenant-specific endpoint paths must be configurable when vendor APIs vary.
- Permission errors should be explained as permission/configuration problems, not generic network failures.

Phase 3 acceptance criteria:

- Teams can enable one or more connectors based on their environment.
- Connector syncs update the asset/component inventory without changing matching logic.
- The UI shows sync health and actionable errors.
- No connector secrets are committed, logged, or rendered in the browser.

First vertical slice:

- `Sample Inventory` proves connector sync, health/status persistence, import-error persistence, asset/component import, external-ID mapping, and asset-match refresh without external credentials.
- Freshservice validates environment setup and can perform a read-only endpoint check when `FRESHSERVICE_TEST_PATH` is supplied. Tenant-specific asset/software sync remains deferred until the correct endpoint paths and permissions are confirmed.
- Jamf is cataloged as a read-only connector shell with setup guidance. Intune now has a setup page for non-secret Microsoft Graph tenant/client metadata and local env-var names; live sync is deferred until Microsoft Graph OAuth and tenant consent are implemented.

## Later Possibilities

- Team ownership workflows and assignment.
- Notifications for confirmed or likely impacted assets.
- CSV export of impacted asset reports.
- Review states such as accepted risk, patched, ignored, and needs owner validation.
- Multi-user authentication and role-based access if the app moves beyond local-only use.
- Hosted deployment after a Strict-profile architecture and security review.
