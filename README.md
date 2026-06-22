# SecurityWatchDaily

SecurityWatchDaily is a local web tool for daily vulnerability monitoring against a customer-managed platform list.

It imports an optional `watchlist.json`, stores editable platforms and sources in SQLite, runs vulnerability checks, suppresses unchanged repeat findings through trace state, and can match findings against a local CSV-backed asset inventory.

## Current Scope

- Local-only web UI for dashboards, platforms, sources, runs, findings, and inventory connectors.
- Assets section for CSV inventory import, asset details, and impacted asset views.
- Connector Catalog with read-only source-of-truth inventory connector status, test, and sync actions.
- SQLite-backed configuration and run history.
- SQLite-backed assets, asset components, product aliases, finding products, version ranges, materialized asset matches, connector status, sync runs, import errors, and connector asset mappings.
- Source-level error handling so one broken feed does not stop the daily run.
- No stored credentials, user accounts, or cloud deployment in the first version.

## Run Locally

```bash
python3 -m securitywatchdaily init
python3 -m securitywatchdaily run --sample --force-visible
python3 -m securitywatchdaily serve
```

Open `http://127.0.0.1:8765`.

If that port is busy, choose another:

```bash
python3 -m securitywatchdaily serve --port 8876
```

## Useful Commands

```bash
python3 -m securitywatchdaily validate
python3 -m securitywatchdaily summary
python3 -m securitywatchdaily run
```

Use `run --sample` to validate the local workflow without relying on network access.

## CSV Asset Inventory

Use **Assets > Import CSV** in the local web UI to upload or paste inventory rows. CSV remains the primary fallback and troubleshooting workflow even when connectors are enabled.

For a step-by-step walkthrough, see [instructions.md](instructions.md). A safe example inventory is available at [sample_asset_inventory.csv](sample_asset_inventory.csv).

Template:

```csv
hostname,owner,location,asset_type,vendor,product,version,platform,last_seen,component_type
```

Notes:

- `hostname` and `product` are required.
- `last_seen` uses `YYYY-MM-DD` when provided.
- One row represents one asset component. Re-importing a hostname replaces that asset's component list.
- Product aliases normalize common variants such as `Windows 11 Pro`, `Microsoft Windows 11`, `PANOS`, and `PAN-OS`.
- Impact confidence labels are `confirmed affected`, `likely affected`, `needs review`, `not affected`, and `unknown`.

## Inventory Connectors

Use **Connectors** in the local web UI to view available inventory connectors, enable or disable them, test setup, and run syncs. Phase 3 starts with a working **Sample Inventory** connector that imports deterministic fixture assets into the same asset/component model used by CSV import.

Freshservice, Jamf, and Microsoft Intune are present as read-only connector shells with setup validation and actionable errors. Credentials are read from local environment variables and are not stored in SQLite, rendered in the browser, or committed.

Connector setup variables:

```bash
FRESHSERVICE_TENANT_URL=https://yourdomain.freshservice.com
FRESHSERVICE_API_KEY=local-api-key
FRESHSERVICE_TEST_PATH=/api/v2/assets
JAMF_BASE_URL=https://yourcompany.jamfcloud.com
INTUNE_TENANT_ID=tenant-id
INTUNE_CLIENT_ID=client-id
```

Freshservice `403` means the API key authenticated but is not authorized for the requested module. Freshservice `404` usually means the tenant-specific endpoint path does not match. Intune live sync is intentionally deferred until Microsoft Graph OAuth and tenant consent are designed.

## Planning Docs

- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)
- [Operations](docs/operations.md)

## Tests

```bash
python3 -m compileall -q securitywatchdaily tests
python3 -m unittest discover -s tests -v
```

## Repository Standards

- Local web binding defaults to `127.0.0.1`.
- User-editable platform and source inputs are validated before saving.
- External source content, connector data, and imported CSV content are treated as untrusted and escaped before rendering.
- Generated databases, imported customer data, reports, connector logs, run logs, caches, and trace files are ignored.
- Tests cover matching, validation, normalization, CSV import, connector status and sync flows, version handling, trace suppression, storage, friendly source errors, and practical web flows.

## Before Network Hosting

Do not expose this app directly to a network without a Strict-profile review for authentication, authorization, CSRF protection, deployment settings, logging, and source-secret handling.
