# SecurityWatchDaily

SecurityWatchDaily is a local web tool for daily vulnerability monitoring against a customer-managed platform list.

It imports an optional `watchlist.json`, stores editable platforms and sources in SQLite, runs vulnerability checks, suppresses unchanged repeat findings through trace state, and can match findings against a local CSV-backed asset inventory.

## Current Scope

- Local-only web UI for dashboards, platforms, sources, runs, and findings.
- Assets section for CSV inventory import, asset details, and impacted asset views.
- SQLite-backed configuration and run history.
- SQLite-backed assets, asset components, product aliases, finding products, version ranges, and materialized asset matches.
- Source-level error handling so one broken feed does not stop the daily run.
- No credentials, API keys, connector integrations, user accounts, or cloud deployment in the first version.

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

Use **Assets > Import CSV** in the local web UI to upload or paste inventory rows. CSV remains the primary Phase 2 workflow; Freshservice, Jamf, Intune, and other source-of-truth connectors are planned for a later phase.

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
- External source content and imported CSV content are treated as untrusted and escaped before rendering.
- Generated databases, imported customer data, reports, run logs, caches, and trace files are ignored.
- Tests cover matching, validation, normalization, CSV import, version handling, trace suppression, storage, friendly source errors, and practical web flows.

## Before Network Hosting

Do not expose this app directly to a network without a Strict-profile review for authentication, authorization, CSRF protection, deployment settings, logging, and source-secret handling.
