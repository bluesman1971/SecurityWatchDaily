# Architecture

SecurityWatchDaily is split into small modules so collection, matching, storage, and the web UI can evolve independently.

## Components

- `collectors/`: source-specific fetch and parse logic.
- `services/`: run orchestration, matching, trace suppression, validation support, and import flow.
- `repositories/`: SQLite persistence for platforms, sources, runs, findings, and trace items.
- `web/`: local HTTP server, HTML rendering, and CSS.
- `cli.py`: local commands for setup, scheduled runs, and serving the UI.

## Data Flow

1. Platforms and sources are loaded from SQLite.
2. Enabled sources collect raw vulnerability/advisory items.
3. Matching rules map findings to enabled platforms.
4. Findings are deduplicated by key.
5. Trace state suppresses unchanged findings.
6. Runs and findings are saved for local review.
7. The web UI reads the same database as the CLI.

## Trust Boundary

External source content is untrusted. It is parsed into structured findings and escaped before browser rendering.

The first version is local-only and has no authentication. Do not expose it directly to a network until auth, authorization, CSRF protection, deployment settings, and logging rules are reviewed under the Strict profile.

## Architectural Decisions

### Local-first application

SecurityWatchDaily starts as a local app bound to `127.0.0.1`. This keeps early setup simple and avoids introducing authentication, authorization, hosting, and multi-tenant boundaries before the workflow is proven.

If the app becomes network-hosted, that work should be reviewed under the Strict profile because it changes trust boundaries and introduces user/session/security concerns.

### Standard library web layer for phase 1

The first local web UI uses Python standard library HTTP serving and server-rendered HTML. This avoids dependency and packaging friction while the product shape is still being validated.

The service, repository, collector, and matching layers are framework-neutral so the web layer can later move to FastAPI or another maintained web framework without rewriting the core behavior.

### SQLite as the local system of record

SQLite stores local configuration, run history, findings, trace state, and future asset inventory data. It is easy to run locally, easy to back up, and good enough for a single-team local workflow.

Generated SQLite databases are ignored by Git. Starter configuration lives in tracked files such as `watchlist.json`, while runtime state stays local.

### Source collectors are isolated

Each external advisory source has its own collector module. Collector failures are recorded as source status errors and do not stop the full run.

This prevents one failed vendor feed from hiding successful results from other sources.

### Matching is a service boundary

Finding-to-platform matching is kept outside collectors and the web UI. This keeps matching behavior testable and prevents UI features from duplicating matching logic.

Phase 2 asset matching should extend this boundary rather than adding matching rules directly into route handlers or import code.

### CSV-first asset impact matching for phase 2

Phase 2 should add asset impact matching through CSV import before adding direct inventory connectors. CSV lets teams prove the asset-to-finding workflow with exports from whatever tools they already use.

The internal model should separate assets from asset components so endpoints, installed software, hardware, firmware, operating systems, and services can all be matched against findings.

Planned phase 2 entities:

- `assets`
- `asset_components`
- `product_aliases`
- `finding_products`
- `finding_version_ranges`
- `finding_asset_matches`

The UI should show match confidence rather than treating every product-name match as confirmed impact.

### Connector catalog for phase 3

Phase 3 should add source-of-truth connectors after CSV matching is useful. Teams should be able to pick which systems they use, such as Freshservice, Jamf, Intune, or other asset inventory sources.

Connectors should map external inventory into the same internal asset/component model used by CSV import. Matching should not care whether an asset came from CSV, Freshservice, Jamf, Intune, or another source.

Connector credentials must not be stored in tracked files. Use environment variables or a local secret store and keep connector settings separate from secrets.

### Read-only connector posture

Inventory connectors should be read-only by default. Their job is to pull asset and software/hardware state into SecurityWatchDaily, not to mutate source-of-truth systems.

Connector errors should be actionable. Permission problems, missing modules, tenant-specific endpoint differences, and network failures should be reported distinctly.

### Version-aware matching with confidence

Asset impact matching should prefer structured version-aware comparisons when affected and fixed version ranges are available.

When version data is missing or source advisories are vague, the app should label the result as likely affected, needs review, unknown, or not affected instead of hiding uncertainty.
