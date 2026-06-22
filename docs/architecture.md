# Architecture

SecurityWatchDaily is split into small modules so collection, matching, storage, and the web UI can evolve independently.

## Components

- `collectors/`: source-specific fetch and parse logic.
- `services/`: run orchestration, matching, trace suppression, validation support, CSV import, and connector sync flow.
- `repositories/`: SQLite persistence for platforms, sources, runs, findings, trace items, assets, and connector state.
- `auth.py`: local admin user creation, password hashing, and credential verification.
- `web/`: local HTTP server, HTML rendering, and CSS.
- `cli.py`: local commands for setup, scheduled runs, and serving the UI.

## Data Flow

1. Platforms and sources are loaded from SQLite.
2. Enabled sources collect raw vulnerability/advisory items.
3. Matching rules map findings to enabled platforms.
4. Findings are deduplicated by key.
5. Trace state suppresses unchanged findings.
6. Runs and findings are saved for local review.
7. CSV imports and connector syncs map inventory into `assets` and `asset_components`.
8. Finding products and asset matches are refreshed from the saved run data and current inventory.
9. The web UI reads the same database as the CLI.

## Trust Boundary

External source content, connector inventory content, and imported CSV inventory content are untrusted. They are parsed into structured records, validated at import boundaries, stored with parameterized SQLite statements, and escaped before browser rendering.

Connector credentials are secrets. They are read from local environment variables or future local-only secret handling, not stored in SQLite connector settings, committed files, sync runs, import errors, or browser-rendered pages.

The local web UI requires an admin login. Admin passwords are stored only as salted PBKDF2-SHA256 password hashes in SQLite. Web access uses process-local server-side session tokens so logout invalidates the current server process session without storing session tokens in the database.

Do not expose the app directly to a network until CSRF protection, hardened persistent sessions, deployment settings, and logging rules are reviewed under the Strict profile.

## Architectural Decisions

### Local-first application

SecurityWatchDaily starts as a local app bound to `127.0.0.1`. Local admin authentication protects the browser control surface while keeping hosting and multi-tenant boundaries out of scope until the workflow is proven.

If the app becomes network-hosted, that work should be reviewed under the Strict profile because it changes trust boundaries and introduces user/session/security concerns.

### Local admin authentication

The Phase 2 authentication model starts with one role: `admin`. Operators bootstrap the first local admin with `python3 -m securitywatchdaily create-admin`; the CLI prompts for a password and stores only a salted PBKDF2-SHA256 hash.

The standard-library hash design avoids adding a packaging dependency before the project has a dependency lock file. Argon2id remains preferred for a future dependency-backed password-hashing upgrade when package installation and lockfile management are in place.

Sessions are stored in memory by the running web process for this phase. This is enough to require server-side validation on protected routes and revoke access on logout, while leaving durable session records, rotation policy, timeout policy, and hardened cookie behavior to the dedicated server-side session phase.

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

CSV import is intentionally local and bounded. Each row represents one component on one asset, and re-importing a hostname replaces that asset's component list so stale software rows do not silently accumulate.

Planned phase 2 entities:

- `assets`
- `asset_components`
- `product_aliases`
- `finding_products`
- `finding_version_ranges`
- `finding_asset_matches`

The UI should show match confidence rather than treating every product-name match as confirmed impact.

The current matching flow stores normalized product aliases, inferred finding products, optional structured version ranges, and materialized finding-asset matches. Product-only matches are labeled as likely affected, missing asset versions with known ranges are labeled as needs review, and structured version hits can become confirmed affected or not affected.

### Connector catalog for phase 3

Phase 3 should add source-of-truth connectors after CSV matching is useful. Teams should be able to pick which systems they use, such as Freshservice, Jamf, Intune, or other asset inventory sources.

Connectors should map external inventory into the same internal asset/component model used by CSV import. Matching should not care whether an asset came from CSV, Freshservice, Jamf, Intune, or another source.

Connector credentials must not be stored in tracked files. Use environment variables or a local secret store and keep connector settings separate from secrets.

The current connector catalog stores connector metadata and non-secret settings in `connectors`, sync attempts in `connector_sync_runs`, per-record validation failures in `connector_import_errors`, and external-ID-to-asset links in `connector_asset_mappings`.

The first working connector is `Sample Inventory`, a deterministic local fixture used to prove the framework, UI, health model, import mapping, and match refresh flow without external credentials. Freshservice, Jamf, and Intune are present as read-only shells with setup validation and clear errors until tenant-specific endpoint and auth work is completed.

### Read-only connector posture

Inventory connectors should be read-only by default. Their job is to pull asset and software/hardware state into SecurityWatchDaily, not to mutate source-of-truth systems.

Connector errors should be actionable. Permission problems, missing modules, tenant-specific endpoint differences, and network failures should be reported distinctly.

Connector sync failures update connector health and sync-run state but do not block vulnerability collection or CSV import. CSV remains the primary fallback and troubleshooting path.

### Version-aware matching with confidence

Asset impact matching should prefer structured version-aware comparisons when affected and fixed version ranges are available.

When version data is missing or source advisories are vague, the app should label the result as likely affected, needs review, unknown, or not affected instead of hiding uncertainty.
