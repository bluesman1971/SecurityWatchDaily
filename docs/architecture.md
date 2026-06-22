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
