# SecurityWatchDaily

SecurityWatchDaily is a local web tool for daily vulnerability monitoring against a customer-managed platform list.

It imports an optional `watchlist.json`, stores editable platforms and sources in SQLite, runs vulnerability checks, and suppresses unchanged repeat findings through trace state.

## Current Scope

- Local-only web UI for dashboards, platforms, sources, runs, and findings.
- SQLite-backed configuration and run history.
- Source-level error handling so one broken feed does not stop the daily run.
- No credentials, API keys, user accounts, or cloud deployment in the first version.

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

## Tests

```bash
python3 -m compileall -q securitywatchdaily tests
python3 -m unittest discover -s tests -v
```

## Repository Standards

- Local web binding defaults to `127.0.0.1`.
- User-editable platform and source inputs are validated before saving.
- External source content is treated as untrusted and escaped before rendering.
- Generated databases, reports, run logs, caches, and trace files are ignored.
- Tests cover matching, validation, trace suppression, storage, friendly source errors, and practical web flows.

## Before Network Hosting

Do not expose this app directly to a network without a Strict-profile review for authentication, authorization, CSRF protection, deployment settings, logging, and source-secret handling.
