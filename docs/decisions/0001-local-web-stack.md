# ADR 0001: Local Web Stack

## Status

Accepted

## Date

2026-06-22

## Context

The existing tool is a Python script with JSON config and local trace files. The next step is a local web tool that teams can use without hand-editing JSON.

## Decision

Use Python standard library HTTP serving, SQLite, and server-rendered HTML for the first local version.

## Options Considered

- FastAPI with templates.
- Flask with templates.
- Python standard library HTTP server.

## Rationale

The standard library option avoids dependency download and packaging friction while the product shape is still forming. It supports a complete local workflow now and keeps the core services framework-neutral.

## Consequences And Risks

The HTTP layer is intentionally modest. If this becomes a shared network service, migrate the web layer to FastAPI or another maintained framework and re-review under the Strict profile.
