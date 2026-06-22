"""SQLite schema and connection helpers."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .errors import StorageError


SCHEMA_VERSION = 1


def connect(db_path: Path) -> sqlite3.Connection:
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    except sqlite3.Error as exc:
        raise StorageError("Could not open the local database.", detail=str(exc)) from exc


def initialize(conn: sqlite3.Connection) -> None:
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS app_meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS platforms (
              id TEXT PRIMARY KEY,
              display_name TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              vendors TEXT NOT NULL DEFAULT '[]',
              keywords TEXT NOT NULL DEFAULT '[]',
              exclude_keywords TEXT NOT NULL DEFAULT '[]',
              minimum_cve_year INTEGER NOT NULL DEFAULT 0,
              default_priority TEXT NOT NULL DEFAULT 'Medium',
              msrc_title_keywords TEXT NOT NULL DEFAULT '[]',
              cisa_keywords TEXT NOT NULL DEFAULT '[]',
              ubuntu_releases TEXT NOT NULL DEFAULT '[]',
              paloalto_products TEXT NOT NULL DEFAULT '[]',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sources (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              source_type TEXT NOT NULL,
              url TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              notes TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS runs (
              run_id TEXT PRIMARY KEY,
              started_at TEXT NOT NULL,
              lookback_start TEXT NOT NULL,
              visible_count INTEGER NOT NULL,
              suppressed_count INTEGER NOT NULL,
              collected_count INTEGER NOT NULL,
              source_status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
              key TEXT NOT NULL,
              platform TEXT NOT NULL,
              title TEXT NOT NULL,
              status TEXT NOT NULL,
              description TEXT NOT NULL,
              action TEXT NOT NULL,
              sources TEXT NOT NULL,
              published TEXT NOT NULL DEFAULT '',
              cves TEXT NOT NULL DEFAULT '[]',
              priority TEXT NOT NULL,
              status_hash TEXT NOT NULL,
              trace_status TEXT NOT NULL,
              epss_score TEXT NOT NULL DEFAULT '',
              epss_percentile TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_key ON findings(key);
            CREATE TABLE IF NOT EXISTS trace_items (
              key TEXT PRIMARY KEY,
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              priority TEXT NOT NULL,
              status_hash TEXT NOT NULL,
              title TEXT NOT NULL,
              platform TEXT NOT NULL,
              times_seen INTEGER NOT NULL
            );
            """
        )
        conn.execute(
            "INSERT OR REPLACE INTO app_meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()
    except sqlite3.Error as exc:
        raise StorageError("Could not initialize the local database.", detail=str(exc)) from exc


def dumps(value: object) -> str:
    return json.dumps(value, sort_keys=True)


def loads_list(value: str) -> list[str]:
    parsed = json.loads(value or "[]")
    return [str(item) for item in parsed]


def loads_dict(value: str) -> dict[str, str]:
    parsed = json.loads(value or "{}")
    return {str(k): str(v) for k, v in parsed.items()}
