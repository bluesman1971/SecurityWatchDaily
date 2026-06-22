"""SQLite schema and connection helpers."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .errors import StorageError


SCHEMA_VERSION = 3


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
            CREATE TABLE IF NOT EXISTS assets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              hostname TEXT NOT NULL UNIQUE,
              owner TEXT NOT NULL DEFAULT '',
              location TEXT NOT NULL DEFAULT '',
              asset_type TEXT NOT NULL DEFAULT '',
              platform TEXT NOT NULL DEFAULT '',
              last_seen TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS asset_components (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
              component_type TEXT NOT NULL DEFAULT 'software',
              vendor TEXT NOT NULL DEFAULT '',
              product TEXT NOT NULL,
              version TEXT NOT NULL DEFAULT '',
              platform TEXT NOT NULL DEFAULT '',
              normalized_vendor TEXT NOT NULL DEFAULT '',
              normalized_product TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_asset_components_asset_id ON asset_components(asset_id);
            CREATE INDEX IF NOT EXISTS idx_asset_components_normalized ON asset_components(normalized_vendor, normalized_product, platform);
            CREATE TABLE IF NOT EXISTS product_aliases (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              raw_vendor TEXT NOT NULL DEFAULT '',
              raw_product TEXT NOT NULL,
              normalized_vendor TEXT NOT NULL DEFAULT '',
              normalized_product TEXT NOT NULL,
              platform TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(raw_vendor, raw_product)
            );
            CREATE INDEX IF NOT EXISTS idx_product_aliases_raw ON product_aliases(raw_vendor, raw_product);
            CREATE TABLE IF NOT EXISTS finding_products (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
              vendor TEXT NOT NULL DEFAULT '',
              product TEXT NOT NULL,
              platform TEXT NOT NULL DEFAULT '',
              source TEXT NOT NULL DEFAULT 'inferred',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(finding_id, vendor, product, platform)
            );
            CREATE INDEX IF NOT EXISTS idx_finding_products_finding_id ON finding_products(finding_id);
            CREATE INDEX IF NOT EXISTS idx_finding_products_normalized ON finding_products(vendor, product, platform);
            CREATE TABLE IF NOT EXISTS finding_version_ranges (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              finding_product_id INTEGER NOT NULL REFERENCES finding_products(id) ON DELETE CASCADE,
              affected_min_version TEXT NOT NULL DEFAULT '',
              affected_max_version TEXT NOT NULL DEFAULT '',
              fixed_version TEXT NOT NULL DEFAULT '',
              exact_version TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_finding_version_ranges_product_id ON finding_version_ranges(finding_product_id);
            CREATE TABLE IF NOT EXISTS finding_asset_matches (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
              asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
              asset_component_id INTEGER REFERENCES asset_components(id) ON DELETE SET NULL,
              confidence TEXT NOT NULL,
              reason TEXT NOT NULL,
              review_state TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(finding_id, asset_id, asset_component_id)
            );
            CREATE INDEX IF NOT EXISTS idx_finding_asset_matches_finding_id ON finding_asset_matches(finding_id);
            CREATE INDEX IF NOT EXISTS idx_finding_asset_matches_asset_id ON finding_asset_matches(asset_id);
            CREATE TABLE IF NOT EXISTS connectors (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              connector_type TEXT NOT NULL,
              description TEXT NOT NULL DEFAULT '',
              enabled INTEGER NOT NULL DEFAULT 0,
              settings_json TEXT NOT NULL DEFAULT '{}',
              last_successful_sync TEXT NOT NULL DEFAULT '',
              last_failed_sync TEXT NOT NULL DEFAULT '',
              last_error TEXT NOT NULL DEFAULT '',
              imported_asset_count INTEGER NOT NULL DEFAULT 0,
              imported_component_count INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS connector_sync_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              connector_id TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
              started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              finished_at TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL,
              action TEXT NOT NULL DEFAULT 'sync',
              imported_asset_count INTEGER NOT NULL DEFAULT 0,
              imported_component_count INTEGER NOT NULL DEFAULT 0,
              error TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_connector_sync_runs_connector_id ON connector_sync_runs(connector_id);
            CREATE TABLE IF NOT EXISTS connector_import_errors (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              sync_run_id INTEGER NOT NULL REFERENCES connector_sync_runs(id) ON DELETE CASCADE,
              connector_id TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
              external_id TEXT NOT NULL DEFAULT '',
              field TEXT NOT NULL DEFAULT '',
              message TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_connector_import_errors_run_id ON connector_import_errors(sync_run_id);
            CREATE TABLE IF NOT EXISTS connector_asset_mappings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              connector_id TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
              external_id TEXT NOT NULL,
              asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(connector_id, external_id)
            );
            CREATE INDEX IF NOT EXISTS idx_connector_asset_mappings_asset_id ON connector_asset_mappings(asset_id);
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
