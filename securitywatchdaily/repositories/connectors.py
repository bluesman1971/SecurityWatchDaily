"""Persistence for read-only inventory connectors."""

from __future__ import annotations

import sqlite3

from securitywatchdaily.models import (
    Connector,
    ConnectorAssetMapping,
    ConnectorImportError,
    ConnectorSyncRun,
)


def row_to_connector(row: sqlite3.Row) -> Connector:
    return Connector(
        id=row["id"],
        name=row["name"],
        connector_type=row["connector_type"],
        description=row["description"],
        enabled=bool(row["enabled"]),
        settings_json=row["settings_json"],
        last_successful_sync=row["last_successful_sync"],
        last_failed_sync=row["last_failed_sync"],
        last_error=row["last_error"],
        imported_asset_count=int(row["imported_asset_count"]),
        imported_component_count=int(row["imported_component_count"]),
    )


def list_connectors(conn: sqlite3.Connection) -> list[Connector]:
    rows = conn.execute("SELECT * FROM connectors ORDER BY name").fetchall()
    return [row_to_connector(row) for row in rows]


def get_connector(conn: sqlite3.Connection, connector_id: str) -> Connector | None:
    row = conn.execute("SELECT * FROM connectors WHERE id = ?", (connector_id,)).fetchone()
    return row_to_connector(row) if row else None


def save_connector(conn: sqlite3.Connection, connector: Connector) -> None:
    conn.execute(
        """
        INSERT INTO connectors (
          id, name, connector_type, description, enabled, settings_json,
          last_successful_sync, last_failed_sync, last_error, imported_asset_count, imported_component_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name=excluded.name,
          connector_type=excluded.connector_type,
          description=excluded.description,
          settings_json=excluded.settings_json,
          updated_at=CURRENT_TIMESTAMP
        """,
        (
            connector.id,
            connector.name,
            connector.connector_type,
            connector.description,
            int(connector.enabled),
            connector.settings_json,
            connector.last_successful_sync,
            connector.last_failed_sync,
            connector.last_error,
            connector.imported_asset_count,
            connector.imported_component_count,
        ),
    )


def set_connector_enabled(conn: sqlite3.Connection, connector_id: str, enabled: bool) -> None:
    conn.execute(
        "UPDATE connectors SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (int(enabled), connector_id),
    )
    conn.commit()


def add_sync_run(conn: sqlite3.Connection, run: ConnectorSyncRun) -> int:
    cursor = conn.execute(
        """
        INSERT INTO connector_sync_runs (
          connector_id, started_at, finished_at, status, action, imported_asset_count, imported_component_count, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run.connector_id,
            run.started_at,
            run.finished_at,
            run.status,
            run.action,
            run.imported_asset_count,
            run.imported_component_count,
            run.error,
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)


def finish_sync_run(
    conn: sqlite3.Connection,
    *,
    sync_run_id: int,
    connector_id: str,
    finished_at: str,
    status: str,
    imported_asset_count: int = 0,
    imported_component_count: int = 0,
    error: str = "",
) -> None:
    conn.execute(
        """
        UPDATE connector_sync_runs
        SET finished_at = ?, status = ?, imported_asset_count = ?, imported_component_count = ?, error = ?
        WHERE id = ?
        """,
        (finished_at, status, imported_asset_count, imported_component_count, error, sync_run_id),
    )
    if status == "success":
        conn.execute(
            """
            UPDATE connectors
            SET last_successful_sync = ?, last_error = '', imported_asset_count = ?,
                imported_component_count = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (finished_at, imported_asset_count, imported_component_count, connector_id),
        )
    else:
        conn.execute(
            """
            UPDATE connectors
            SET last_failed_sync = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (finished_at, error, connector_id),
        )
    conn.commit()


def list_sync_runs(conn: sqlite3.Connection, connector_id: str, *, limit: int = 10) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """
            SELECT * FROM connector_sync_runs
            WHERE connector_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (connector_id, limit),
        )
    )


def add_import_error(conn: sqlite3.Connection, error: ConnectorImportError) -> int:
    cursor = conn.execute(
        """
        INSERT INTO connector_import_errors (sync_run_id, connector_id, external_id, field, message)
        VALUES (?, ?, ?, ?, ?)
        """,
        (error.sync_run_id, error.connector_id, error.external_id, error.field, error.message),
    )
    return int(cursor.lastrowid)


def list_import_errors(conn: sqlite3.Connection, sync_run_id: int) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """
            SELECT * FROM connector_import_errors
            WHERE sync_run_id = ?
            ORDER BY id
            """,
            (sync_run_id,),
        )
    )


def save_asset_mapping(conn: sqlite3.Connection, mapping: ConnectorAssetMapping) -> int:
    conn.execute(
        """
        INSERT INTO connector_asset_mappings (connector_id, external_id, asset_id)
        VALUES (?, ?, ?)
        ON CONFLICT(connector_id, external_id) DO UPDATE SET
          asset_id=excluded.asset_id,
          updated_at=CURRENT_TIMESTAMP
        """,
        (mapping.connector_id, mapping.external_id, mapping.asset_id),
    )
    row = conn.execute(
        """
        SELECT id FROM connector_asset_mappings
        WHERE connector_id = ? AND external_id = ?
        """,
        (mapping.connector_id, mapping.external_id),
    ).fetchone()
    return int(row["id"])
