"""Persistence for source definitions."""

from __future__ import annotations

import sqlite3

from securitywatchdaily.models import Source
from securitywatchdaily.validation import validate_source


def row_to_source(row: sqlite3.Row) -> Source:
    return Source(
        id=row["id"],
        name=row["name"],
        source_type=row["source_type"],
        url=row["url"],
        enabled=bool(row["enabled"]),
        notes=row["notes"],
    )


def list_sources(conn: sqlite3.Connection, *, enabled_only: bool = False) -> list[Source]:
    sql = "SELECT * FROM sources"
    if enabled_only:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY name"
    return [row_to_source(row) for row in conn.execute(sql)]


def get_source(conn: sqlite3.Connection, source_id: str) -> Source | None:
    row = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
    return row_to_source(row) if row else None


def save_source(conn: sqlite3.Connection, source: Source, *, allow_update: bool = True) -> None:
    existing = get_source(conn, source.id)
    validate_source(source, existing_ids=set() if existing and allow_update else {s.id for s in list_sources(conn)})
    conn.execute(
        """
        INSERT INTO sources (id, name, source_type, url, enabled, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name=excluded.name,
          source_type=excluded.source_type,
          url=excluded.url,
          enabled=excluded.enabled,
          notes=excluded.notes,
          updated_at=CURRENT_TIMESTAMP
        """,
        (source.id, source.name, source.source_type, source.url, int(source.enabled), source.notes),
    )
    conn.commit()


def set_source_enabled(conn: sqlite3.Connection, source_id: str, enabled: bool) -> None:
    conn.execute(
        "UPDATE sources SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (int(enabled), source_id),
    )
    conn.commit()
