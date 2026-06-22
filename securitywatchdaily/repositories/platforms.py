"""Persistence for platform watch rules."""

from __future__ import annotations

import sqlite3

from securitywatchdaily.database import dumps, loads_list
from securitywatchdaily.models import Platform
from securitywatchdaily.validation import validate_platform


def row_to_platform(row: sqlite3.Row) -> Platform:
    return Platform(
        id=row["id"],
        display_name=row["display_name"],
        enabled=bool(row["enabled"]),
        vendors=loads_list(row["vendors"]),
        keywords=loads_list(row["keywords"]),
        exclude_keywords=loads_list(row["exclude_keywords"]),
        minimum_cve_year=int(row["minimum_cve_year"]),
        default_priority=row["default_priority"],
        msrc_title_keywords=loads_list(row["msrc_title_keywords"]),
        cisa_keywords=loads_list(row["cisa_keywords"]),
        ubuntu_releases=loads_list(row["ubuntu_releases"]),
        paloalto_products=loads_list(row["paloalto_products"]),
    )


def list_platforms(conn: sqlite3.Connection, *, enabled_only: bool = False) -> list[Platform]:
    sql = "SELECT * FROM platforms"
    params: tuple[object, ...] = ()
    if enabled_only:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY display_name"
    return [row_to_platform(row) for row in conn.execute(sql, params)]


def get_platform(conn: sqlite3.Connection, platform_id: str) -> Platform | None:
    row = conn.execute("SELECT * FROM platforms WHERE id = ?", (platform_id,)).fetchone()
    return row_to_platform(row) if row else None


def save_platform(conn: sqlite3.Connection, platform: Platform, *, allow_update: bool = True) -> None:
    existing = get_platform(conn, platform.id)
    validate_platform(platform, existing_ids=set() if existing and allow_update else {p.id for p in list_platforms(conn)})
    conn.execute(
        """
        INSERT INTO platforms (
          id, display_name, enabled, vendors, keywords, exclude_keywords, minimum_cve_year,
          default_priority, msrc_title_keywords, cisa_keywords, ubuntu_releases, paloalto_products
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          display_name=excluded.display_name,
          enabled=excluded.enabled,
          vendors=excluded.vendors,
          keywords=excluded.keywords,
          exclude_keywords=excluded.exclude_keywords,
          minimum_cve_year=excluded.minimum_cve_year,
          default_priority=excluded.default_priority,
          msrc_title_keywords=excluded.msrc_title_keywords,
          cisa_keywords=excluded.cisa_keywords,
          ubuntu_releases=excluded.ubuntu_releases,
          paloalto_products=excluded.paloalto_products,
          updated_at=CURRENT_TIMESTAMP
        """,
        (
            platform.id,
            platform.display_name,
            int(platform.enabled),
            dumps(platform.vendors),
            dumps(platform.keywords),
            dumps(platform.exclude_keywords),
            platform.minimum_cve_year,
            platform.default_priority,
            dumps(platform.msrc_title_keywords),
            dumps(platform.cisa_keywords),
            dumps(platform.ubuntu_releases),
            dumps(platform.paloalto_products),
        ),
    )
    conn.commit()


def set_platform_enabled(conn: sqlite3.Connection, platform_id: str, enabled: bool) -> None:
    conn.execute(
        "UPDATE platforms SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (int(enabled), platform_id),
    )
    conn.commit()
