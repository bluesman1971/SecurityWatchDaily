"""Import existing JSON watchlist data into SQLite."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from securitywatchdaily.models import Platform
from securitywatchdaily.repositories.platforms import list_platforms, save_platform
from securitywatchdaily.repositories.sources import list_sources, save_source

from .source_defaults import DEFAULT_SOURCES


def import_watchlist(conn: sqlite3.Connection, path: Path) -> int:
    if not path.exists():
        return 0
    data = json.loads(path.read_text(encoding="utf-8"))
    imported = 0
    for item in data.get("platforms", []):
        platform = Platform(
            id=item.get("id", ""),
            display_name=item.get("display_name", item.get("id", "")),
            enabled=bool(item.get("enabled", True)),
            vendors=list(item.get("vendors", [])),
            keywords=list(item.get("keywords", [])),
            exclude_keywords=list(item.get("exclude_keywords", [])),
            minimum_cve_year=int(item.get("minimum_cve_year", 0) or 0),
            default_priority=item.get("default_priority", "Medium"),
            msrc_title_keywords=list(item.get("msrc_title_keywords", [])),
            cisa_keywords=list(item.get("cisa_keywords", [])),
            ubuntu_releases=list(item.get("ubuntu_releases", [])),
            paloalto_products=list(item.get("paloalto_products", [])),
        )
        save_platform(conn, platform)
        imported += 1
    return imported


def seed_defaults(conn: sqlite3.Connection, watchlist_path: Path) -> dict[str, int]:
    platform_count = len(list_platforms(conn))
    source_count = len(list_sources(conn))
    imported_platforms = 0
    if platform_count == 0:
        imported_platforms = import_watchlist(conn, watchlist_path)
    if source_count == 0:
        for source in DEFAULT_SOURCES:
            save_source(conn, source)
    return {"platforms": imported_platforms, "sources": len(DEFAULT_SOURCES) if source_count == 0 else 0}
