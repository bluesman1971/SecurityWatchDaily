"""Persistence for local asset inventory and impact matches."""

from __future__ import annotations

import sqlite3

from securitywatchdaily.models import (
    Asset,
    AssetComponent,
    FindingAssetMatch,
    FindingProduct,
    FindingVersionRange,
    ProductAlias,
)


def row_to_asset(row: sqlite3.Row) -> Asset:
    return Asset(
        id=int(row["id"]),
        hostname=row["hostname"],
        owner=row["owner"],
        location=row["location"],
        asset_type=row["asset_type"],
        platform=row["platform"],
        last_seen=row["last_seen"],
    )


def row_to_component(row: sqlite3.Row) -> AssetComponent:
    return AssetComponent(
        id=int(row["id"]),
        asset_id=int(row["asset_id"]),
        component_type=row["component_type"],
        vendor=row["vendor"],
        product=row["product"],
        version=row["version"],
        platform=row["platform"],
        normalized_vendor=row["normalized_vendor"],
        normalized_product=row["normalized_product"],
    )


def list_assets(conn: sqlite3.Connection) -> list[Asset]:
    rows = conn.execute("SELECT * FROM assets ORDER BY hostname").fetchall()
    return [row_to_asset(row) for row in rows]


def get_asset(conn: sqlite3.Connection, asset_id: int) -> Asset | None:
    row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    return row_to_asset(row) if row else None


def get_asset_by_hostname(conn: sqlite3.Connection, hostname: str) -> Asset | None:
    row = conn.execute("SELECT * FROM assets WHERE hostname = ?", (hostname,)).fetchone()
    return row_to_asset(row) if row else None


def upsert_asset(conn: sqlite3.Connection, asset: Asset) -> int:
    conn.execute(
        """
        INSERT INTO assets (hostname, owner, location, asset_type, platform, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
          owner=excluded.owner,
          location=excluded.location,
          asset_type=excluded.asset_type,
          platform=excluded.platform,
          last_seen=excluded.last_seen,
          updated_at=CURRENT_TIMESTAMP
        """,
        (asset.hostname, asset.owner, asset.location, asset.asset_type, asset.platform, asset.last_seen),
    )
    row = conn.execute("SELECT id FROM assets WHERE hostname = ?", (asset.hostname,)).fetchone()
    return int(row["id"])


def replace_components_for_assets(conn: sqlite3.Connection, asset_ids: set[int]) -> None:
    if not asset_ids:
        return
    placeholders = ",".join("?" for _ in asset_ids)
    conn.execute(f"DELETE FROM asset_components WHERE asset_id IN ({placeholders})", tuple(asset_ids))


def add_asset_component(conn: sqlite3.Connection, component: AssetComponent) -> int:
    cursor = conn.execute(
        """
        INSERT INTO asset_components (
          asset_id, component_type, vendor, product, version, platform, normalized_vendor, normalized_product
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            component.asset_id,
            component.component_type,
            component.vendor,
            component.product,
            component.version,
            component.platform,
            component.normalized_vendor,
            component.normalized_product,
        ),
    )
    return int(cursor.lastrowid)


def list_asset_components(conn: sqlite3.Connection, *, asset_id: int | None = None) -> list[AssetComponent]:
    sql = "SELECT * FROM asset_components"
    params: list[object] = []
    if asset_id is not None:
        sql += " WHERE asset_id = ?"
        params.append(asset_id)
    sql += " ORDER BY normalized_vendor, normalized_product, product"
    return [row_to_component(row) for row in conn.execute(sql, params)]


def row_to_alias(row: sqlite3.Row) -> ProductAlias:
    return ProductAlias(
        id=int(row["id"]),
        raw_vendor=row["raw_vendor"],
        raw_product=row["raw_product"],
        normalized_vendor=row["normalized_vendor"],
        normalized_product=row["normalized_product"],
        platform=row["platform"],
    )


def list_product_aliases(conn: sqlite3.Connection) -> list[ProductAlias]:
    return [row_to_alias(row) for row in conn.execute("SELECT * FROM product_aliases ORDER BY raw_vendor, raw_product")]


def get_product_alias(conn: sqlite3.Connection, raw_vendor: str, raw_product: str) -> ProductAlias | None:
    row = conn.execute(
        "SELECT * FROM product_aliases WHERE raw_vendor = ? AND raw_product = ?",
        (raw_vendor, raw_product),
    ).fetchone()
    return row_to_alias(row) if row else None


def save_product_alias(conn: sqlite3.Connection, alias: ProductAlias) -> int:
    conn.execute(
        """
        INSERT INTO product_aliases (raw_vendor, raw_product, normalized_vendor, normalized_product, platform)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(raw_vendor, raw_product) DO UPDATE SET
          normalized_vendor=excluded.normalized_vendor,
          normalized_product=excluded.normalized_product,
          platform=excluded.platform,
          updated_at=CURRENT_TIMESTAMP
        """,
        (alias.raw_vendor, alias.raw_product, alias.normalized_vendor, alias.normalized_product, alias.platform),
    )
    row = conn.execute(
        "SELECT id FROM product_aliases WHERE raw_vendor = ? AND raw_product = ?",
        (alias.raw_vendor, alias.raw_product),
    ).fetchone()
    return int(row["id"])


def add_finding_product(conn: sqlite3.Connection, product: FindingProduct) -> int:
    conn.execute(
        """
        INSERT INTO finding_products (finding_id, vendor, product, platform, source)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(finding_id, vendor, product, platform) DO UPDATE SET
          source=excluded.source,
          updated_at=CURRENT_TIMESTAMP
        """,
        (product.finding_id, product.vendor, product.product, product.platform, product.source),
    )
    row = conn.execute(
        """
        SELECT id FROM finding_products
        WHERE finding_id = ? AND vendor = ? AND product = ? AND platform = ?
        """,
        (product.finding_id, product.vendor, product.product, product.platform),
    ).fetchone()
    return int(row["id"])


def add_finding_version_range(conn: sqlite3.Connection, version_range: FindingVersionRange) -> int:
    cursor = conn.execute(
        """
        INSERT INTO finding_version_ranges (
          finding_product_id, affected_min_version, affected_max_version, fixed_version, exact_version
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            version_range.finding_product_id,
            version_range.affected_min_version,
            version_range.affected_max_version,
            version_range.fixed_version,
            version_range.exact_version,
        ),
    )
    return int(cursor.lastrowid)


def list_finding_products(conn: sqlite3.Connection, *, finding_id: int | None = None) -> list[sqlite3.Row]:
    sql = """
        SELECT fp.*, f.key AS finding_key, f.title AS finding_title, f.platform AS finding_platform
        FROM finding_products fp
        JOIN findings f ON f.id = fp.finding_id
    """
    params: list[object] = []
    if finding_id is not None:
        sql += " WHERE fp.finding_id = ?"
        params.append(finding_id)
    sql += " ORDER BY fp.vendor, fp.product"
    return list(conn.execute(sql, params))


def list_finding_version_ranges(conn: sqlite3.Connection, finding_product_id: int) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            "SELECT * FROM finding_version_ranges WHERE finding_product_id = ? ORDER BY id",
            (finding_product_id,),
        )
    )


def replace_matches(conn: sqlite3.Connection, matches: list[FindingAssetMatch]) -> None:
    finding_ids = {match.finding_id for match in matches}
    if finding_ids:
        placeholders = ",".join("?" for _ in finding_ids)
        conn.execute(f"DELETE FROM finding_asset_matches WHERE finding_id IN ({placeholders})", tuple(finding_ids))
    conn.executemany(
        """
        INSERT INTO finding_asset_matches (
          finding_id, asset_id, asset_component_id, confidence, reason, review_state
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(finding_id, asset_id, asset_component_id) DO UPDATE SET
          confidence=excluded.confidence,
          reason=excluded.reason,
          review_state=excluded.review_state,
          updated_at=CURRENT_TIMESTAMP
        """,
        [
            (
                match.finding_id,
                match.asset_id,
                match.asset_component_id,
                match.confidence,
                match.reason,
                match.review_state,
            )
            for match in matches
        ],
    )


def clear_matches_for_findings(conn: sqlite3.Connection, finding_ids: set[int]) -> None:
    if not finding_ids:
        return
    placeholders = ",".join("?" for _ in finding_ids)
    conn.execute(f"DELETE FROM finding_asset_matches WHERE finding_id IN ({placeholders})", tuple(finding_ids))


def list_matches_for_finding(conn: sqlite3.Connection, finding_id: int) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """
            SELECT fam.*, a.hostname, a.owner, a.location, a.asset_type,
                   ac.vendor, ac.product, ac.version, ac.normalized_vendor, ac.normalized_product
            FROM finding_asset_matches fam
            JOIN assets a ON a.id = fam.asset_id
            LEFT JOIN asset_components ac ON ac.id = fam.asset_component_id
            WHERE fam.finding_id = ?
            ORDER BY
              CASE fam.confidence
                WHEN 'confirmed affected' THEN 5
                WHEN 'likely affected' THEN 4
                WHEN 'needs review' THEN 3
                WHEN 'unknown' THEN 2
                ELSE 1
              END DESC,
              a.hostname
            """,
            (finding_id,),
        )
    )


def list_matches_for_asset(conn: sqlite3.Connection, asset_id: int) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """
            SELECT fam.*, f.key, f.title, f.platform AS finding_platform, f.priority,
                   ac.vendor, ac.product, ac.version, ac.normalized_vendor, ac.normalized_product
            FROM finding_asset_matches fam
            JOIN findings f ON f.id = fam.finding_id
            LEFT JOIN asset_components ac ON ac.id = fam.asset_component_id
            WHERE fam.asset_id = ?
            ORDER BY
              CASE fam.confidence
                WHEN 'confirmed affected' THEN 5
                WHEN 'likely affected' THEN 4
                WHEN 'needs review' THEN 3
                WHEN 'unknown' THEN 2
                ELSE 1
              END DESC,
              f.priority DESC,
              f.key
            """,
            (asset_id,),
        )
    )
