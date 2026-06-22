"""CSV import for Phase 2 asset inventory."""

from __future__ import annotations

import csv
import io
import re
import sqlite3
from dataclasses import dataclass, field

from securitywatchdaily.models import Asset, AssetComponent
from securitywatchdaily.repositories.assets import add_asset_component, replace_components_for_assets, upsert_asset

from .normalization_service import normalize_pair, normalize_token, seed_product_aliases


SUPPORTED_FIELDS = {
    "hostname",
    "owner",
    "team",
    "location",
    "asset_type",
    "type",
    "vendor",
    "product",
    "version",
    "platform",
    "last_seen",
    "component_type",
}


@dataclass(frozen=True)
class ImportErrorDetail:
    row: int
    field: str
    message: str


@dataclass(frozen=True)
class ImportResult:
    assets_imported: int
    components_imported: int
    errors: list[ImportErrorDetail] = field(default_factory=list)


def csv_template() -> str:
    return "hostname,owner,location,asset_type,vendor,product,version,platform,last_seen,component_type\n"


def parse_inventory_csv(content: str) -> tuple[list[dict[str, str]], list[ImportErrorDetail]]:
    errors: list[ImportErrorDetail] = []
    if not content.strip():
        return [], [ImportErrorDetail(1, "file", "CSV content is empty.")]
    sample = content[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample)
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(content), dialect=dialect)
    if not reader.fieldnames:
        return [], [ImportErrorDetail(1, "header", "CSV header row is required.")]
    headers = [normalize_header(name) for name in reader.fieldnames]
    unknown = sorted({header for header in headers if header and header not in SUPPORTED_FIELDS})
    if unknown:
        errors.extend(ImportErrorDetail(1, field, "Field is not supported by the Phase 2 CSV template.") for field in unknown)
    rows: list[dict[str, str]] = []
    for row_number, row in enumerate(reader, start=2):
        normalized = {normalize_header(key): (value or "").strip() for key, value in row.items() if key is not None}
        if not any(normalized.values()):
            continue
        row_errors = validate_row(row_number, normalized)
        errors.extend(row_errors)
        rows.append(normalized)
    return rows, errors


def import_inventory_csv(conn: sqlite3.Connection, content: str) -> ImportResult:
    seed_product_aliases(conn)
    rows, errors = parse_inventory_csv(content)
    if errors:
        return ImportResult(0, 0, errors)

    asset_ids: set[int] = set()
    asset_count = 0
    component_count = 0
    for row in rows:
        hostname = row["hostname"].strip()
        asset = Asset(
            id=None,
            hostname=hostname,
            owner=row.get("owner") or row.get("team", ""),
            location=row.get("location", ""),
            asset_type=row.get("asset_type") or row.get("type", ""),
            platform=normalize_token(row.get("platform", "")),
            last_seen=row.get("last_seen", ""),
        )
        asset_id = upsert_asset(conn, asset)
        if asset_id not in asset_ids:
            asset_count += 1
        asset_ids.add(asset_id)

    replace_components_for_assets(conn, asset_ids)
    for row in rows:
        vendor = row.get("vendor", "")
        product = row.get("product", "")
        if not product:
            continue
        asset_id = upsert_asset(
            conn,
            Asset(
                id=None,
                hostname=row["hostname"],
                owner=row.get("owner") or row.get("team", ""),
                location=row.get("location", ""),
                asset_type=row.get("asset_type") or row.get("type", ""),
                platform=normalize_token(row.get("platform", "")),
                last_seen=row.get("last_seen", ""),
            ),
        )
        normalized_vendor, normalized_product, normalized_platform = normalize_pair(
            conn,
            vendor,
            product,
            row.get("platform", ""),
        )
        add_asset_component(
            conn,
            AssetComponent(
                id=None,
                asset_id=asset_id,
                component_type=normalize_token(row.get("component_type") or "software"),
                vendor=vendor,
                product=product,
                version=row.get("version", ""),
                platform=normalized_platform,
                normalized_vendor=normalized_vendor,
                normalized_product=normalized_product,
            ),
        )
        component_count += 1
    conn.commit()
    return ImportResult(asset_count, component_count, [])


def normalize_header(value: str | None) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", (value or "").strip().casefold()).strip("_")


def validate_row(row_number: int, row: dict[str, str]) -> list[ImportErrorDetail]:
    errors: list[ImportErrorDetail] = []
    if not row.get("hostname"):
        errors.append(ImportErrorDetail(row_number, "hostname", "Hostname is required."))
    if not row.get("product"):
        errors.append(ImportErrorDetail(row_number, "product", "Product is required for impact matching."))
    if row.get("last_seen") and not re.match(r"^\d{4}-\d{2}-\d{2}$", row["last_seen"]):
        errors.append(ImportErrorDetail(row_number, "last_seen", "Use YYYY-MM-DD format."))
    if len(row.get("hostname", "")) > 255:
        errors.append(ImportErrorDetail(row_number, "hostname", "Hostname must be 255 characters or fewer."))
    for field_name in ("vendor", "product", "platform", "version"):
        if len(row.get(field_name, "")) > 255:
            errors.append(ImportErrorDetail(row_number, field_name, "Value must be 255 characters or fewer."))
    return errors
