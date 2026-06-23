"""CSV import for Phase 2 asset inventory."""

from __future__ import annotations

import csv
import io
import re
import sqlite3
from dataclasses import dataclass, field

from .inventory_import_service import InventoryComponent, InventoryRecord, import_inventory


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
MAX_CSV_ROWS = 10_000
MAX_FIELD_LENGTH = 255


@dataclass(frozen=True)
class ImportErrorDetail:
    row: int
    field: str
    message: str


@dataclass(frozen=True)
class ImportResult:
    assets_imported: int
    components_imported: int
    matches_refreshed: int = 0
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
    if dialect.delimiter not in {",", "\t", ";"}:
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
        if row_number > MAX_CSV_ROWS + 1:
            errors.append(ImportErrorDetail(row_number, "file", f"CSV imports are limited to {MAX_CSV_ROWS} data rows."))
            break
        if None in row:
            errors.append(ImportErrorDetail(row_number, "row", "Row has more values than the CSV header."))
            continue
        normalized = {normalize_header(key): (value or "").strip() for key, value in row.items() if key is not None}
        if not any(normalized.values()):
            continue
        row_errors = validate_row(row_number, normalized)
        errors.extend(row_errors)
        rows.append(normalized)
    return rows, errors


def import_inventory_csv(conn: sqlite3.Connection, content: str) -> ImportResult:
    rows, errors = parse_inventory_csv(content)
    if errors:
        return ImportResult(0, 0, errors=errors)

    records, record_rows = _group_rows_into_records(rows)
    result = import_inventory(conn, records)
    if result.errors:
        return ImportResult(0, 0, errors=_translate_errors(result.errors, record_rows))
    return ImportResult(result.assets_imported, result.components_imported, matches_refreshed=result.matches_refreshed)


def _group_rows_into_records(rows: list[dict[str, str]]) -> tuple[list[InventoryRecord], list[list[int]]]:
    """Collapse flat CSV rows into one InventoryRecord per hostname, since rows
    that share a hostname are components of the same asset. Returns the records
    and, parallel to them, the source row numbers of each record's components so
    errors can be reported against the original spreadsheet row."""
    order: list[str] = []
    assets: dict[str, dict[str, str]] = {}
    components: dict[str, list[InventoryComponent]] = {}
    source_rows: dict[str, list[int]] = {}
    for offset, row in enumerate(rows):
        hostname = row.get("hostname", "").strip()
        if hostname not in assets:
            order.append(hostname)
            components[hostname] = []
            source_rows[hostname] = []
        assets[hostname] = row
        components[hostname].append(
            InventoryComponent(
                component_type=row.get("component_type", ""),
                vendor=row.get("vendor", ""),
                product=row.get("product", ""),
                version=row.get("version", ""),
                platform=row.get("platform", ""),
            )
        )
        source_rows[hostname].append(offset + 2)
    records = [
        InventoryRecord(
            hostname=assets[hostname]["hostname"],
            owner=assets[hostname].get("owner") or assets[hostname].get("team", ""),
            location=assets[hostname].get("location", ""),
            asset_type=assets[hostname].get("asset_type") or assets[hostname].get("type", ""),
            platform=assets[hostname].get("platform", ""),
            last_seen=assets[hostname].get("last_seen", ""),
            components=components[hostname],
        )
        for hostname in order
    ]
    return records, [source_rows[hostname] for hostname in order]


def _translate_errors(errors, record_rows: list[list[int]]) -> list[ImportErrorDetail]:
    """Map record/component indexes from the import core back to CSV row numbers."""
    translated: list[ImportErrorDetail] = []
    for error in errors:
        rows_for_record = record_rows[error.record_index]
        if error.component_index is not None and 1 <= error.component_index <= len(rows_for_record):
            row_number = rows_for_record[error.component_index - 1]
        else:
            row_number = rows_for_record[0] if rows_for_record else error.record_index + 2
        translated.append(ImportErrorDetail(row_number, error.field, error.message))
    return translated


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
    for field_name in SUPPORTED_FIELDS:
        if len(row.get(field_name, "")) > MAX_FIELD_LENGTH:
            errors.append(ImportErrorDetail(row_number, field_name, f"Value must be {MAX_FIELD_LENGTH} characters or fewer."))
    return errors
