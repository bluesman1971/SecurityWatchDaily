"""Inventory import: the single deep module that applies a batch of inventory
records to the local Asset/Component inventory and refreshes impact matches.

CSV import and connector sync are thin adapters that translate their own formats
into ``InventoryRecord`` values and call :func:`import_inventory`. The two-phase
write (upsert assets, replace their components, normalize and re-add components),
the connector mapping, and the post-import match refresh all live here so both
adapters get identical behavior.

Validation is all-or-nothing: if any record in the batch is invalid, nothing is
written and every error is returned at once.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field

from securitywatchdaily.models import Asset, AssetComponent, ConnectorAssetMapping
from securitywatchdaily.repositories.assets import (
    add_asset_component,
    replace_components_for_assets,
    upsert_asset,
)
from securitywatchdaily.repositories.connectors import save_asset_mapping
from securitywatchdaily.repositories.runs import latest_run
from securitywatchdaily.services.asset_matching_service import refresh_asset_matches_for_run
from securitywatchdaily.services.normalization_service import normalize_pair, normalize_token, seed_product_aliases


MAX_FIELD_LENGTH = 255
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_ASSET_FIELDS = ("external_id", "hostname", "owner", "location", "asset_type", "platform", "last_seen")
_COMPONENT_FIELDS = ("component_type", "vendor", "product", "version", "platform")


@dataclass(frozen=True)
class InventoryComponent:
    """One piece of software, firmware, or OS installed on an asset."""

    component_type: str = "software"
    vendor: str = ""
    product: str = ""
    version: str = ""
    platform: str = ""


@dataclass(frozen=True)
class InventoryRecord:
    """One asset plus its components — the neutral shape every import source
    translates into before anything is stored. ``external_id`` is filled by
    connectors and left blank by CSV import."""

    hostname: str
    owner: str = ""
    location: str = ""
    asset_type: str = ""
    platform: str = ""
    last_seen: str = ""
    external_id: str = ""
    components: list[InventoryComponent] = field(default_factory=list)


@dataclass(frozen=True)
class InventoryImportError:
    """A validation failure pointing at a record (and optionally a component)
    within the batch. Adapters translate ``record_index``/``component_index``
    back into a CSV row number or a connector external id."""

    record_index: int
    field: str
    message: str
    component_index: int | None = None


@dataclass(frozen=True)
class InventoryImportResult:
    assets_imported: int
    components_imported: int
    matches_refreshed: int
    asset_id_by_index: dict[int, int]
    errors: list[InventoryImportError]


def validate_records(records: list[InventoryRecord], *, require_external_id: bool) -> list[InventoryImportError]:
    errors: list[InventoryImportError] = []
    for index, record in enumerate(records):
        if require_external_id and not record.external_id.strip():
            errors.append(InventoryImportError(index, "external_id", "External ID is required for connector mapping."))
        if not record.hostname.strip():
            errors.append(InventoryImportError(index, "hostname", "Hostname is required."))
        if record.last_seen and not _DATE_RE.match(record.last_seen):
            errors.append(InventoryImportError(index, "last_seen", "Use YYYY-MM-DD format."))
        for field_name in _ASSET_FIELDS:
            if len(getattr(record, field_name, "")) > MAX_FIELD_LENGTH:
                errors.append(InventoryImportError(index, field_name, "Value must be 255 characters or fewer."))
        if not record.components:
            errors.append(
                InventoryImportError(index, "components", "At least one component is required for impact matching.")
            )
        for component_index, component in enumerate(record.components, start=1):
            if not component.product.strip():
                errors.append(InventoryImportError(index, "product", "Product is required.", component_index))
            for field_name in _COMPONENT_FIELDS:
                if len(getattr(component, field_name, "")) > MAX_FIELD_LENGTH:
                    errors.append(
                        InventoryImportError(index, field_name, "Value must be 255 characters or fewer.", component_index)
                    )
    return errors


def import_inventory(
    conn: sqlite3.Connection,
    records: list[InventoryRecord],
    *,
    connector_id: str | None = None,
) -> InventoryImportResult:
    """Apply a batch of inventory records. When ``connector_id`` is given, each
    record's ``external_id`` is mapped to its stored asset id and the batch must
    carry external ids. Returns counts, the per-record asset-id map, and any
    validation errors (in which case nothing is written)."""
    errors = validate_records(records, require_external_id=connector_id is not None)
    if errors:
        return InventoryImportResult(0, 0, 0, {}, errors)

    seed_product_aliases(conn)

    asset_id_by_index: dict[int, int] = {}
    asset_ids: set[int] = set()
    for index, record in enumerate(records):
        asset_id = upsert_asset(
            conn,
            Asset(
                id=None,
                hostname=record.hostname.strip(),
                owner=record.owner.strip(),
                location=record.location.strip(),
                asset_type=normalize_token(record.asset_type),
                platform=normalize_token(record.platform),
                last_seen=record.last_seen.strip(),
            ),
        )
        asset_id_by_index[index] = asset_id
        asset_ids.add(asset_id)
        if connector_id is not None:
            save_asset_mapping(conn, ConnectorAssetMapping(None, connector_id, record.external_id.strip(), asset_id))

    replace_components_for_assets(conn, asset_ids)
    component_count = 0
    for index, record in enumerate(records):
        asset_id = asset_id_by_index[index]
        for component in record.components:
            normalized_vendor, normalized_product, normalized_platform = normalize_pair(
                conn,
                component.vendor,
                component.product,
                component.platform or record.platform,
            )
            add_asset_component(
                conn,
                AssetComponent(
                    id=None,
                    asset_id=asset_id,
                    component_type=normalize_token(component.component_type or "software"),
                    vendor=component.vendor.strip(),
                    product=component.product.strip(),
                    version=component.version.strip(),
                    platform=normalized_platform,
                    normalized_vendor=normalized_vendor,
                    normalized_product=normalized_product,
                ),
            )
            component_count += 1

    run = latest_run(conn)
    matches_refreshed = refresh_asset_matches_for_run(conn, run.run_id) if run else 0
    conn.commit()
    return InventoryImportResult(len(asset_ids), component_count, matches_refreshed, asset_id_by_index, [])
