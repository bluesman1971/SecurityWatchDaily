"""Read-only inventory connector orchestration."""

from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import urllib.error
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

from securitywatchdaily.collectors.http import open_external_url, read_external_response
from securitywatchdaily.errors import AppError, ConfigValidationError
from securitywatchdaily.models import (
    Connector,
    ConnectorImportError,
    ConnectorSyncRun,
)
from securitywatchdaily.repositories.connectors import (
    add_import_error,
    add_sync_run,
    finish_sync_run,
    get_connector,
    save_connector,
    update_connector_settings,
)
from securitywatchdaily.services.inventory_import_service import (
    InventoryComponent,
    InventoryRecord,
    import_inventory,
)


MAX_FIELD_LENGTH = 255
ENV_VAR_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,80}$")
GUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
INTUNE_PERMISSION = "DeviceManagementManagedDevices.Read.All"
INTUNE_CLOUDS = {
    "global": {
        "label": "Global - graph.microsoft.com",
        "authority_host": "https://login.microsoftonline.com",
        "graph_host": "https://graph.microsoft.com",
    },
    "usgov_l4": {
        "label": "US Government L4",
        "authority_host": "https://login.microsoftonline.us",
        "graph_host": "https://graph.microsoft.us",
    },
    "usgov_l5": {
        "label": "US Government L5",
        "authority_host": "https://login.microsoftonline.us",
        "graph_host": "https://dod-graph.microsoft.us",
    },
    "china": {
        "label": "China operated by 21Vianet",
        "authority_host": "https://login.chinacloudapi.cn",
        "graph_host": "https://microsoftgraph.chinacloudapi.cn",
    },
}
DEFAULT_INTUNE_SETTINGS = {
    "display_name": "Corporate Intune",
    "cloud": "global",
    "tenant_id": "",
    "client_id": "",
    "tenant_env_var": "INTUNE_TENANT_ID",
    "client_env_var": "INTUNE_CLIENT_ID",
    "secret_env_var": "INTUNE_CLIENT_SECRET",
    "graph_permissions": [INTUNE_PERMISSION],
    "read_only": True,
    "secret_storage": "environment",
}


@dataclass(frozen=True)
class ConnectorComponentRecord:
    component_type: str
    vendor: str
    product: str
    version: str = ""
    platform: str = ""


@dataclass(frozen=True)
class ConnectorAssetRecord:
    external_id: str
    hostname: str
    owner: str = ""
    location: str = ""
    asset_type: str = ""
    platform: str = ""
    last_seen: str = ""
    components: list[ConnectorComponentRecord] = field(default_factory=list)


@dataclass(frozen=True)
class ConnectorActionResult:
    success: bool
    message: str
    sync_run_id: int | None = None
    imported_asset_count: int = 0
    imported_component_count: int = 0
    match_count: int = 0


@dataclass(frozen=True)
class ImportValidationError:
    external_id: str
    field: str
    message: str


CONNECTOR_CATALOG = [
    Connector(
        id="sample_inventory",
        name="Sample Inventory",
        connector_type="sample",
        description="Local read-only fixture for proving connector sync and matching without external credentials.",
        settings_json=json.dumps({"secrets": [], "read_only": True}, sort_keys=True),
    ),
    Connector(
        id="freshservice",
        name="Freshservice",
        connector_type="freshservice",
        description="Read-only ITSM/ITAM asset inventory connector shell. Uses env vars for tenant URL and API key.",
        settings_json=json.dumps(
            {
                "env": ["FRESHSERVICE_TENANT_URL", "FRESHSERVICE_API_KEY"],
                "optional_env": ["FRESHSERVICE_TEST_PATH", "FRESHSERVICE_ASSETS_PATH"],
                "read_only": True,
            },
            sort_keys=True,
        ),
    ),
    Connector(
        id="jamf",
        name="Jamf",
        connector_type="jamf",
        description="Read-only Jamf device and installed-application connector shell.",
        settings_json=json.dumps(
            {
                "env": ["JAMF_BASE_URL"],
                "optional_env": ["JAMF_CLIENT_ID", "JAMF_CLIENT_SECRET"],
                "read_only": True,
            },
            sort_keys=True,
        ),
    ),
    Connector(
        id="intune",
        name="Microsoft Intune",
        connector_type="intune",
        description="Read-only Intune connector shell for managed devices and detected applications.",
        settings_json=json.dumps(
            {
                **DEFAULT_INTUNE_SETTINGS,
                "tenant_id": "",
                "client_id": "",
            },
            sort_keys=True,
        ),
    ),
]


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def seed_connector_catalog(conn: sqlite3.Connection) -> None:
    for connector in CONNECTOR_CATALOG:
        save_connector(conn, connector)
    conn.commit()


def test_connector(conn: sqlite3.Connection, connector_id: str) -> ConnectorActionResult:
    connector = load_connector(conn, connector_id)
    try:
        if connector.connector_type == "sample":
            records = sample_inventory_records()
            return ConnectorActionResult(True, f"Sample connector is ready with {len(records)} fixture assets.")
        if connector.connector_type == "freshservice":
            validate_freshservice_setup()
            maybe_test_freshservice_endpoint()
            return ConnectorActionResult(True, "Freshservice setup values are present and the read-only test passed.")
        if connector.connector_type == "jamf":
            validate_jamf_setup()
        if connector.connector_type == "intune":
            settings = intune_settings_from_connector(connector)
            validate_intune_setup(settings)
    except AppError as exc:
        return ConnectorActionResult(False, exc.detail or exc.message)
    return ConnectorActionResult(
        False,
        "This connector shell is present, but live sync is not implemented in this phase.",
    )


def sync_connector(conn: sqlite3.Connection, connector_id: str) -> ConnectorActionResult:
    connector = load_connector(conn, connector_id)
    started_at = utc_now()
    sync_run_id = add_sync_run(
        conn,
        ConnectorSyncRun(
            id=None,
            connector_id=connector.id,
            started_at=started_at,
            status="running",
            action="sync",
        ),
    )
    try:
        if not connector.enabled:
            raise ConfigValidationError("Connector is disabled.", detail="Enable the connector before syncing it.")
        records = collect_records(connector)
        asset_count, component_count, match_count, validation_errors = import_connector_records(
            conn,
            connector.id,
            sync_run_id,
            records,
        )
        if validation_errors:
            raise ConfigValidationError(
                "Connector data needs review.",
                detail=f"{len(validation_errors)} imported records failed validation. Review the sync errors below.",
            )
        finished_at = utc_now()
        finish_sync_run(
            conn,
            sync_run_id=sync_run_id,
            connector_id=connector.id,
            finished_at=finished_at,
            status="success",
            imported_asset_count=asset_count,
            imported_component_count=component_count,
        )
        return ConnectorActionResult(
            True,
            "Connector sync complete.",
            sync_run_id,
            asset_count,
            component_count,
            match_count,
        )
    except AppError as exc:
        detail = exc.detail or exc.message
        finish_sync_run(
            conn,
            sync_run_id=sync_run_id,
            connector_id=connector.id,
            finished_at=utc_now(),
            status="failed",
            error=detail,
        )
        return ConnectorActionResult(False, detail, sync_run_id)
    except Exception as exc:
        detail = f"Unexpected connector failure: {type(exc).__name__}."
        finish_sync_run(
            conn,
            sync_run_id=sync_run_id,
            connector_id=connector.id,
            finished_at=utc_now(),
            status="failed",
            error=detail,
        )
        return ConnectorActionResult(False, detail, sync_run_id)


def load_connector(conn: sqlite3.Connection, connector_id: str) -> Connector:
    connector = get_connector(conn, connector_id)
    if not connector:
        raise ConfigValidationError(
            "Connector was not found.",
            detail="Open the Connector Catalog and choose an available connector.",
        )
    return connector


def collect_records(connector: Connector) -> list[ConnectorAssetRecord]:
    if connector.connector_type == "sample":
        return sample_inventory_records()
    if connector.connector_type == "freshservice":
        validate_freshservice_setup()
        raise ConfigValidationError(
            "Freshservice live sync is not configured.",
            detail=(
                "Freshservice tenant schemas vary. Set up and validate the tenant-specific asset/software paths before "
                "enabling live import; CSV import remains the fallback."
            ),
        )
    if connector.connector_type == "jamf":
        validate_jamf_setup()
        raise ConfigValidationError(
            "Jamf live sync is not implemented yet.",
            detail=(
                "The connector shell validates setup, but OAuth/token handling and endpoint mapping need "
                "the next vertical slice."
            ),
        )
    if connector.connector_type == "intune":
        settings = intune_settings_from_connector(connector)
        validate_intune_setup(settings)
        raise ConfigValidationError(
            "Intune live sync is not implemented yet.",
            detail=(
                "Microsoft Graph OAuth and tenant consent need the next connector slice. Required read permission is "
                f"{INTUNE_PERMISSION}."
            ),
        )
    raise ConfigValidationError("Connector type is not supported.", detail=connector.connector_type)


def sample_inventory_records() -> list[ConnectorAssetRecord]:
    return [
        ConnectorAssetRecord(
            external_id="sample:laptop-1",
            hostname="connector-laptop-1",
            owner="IT",
            location="HQ",
            asset_type="laptop",
            platform="Windows 11",
            last_seen="2026-06-21",
            components=[
                ConnectorComponentRecord(
                    "operating_system",
                    "Microsoft",
                    "Windows 11 Pro",
                    "10.0.22631",
                    "Windows 11",
                ),
                ConnectorComponentRecord("software", "Microsoft", "Office", "16.0", "microsoft_365"),
            ],
        ),
        ConnectorAssetRecord(
            external_id="sample:firewall-1",
            hostname="connector-firewall-1",
            owner="Network",
            location="Data Center",
            asset_type="firewall",
            platform="PAN-OS",
            last_seen="2026-06-21",
            components=[
                ConnectorComponentRecord("firmware", "Palo Alto Networks", "PAN-OS", "11.1.4", "palo_alto_pan_os"),
            ],
        ),
    ]


def import_connector_records(
    conn: sqlite3.Connection,
    connector_id: str,
    sync_run_id: int,
    records: list[ConnectorAssetRecord],
) -> tuple[int, int, int, list[ImportValidationError]]:
    """Connector adapter over the inventory import core: translate connector
    records into InventoryRecords, import them under all-or-nothing validation,
    persist any errors against the sync run, and return counts plus the errors."""
    inventory_records = [_to_inventory_record(record) for record in records]
    result = import_inventory(conn, inventory_records, connector_id=connector_id)
    errors = [
        ImportValidationError(
            records[error.record_index].external_id,
            _connector_field_name(error),
            error.message,
        )
        for error in result.errors
    ]
    for error in errors:
        add_import_error(
            conn,
            ConnectorImportError(None, sync_run_id, connector_id, error.external_id, error.field, error.message),
        )
    if errors:
        conn.commit()
    return result.assets_imported, result.components_imported, result.matches_refreshed, errors


def _to_inventory_record(record: ConnectorAssetRecord) -> InventoryRecord:
    return InventoryRecord(
        hostname=record.hostname,
        owner=record.owner,
        location=record.location,
        asset_type=record.asset_type,
        platform=record.platform,
        last_seen=record.last_seen,
        external_id=record.external_id,
        components=[
            InventoryComponent(
                component_type=component.component_type,
                vendor=component.vendor,
                product=component.product,
                version=component.version,
                platform=component.platform,
            )
            for component in record.components
        ],
    )


def _connector_field_name(error) -> str:
    if error.component_index is not None:
        return f"components[{error.component_index}].{error.field}"
    return error.field


def validate_freshservice_setup() -> None:
    tenant_url = os.environ.get("FRESHSERVICE_TENANT_URL", "").strip()
    api_key = os.environ.get("FRESHSERVICE_API_KEY", "").strip()
    if not tenant_url:
        raise ConfigValidationError(
            "Freshservice tenant URL is missing.",
            detail="Set FRESHSERVICE_TENANT_URL in your local environment.",
        )
    if not api_key:
        raise ConfigValidationError(
            "Freshservice API key is missing.",
            detail="Set FRESHSERVICE_API_KEY in your local environment; do not commit it.",
        )
    parsed = urlparse(tenant_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ConfigValidationError(
            "Freshservice tenant URL is invalid.",
            detail="Use the full https://yourdomain.freshservice.com URL.",
        )


def maybe_test_freshservice_endpoint() -> None:
    test_path = os.environ.get("FRESHSERVICE_TEST_PATH", "").strip()
    if not test_path:
        return
    tenant_url = os.environ["FRESHSERVICE_TENANT_URL"].strip().rstrip("/") + "/"
    url = urljoin(tenant_url, test_path.lstrip("/"))
    api_key = os.environ["FRESHSERVICE_API_KEY"].strip()
    token = base64.b64encode(f"{api_key}:X".encode("utf-8")).decode("ascii")
    try:
        with open_external_url(url, timeout=20, headers={"Authorization": f"Basic {token}"}) as response:
            read_external_response(response, max_bytes=1024)
    except AppError as exc:
        raise ConfigValidationError(
            "Freshservice endpoint could not be reached.",
            detail=exc.detail or "Check the base URL and local network access.",
        ) from exc
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            raise ConfigValidationError(
                "Freshservice permission denied.",
                detail=(
                    "HTTP 403 means the API key authenticated but is not authorized for that "
                    "asset/software endpoint."
                ),
            ) from exc
        if exc.code == 404:
            raise ConfigValidationError(
                "Freshservice endpoint was not found.",
                detail=(
                    "HTTP 404 usually means the path does not match this tenant or module. "
                    "Confirm the tenant-specific asset/software endpoint."
                ),
            ) from exc
        raise ConfigValidationError(
            "Freshservice endpoint check failed.",
            detail=f"Freshservice returned HTTP {exc.code}.",
        ) from exc
    except urllib.error.URLError as exc:
        raise ConfigValidationError(
            "Freshservice endpoint could not be reached.",
            detail="Check the base URL and local network access.",
        ) from exc


def validate_jamf_setup() -> None:
    base_url = os.environ.get("JAMF_BASE_URL", "").strip()
    if not base_url:
        raise ConfigValidationError(
            "Jamf base URL is missing.",
            detail="Set JAMF_BASE_URL in your local environment.",
        )
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ConfigValidationError(
            "Jamf base URL is invalid.",
            detail="Use the full https://yourcompany.jamfcloud.com URL.",
        )


def intune_settings_from_connector(connector: Connector) -> dict[str, object]:
    try:
        raw = json.loads(connector.settings_json or "{}")
    except json.JSONDecodeError:
        raw = {}
    settings = {**DEFAULT_INTUNE_SETTINGS, **raw}
    if settings.get("cloud") not in INTUNE_CLOUDS:
        settings["cloud"] = DEFAULT_INTUNE_SETTINGS["cloud"]
    settings["graph_permissions"] = [INTUNE_PERMISSION]
    settings["read_only"] = True
    settings["secret_storage"] = "environment"
    return settings


def build_intune_settings(form: dict[str, str]) -> dict[str, object]:
    settings = {
        **DEFAULT_INTUNE_SETTINGS,
        "display_name": form.get("display_name", "").strip() or DEFAULT_INTUNE_SETTINGS["display_name"],
        "cloud": form.get("cloud", DEFAULT_INTUNE_SETTINGS["cloud"]).strip(),
        "tenant_id": form.get("tenant_id", "").strip(),
        "client_id": form.get("client_id", "").strip(),
        "tenant_env_var": form.get("tenant_env_var", DEFAULT_INTUNE_SETTINGS["tenant_env_var"]).strip(),
        "client_env_var": form.get("client_env_var", DEFAULT_INTUNE_SETTINGS["client_env_var"]).strip(),
        "secret_env_var": form.get("secret_env_var", DEFAULT_INTUNE_SETTINGS["secret_env_var"]).strip(),
    }
    validate_intune_settings(settings)
    return settings


def save_intune_settings(conn: sqlite3.Connection, form: dict[str, str]) -> dict[str, object]:
    settings = build_intune_settings(form)
    update_connector_settings(conn, "intune", json.dumps(settings, sort_keys=True))
    return settings


def validate_intune_settings(settings: dict[str, object]) -> None:
    for field_name in ("display_name", "tenant_id", "client_id", "tenant_env_var", "client_env_var", "secret_env_var"):
        value = str(settings.get(field_name, "") or "")
        if len(value) > MAX_FIELD_LENGTH:
            raise ConfigValidationError("Intune setup is invalid.", detail=f"{field_name} must be 255 characters or fewer.")
    if settings.get("cloud") not in INTUNE_CLOUDS:
        raise ConfigValidationError("Intune cloud is invalid.", detail="Choose one of the supported Microsoft Graph clouds.")
    if settings.get("tenant_id") and not GUID_PATTERN.match(str(settings["tenant_id"])):
        raise ConfigValidationError("Tenant ID is invalid.", detail="Use the Microsoft Entra tenant GUID.")
    if settings.get("client_id") and not GUID_PATTERN.match(str(settings["client_id"])):
        raise ConfigValidationError("Client ID is invalid.", detail="Use the app registration client GUID.")
    for field_name in ("tenant_env_var", "client_env_var", "secret_env_var"):
        if not ENV_VAR_PATTERN.match(str(settings.get(field_name, ""))):
            raise ConfigValidationError(
                "Environment variable name is invalid.",
                detail=f"{field_name} must use uppercase letters, numbers, and underscores.",
            )


def intune_env_export(settings: dict[str, object]) -> str:
    tenant_value = str(settings.get("tenant_id", "") or "00000000-0000-0000-0000-000000000000")
    client_value = str(settings.get("client_id", "") or "11111111-1111-1111-1111-111111111111")
    tenant_env = str(settings.get("tenant_env_var", DEFAULT_INTUNE_SETTINGS["tenant_env_var"]))
    client_env = str(settings.get("client_env_var", DEFAULT_INTUNE_SETTINGS["client_env_var"]))
    secret_env = str(settings.get("secret_env_var", DEFAULT_INTUNE_SETTINGS["secret_env_var"]))
    return "\n".join(
        [
            f'export {tenant_env}="{tenant_value}"',
            f'export {client_env}="{client_value}"',
            f'export {secret_env}="[enter locally]"',
        ]
    )


def validate_intune_setup(settings: dict[str, object] | None = None) -> None:
    settings = {**DEFAULT_INTUNE_SETTINGS, **(settings or {})}
    validate_intune_settings(settings)
    tenant_env = str(settings["tenant_env_var"])
    client_env = str(settings["client_env_var"])
    secret_env = str(settings["secret_env_var"])
    missing = [name for name in (tenant_env, client_env, secret_env) if not os.environ.get(name, "").strip()]
    if missing:
        raise ConfigValidationError(
            "Intune setup is incomplete.",
            detail=f"Set {', '.join(missing)} in your local environment.",
        )
