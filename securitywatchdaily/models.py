"""Core data models used across CLI, services, storage, and web UI."""

from __future__ import annotations

from dataclasses import dataclass, field


VALID_PRIORITIES = {"Critical", "High", "Medium", "Watch", "Info"}
MATCH_CONFIDENCES = {"confirmed affected", "likely affected", "needs review", "not affected", "unknown"}
CONNECTOR_STATUSES = {"available", "enabled", "disabled", "error"}


@dataclass(frozen=True)
class Platform:
    id: str
    display_name: str
    enabled: bool = True
    vendors: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    exclude_keywords: list[str] = field(default_factory=list)
    minimum_cve_year: int = 0
    default_priority: str = "Medium"
    msrc_title_keywords: list[str] = field(default_factory=list)
    cisa_keywords: list[str] = field(default_factory=list)
    ubuntu_releases: list[str] = field(default_factory=list)
    paloalto_products: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    source_type: str
    url: str
    enabled: bool = True
    notes: str = ""


@dataclass
class Finding:
    key: str
    platform: str
    title: str
    status: str
    description: str
    action: str
    sources: list[str]
    published: str = ""
    cves: list[str] = field(default_factory=list)
    priority: str = "Watch"
    status_hash: str = ""
    trace_status: str = "new"
    epss_score: str = ""
    epss_percentile: str = ""
    id: int | None = None
    run_id: str = ""


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    started_at: str
    lookback_start: str
    visible_count: int
    suppressed_count: int
    collected_count: int
    source_status: dict[str, str]


@dataclass(frozen=True)
class Asset:
    id: int | None
    hostname: str
    owner: str = ""
    location: str = ""
    asset_type: str = ""
    platform: str = ""
    last_seen: str = ""


@dataclass(frozen=True)
class AssetComponent:
    id: int | None
    asset_id: int
    component_type: str
    vendor: str
    product: str
    version: str = ""
    platform: str = ""
    normalized_vendor: str = ""
    normalized_product: str = ""


@dataclass(frozen=True)
class ProductAlias:
    id: int | None
    raw_vendor: str
    raw_product: str
    normalized_vendor: str
    normalized_product: str
    platform: str = ""


@dataclass(frozen=True)
class FindingProduct:
    id: int | None
    finding_id: int
    vendor: str
    product: str
    platform: str = ""
    source: str = "inferred"


@dataclass(frozen=True)
class FindingVersionRange:
    id: int | None
    finding_product_id: int
    affected_min_version: str = ""
    affected_max_version: str = ""
    fixed_version: str = ""
    exact_version: str = ""


@dataclass(frozen=True)
class FindingAssetMatch:
    id: int | None
    finding_id: int
    asset_id: int
    asset_component_id: int | None
    confidence: str
    reason: str
    review_state: str = ""


@dataclass(frozen=True)
class Connector:
    id: str
    name: str
    connector_type: str
    description: str
    enabled: bool = False
    settings_json: str = "{}"
    last_successful_sync: str = ""
    last_failed_sync: str = ""
    last_error: str = ""
    imported_asset_count: int = 0
    imported_component_count: int = 0


@dataclass(frozen=True)
class ConnectorSyncRun:
    id: int | None
    connector_id: str
    started_at: str
    finished_at: str = ""
    status: str = "running"
    action: str = "sync"
    imported_asset_count: int = 0
    imported_component_count: int = 0
    error: str = ""


@dataclass(frozen=True)
class ConnectorImportError:
    id: int | None
    sync_run_id: int
    connector_id: str
    external_id: str
    field: str
    message: str


@dataclass(frozen=True)
class ConnectorAssetMapping:
    id: int | None
    connector_id: str
    external_id: str
    asset_id: int
