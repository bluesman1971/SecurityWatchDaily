"""Core data models used across CLI, services, storage, and web UI."""

from __future__ import annotations

from dataclasses import dataclass, field


VALID_PRIORITIES = {"Critical", "High", "Medium", "Watch", "Info"}


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


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    started_at: str
    lookback_start: str
    visible_count: int
    suppressed_count: int
    collected_count: int
    source_status: dict[str, str]
