"""Validation helpers for user-editable platform and source configuration."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .errors import ConfigValidationError
from .models import Platform, Source, VALID_PRIORITIES

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
BROAD_KEYWORDS = {"365", "word", "switch", "edge", "office", "linux"}


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def validate_platform(platform: Platform, existing_ids: set[str] | None = None) -> None:
    errors: list[str] = []
    if not ID_RE.match(platform.id):
        errors.append("Platform ID must be 2-64 lowercase letters, numbers, hyphens, or underscores.")
    if existing_ids and platform.id in existing_ids:
        errors.append(f"Platform ID '{platform.id}' already exists.")
    if not platform.display_name.strip():
        errors.append("Display name is required.")
    if not platform.keywords and not platform.msrc_title_keywords and not platform.cisa_keywords:
        errors.append("Add at least one keyword or source-specific keyword.")
    if platform.default_priority not in VALID_PRIORITIES:
        errors.append(f"Default priority must be one of: {', '.join(sorted(VALID_PRIORITIES))}.")
    if platform.minimum_cve_year and platform.minimum_cve_year < 1999:
        errors.append("Minimum CVE year must be 1999 or later.")
    if errors:
        raise ConfigValidationError("Platform could not be saved.", detail=" ".join(errors))


def validate_source(source: Source, existing_ids: set[str] | None = None) -> None:
    errors: list[str] = []
    if not ID_RE.match(source.id):
        errors.append("Source ID must be 2-64 lowercase letters, numbers, hyphens, or underscores.")
    if existing_ids and source.id in existing_ids:
        errors.append(f"Source ID '{source.id}' already exists.")
    if not source.name.strip():
        errors.append("Source name is required.")
    if source.source_type not in {"msrc", "cisa", "ubuntu", "paloalto", "hn", "epss", "generic"}:
        errors.append("Source type is not supported.")
    parsed = urlparse(source.url)
    if source.source_type == "msrc" and not source.url:
        pass
    elif parsed.scheme not in {"http", "https"} or not parsed.netloc:
        errors.append("Source URL must be a valid http or https URL.")
    if errors:
        raise ConfigValidationError("Source could not be saved.", detail=" ".join(errors))
