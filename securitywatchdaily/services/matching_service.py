"""Platform matching with conservative keyword behavior."""

from __future__ import annotations

import re

from securitywatchdaily.models import Platform


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").casefold()).strip()


def keyword_matches(text: str, keyword: str) -> bool:
    haystack = normalize_text(text)
    needle = normalize_text(keyword)
    if not needle:
        return False
    if any(ch.isspace() for ch in needle) or "-" in needle:
        return needle in haystack
    return re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", haystack) is not None


def any_keyword(text: str, keywords: list[str]) -> bool:
    return any(keyword_matches(text, keyword) for keyword in keywords or [])


def cve_year(cve: str) -> int:
    match = re.match(r"CVE-(\d{4})-", cve or "", re.I)
    return int(match.group(1)) if match else 0


def match_platform(
    text: str,
    platforms: list[Platform],
    *,
    keyword_field: str = "keywords",
    cve_year_value: int | None = None,
) -> Platform | None:
    for platform in platforms:
        if not platform.enabled:
            continue
        if cve_year_value is not None and cve_year_value < platform.minimum_cve_year:
            continue
        if any_keyword(text, platform.exclude_keywords):
            continue
        keywords = getattr(platform, keyword_field, None) or platform.keywords
        if any_keyword(text, keywords):
            return platform
    return None


def preview_platform_matches(platform: Platform, samples: list[str]) -> list[tuple[str, bool]]:
    results: list[tuple[str, bool]] = []
    for sample in samples:
        excluded = any_keyword(sample, platform.exclude_keywords)
        included = any_keyword(sample, platform.keywords) and not excluded
        results.append((sample, included))
    return results
