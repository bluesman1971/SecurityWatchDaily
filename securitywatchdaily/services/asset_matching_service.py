"""Asset-to-finding impact matching."""

from __future__ import annotations

import re
import sqlite3

from securitywatchdaily.models import Finding, FindingAssetMatch, FindingProduct
from securitywatchdaily.repositories.assets import (
    add_finding_product,
    clear_matches_for_findings,
    list_asset_components,
    list_finding_products,
    list_finding_version_ranges,
    replace_matches,
)
from securitywatchdaily.repositories.platforms import list_platforms
from securitywatchdaily.repositories.runs import list_findings

from .matching_service import keyword_matches
from .normalization_service import normalize_pair, normalize_token, seed_product_aliases


def refresh_asset_matches_for_run(conn: sqlite3.Connection, run_id: str) -> int:
    seed_product_aliases(conn)
    sync_finding_products(conn, run_id)
    findings = [finding for finding in list_findings(conn, run_id=run_id) if finding.id is not None]
    finding_ids = {int(finding.id) for finding in findings if finding.id is not None}
    clear_matches_for_findings(conn, finding_ids)
    matches: list[FindingAssetMatch] = []
    components = list_asset_components(conn)
    for finding in findings:
        products = list_finding_products(conn, finding_id=int(finding.id))
        for product in products:
            ranges = list_finding_version_ranges(conn, int(product["id"]))
            for component in components:
                match = match_component_to_product(
                    finding_id=int(finding.id),
                    finding_product=product,
                    version_ranges=ranges,
                    component=component,
                )
                if match:
                    matches.append(match)
    replace_matches(conn, matches)
    conn.commit()
    return len(matches)


def sync_finding_products(conn: sqlite3.Connection, run_id: str) -> None:
    platforms = list_platforms(conn)
    findings = [finding for finding in list_findings(conn, run_id=run_id) if finding.id is not None]
    for finding in findings:
        platform = next((item for item in platforms if item.display_name == finding.platform or item.id == finding.platform), None)
        for vendor, product, platform_id in infer_products_for_finding(conn, finding, platform):
            add_finding_product(
                conn,
                FindingProduct(
                    id=None,
                    finding_id=int(finding.id),
                    vendor=vendor,
                    product=product,
                    platform=platform_id,
                    source="inferred",
                ),
            )


def infer_products_for_finding(conn: sqlite3.Connection, finding: Finding, platform) -> set[tuple[str, str, str]]:
    text = " ".join([finding.platform, finding.title, finding.description, finding.action])
    candidates: set[tuple[str, str, str]] = set()
    if platform is not None:
        vendors = platform.vendors or [""]
        product_names = []
        product_names.append(platform.display_name.split("/")[0].strip())
        product_names.extend(platform.paloalto_products)
        product_names.extend(platform.ubuntu_releases)
        product_names.extend(keyword for keyword in platform.keywords if " " in keyword or "-" in keyword)
        for vendor in vendors:
            for product in product_names:
                if not product:
                    continue
                normalized_vendor, normalized_product, normalized_platform = normalize_pair(conn, vendor, product, platform.id)
                candidates.add((normalized_vendor, normalized_product, normalized_platform or platform.id))
    for vendor, product in extract_title_products(text):
        normalized_vendor, normalized_product, normalized_platform = normalize_pair(conn, vendor, product, "")
        candidates.add((normalized_vendor, normalized_product, normalized_platform))
    return candidates


def extract_title_products(text: str) -> set[tuple[str, str]]:
    normalized = normalize_token(text)
    pairs: set[tuple[str, str]] = set()
    known = [
        ("microsoft", "windows 11"),
        ("microsoft", "microsoft 365"),
        ("microsoft", "office"),
        ("canonical", "ubuntu"),
        ("palo alto networks", "pan-os"),
        ("cisco", "meraki"),
    ]
    for vendor, product in known:
        if keyword_matches(normalized, product) or keyword_matches(normalized, vendor):
            pairs.add((vendor, product))
    return pairs


def match_component_to_product(
    *,
    finding_id: int,
    finding_product: sqlite3.Row,
    version_ranges: list[sqlite3.Row],
    component,
) -> FindingAssetMatch | None:
    if not product_matches(finding_product, component):
        return None
    confidence, reason = classify_version_match(version_ranges, component.version)
    return FindingAssetMatch(
        id=None,
        finding_id=finding_id,
        asset_id=component.asset_id,
        asset_component_id=component.id,
        confidence=confidence,
        reason=reason,
    )


def product_matches(finding_product: sqlite3.Row, component) -> bool:
    product_match = finding_product["product"] == component.normalized_product
    vendor_match = not finding_product["vendor"] or not component.normalized_vendor or finding_product["vendor"] == component.normalized_vendor
    platform_match = not finding_product["platform"] or not component.platform or finding_product["platform"] == component.platform
    return product_match and vendor_match and platform_match


def classify_version_match(version_ranges: list[sqlite3.Row], asset_version: str) -> tuple[str, str]:
    if not version_ranges:
        return "likely affected", "Product matched; no structured affected-version range is available."
    if not asset_version.strip():
        return "needs review", "Product matched, but the asset version is missing."
    saw_unknown = False
    for version_range in version_ranges:
        result = version_in_range(
            asset_version,
            exact=version_range["exact_version"],
            minimum=version_range["affected_min_version"],
            maximum=version_range["affected_max_version"],
            fixed=version_range["fixed_version"],
        )
        if result is True:
            return "confirmed affected", "Product and version matched a structured affected range."
        if result is False:
            continue
        saw_unknown = True
    if saw_unknown:
        return "unknown", "Product matched, but the asset version could not be compared to the structured range."
    return "not affected", "Product matched, but the asset version is outside known affected ranges."


def version_in_range(asset_version: str, *, exact: str = "", minimum: str = "", maximum: str = "", fixed: str = "") -> bool | None:
    asset = version_key(asset_version)
    if not asset:
        return None
    if exact:
        expected = version_key(exact)
        return asset == expected if expected else None
    if fixed:
        fixed_key = version_key(fixed)
        if fixed_key:
            return asset < fixed_key
    if minimum:
        min_key = version_key(minimum)
        if min_key and asset < min_key:
            return False
    if maximum:
        max_key = version_key(maximum)
        if max_key and asset > max_key:
            return False
    return True


def version_key(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version or "")
    return tuple(int(part) for part in parts)
