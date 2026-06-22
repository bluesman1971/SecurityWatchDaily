"""CISA Known Exploited Vulnerabilities collector."""

from __future__ import annotations

import datetime as dt

from securitywatchdaily.collectors.http import fetch_json
from securitywatchdaily.models import Finding, Platform, Source
from securitywatchdaily.services.finding_service import make_finding
from securitywatchdaily.services.matching_service import any_keyword, cve_year, match_platform


def collect(source: Source, platforms: list[Platform]) -> list[Finding]:
    data = fetch_json(source.url)
    if not isinstance(data, dict):
        return []
    cutoff = (dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=60)).isoformat()
    findings: list[Finding] = []
    for item in data.get("vulnerabilities", [])[:250]:
        date_added = item.get("dateAdded", "")
        if date_added and date_added < cutoff:
            continue
        vendor = item.get("vendorProject", "")
        product = item.get("product", "")
        name = item.get("vulnerabilityName", "")
        desc = item.get("shortDescription", "")
        blob = " ".join([vendor, product, name, desc])
        platform = match_platform(blob, platforms, keyword_field="cisa_keywords", cve_year_value=cve_year(item.get("cveID", "")))
        if not platform:
            continue
        if platform.id in {"windows_11", "m365", "office"} and vendor.casefold() != "microsoft":
            chromium_ok = platform.id == "windows_11" and vendor.casefold() == "google" and any_keyword(product, ["chromium"])
            if not chromium_ok:
                continue
        findings.append(
            make_finding(
                item["cveID"],
                platform.display_name,
                name,
                "CISA KEV: known exploited in the wild",
                desc,
                "Follow vendor mitigation/patch guidance and CISA KEV due dates; prioritize exposed assets.",
                [source.name],
                published=date_added,
                priority="High",
            )
        )
    return findings
