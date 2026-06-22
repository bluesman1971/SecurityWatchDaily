"""Hacker News CVE signal collector."""

from __future__ import annotations

import datetime as dt
import re

from securitywatchdaily.collectors.http import fetch_json
from securitywatchdaily.models import Finding, Platform, Source
from securitywatchdaily.services.finding_service import make_finding
from securitywatchdaily.services.matching_service import any_keyword


def collect(source: Source, platforms: list[Platform]) -> list[Finding]:
    start = int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)).timestamp())
    url = source.url.replace("{start}", str(start))
    data = fetch_json(url)
    if not isinstance(data, dict):
        return []
    keywords = sorted({kw for p in platforms if p.enabled for kw in p.keywords})
    findings: list[Finding] = []
    for hit in data.get("hits", [])[:20]:
        text = " ".join(str(hit.get(k, "")) for k in ["title", "url", "story_text"])
        has_cve = bool(re.search(r"CVE-\d{4}-\d{4,7}", text, re.I))
        security_context = any(term in text.casefold() for term in ["vulnerability", "exploit", "zero-day", "0-day", "security advisory", "patch tuesday"])
        if has_cve and security_context and any_keyword(text, keywords):
            key = hit.get("objectID") or hit.get("story_id") or hit.get("created_at_i")
            findings.append(
                make_finding(
                    f"HN-{key}",
                    "Security news / community signal",
                    hit.get("title", "HN CVE mention"),
                    "Hacker News CVE mention in last 24h",
                    hit.get("url", ""),
                    "Review story/comments for exploit chatter; confirm against vendor sources before action.",
                    [source.name],
                    published=hit.get("created_at", ""),
                    priority="Watch",
                )
            )
    return findings
