"""Microsoft Security Response Center collector."""

from __future__ import annotations

import datetime as dt
import re

from securitywatchdaily.collectors.http import fetch_json
from securitywatchdaily.models import Finding, Platform, Source
from securitywatchdaily.services.finding_service import make_finding
from securitywatchdaily.services.matching_service import any_keyword
from securitywatchdaily.services.priority_service import normalize_priority


def current_msrc_urls(now: dt.datetime | None = None) -> list[str]:
    current = now or dt.datetime.now(dt.timezone.utc)
    month = current.strftime("%Y-%b")
    previous = (current.replace(day=1) - dt.timedelta(days=1)).strftime("%Y-%b")
    return [
        f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}",
        f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{previous}",
    ]


def collect(source: Source, platforms: list[Platform]) -> list[Finding]:
    urls = [source.url] if source.url else current_msrc_urls()
    data = None
    for url in urls:
        try:
            data = fetch_json(url)
            break
        except Exception:
            if url == urls[-1]:
                raise
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    candidates = [p for p in platforms if p.enabled and p.msrc_title_keywords]
    for vuln in data.get("Vulnerability", []):
        cve = vuln.get("CVE", "")
        title = vuln.get("Title", {}).get("Value", "")
        platform = next((p for p in candidates if any_keyword(title, p.msrc_title_keywords)), None)
        if not platform:
            continue
        threat_blob = ";".join(t.get("Description", {}).get("Value", "") for t in vuln.get("Threats", []))
        title_low = title.casefold()
        include = "Publicly Disclosed:Yes" in threat_blob or "Exploited:Yes" in threat_blob
        if any(x in title_low for x in ["office", "word", "excel", "outlook", "powerpoint", "visio", "microsoft 365", "copilot"]):
            include = include or any(y in title_low for y in ["remote code execution", "information disclosure", "elevation of privilege", "security feature bypass"])
        if not include:
            continue
        desc = ""
        for note in vuln.get("Notes", []):
            if note.get("Title") == "Description":
                desc = re.sub("<[^<]+?>", "", note.get("Value", "")).strip()
                break
        score = ""
        if vuln.get("CVSSScoreSets"):
            score = str(vuln["CVSSScoreSets"][0].get("BaseScore", ""))
        priority = "High" if "Exploited:Yes" in threat_blob or ("Publicly Disclosed:Yes" in threat_blob and score and float(score) >= 7.0) else normalize_priority(threat_blob, title)
        findings.append(
            make_finding(
                cve,
                platform.display_name,
                title,
                threat_blob or "Microsoft security update",
                desc[:420],
                "Apply relevant Microsoft security updates; verify fixed builds/channels in Microsoft admin/update tooling.",
                [source.name],
                priority=priority,
            )
        )
    return findings
