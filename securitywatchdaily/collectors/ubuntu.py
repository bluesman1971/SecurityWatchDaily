"""Ubuntu Security Notice RSS collector."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from securitywatchdaily.collectors.http import fetch_text
from securitywatchdaily.errors import SourceParseError
from securitywatchdaily.models import Finding, Platform, Source
from securitywatchdaily.services.finding_service import make_finding


def collect(source: Source, platforms: list[Platform]) -> list[Finding]:
    ubuntu_platforms = [p for p in platforms if p.enabled and p.ubuntu_releases]
    if not ubuntu_platforms:
        return []
    text = fetch_text(source.url)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise SourceParseError("Ubuntu source returned invalid RSS XML.", detail=str(exc)) from exc
    releases = [rel for p in ubuntu_platforms for rel in p.ubuntu_releases]
    platform = ubuntu_platforms[0]
    findings: list[Finding] = []
    for item in root.findall("./channel/item")[:20]:
        title = item.findtext("title") or ""
        link = item.findtext("link") or ""
        desc = item.findtext("description") or ""
        pub = item.findtext("pubDate") or ""
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", desc, re.I)))
        if not cves:
            continue
        if releases and not any(rel in desc for rel in releases):
            continue
        key = re.sub(r":.*", "", title)
        findings.append(
            make_finding(
                key,
                platform.display_name,
                title,
                "Ubuntu Security Notice",
                desc.replace("\n", " ")[:430],
                "Patch affected packages via apt/unattended-upgrades; prioritize internet-facing services and parsers.",
                [source.name, link],
                published=pub,
                cves=cves,
                priority=platform.default_priority,
            )
        )
    return findings
