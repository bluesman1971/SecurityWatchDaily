"""Ubuntu Security Notice RSS collector."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from securitywatchdaily.collectors.http import fetch_text
from securitywatchdaily.errors import SourceParseError
from securitywatchdaily.models import Finding, Platform, Source
from securitywatchdaily.services.finding_service import make_finding


# A DOCTYPE / DTD is required to define the custom entities used by
# entity-expansion ("billion laughs") denial-of-service payloads. RSS feeds do
# not need one, so we reject any DTD before parsing. This is the same core
# defense provided by defusedxml's forbid_dtd, kept dependency-free so the
# project preserves its standard-library-only runtime posture.
_DOCTYPE_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)


def _parse_rss_safely(text: str) -> ET.Element:
    if _DOCTYPE_RE.search(text):
        raise SourceParseError(
            "Ubuntu source XML was rejected.",
            detail="The feed declared a document type definition (DTD), which is not allowed for security reasons.",
        )
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise SourceParseError("Ubuntu source returned invalid RSS XML.", detail=str(exc)) from exc


def collect(source: Source, platforms: list[Platform]) -> list[Finding]:
    ubuntu_platforms = [p for p in platforms if p.enabled and p.ubuntu_releases]
    if not ubuntu_platforms:
        return []
    text = fetch_text(source.url)
    root = _parse_rss_safely(text)
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
