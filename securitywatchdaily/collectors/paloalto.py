"""Palo Alto Networks advisory CSV collector."""

from __future__ import annotations

import csv
import io

from securitywatchdaily.collectors.http import fetch_text
from securitywatchdaily.models import Finding, Platform, Source
from securitywatchdaily.services.finding_service import make_finding


def collect(source: Source, platforms: list[Platform]) -> list[Finding]:
    pan_platforms = [p for p in platforms if p.enabled and p.paloalto_products]
    if not pan_platforms:
        return []
    text = fetch_text(source.url)
    products = [prod for p in pan_platforms for prod in p.paloalto_products]
    platform = pan_platforms[0]
    findings: list[Finding] = []
    for row in csv.DictReader(io.StringIO(text)):
        product = row.get("Product", "")
        if products and not any(prod in product for prod in products):
            continue
        title = row.get("Title", "")
        severity = (row.get("Severity", "") or "Watch").title()
        priority = "High" if severity in {"Critical", "High"} or any(term in title.casefold() for term in ["authentication bypass", "remote code execution"]) else platform.default_priority
        findings.append(
            make_finding(
                row.get("ID", ""),
                platform.display_name,
                title,
                f"Palo Alto advisory severity: {severity}; updated {row.get('Date updated', '')}",
                row.get("Problem", "")[:430],
                "Upgrade to fixed PAN-OS/Prisma Access/Cloud NGFW versions; apply workarounds where listed.",
                [source.name, row.get("URL", "")],
                published=row.get("Date published", ""),
                priority=priority,
            )
        )
    return findings
