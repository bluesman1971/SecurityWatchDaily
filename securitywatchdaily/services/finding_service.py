"""Finding creation and deduplication."""

from __future__ import annotations

import hashlib
import re

from securitywatchdaily.models import Finding

from .priority_service import normalize_priority, severity_rank


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def make_finding(
    key: str,
    platform: str,
    title: str,
    status: str,
    description: str,
    action: str,
    sources: list[str],
    *,
    published: str = "",
    cves: list[str] | None = None,
    priority: str | None = None,
) -> Finding:
    cve_list = cves or sorted({c.upper() for c in CVE_RE.findall(" ".join([key, title, description, status]))})
    final_priority = priority or normalize_priority(status, title)
    stable = "|".join([final_priority, platform, key, title, status, description, action, ",".join(sorted(sources))])
    return Finding(
        key=key,
        platform=platform,
        title=title,
        status=status,
        description=description,
        action=action,
        sources=sources,
        published=published,
        cves=cve_list,
        priority=final_priority,
        status_hash=hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16],
    )


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        old = deduped.get(finding.key)
        if old is None:
            deduped[finding.key] = finding
            continue
        old.sources = sorted(set(old.sources + finding.sources))
        if severity_rank(finding.priority) > severity_rank(old.priority) or len(finding.description) > len(old.description):
            finding.sources = old.sources
            deduped[finding.key] = finding
    return list(deduped.values())
