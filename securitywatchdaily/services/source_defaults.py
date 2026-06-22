"""Default source definitions for a fresh local database."""

from __future__ import annotations

from securitywatchdaily.models import Source


DEFAULT_SOURCES = [
    Source(
        id="msrc",
        name="Microsoft MSRC CVRF",
        source_type="msrc",
        url="",
        notes="Uses current and previous month CVRF endpoints.",
    ),
    Source(
        id="cisa_kev",
        name="CISA KEV JSON",
        source_type="cisa",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ),
    Source(
        id="ubuntu_usn",
        name="Ubuntu USN RSS",
        source_type="ubuntu",
        url="https://ubuntu.com/security/notices/rss.xml",
    ),
    Source(
        id="paloalto_advisories",
        name="Palo Alto advisory CSV",
        source_type="paloalto",
        url="https://security.paloaltonetworks.com/csv?",
    ),
    Source(
        id="hackernews_cve",
        name="Hacker News Algolia CVE search",
        source_type="hn",
        url="https://hn.algolia.com/api/v1/search_by_date?query=CVE&tags=story&numericFilters=created_at_i>{start}",
        notes="Community signal only; confirm against vendor sources.",
    ),
]
