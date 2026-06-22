"""Priority normalization and ordering."""

from __future__ import annotations


RANKS = {"Critical": 4, "High": 3, "Medium": 2, "Watch": 1, "Info": 0}


def severity_rank(priority: str) -> int:
    return RANKS.get(priority, 0)


def normalize_priority(status: str, title: str = "") -> str:
    text = f"{status} {title}".casefold()
    if any(term in text for term in ["actively exploited", "kev", "exploited:yes", "ransomware"]):
        return "High"
    if any(term in text for term in ["critical", "rce", "remote code execution"]):
        return "High"
    if any(term in text for term in ["publicly disclosed", "authentication bypass", "privilege"]):
        return "Medium"
    return "Watch"
