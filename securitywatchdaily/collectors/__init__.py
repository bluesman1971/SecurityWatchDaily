"""Collector registry."""

from __future__ import annotations

from securitywatchdaily.models import Finding, Platform, Source

from . import cisa, hn, msrc, paloalto, ubuntu


COLLECTORS = {
    "msrc": msrc.collect,
    "cisa": cisa.collect,
    "ubuntu": ubuntu.collect,
    "paloalto": paloalto.collect,
    "hn": hn.collect,
}


def collect_source(source: Source, platforms: list[Platform]) -> list[Finding]:
    collector = COLLECTORS.get(source.source_type)
    if not collector:
        return []
    return collector(source, platforms)
