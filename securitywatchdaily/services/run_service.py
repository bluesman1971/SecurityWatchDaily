"""Run orchestration for collection, trace filtering, and persistence."""

from __future__ import annotations

import datetime as dt
import sqlite3

from securitywatchdaily.collectors import collect_source
from securitywatchdaily.errors import AppError
from securitywatchdaily.models import Finding, RunRecord
from securitywatchdaily.repositories.platforms import list_platforms
from securitywatchdaily.repositories.runs import save_run
from securitywatchdaily.repositories.sources import list_sources

from .finding_service import deduplicate_findings, make_finding
from .trace_service import apply_trace


SAMPLE_FINDINGS = [
    make_finding(
        "CVE-2026-0001",
        "Windows 11 / Microsoft endpoint stack",
        "Microsoft Windows Sample Remote Code Execution Vulnerability",
        "Publicly Disclosed:Yes; Exploited:No",
        "Offline sample finding used to validate local workflow without network access.",
        "Apply relevant Microsoft security updates after confirming affected builds.",
        ["Offline sample"],
        priority="High",
    ),
    make_finding(
        "CVE-2026-0002",
        "Palo Alto firewalls / PAN-OS",
        "PAN-OS Sample Privilege Escalation Vulnerability",
        "Vendor advisory severity: Medium",
        "Offline sample finding used to validate trace suppression and UI rendering.",
        "Review affected versions and schedule upgrade if applicable.",
        ["Offline sample"],
        priority="Medium",
    ),
]


def run_watch(conn: sqlite3.Connection, *, offline_sample: bool = False, force_visible: bool = False) -> RunRecord:
    now = dt.datetime.now(dt.timezone.utc)
    run_id = now.strftime("%Y-%m-%dT%H-%M-%SZ")
    lookback = (now - dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    platforms = list_platforms(conn, enabled_only=True)
    sources = list_sources(conn, enabled_only=True)
    findings: list[Finding] = []
    source_status: dict[str, str] = {}

    if offline_sample:
        findings.extend(SAMPLE_FINDINGS)
        source_status["Offline sample"] = "ok"
    else:
        for source in sources:
            try:
                collected = collect_source(source, platforms)
                findings.extend(collected)
                source_status[source.name] = f"ok ({len(collected)} findings)"
            except AppError as exc:
                source_status[source.name] = exc.detail or exc.message
            except Exception as exc:
                source_status[source.name] = f"Unexpected collector error: {type(exc).__name__}: {exc}"

    findings = deduplicate_findings(findings)
    visible, suppressed = apply_trace(conn, findings, run_id)
    if force_visible:
        visible = findings
        suppressed = []
        for finding in visible:
            if finding.trace_status == "unchanged_suppressed":
                finding.trace_status = "forced_visible"
    record = RunRecord(
        run_id=run_id,
        started_at=now.isoformat(),
        lookback_start=lookback,
        visible_count=len(visible),
        suppressed_count=len(suppressed),
        collected_count=len(findings),
        source_status=source_status,
    )
    save_run(conn, record, findings)
    return record
