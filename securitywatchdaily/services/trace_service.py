"""Trace-state suppression for repeat findings."""

from __future__ import annotations

import sqlite3

from securitywatchdaily.models import Finding
from securitywatchdaily.repositories.runs import get_trace_item, upsert_trace_item


def apply_trace(conn: sqlite3.Connection, findings: list[Finding], run_id: str) -> tuple[list[Finding], list[Finding]]:
    visible: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        previous = get_trace_item(conn, finding.key)
        if previous is None:
            finding.trace_status = "new"
            visible.append(finding)
            first_seen = run_id
            times_seen = 1
        else:
            first_seen = previous["first_seen"]
            times_seen = int(previous["times_seen"]) + 1
            if previous["priority"] != finding.priority:
                finding.trace_status = f"priority_changed:{previous['priority']}->{finding.priority}"
                visible.append(finding)
            elif previous["status_hash"] != finding.status_hash:
                finding.trace_status = "details_changed"
                visible.append(finding)
            else:
                finding.trace_status = "unchanged_suppressed"
                suppressed.append(finding)
        upsert_trace_item(conn, finding, run_id, first_seen, times_seen)
    conn.commit()
    return visible, suppressed
