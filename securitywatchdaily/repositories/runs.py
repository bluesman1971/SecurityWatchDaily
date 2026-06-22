"""Persistence for runs, findings, and trace state."""

from __future__ import annotations

import sqlite3

from securitywatchdaily.database import dumps, loads_dict, loads_list
from securitywatchdaily.models import Finding, RunRecord


def save_run(conn: sqlite3.Connection, record: RunRecord, findings: list[Finding]) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO runs (
          run_id, started_at, lookback_start, visible_count, suppressed_count, collected_count, source_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.run_id,
            record.started_at,
            record.lookback_start,
            record.visible_count,
            record.suppressed_count,
            record.collected_count,
            dumps(record.source_status),
        ),
    )
    conn.execute("DELETE FROM findings WHERE run_id = ?", (record.run_id,))
    conn.executemany(
        """
        INSERT INTO findings (
          run_id, key, platform, title, status, description, action, sources, published, cves,
          priority, status_hash, trace_status, epss_score, epss_percentile
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                record.run_id,
                f.key,
                f.platform,
                f.title,
                f.status,
                f.description,
                f.action,
                dumps(f.sources),
                f.published,
                dumps(f.cves),
                f.priority,
                f.status_hash,
                f.trace_status,
                f.epss_score,
                f.epss_percentile,
            )
            for f in findings
        ],
    )
    conn.commit()


def list_runs(conn: sqlite3.Connection, *, limit: int = 20) -> list[RunRecord]:
    rows = conn.execute(
        "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        RunRecord(
            run_id=row["run_id"],
            started_at=row["started_at"],
            lookback_start=row["lookback_start"],
            visible_count=int(row["visible_count"]),
            suppressed_count=int(row["suppressed_count"]),
            collected_count=int(row["collected_count"]),
            source_status=loads_dict(row["source_status"]),
        )
        for row in rows
    ]


def latest_run(conn: sqlite3.Connection) -> RunRecord | None:
    rows = list_runs(conn, limit=1)
    return rows[0] if rows else None


def list_findings(conn: sqlite3.Connection, *, run_id: str | None = None, visible_only: bool = False) -> list[Finding]:
    sql = "SELECT * FROM findings"
    clauses: list[str] = []
    params: list[object] = []
    if run_id:
        clauses.append("run_id = ?")
        params.append(run_id)
    if visible_only:
        clauses.append("trace_status != 'unchanged_suppressed'")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY CASE priority WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 WHEN 'Watch' THEN 1 ELSE 0 END DESC, platform, key"
    return [
        Finding(
            key=row["key"],
            platform=row["platform"],
            title=row["title"],
            status=row["status"],
            description=row["description"],
            action=row["action"],
            sources=loads_list(row["sources"]),
            published=row["published"],
            cves=loads_list(row["cves"]),
            priority=row["priority"],
            status_hash=row["status_hash"],
            trace_status=row["trace_status"],
            epss_score=row["epss_score"],
            epss_percentile=row["epss_percentile"],
            id=int(row["id"]),
            run_id=row["run_id"],
        )
        for row in conn.execute(sql, params)
    ]


def get_finding(conn: sqlite3.Connection, finding_id: int) -> Finding | None:
    row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if not row:
        return None
    return Finding(
        key=row["key"],
        platform=row["platform"],
        title=row["title"],
        status=row["status"],
        description=row["description"],
        action=row["action"],
        sources=loads_list(row["sources"]),
        published=row["published"],
        cves=loads_list(row["cves"]),
        priority=row["priority"],
        status_hash=row["status_hash"],
        trace_status=row["trace_status"],
        epss_score=row["epss_score"],
        epss_percentile=row["epss_percentile"],
        id=int(row["id"]),
        run_id=row["run_id"],
    )


def get_trace_item(conn: sqlite3.Connection, key: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM trace_items WHERE key = ?", (key,)).fetchone()


def upsert_trace_item(conn: sqlite3.Connection, finding: Finding, run_id: str, first_seen: str, times_seen: int) -> None:
    conn.execute(
        """
        INSERT INTO trace_items (key, first_seen, last_seen, priority, status_hash, title, platform, times_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
          last_seen=excluded.last_seen,
          priority=excluded.priority,
          status_hash=excluded.status_hash,
          title=excluded.title,
          platform=excluded.platform,
          times_seen=excluded.times_seen
        """,
        (
            finding.key,
            first_seen,
            run_id,
            finding.priority,
            finding.status_hash,
            finding.title,
            finding.platform,
            times_seen,
        ),
    )
