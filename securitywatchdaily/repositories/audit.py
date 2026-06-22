"""Local audit event persistence."""

from __future__ import annotations

import sqlite3

from securitywatchdaily.database import dumps, loads_dict


def add_audit_event(
    conn: sqlite3.Connection,
    *,
    action: str,
    username: str,
    result: str,
    context: dict[str, object] | None = None,
) -> None:
    safe_context = {str(key): str(value) for key, value in (context or {}).items()}
    conn.execute(
        """
        INSERT INTO audit_events(action, username, result, context_json)
        VALUES(?, ?, ?, ?)
        """,
        (action, username, result, dumps(safe_context)),
    )
    conn.commit()


def list_audit_events(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM audit_events ORDER BY id"))


def audit_context(row: sqlite3.Row) -> dict[str, str]:
    return loads_dict(row["context_json"])
