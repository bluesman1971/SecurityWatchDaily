"""Local admin authentication helpers."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import os
import re
import secrets
import sqlite3

from .errors import AppError

HASH_SCHEME = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
ADMIN_ROLE = "admin"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
SESSION_TOKEN_BYTES = 32
CSRF_TOKEN_BYTES = 32
SESSION_IDLE_TIMEOUT = timedelta(hours=8)
SESSION_ABSOLUTE_TIMEOUT = timedelta(hours=24)
SESSION_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def hash_password(password: str) -> str:
    _validate_password(password)
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "$".join(
        [
            HASH_SCHEME,
            str(PBKDF2_ITERATIONS),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        ]
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, iterations_text, salt_text, digest_text = password_hash.split("$", 3)
        if scheme != HASH_SCHEME:
            return False
        iterations = int(iterations_text)
        salt = base64.b64decode(salt_text.encode("ascii"), validate=True)
        expected = base64.b64decode(digest_text.encode("ascii"), validate=True)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def create_admin_user(conn: sqlite3.Connection, username: str, password: str) -> sqlite3.Row:
    username = _validate_username(username)
    password_hash = hash_password(password)
    try:
        conn.execute(
            """
            INSERT INTO users(username, password_hash, role)
            VALUES(?, ?, ?)
            """,
            (username, password_hash, ADMIN_ROLE),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise AppError("Admin user already exists.", detail=f"Username '{username}' already exists.") from exc
    row = get_user_by_username(conn, username)
    if row is None:
        raise AppError("Admin user could not be created.")
    return row


def list_admin_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT
          users.id,
          users.username,
          users.role,
          users.created_at,
          users.updated_at,
          users.last_login_at,
          COUNT(sessions.id) AS active_sessions
        FROM users
        LEFT JOIN sessions ON sessions.user_id = users.id
        WHERE users.role = ?
        GROUP BY users.id
        ORDER BY users.username
        """,
        (ADMIN_ROLE,),
    ).fetchall()


def delete_admin_user(conn: sqlite3.Connection, user_id: int, *, current_user_id: int) -> None:
    if user_id == current_user_id:
        raise AppError("Admin user could not be deleted.", detail="You cannot delete the account you are currently using.")
    existing = get_user_by_id(conn, user_id)
    if existing is None or existing["role"] != ADMIN_ROLE:
        raise AppError("Admin user could not be deleted.", detail="The requested admin user was not found.")
    if admin_user_count(conn) <= 1:
        raise AppError("Admin user could not be deleted.", detail="At least one admin user must remain.")
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()


def authenticate_user(conn: sqlite3.Connection, username: str, password: str) -> sqlite3.Row | None:
    row = get_user_by_username(conn, username.strip())
    if row is None or row["role"] != ADMIN_ROLE:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    conn.execute(
        "UPDATE users SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (row["id"],),
    )
    conn.commit()
    return get_user_by_username(conn, row["username"])


def create_session(conn: sqlite3.Connection, user_id: int, *, now: datetime | None = None) -> str:
    now = _utc_now(now)
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    csrf_token = secrets.token_urlsafe(CSRF_TOKEN_BYTES)
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.execute(
        """
        INSERT INTO sessions(user_id, token_hash, csrf_token, created_at, last_seen_at, absolute_expires_at)
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            hash_session_token(token),
            csrf_token,
            _format_time(now),
            _format_time(now),
            _format_time(now + SESSION_ABSOLUTE_TIMEOUT),
        ),
    )
    conn.commit()
    return token


def validate_session(conn: sqlite3.Connection, token: str, *, now: datetime | None = None) -> sqlite3.Row | None:
    if not token:
        return None
    now = _utc_now(now)
    row = conn.execute(
        """
        SELECT
          sessions.id AS session_id,
          sessions.csrf_token,
          sessions.last_seen_at,
          sessions.absolute_expires_at,
          users.id,
          users.username,
          users.role,
          users.created_at,
          users.updated_at,
          users.last_login_at
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ?
        """,
        (hash_session_token(token),),
    ).fetchone()
    if row is None:
        return None
    if row["role"] != ADMIN_ROLE or _session_is_expired(row, now):
        conn.execute("DELETE FROM sessions WHERE id = ?", (row["session_id"],))
        conn.commit()
        return None
    conn.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (_format_time(now), row["session_id"]))
    conn.commit()
    return row


def destroy_session(conn: sqlite3.Connection, token: str) -> None:
    if not token:
        return
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_session_token(token),))
    conn.commit()


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, username, password_hash, role, created_at, updated_at, last_login_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, username, role, created_at, updated_at, last_login_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def admin_user_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role = ?", (ADMIN_ROLE,)).fetchone()
    return int(row["count"] if row else 0)


def _session_is_expired(row: sqlite3.Row, now: datetime) -> bool:
    try:
        last_seen_at = _parse_time(row["last_seen_at"])
        absolute_expires_at = _parse_time(row["absolute_expires_at"])
    except ValueError:
        return True
    return now - last_seen_at > SESSION_IDLE_TIMEOUT or now >= absolute_expires_at


def _utc_now(now: datetime | None = None) -> datetime:
    value = now or datetime.now(UTC)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0)


def _format_time(value: datetime) -> str:
    return _utc_now(value).strftime(SESSION_TIME_FORMAT)


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, SESSION_TIME_FORMAT).replace(tzinfo=UTC)


def _validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME_RE.match(username):
        raise AppError(
            "Username is invalid.",
            detail="Use 3-64 letters, numbers, dots, underscores, or hyphens.",
        )
    return username


def _validate_password(password: str) -> None:
    if len(password) < 12:
        raise AppError("Password is too short.", detail="Use at least 12 characters for the admin password.")
