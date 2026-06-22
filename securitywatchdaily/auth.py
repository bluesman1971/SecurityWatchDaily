"""Local admin authentication helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import sqlite3

from .errors import AppError

HASH_SCHEME = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
ADMIN_ROLE = "admin"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")


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
