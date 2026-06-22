import contextlib
from datetime import UTC, datetime, timedelta
import http.client
import io
import re
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from securitywatchdaily.auth import (
    SESSION_ABSOLUTE_TIMEOUT,
    SESSION_IDLE_TIMEOUT,
    authenticate_user,
    create_admin_user,
    create_session,
    delete_admin_user,
    hash_session_token,
    list_admin_users,
    validate_session,
)
from securitywatchdaily.cli import main
from securitywatchdaily.database import connect, initialize
from securitywatchdaily.web.server import serve


class AuthStorageTests(unittest.TestCase):
    def make_conn(self) -> sqlite3.Connection:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        conn = connect(Path(tmp.name) / "app.sqlite3")
        self.addCleanup(conn.close)
        initialize(conn)
        return conn

    def test_create_admin_user(self):
        conn = self.make_conn()
        user = create_admin_user(conn, "admin", "correct horse battery staple")
        self.assertEqual(user["username"], "admin")
        self.assertEqual(user["role"], "admin")

    def test_list_admin_users_includes_session_count(self):
        conn = self.make_conn()
        user = create_admin_user(conn, "admin", "correct horse battery staple")
        create_session(conn, int(user["id"]))
        users = list_admin_users(conn)
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["username"], "admin")
        self.assertEqual(users[0]["active_sessions"], 1)

    def test_delete_admin_user_removes_sessions(self):
        conn = self.make_conn()
        current = create_admin_user(conn, "admin", "correct horse battery staple")
        other = create_admin_user(conn, "backup", "another correct horse battery")
        token = create_session(conn, int(other["id"]))
        delete_admin_user(conn, int(other["id"]), current_user_id=int(current["id"]))
        self.assertIsNone(conn.execute("SELECT id FROM users WHERE username = ?", ("backup",)).fetchone())
        self.assertIsNone(validate_session(conn, token))

    def test_delete_admin_user_rejects_current_user(self):
        conn = self.make_conn()
        current = create_admin_user(conn, "admin", "correct horse battery staple")
        with self.assertRaisesRegex(Exception, "Admin user could not be deleted"):
            delete_admin_user(conn, int(current["id"]), current_user_id=int(current["id"]))

    def test_password_hash_is_stored_not_plaintext(self):
        conn = self.make_conn()
        password = "correct horse battery staple"
        create_admin_user(conn, "admin", password)
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?", ("admin",)).fetchone()
        self.assertIsNotNone(row)
        self.assertNotEqual(row["password_hash"], password)
        self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$"))

    def test_session_token_is_hashed_and_validated_server_side(self):
        conn = self.make_conn()
        user = create_admin_user(conn, "admin", "correct horse battery staple")
        token = create_session(conn, int(user["id"]), now=datetime(2026, 6, 22, 12, 0, tzinfo=UTC))
        row = conn.execute("SELECT token_hash FROM sessions WHERE user_id = ?", (user["id"],)).fetchone()
        self.assertIsNotNone(row)
        self.assertNotEqual(row["token_hash"], token)
        self.assertEqual(row["token_hash"], hash_session_token(token))
        validated = validate_session(conn, token, now=datetime(2026, 6, 22, 12, 5, tzinfo=UTC))
        self.assertIsNotNone(validated)
        self.assertEqual(validated["username"], "admin")

    def test_idle_expired_session_is_rejected(self):
        conn = self.make_conn()
        user = create_admin_user(conn, "admin", "correct horse battery staple")
        issued_at = datetime(2026, 6, 22, 12, 0, tzinfo=UTC)
        token = create_session(conn, int(user["id"]), now=issued_at)
        validated = validate_session(conn, token, now=issued_at + SESSION_IDLE_TIMEOUT + timedelta(seconds=1))
        self.assertIsNone(validated)
        count = conn.execute("SELECT COUNT(*) AS count FROM sessions").fetchone()["count"]
        self.assertEqual(count, 0)

    def test_absolute_expired_session_is_rejected(self):
        conn = self.make_conn()
        user = create_admin_user(conn, "admin", "correct horse battery staple")
        issued_at = datetime(2026, 6, 22, 12, 0, tzinfo=UTC)
        token = create_session(conn, int(user["id"]), now=issued_at)
        conn.execute(
            "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
            ("2026-06-23T11:59:59Z", hash_session_token(token)),
        )
        conn.commit()
        validated = validate_session(conn, token, now=issued_at + SESSION_ABSOLUTE_TIMEOUT)
        self.assertIsNone(validated)
        count = conn.execute("SELECT COUNT(*) AS count FROM sessions").fetchone()["count"]
        self.assertEqual(count, 0)

    def test_cli_create_admin_bootstrap_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "app.sqlite3"
            stdout = io.StringIO()
            stdin = io.StringIO("correct horse battery staple\n")
            with contextlib.redirect_stdout(stdout), mock.patch("sys.stdin", stdin):
                result = main(["--db", str(db_path), "create-admin", "--username", "admin", "--password-stdin"])
            self.assertEqual(result, 0)
            self.assertIn('"created": true', stdout.getvalue())
            conn = connect(db_path)
            try:
                initialize(conn)
                self.assertIsNotNone(authenticate_user(conn, "admin", "correct horse battery staple"))
            finally:
                conn.close()


class AuthWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "app.sqlite3"
        conn = connect(self.db_path)
        try:
            initialize(conn)
            create_admin_user(conn, "admin", "correct horse battery staple")
        finally:
            conn.close()
        self.server = serve("127.0.0.1", 0, self.db_path)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read().decode("utf-8")
        set_cookie = response.getheader("Set-Cookie")
        location = response.getheader("Location")
        conn.close()
        return response.status, data, set_cookie, location

    def login(self, username="admin", password="correct horse battery staple"):
        body = f"username={username}&password={password.replace(' ', '+')}"
        return self.request("POST", "/login", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})

    def origin(self):
        return f"http://127.0.0.1:{self.port}"

    def csrf_token(self, cookie, path="/"):
        status, data, _, _ = self.request("GET", path, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        match = re.search(r'name="csrf_token" value="([^"]+)"', data)
        self.assertIsNotNone(match)
        return match.group(1)

    def test_valid_login_succeeds(self):
        status, _, set_cookie, location = self.login()
        self.assertEqual(status, 303)
        self.assertEqual(location, "/")
        self.assertIn("swd_session=", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)
        self.assertIn("Path=/", set_cookie)
        self.assertNotIn("Secure", set_cookie)

    def test_session_cookie_token_is_not_stored_plaintext_in_sqlite(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        token = cookie.split("=", 1)[1]
        conn = connect(self.db_path)
        try:
            row = conn.execute("SELECT token_hash FROM sessions").fetchone()
            self.assertIsNotNone(row)
            self.assertNotEqual(row["token_hash"], token)
            self.assertEqual(row["token_hash"], hash_session_token(token))
        finally:
            conn.close()

    def test_session_token_hash_is_accepted_server_side(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        status, data, _, _ = self.request("GET", "/", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertIn("Daily vulnerability watch", data)

    def test_invalid_password_fails(self):
        status, data, set_cookie, _ = self.login(password="wrong password value")
        self.assertEqual(status, 401)
        self.assertIn("Invalid username or password", data)
        self.assertIsNone(set_cookie)

    def test_unknown_username_fails(self):
        status, data, set_cookie, _ = self.login(username="nobody")
        self.assertEqual(status, 401)
        self.assertIn("Invalid username or password", data)
        self.assertIsNone(set_cookie)

    def test_protected_get_routes_reject_unauthenticated_users(self):
        paths = [
            "/",
            "/platforms",
            "/platforms/new",
            "/sources",
            "/sources/new",
            "/runs",
            "/findings",
            "/findings/1",
            "/assets",
            "/assets/import",
            "/assets/1",
            "/connectors",
            "/connectors/sample_inventory",
            "/connectors/intune/setup",
            "/admin/users",
        ]
        for path in paths:
            with self.subTest(path=path):
                status, _, _, location = self.request("GET", path)
                self.assertEqual(status, 303)
                self.assertEqual(location, f"/login?next={path}")

    def test_protected_post_routes_reject_unauthenticated_users(self):
        paths = [
            "/platforms",
            "/platforms/toggle",
            "/sources",
            "/sources/toggle",
            "/run-now",
            "/run-sample",
            "/assets/import",
            "/connectors/toggle",
            "/connectors/test",
            "/connectors/sync",
            "/connectors/intune/settings",
            "/admin/users",
            "/admin/users/delete",
        ]
        for path in paths:
            with self.subTest(path=path):
                status, data, _, _ = self.request(
                    "POST",
                    path,
                    body="id=sample_inventory",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                self.assertEqual(status, 401)
                self.assertIn("Authentication required", data)

    def test_each_protected_post_route_rejects_missing_csrf(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        paths = [
            "/platforms",
            "/platforms/toggle",
            "/sources",
            "/sources/toggle",
            "/run-now",
            "/run-sample",
            "/assets/import",
            "/connectors/toggle",
            "/connectors/test",
            "/connectors/sync",
            "/connectors/intune/settings",
            "/admin/users",
            "/admin/users/delete",
            "/logout",
        ]
        for path in paths:
            with self.subTest(path=path):
                status, data, _, _ = self.request(
                    "POST",
                    path,
                    body="id=sample_inventory",
                    headers={
                        "Cookie": cookie,
                        "Origin": self.origin(),
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                self.assertEqual(status, 403)
                self.assertIn("Forbidden", data)

    def test_invalid_csrf_is_rejected(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        status, data, _, _ = self.request(
            "POST",
            "/run-sample",
            body="csrf_token=invalid",
            headers={"Cookie": cookie, "Origin": self.origin(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 403)
        self.assertIn("Forbidden", data)

    def test_bad_origin_is_rejected(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        csrf_token = self.csrf_token(cookie)
        status, data, _, _ = self.request(
            "POST",
            "/run-sample",
            body=f"csrf_token={csrf_token}",
            headers={
                "Cookie": cookie,
                "Origin": "http://evil.example",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        self.assertEqual(status, 403)
        self.assertIn("Forbidden", data)

    def test_valid_authenticated_same_origin_post_succeeds(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        csrf_token = self.csrf_token(cookie)
        status, _, _, location = self.request(
            "POST",
            "/run-sample",
            body=f"csrf_token={csrf_token}",
            headers={"Cookie": cookie, "Origin": self.origin(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303)
        self.assertEqual(location, "/")

    def test_logout_requires_valid_csrf(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        status, data, _, _ = self.request(
            "POST",
            "/logout",
            body="csrf_token=invalid",
            headers={"Cookie": cookie, "Origin": self.origin(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 403)
        self.assertIn("Forbidden", data)

        csrf_token = self.csrf_token(cookie)
        status, _, clear_cookie, location = self.request(
            "POST",
            "/logout",
            body=f"csrf_token={csrf_token}",
            headers={"Cookie": cookie, "Origin": self.origin(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303)
        self.assertEqual(location, "/login")
        self.assertIn("Max-Age=0", clear_cookie)

    def test_public_routes_remain_public(self):
        status, data, _, _ = self.request("GET", "/login")
        self.assertEqual(status, 200)
        self.assertIn("Login", data)

        status, data, _, _ = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertIn('"ok": true', data)

        status, data, _, _ = self.request("GET", "/static/app.css")
        self.assertEqual(status, 200)
        self.assertIn(":root", data)

    def test_logout_invalidates_access(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        csrf_token = self.csrf_token(cookie)

        status, _, _, _ = self.request("GET", "/", headers={"Cookie": cookie})
        self.assertEqual(status, 200)

        status, _, clear_cookie, _ = self.request(
            "POST",
            "/logout",
            body=f"csrf_token={csrf_token}",
            headers={"Cookie": cookie, "Origin": self.origin(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303)
        self.assertIn("Max-Age=0", clear_cookie)
        conn = connect(self.db_path)
        try:
            count = conn.execute("SELECT COUNT(*) AS count FROM sessions").fetchone()["count"]
            self.assertEqual(count, 0)
        finally:
            conn.close()

        status, _, _, location = self.request("GET", "/", headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        self.assertEqual(location, "/login?next=/")

    def test_login_rotates_and_replaces_prior_session_token(self):
        status, _, first_set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        first_cookie = first_set_cookie.split(";", 1)[0]

        status, _, second_set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        second_cookie = second_set_cookie.split(";", 1)[0]
        self.assertNotEqual(first_cookie, second_cookie)

        conn = connect(self.db_path)
        try:
            count = conn.execute("SELECT COUNT(*) AS count FROM sessions").fetchone()["count"]
            self.assertEqual(count, 1)
        finally:
            conn.close()

        status, _, _, location = self.request("GET", "/", headers={"Cookie": first_cookie})
        self.assertEqual(status, 303)
        self.assertEqual(location, "/login?next=/")

        status, data, _, _ = self.request("GET", "/", headers={"Cookie": second_cookie})
        self.assertEqual(status, 200)
        self.assertIn("Daily vulnerability watch", data)

    def test_expired_idle_session_cookie_is_rejected(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        token = cookie.split("=", 1)[1]
        conn = connect(self.db_path)
        try:
            expired_last_seen = datetime.now(UTC) - SESSION_IDLE_TIMEOUT - timedelta(seconds=1)
            conn.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
                (expired_last_seen.strftime("%Y-%m-%dT%H:%M:%SZ"), hash_session_token(token)),
            )
            conn.commit()
        finally:
            conn.close()
        status, _, _, location = self.request("GET", "/", headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        self.assertEqual(location, "/login?next=/")

    def test_expired_absolute_session_cookie_is_rejected(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        token = cookie.split("=", 1)[1]
        conn = connect(self.db_path)
        try:
            expired_at = datetime.now(UTC) - timedelta(seconds=1)
            conn.execute(
                "UPDATE sessions SET absolute_expires_at = ? WHERE token_hash = ?",
                (expired_at.strftime("%Y-%m-%dT%H:%M:%SZ"), hash_session_token(token)),
            )
            conn.commit()
        finally:
            conn.close()
        status, _, _, location = self.request("GET", "/", headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        self.assertEqual(location, "/login?next=/")

    def test_session_ids_in_urls_are_rejected(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        token = set_cookie.split(";", 1)[0].split("=", 1)[1]
        status, data, _, _ = self.request("GET", f"/?swd_session={token}")
        self.assertEqual(status, 400)
        self.assertIn("Bad request", data)

        status, _, _, location = self.request("GET", f"/?session_id={token}")
        self.assertEqual(status, 400)
        self.assertIsNone(location)

    def test_admin_users_panel_creates_user(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        status, data, _, _ = self.request("GET", "/admin/users", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertIn("Admin users", data)
        self.assertIn("admin", data)
        csrf_token = self.csrf_token(cookie, "/admin/users")

        body = (
            "username=backup&password=another+correct+horse+battery&"
            f"confirm_password=another+correct+horse+battery&csrf_token={csrf_token}"
        )
        status, data, _, _ = self.request(
            "POST",
            "/admin/users",
            body=body,
            headers={"Cookie": cookie, "Origin": self.origin(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 200)
        self.assertIn("Admin user &#x27;backup&#x27; created.", data)
        self.assertIn("backup", data)

        status, _, backup_cookie, _ = self.login(username="backup", password="another correct horse battery")
        self.assertEqual(status, 303)
        self.assertIn("swd_session=", backup_cookie)

    def test_admin_users_panel_rejects_password_mismatch(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        csrf_token = self.csrf_token(cookie, "/admin/users")
        body = (
            "username=backup&password=another+correct+horse+battery&"
            f"confirm_password=different+correct+horse&csrf_token={csrf_token}"
        )
        status, data, _, _ = self.request(
            "POST",
            "/admin/users",
            body=body,
            headers={"Cookie": cookie, "Origin": self.origin(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 200)
        self.assertIn("Passwords did not match.", data)

    def test_admin_users_panel_deletes_user_and_invalidates_session(self):
        conn = connect(self.db_path)
        try:
            backup = create_admin_user(conn, "backup", "another correct horse battery")
            backup_id = int(backup["id"])
        finally:
            conn.close()
        status, _, backup_set_cookie, _ = self.login(username="backup", password="another correct horse battery")
        self.assertEqual(status, 303)
        backup_cookie = backup_set_cookie.split(";", 1)[0]
        status, _, admin_set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        admin_cookie = admin_set_cookie.split(";", 1)[0]
        csrf_token = self.csrf_token(admin_cookie, "/admin/users")

        status, data, _, _ = self.request(
            "POST",
            "/admin/users/delete",
            body=f"user_id={backup_id}&csrf_token={csrf_token}",
            headers={"Cookie": admin_cookie, "Origin": self.origin(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 200)
        self.assertIn("Admin user deleted.", data)
        self.assertNotIn("<b>backup</b>", data)

        status, _, _, location = self.request("GET", "/", headers={"Cookie": backup_cookie})
        self.assertEqual(status, 303)
        self.assertEqual(location, "/login?next=/")

    def test_admin_users_panel_rejects_self_delete(self):
        status, _, set_cookie, _ = self.login()
        self.assertEqual(status, 303)
        cookie = set_cookie.split(";", 1)[0]
        conn = connect(self.db_path)
        try:
            admin_id = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()["id"]
        finally:
            conn.close()
        csrf_token = self.csrf_token(cookie, "/admin/users")
        status, data, _, _ = self.request(
            "POST",
            "/admin/users/delete",
            body=f"user_id={admin_id}&csrf_token={csrf_token}",
            headers={"Cookie": cookie, "Origin": self.origin(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 400)
        self.assertIn("You cannot delete the account you are currently using.", data)


if __name__ == "__main__":
    unittest.main()
