import contextlib
import http.client
import io
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from securitywatchdaily.auth import authenticate_user, create_admin_user
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

    def test_password_hash_is_stored_not_plaintext(self):
        conn = self.make_conn()
        password = "correct horse battery staple"
        create_admin_user(conn, "admin", password)
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?", ("admin",)).fetchone()
        self.assertIsNotNone(row)
        self.assertNotEqual(row["password_hash"], password)
        self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$"))

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

    def test_valid_login_succeeds(self):
        status, _, set_cookie, location = self.login()
        self.assertEqual(status, 303)
        self.assertEqual(location, "/")
        self.assertIn("swd_session=", set_cookie)

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

        status, _, _, _ = self.request("GET", "/", headers={"Cookie": cookie})
        self.assertEqual(status, 200)

        status, _, clear_cookie, _ = self.request("POST", "/logout", headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        self.assertIn("Max-Age=0", clear_cookie)

        status, _, _, location = self.request("GET", "/", headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        self.assertEqual(location, "/login?next=/")


if __name__ == "__main__":
    unittest.main()
