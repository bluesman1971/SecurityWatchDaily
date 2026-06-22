import contextlib
import http.client
import io
import re
import tempfile
import threading
import time
import unittest
from pathlib import Path

from securitywatchdaily.auth import create_admin_user
from securitywatchdaily.cli import build_parser, main
from securitywatchdaily.database import connect, initialize
from securitywatchdaily.errors import AppError
from securitywatchdaily.web.server import serve


class SharedModeGateTests(unittest.TestCase):
    def test_loopback_bind_is_allowed_without_shared_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = serve("127.0.0.1", 0, Path(tmp) / "app.sqlite3")
            try:
                self.assertEqual(server.server_address[0], "127.0.0.1")
            finally:
                server.server_close()

    def test_unsafe_bind_hosts_are_rejected_without_shared_mode(self):
        unsafe_hosts = ["0.0.0.0", "::", "192.168.1.10"]
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "app.sqlite3"
            for host in unsafe_hosts:
                with self.subTest(host=host):
                    with self.assertRaises(AppError) as ctx:
                        serve(host, 0, db_path)
                    self.assertIn("non-loopback", ctx.exception.message)

    def test_shared_mode_requires_public_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(AppError) as ctx:
                serve("0.0.0.0", 0, Path(tmp) / "app.sqlite3", shared=True)
        self.assertIn("public URL", ctx.exception.message)

    def test_shared_mode_rejects_http_public_url_without_testing_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(AppError) as ctx:
                serve("127.0.0.1", 0, Path(tmp) / "app.sqlite3", shared=True, public_url="http://127.0.0.1:8765")
        self.assertIn("requires HTTPS", ctx.exception.message)

    def test_insecure_shared_testing_is_loopback_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(AppError) as ctx:
                serve(
                    "127.0.0.1",
                    0,
                    Path(tmp) / "app.sqlite3",
                    shared=True,
                    public_url="http://192.168.1.10:8765",
                    allow_insecure_shared_testing=True,
                )
        self.assertIn("loopback", ctx.exception.message)

    def test_shared_mode_allows_https_public_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = serve("127.0.0.1", 0, Path(tmp) / "app.sqlite3", shared=True, public_url="https://swd.example.local")
            try:
                self.assertEqual(server.RequestHandlerClass.context.public_url, "https://swd.example.local")
            finally:
                server.server_close()

    def test_insecure_shared_testing_allows_loopback_http_public_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = serve(
                "127.0.0.1",
                0,
                Path(tmp) / "app.sqlite3",
                shared=True,
                public_url="http://127.0.0.1:8765",
                allow_insecure_shared_testing=True,
            )
            try:
                self.assertEqual(server.RequestHandlerClass.context.public_url, "http://127.0.0.1:8765")
            finally:
                server.server_close()

    def test_cli_accepts_explicit_shared_flag(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "serve",
                "--host",
                "0.0.0.0",
                "--shared",
                "--public-url",
                "https://swd.example.local",
                "--allow-insecure-shared-testing",
            ]
        )
        self.assertTrue(args.shared)
        self.assertEqual(args.public_url, "https://swd.example.local")
        self.assertTrue(args.allow_insecure_shared_testing)

    def test_cli_shared_flag_defaults_to_false(self):
        parser = build_parser()
        args = parser.parse_args(["serve"])
        self.assertIs(args.shared, False)

    def test_cli_rejects_unsafe_host_without_shared_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = main(["--db", str(Path(tmp) / "app.sqlite3"), "serve", "--host", "0.0.0.0"])
        self.assertEqual(result, 1)
        self.assertIn("non-loopback", stderr.getvalue())

    def test_cli_shared_mode_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = main(["--db", str(Path(tmp) / "app.sqlite3"), "serve", "--host", "0.0.0.0", "--shared"])
        self.assertEqual(result, 1)
        self.assertIn("public URL", stderr.getvalue())

    def test_shared_https_session_cookie_is_secure_and_origin_uses_public_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "app.sqlite3"
            conn = connect(db_path)
            try:
                initialize(conn)
                create_admin_user(conn, "admin", "correct horse battery staple")
            finally:
                conn.close()
            server = serve("127.0.0.1", 0, db_path, shared=True, public_url="https://swd.example.local")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            time.sleep(0.05)
            try:
                status, _, cookie, _ = self._request(
                    server,
                    "POST",
                    "/login",
                    body="username=admin&password=correct+horse+battery+staple",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                self.assertEqual(status, 303)
                self.assertIn("Secure", cookie)
                csrf_token = self._csrf_token(server, cookie.split(";", 1)[0])
                status, data, _, _ = self._request(
                    server,
                    "POST",
                    "/run-sample",
                    body=f"csrf_token={csrf_token}",
                    headers={
                        "Cookie": cookie.split(";", 1)[0],
                        "Origin": "http://127.0.0.1",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                self.assertEqual(status, 403)
                self.assertIn("Forbidden", data)
                status, _, _, location = self._request(
                    server,
                    "POST",
                    "/run-sample",
                    body=f"csrf_token={csrf_token}",
                    headers={
                        "Cookie": cookie.split(";", 1)[0],
                        "Origin": "https://swd.example.local",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                self.assertEqual(status, 303)
                self.assertEqual(location, "/")
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_insecure_shared_testing_cookie_is_not_secure(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "app.sqlite3"
            conn = connect(db_path)
            try:
                initialize(conn)
                create_admin_user(conn, "admin", "correct horse battery staple")
            finally:
                conn.close()
            server = serve(
                "127.0.0.1",
                0,
                db_path,
                shared=True,
                public_url="http://127.0.0.1:8765",
                allow_insecure_shared_testing=True,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            time.sleep(0.05)
            try:
                status, _, cookie, _ = self._request(
                    server,
                    "POST",
                    "/login",
                    body="username=admin&password=correct+horse+battery+staple",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                self.assertEqual(status, 303)
                self.assertNotIn("Secure", cookie)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def _request(self, server, method, path, *, body="", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read().decode("utf-8")
        set_cookie = response.getheader("Set-Cookie")
        location = response.getheader("Location")
        conn.close()
        return response.status, data, set_cookie, location

    def _csrf_token(self, server, cookie):
        status, data, _, _ = self._request(server, "GET", "/", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        match = re.search(r'name="csrf_token" value="([^"]+)"', data)
        self.assertIsNotNone(match)
        return match.group(1)


if __name__ == "__main__":
    unittest.main()
