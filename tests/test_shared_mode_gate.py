import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from securitywatchdaily.cli import build_parser, main
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

    def test_shared_mode_fails_closed_until_remaining_prerequisites_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(AppError) as ctx:
                serve("0.0.0.0", 0, Path(tmp) / "app.sqlite3", shared=True)
        self.assertIn("Shared mode is not available yet", ctx.exception.message)
        self.assertIn("browser security headers", ctx.exception.detail)
        self.assertIn("upload hardening", ctx.exception.detail)

    def test_cli_accepts_explicit_shared_flag(self):
        parser = build_parser()
        args = parser.parse_args(["serve", "--host", "0.0.0.0", "--shared"])
        self.assertTrue(args.shared)

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
        self.assertIn("Shared mode is not available yet", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
