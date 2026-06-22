import http.client
import contextlib
import io
import re
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from securitywatchdaily.auth import create_admin_user
from securitywatchdaily.database import connect, initialize
from securitywatchdaily.web.server import serve


class WebTests(unittest.TestCase):
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
        self.cookie = self.login()
        self.csrf_token = self.fetch_csrf_token("/")

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        status, data, response_headers = self.request_with_headers(method, path, body=body, headers=headers)
        return status, data, response_headers.get("Set-Cookie")

    def request_with_headers(self, method, path, body=None, headers=None):
        headers = dict(headers or {})
        if self.cookie:
            headers.setdefault("Cookie", self.cookie)
        if method == "POST" and self.cookie:
            headers.setdefault("Origin", self.origin())
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            body = self.with_csrf(body)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read().decode("utf-8")
        response_headers = {name: value for name, value in response.getheaders()}
        conn.close()
        return response.status, data, response_headers

    def login(self):
        previous_cookie = getattr(self, "cookie", "")
        self.cookie = ""
        status, _, set_cookie = self.request(
            "POST",
            "/login",
            body="username=admin&password=correct+horse+battery+staple",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.cookie = previous_cookie
        self.assertEqual(status, 303)
        self.assertIsNotNone(set_cookie)
        return set_cookie.split(";", 1)[0]

    def origin(self):
        return f"http://127.0.0.1:{self.port}"

    def fetch_csrf_token(self, path):
        status, data, _ = self.request("GET", path)
        self.assertEqual(status, 200)
        match = re.search(r'name="csrf_token" value="([^"]+)"', data)
        self.assertIsNotNone(match)
        return match.group(1)

    def with_csrf(self, body):
        body = body or ""
        if "csrf_token=" in body:
            return body
        separator = "&" if body else ""
        return f"{body}{separator}csrf_token={self.csrf_token}"

    def test_dashboard_renders(self):
        status, data, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("Daily vulnerability watch", data)

    def test_html_routes_include_security_headers(self):
        for path in ["/", "/login"]:
            with self.subTest(path=path):
                status, _, headers = self.request_with_headers("GET", path)
                self.assertIn(status, {200, 401})
                self.assertEqual(
                    headers.get("Content-Security-Policy"),
                    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                )
                self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
                self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
                self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_static_css_keeps_content_type_and_nosniff(self):
        status, _, headers = self.request_with_headers("GET", "/static/app.css")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "text/css; charset=utf-8")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_malformed_asset_and_finding_ids_fail_safely(self):
        for path, label in [("/assets/not-an-int", "requested asset was not found"), ("/findings/not-an-int", "requested finding was not found")]:
            with self.subTest(path=path):
                status, data, _ = self.request("GET", path)
                self.assertIn(status, {400, 404})
                self.assertIn(label, data)
                self.assertNotIn("ValueError", data)
                self.assertNotIn("invalid literal", data)

    def test_invalid_minimum_cve_year_returns_validation_error(self):
        body = (
            "id=phase7_platform&display_name=Phase+7+Platform&keywords=phase7&"
            "minimum_cve_year=twenty&default_priority=Medium"
        )
        status, data, _ = self.request("POST", "/platforms", body=body)
        self.assertEqual(status, 400)
        self.assertIn("Minimum CVE year must be a whole number.", data)
        self.assertNotIn("ValueError", data)
        self.assertNotIn("invalid literal", data)

    def test_unexpected_get_errors_render_safe_generic_page(self):
        def boom(handler):
            raise RuntimeError(
                "RuntimeError /Users/thomasbaker/security-vuln-watch "
                "FRESHSERVICE_API_KEY=live-secret Bearer abc123 csrf_token=token123 "
                "https://user:password@example.com/feed"
            )

        with mock.patch.object(self.server.RequestHandlerClass, "dashboard", boom):
            with contextlib.redirect_stderr(io.StringIO()):
                status, data, _ = self.request("GET", "/")
        self.assertEqual(status, 500)
        self.assertIn("Unexpected local error", data)
        for unsafe in [
            "RuntimeError",
            "Traceback",
            "/Users/thomasbaker/security-vuln-watch",
            "live-secret",
            "Bearer abc123",
            "csrf_token=token123",
            "https://user:password@example.com/feed",
        ]:
            self.assertNotIn(unsafe, data)

    def test_unexpected_post_errors_render_safe_generic_page(self):
        def boom(handler, *, offline_sample):
            raise RuntimeError(
                "RuntimeError /Users/thomasbaker/security-vuln-watch "
                "client_secret=live-secret swd_session=session123 https://user:password@example.com/feed"
            )

        with mock.patch.object(self.server.RequestHandlerClass, "run_now", boom):
            with contextlib.redirect_stderr(io.StringIO()):
                status, data, _ = self.request("POST", "/run-sample", body="")
        self.assertEqual(status, 500)
        self.assertIn("Unexpected local error", data)
        for unsafe in [
            "RuntimeError",
            "Traceback",
            "/Users/thomasbaker/security-vuln-watch",
            "live-secret",
            "swd_session=session123",
            "https://user:password@example.com/feed",
        ]:
            self.assertNotIn(unsafe, data)

    def test_sample_run_from_web(self):
        status, _, _ = self.request("POST", "/run-sample", body="")
        self.assertEqual(status, 303)
        status, data, _ = self.request("GET", "/findings")
        self.assertEqual(status, 200)
        self.assertIn("CVE-2026-0001", data)

    def test_asset_import_error_lists_row_and_field(self):
        body = "csv_text=hostname%2Cproduct%0A%2CWindows%2011"
        status, data, _ = self.request(
            "POST",
            "/assets/import",
            body=body,
        )
        self.assertEqual(status, 400)
        self.assertIn("Import needs changes", data)
        self.assertIn("hostname", data)

    def test_asset_import_list_detail_and_finding_impacts_render(self):
        body = (
            "csv_text=hostname%2Cowner%2Cvendor%2Cproduct%2Cversion%2Cplatform%0A"
            "laptop-1%2CIT%2CMicrosoft%2CWindows%2011%20Pro%2C10.0.22631%2CWindows%2011"
        )
        status, data, _ = self.request(
            "POST",
            "/assets/import",
            body=body,
        )
        self.assertEqual(status, 200)
        self.assertIn("Import complete", data)
        status, _, _ = self.request("POST", "/run-sample", body="")
        self.assertEqual(status, 303)
        status, assets, _ = self.request("GET", "/assets")
        self.assertEqual(status, 200)
        self.assertIn("laptop-1", assets)
        status, detail, _ = self.request("GET", "/assets/1")
        self.assertEqual(status, 200)
        self.assertIn("Related findings", detail)
        self.assertIn("CVE-2026-0001", detail)
        status, finding, _ = self.request("GET", "/findings/1")
        self.assertEqual(status, 200)
        self.assertIn("Impacted assets", finding)
        self.assertIn("laptop-1", finding)

    def test_connector_catalog_detail_and_sample_sync_render(self):
        status, catalog, _ = self.request("GET", "/connectors")
        self.assertEqual(status, 200)
        self.assertIn("Connector Catalog", catalog)
        self.assertIn("Sample Inventory", catalog)

        status, detail, _ = self.request("GET", "/connectors/sample_inventory")
        self.assertEqual(status, 200)
        self.assertIn("Credentials are read from local environment variables", detail)

        body = "id=sample_inventory&enabled=1"
        status, _, _ = self.request(
            "POST",
            "/connectors/toggle",
            body=body,
        )
        self.assertEqual(status, 303)

        status, test_result, _ = self.request(
            "POST",
            "/connectors/test",
            body="id=sample_inventory",
        )
        self.assertEqual(status, 200)
        self.assertIn("Sample connector is ready", test_result)

        status, _, _ = self.request("POST", "/run-sample", body="")
        self.assertEqual(status, 303)
        status, sync_result, _ = self.request(
            "POST",
            "/connectors/sync",
            body="id=sample_inventory",
        )
        self.assertEqual(status, 200)
        self.assertIn("2 assets and 3 components imported", sync_result)
        status, assets, _ = self.request("GET", "/assets")
        self.assertEqual(status, 200)
        self.assertIn("connector-laptop-1", assets)

    def test_intune_setup_page_saves_non_secret_settings(self):
        status, detail, _ = self.request("GET", "/connectors/intune")
        self.assertEqual(status, 200)
        self.assertIn("Configure Intune", detail)

        status, setup, _ = self.request("GET", "/connectors/intune/setup")
        self.assertEqual(status, 200)
        self.assertIn("Add Microsoft Intune", setup)
        self.assertIn("DeviceManagementManagedDevices.Read.All", setup)
        self.assertIn("INTUNE_CLIENT_SECRET", setup)

        body = (
            "display_name=Corporate+Intune&cloud=global&"
            "tenant_id=22222222-2222-2222-2222-222222222222&"
            "client_id=33333333-3333-3333-3333-333333333333&"
            "tenant_env_var=ACME_INTUNE_TENANT_ID&"
            "client_env_var=ACME_INTUNE_CLIENT_ID&"
            "secret_env_var=ACME_INTUNE_CLIENT_SECRET&"
            "client_secret=do-not-store-this"
        )
        status, saved, _ = self.request(
            "POST",
            "/connectors/intune/settings",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 200)
        self.assertIn("Intune connector settings saved", saved)
        self.assertIn("ACME_INTUNE_CLIENT_SECRET", saved)
        self.assertNotIn("do-not-store-this", saved)


if __name__ == "__main__":
    unittest.main()
