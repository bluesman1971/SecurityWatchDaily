import http.client
import re
import tempfile
import threading
import time
import unittest
from pathlib import Path

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
        set_cookie = response.getheader("Set-Cookie")
        conn.close()
        return response.status, data, set_cookie

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
