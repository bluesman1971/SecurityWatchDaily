import http.client
import tempfile
import threading
import time
import unittest
from pathlib import Path

from securitywatchdaily.web.server import serve


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = serve("127.0.0.1", 0, Path(self.tmp.name) / "app.sqlite3")
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
        conn.close()
        return response.status, data

    def test_dashboard_renders(self):
        status, data = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("Daily vulnerability watch", data)

    def test_sample_run_from_web(self):
        status, _ = self.request("POST", "/run-sample", body="", headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 303)
        status, data = self.request("GET", "/findings")
        self.assertEqual(status, 200)
        self.assertIn("CVE-2026-0001", data)

    def test_asset_import_error_lists_row_and_field(self):
        body = "csv_text=hostname%2Cproduct%0A%2CWindows%2011"
        status, data = self.request(
            "POST",
            "/assets/import",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 400)
        self.assertIn("Import needs changes", data)
        self.assertIn("hostname", data)

    def test_asset_import_list_detail_and_finding_impacts_render(self):
        body = (
            "csv_text=hostname%2Cowner%2Cvendor%2Cproduct%2Cversion%2Cplatform%0A"
            "laptop-1%2CIT%2CMicrosoft%2CWindows%2011%20Pro%2C10.0.22631%2CWindows%2011"
        )
        status, data = self.request(
            "POST",
            "/assets/import",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 200)
        self.assertIn("Import complete", data)
        status, _ = self.request("POST", "/run-sample", body="", headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 303)
        status, assets = self.request("GET", "/assets")
        self.assertEqual(status, 200)
        self.assertIn("laptop-1", assets)
        status, detail = self.request("GET", "/assets/1")
        self.assertEqual(status, 200)
        self.assertIn("Related findings", detail)
        self.assertIn("CVE-2026-0001", detail)
        status, finding = self.request("GET", "/findings/1")
        self.assertEqual(status, 200)
        self.assertIn("Impacted assets", finding)
        self.assertIn("laptop-1", finding)

    def test_connector_catalog_detail_and_sample_sync_render(self):
        status, catalog = self.request("GET", "/connectors")
        self.assertEqual(status, 200)
        self.assertIn("Connector Catalog", catalog)
        self.assertIn("Sample Inventory", catalog)

        status, detail = self.request("GET", "/connectors/sample_inventory")
        self.assertEqual(status, 200)
        self.assertIn("Credentials are read from local environment variables", detail)

        body = "id=sample_inventory&enabled=1"
        status, _ = self.request(
            "POST",
            "/connectors/toggle",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303)

        status, test_result = self.request(
            "POST",
            "/connectors/test",
            body="id=sample_inventory",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 200)
        self.assertIn("Sample connector is ready", test_result)

        status, _ = self.request("POST", "/run-sample", body="", headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 303)
        status, sync_result = self.request(
            "POST",
            "/connectors/sync",
            body="id=sample_inventory",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 200)
        self.assertIn("2 assets and 3 components imported", sync_result)
        status, assets = self.request("GET", "/assets")
        self.assertEqual(status, 200)
        self.assertIn("connector-laptop-1", assets)


if __name__ == "__main__":
    unittest.main()
