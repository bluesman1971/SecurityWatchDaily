import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from securitywatchdaily.database import connect, initialize
from securitywatchdaily.models import ConnectorSyncRun
from securitywatchdaily.repositories.assets import get_asset_by_hostname, list_asset_components, list_matches_for_asset
from securitywatchdaily.repositories.connectors import (
    add_sync_run,
    get_connector,
    list_import_errors,
    set_connector_enabled,
)
from securitywatchdaily.repositories.runs import list_findings
from securitywatchdaily.services.asset_import_service import import_inventory_csv
from securitywatchdaily.services.connector_service import (
    ConnectorAssetRecord,
    ConnectorComponentRecord,
    import_connector_records,
    seed_connector_catalog,
    sync_connector,
    test_connector,
)
from securitywatchdaily.services.import_service import seed_defaults
from securitywatchdaily.services.run_service import run_watch


class ConnectorTests(unittest.TestCase):
    def make_conn(self) -> sqlite3.Connection:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "app.sqlite3"
        conn = connect(path)
        self.addCleanup(conn.close)
        initialize(conn)
        seed_defaults(conn, Path("missing-watchlist.json"))
        seed_connector_catalog(conn)
        return conn

    def test_connector_catalog_seeds_without_secrets(self):
        conn = self.make_conn()
        freshservice = get_connector(conn, "freshservice")
        self.assertIsNotNone(freshservice)
        self.assertIn("FRESHSERVICE_API_KEY", freshservice.settings_json)
        self.assertNotIn("example-api-key", freshservice.settings_json)
        self.assertFalse(freshservice.enabled)

    def test_freshservice_validation_reports_missing_env_without_secret_rendering(self):
        conn = self.make_conn()
        with patch.dict(os.environ, {}, clear=True):
            result = test_connector(conn, "freshservice")
        self.assertFalse(result.success)
        self.assertIn("FRESHSERVICE_TENANT_URL", result.message)
        self.assertNotIn("API key:", result.message)

    def test_sample_connector_sync_persists_health_and_mapping(self):
        conn = self.make_conn()
        set_connector_enabled(conn, "sample_inventory", True)
        run_watch(conn, offline_sample=True, force_visible=True)

        result = sync_connector(conn, "sample_inventory")

        self.assertTrue(result.success)
        self.assertEqual(result.imported_asset_count, 2)
        self.assertEqual(result.imported_component_count, 3)
        connector = get_connector(conn, "sample_inventory")
        self.assertEqual(connector.imported_asset_count, 2)
        self.assertEqual(connector.last_error, "")
        asset = get_asset_by_hostname(conn, "connector-laptop-1")
        self.assertIsNotNone(asset)
        mapping = conn.execute(
            "SELECT * FROM connector_asset_mappings WHERE connector_id = ? AND external_id = ?",
            ("sample_inventory", "sample:laptop-1"),
        ).fetchone()
        self.assertEqual(mapping["asset_id"], asset.id)
        components = list_asset_components(conn, asset_id=asset.id)
        self.assertEqual(len(components), 2)
        self.assertTrue(any(component.normalized_product == "windows 11" for component in components))
        matches = list_matches_for_asset(conn, asset.id)
        self.assertTrue(any(row["key"] == "CVE-2026-0001" for row in matches))

    def test_connector_import_errors_are_persisted(self):
        conn = self.make_conn()
        sync_run_id = add_sync_run(
            conn,
            ConnectorSyncRun(None, "sample_inventory", "2026-06-22T00:00:00Z", status="running"),
        )
        asset_count, component_count, errors = import_connector_records(
            conn,
            "sample_inventory",
            sync_run_id,
            [
                ConnectorAssetRecord(
                    external_id="bad:1",
                    hostname="",
                    components=[ConnectorComponentRecord("software", "Microsoft", "", "1.0")],
                )
            ],
        )
        saved_errors = list_import_errors(conn, sync_run_id)
        self.assertEqual(asset_count, 0)
        self.assertEqual(component_count, 0)
        self.assertEqual(len(errors), 2)
        self.assertEqual(len(saved_errors), 2)
        self.assertEqual(saved_errors[0]["connector_id"], "sample_inventory")

    def test_connector_failure_does_not_break_csv_import_or_collection(self):
        conn = self.make_conn()
        failed = sync_connector(conn, "sample_inventory")
        self.assertFalse(failed.success)
        result = import_inventory_csv(
            conn,
            "hostname,owner,vendor,product,version,platform,last_seen\n"
            "csv-laptop,IT,Microsoft,Windows 11 Pro,10.0.22631,Windows 11,2026-06-20\n",
        )
        self.assertEqual(result.errors, [])
        run = run_watch(conn, offline_sample=True, force_visible=True)
        findings = list_findings(conn, run_id=run.run_id)
        self.assertTrue(any(finding.key == "CVE-2026-0001" for finding in findings))
        self.assertIsNotNone(get_asset_by_hostname(conn, "csv-laptop"))


if __name__ == "__main__":
    unittest.main()
