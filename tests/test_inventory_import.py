import sqlite3
import tempfile
import unittest
from pathlib import Path

from securitywatchdaily.database import connect, initialize
from securitywatchdaily.repositories.assets import get_asset_by_hostname, list_asset_components
from securitywatchdaily.services.connector_service import seed_connector_catalog
from securitywatchdaily.services.import_service import seed_defaults
from securitywatchdaily.services.inventory_import_service import (
    InventoryComponent,
    InventoryRecord,
    import_inventory,
)


class InventoryImportTests(unittest.TestCase):
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

    def record(self, hostname="host-1", **overrides) -> InventoryRecord:
        fields = {
            "hostname": hostname,
            "components": [InventoryComponent("software", "Microsoft", "Windows 11 Pro", "10.0.22631", "Windows 11")],
        }
        fields.update(overrides)
        return InventoryRecord(**fields)

    def test_imports_assets_and_normalizes_components(self):
        conn = self.make_conn()
        result = import_inventory(conn, [self.record()])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.assets_imported, 1)
        self.assertEqual(result.components_imported, 1)
        asset = get_asset_by_hostname(conn, "host-1")
        self.assertIsNotNone(asset)
        components = list_asset_components(conn, asset_id=asset.id)
        self.assertEqual(components[0].normalized_product, "windows 11")

    def test_all_or_nothing_writes_nothing_on_any_error(self):
        conn = self.make_conn()
        good = self.record(hostname="good-host")
        bad = self.record(hostname="")  # missing hostname
        result = import_inventory(conn, [good, bad])
        self.assertEqual(result.assets_imported, 0)
        self.assertTrue(any(error.field == "hostname" for error in result.errors))
        # The valid record must not have been written.
        self.assertIsNone(get_asset_by_hostname(conn, "good-host"))

    def test_connector_id_requires_external_id_and_writes_mapping(self):
        conn = self.make_conn()
        missing = self.record(hostname="mapped-host")  # no external_id
        result = import_inventory(conn, [missing], connector_id="sample_inventory")
        self.assertTrue(any(error.field == "external_id" for error in result.errors))

        ok = self.record(hostname="mapped-host", external_id="ext:1")
        result = import_inventory(conn, [ok], connector_id="sample_inventory")
        self.assertEqual(result.errors, [])
        asset = get_asset_by_hostname(conn, "mapped-host")
        mapping = conn.execute(
            "SELECT asset_id FROM connector_asset_mappings WHERE connector_id = ? AND external_id = ?",
            ("sample_inventory", "ext:1"),
        ).fetchone()
        self.assertEqual(mapping["asset_id"], asset.id)

    def test_component_error_points_at_component(self):
        conn = self.make_conn()
        record = InventoryRecord(
            hostname="host-1",
            components=[InventoryComponent("software", "Microsoft", "")],  # blank product
        )
        result = import_inventory(conn, [record])
        product_errors = [error for error in result.errors if error.field == "product"]
        self.assertEqual(len(product_errors), 1)
        self.assertEqual(product_errors[0].component_index, 1)

    def test_reimport_replaces_components_for_asset(self):
        conn = self.make_conn()
        import_inventory(conn, [self.record(hostname="host-1")])
        replacement = InventoryRecord(
            hostname="host-1",
            components=[InventoryComponent("software", "Mozilla", "Firefox", "120.0")],
        )
        import_inventory(conn, [replacement])
        asset = get_asset_by_hostname(conn, "host-1")
        components = list_asset_components(conn, asset_id=asset.id)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0].product, "Firefox")


if __name__ == "__main__":
    unittest.main()
