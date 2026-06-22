import sqlite3
import tempfile
import unittest
from pathlib import Path

from securitywatchdaily.database import connect, initialize
from securitywatchdaily.models import FindingProduct, FindingVersionRange, ProductAlias
from securitywatchdaily.repositories.assets import (
    add_finding_product,
    add_finding_version_range,
    get_asset_by_hostname,
    list_asset_components,
    list_matches_for_asset,
    save_product_alias,
)
from securitywatchdaily.repositories.runs import list_findings
from securitywatchdaily.services.asset_import_service import import_inventory_csv, parse_inventory_csv
from securitywatchdaily.services.asset_matching_service import (
    classify_version_match,
    refresh_asset_matches_for_run,
    version_in_range,
)
from securitywatchdaily.services.import_service import seed_defaults
from securitywatchdaily.services.normalization_service import normalize_pair
from securitywatchdaily.services.run_service import run_watch


class AssetTests(unittest.TestCase):
    def make_conn(self) -> sqlite3.Connection:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "app.sqlite3"
        conn = connect(path)
        self.addCleanup(conn.close)
        initialize(conn)
        seed_defaults(conn, Path("missing-watchlist.json"))
        return conn

    def test_csv_parser_reports_row_and_field_errors(self):
        _, errors = parse_inventory_csv("hostname,product,last_seen\n,Windows 11,2026-13-01\n")
        self.assertEqual([(error.row, error.field) for error in errors], [(2, "hostname")])

    def test_csv_import_normalizes_aliases_and_saves_components(self):
        conn = self.make_conn()
        result = import_inventory_csv(
            conn,
            "hostname,owner,vendor,product,version,platform,last_seen\n"
            "laptop-1,IT,Microsoft,Windows 11 Pro,10.0.22631,Windows 11,2026-06-20\n",
        )
        self.assertEqual(result.errors, [])
        asset = get_asset_by_hostname(conn, "laptop-1")
        self.assertIsNotNone(asset)
        components = list_asset_components(conn, asset_id=asset.id)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0].normalized_vendor, "microsoft")
        self.assertEqual(components[0].normalized_product, "windows 11")

    def test_custom_product_alias_is_used(self):
        conn = self.make_conn()
        save_product_alias(conn, ProductAlias(None, "acme", "edge widget", "acme", "widget", "widgets"))
        conn.commit()
        self.assertEqual(normalize_pair(conn, "Acme", "Edge Widget", ""), ("acme", "widget", "widgets"))

    def test_version_range_handling(self):
        self.assertTrue(version_in_range("10.0.1", minimum="10.0.0", maximum="10.0.5"))
        self.assertFalse(version_in_range("10.0.6", minimum="10.0.0", maximum="10.0.5"))
        self.assertTrue(version_in_range("9.9", fixed="10.0"))
        self.assertFalse(version_in_range("10.0", fixed="10.0"))

    def test_matching_materializes_likely_affected_from_import_and_sample_run(self):
        conn = self.make_conn()
        import_inventory_csv(
            conn,
            "hostname,owner,vendor,product,version,platform,last_seen\n"
            "laptop-1,IT,Microsoft,Windows 11 Pro,10.0.22631,Windows 11,2026-06-20\n",
        )
        run = run_watch(conn, offline_sample=True, force_visible=True)
        asset = get_asset_by_hostname(conn, "laptop-1")
        matches = list_matches_for_asset(conn, asset.id)
        self.assertEqual(run.visible_count, 2)
        self.assertTrue(any(row["key"] == "CVE-2026-0001" for row in matches))
        self.assertTrue(any(row["confidence"] == "likely affected" for row in matches))

    def test_structured_version_range_can_confirm_or_clear_match(self):
        conn = self.make_conn()
        import_inventory_csv(
            conn,
            "hostname,vendor,product,version,platform\n"
            "laptop-1,Microsoft,Windows 11 Pro,10.0.22631,Windows 11\n",
        )
        run = run_watch(conn, offline_sample=True, force_visible=True)
        finding = next(item for item in list_findings(conn, run_id=run.run_id) if item.key == "CVE-2026-0001")
        finding_product_id = add_finding_product(
            conn,
            FindingProduct(None, finding.id, "microsoft", "windows 11", "windows_11", "manual"),
        )
        add_finding_version_range(conn, FindingVersionRange(None, finding_product_id, fixed_version="10.0.22632"))
        refresh_asset_matches_for_run(conn, run.run_id)
        asset = get_asset_by_hostname(conn, "laptop-1")
        matches = list_matches_for_asset(conn, asset.id)
        self.assertTrue(any(row["confidence"] == "confirmed affected" for row in matches))

    def test_classify_missing_asset_version_needs_review(self):
        class FakeRow(dict):
            def __getitem__(self, key):
                return dict.__getitem__(self, key)

        confidence, reason = classify_version_match([FakeRow(exact_version="", affected_min_version="", affected_max_version="", fixed_version="1.2.0")], "")
        self.assertEqual(confidence, "needs review")
        self.assertIn("version is missing", reason)

    def test_classify_unparseable_asset_version_unknown(self):
        class FakeRow(dict):
            def __getitem__(self, key):
                return dict.__getitem__(self, key)

        confidence, reason = classify_version_match([FakeRow(exact_version="", affected_min_version="", affected_max_version="", fixed_version="1.2.0")], "current")
        self.assertEqual(confidence, "unknown")
        self.assertIn("could not be compared", reason)


if __name__ == "__main__":
    unittest.main()
