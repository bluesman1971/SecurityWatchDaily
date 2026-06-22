import sqlite3
import tempfile
import unittest
from pathlib import Path

from securitywatchdaily.database import connect, initialize
from securitywatchdaily.models import Platform
from securitywatchdaily.repositories.platforms import list_platforms, save_platform
from securitywatchdaily.repositories.runs import latest_run, list_findings
from securitywatchdaily.services.run_service import run_watch


class StorageRunTests(unittest.TestCase):
    def make_conn(self) -> sqlite3.Connection:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "app.sqlite3"
        conn = connect(path)
        self.addCleanup(conn.close)
        initialize(conn)
        return conn

    def test_platform_roundtrip(self):
        conn = self.make_conn()
        save_platform(conn, Platform(id="windows_11", display_name="Windows 11", keywords=["windows"]))
        platforms = list_platforms(conn)
        self.assertEqual(len(platforms), 1)
        self.assertEqual(platforms[0].display_name, "Windows 11")

    def test_sample_run_and_trace_suppression(self):
        conn = self.make_conn()
        first = run_watch(conn, offline_sample=True, force_visible=False)
        second = run_watch(conn, offline_sample=True, force_visible=False)
        self.assertEqual(first.visible_count, 2)
        self.assertEqual(second.visible_count, 0)
        self.assertEqual(second.suppressed_count, 2)
        latest = latest_run(conn)
        self.assertIsNotNone(latest)
        self.assertEqual(len(list_findings(conn, run_id=latest.run_id)), 2)


if __name__ == "__main__":
    unittest.main()
