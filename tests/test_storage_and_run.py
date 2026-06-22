import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from securitywatchdaily.database import connect, initialize
from securitywatchdaily.errors import SourceFetchError
from securitywatchdaily.models import Platform, Source
from securitywatchdaily.repositories.platforms import list_platforms, save_platform
from securitywatchdaily.repositories.runs import latest_run, list_findings
from securitywatchdaily.repositories.sources import save_source
from securitywatchdaily.services.finding_service import make_finding
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

    def test_one_timing_out_or_oversized_source_does_not_stop_full_run(self):
        conn = self.make_conn()
        save_platform(conn, Platform(id="windows_11", display_name="Windows 11", keywords=["windows"]))
        save_source(conn, Source(id="bad_source", name="Bad Source", source_type="cisa", url="https://bad.example/feed.json"))
        save_source(conn, Source(id="good_source", name="Good Source", source_type="cisa", url="https://good.example/feed.json"))

        def fake_collect(source, platforms):
            if source.id == "bad_source":
                raise SourceFetchError(
                    "Source response is too large.",
                    detail="bad.example: response exceeded the external source limit.",
                )
            return [
                make_finding(
                    "CVE-2026-9999",
                    "Windows 11",
                    "Sample finding",
                    "Test status",
                    "Test description",
                    "Test action",
                    [source.name],
                    priority="High",
                )
            ]

        with patch("securitywatchdaily.services.run_service.collect_source", side_effect=fake_collect):
            run = run_watch(conn)

        self.assertEqual(run.collected_count, 1)
        self.assertIn("response exceeded the external source limit", run.source_status["Bad Source"])
        self.assertIn("ok (1 findings)", run.source_status["Good Source"])
        findings = list_findings(conn, run_id=run.run_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].key, "CVE-2026-9999")


if __name__ == "__main__":
    unittest.main()
