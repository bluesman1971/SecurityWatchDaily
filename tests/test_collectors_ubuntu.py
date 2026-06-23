import unittest
from unittest.mock import patch

from securitywatchdaily.collectors import ubuntu
from securitywatchdaily.collectors.ubuntu import _parse_rss_safely, collect
from securitywatchdaily.errors import SourceParseError
from securitywatchdaily.models import Platform, Source


# A small "billion laughs"-style payload: the entity expansion lives entirely
# inside a DTD, which is exactly what the collector must refuse to parse.
BILLION_LAUGHS = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE lolz ['
    '<!ENTITY lol "lol">'
    '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">'
    '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">'
    ']>'
    '<rss><channel><item><title>&lol3;</title></item></channel></rss>'
)

VALID_RSS = (
    '<rss><channel>'
    '<item><title>USN-1234-1</title>'
    '<link>https://ubuntu.com/security/notices/USN-1234-1</link>'
    '<description>Ubuntu 22.04 LTS fix for CVE-2026-0001</description>'
    '<pubDate>Mon, 22 Jun 2026 00:00:00 +0000</pubDate>'
    '</item></channel></rss>'
)


class UbuntuCollectorXmlSafetyTests(unittest.TestCase):
    def test_parse_rejects_dtd_payload(self):
        with self.assertRaises(SourceParseError):
            _parse_rss_safely(BILLION_LAUGHS)

    def test_parse_accepts_normal_rss(self):
        root = _parse_rss_safely(VALID_RSS)
        self.assertEqual(root.tag, "rss")

    def test_collect_rejects_dtd_feed(self):
        source = Source(id="ubuntu", name="Ubuntu", source_type="ubuntu", url="https://ubuntu.com/feed.xml")
        platform = Platform(id="ubuntu_server", display_name="Ubuntu", ubuntu_releases=["Ubuntu 22.04"])
        with patch.object(ubuntu, "fetch_text", return_value=BILLION_LAUGHS):
            with self.assertRaises(SourceParseError):
                collect(source, [platform])

    def test_collect_parses_clean_feed(self):
        source = Source(id="ubuntu", name="Ubuntu", source_type="ubuntu", url="https://ubuntu.com/feed.xml")
        platform = Platform(id="ubuntu_server", display_name="Ubuntu", ubuntu_releases=["Ubuntu 22.04"])
        with patch.object(ubuntu, "fetch_text", return_value=VALID_RSS):
            findings = collect(source, [platform])
        self.assertEqual(len(findings), 1)
        self.assertIn("CVE-2026-0001", findings[0].cves)


if __name__ == "__main__":
    unittest.main()
