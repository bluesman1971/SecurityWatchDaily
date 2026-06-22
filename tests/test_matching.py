import unittest

from securitywatchdaily.models import Platform
from securitywatchdaily.services.matching_service import keyword_matches, match_platform


class MatchingTests(unittest.TestCase):
    def test_keyword_does_not_match_inside_larger_word(self):
        self.assertFalse(keyword_matches("WebPros WordPress advisory", "word"))

    def test_phrase_matches_normally(self):
        self.assertTrue(keyword_matches("Microsoft 365 Copilot disclosure", "microsoft 365"))

    def test_exclude_keyword_blocks_platform(self):
        platform = Platform(
            id="cisco_meraki",
            display_name="Cisco Meraki",
            keywords=["cisco", "meraki"],
            exclude_keywords=["sd-wan"],
        )
        self.assertIsNone(match_platform("Cisco Catalyst SD-WAN Controller", [platform]))


if __name__ == "__main__":
    unittest.main()
