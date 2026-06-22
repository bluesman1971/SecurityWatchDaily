import socket
import unittest
import urllib.error
from unittest.mock import patch

from securitywatchdaily.collectors.http import fetch_json, fetch_text
from securitywatchdaily.errors import SourceFetchError, SourceParseError


class HttpErrorTests(unittest.TestCase):
    def test_dns_error_is_user_friendly(self):
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError(socket.gaierror(8, "nodename nor servname provided")),
        ):
            with self.assertRaises(SourceFetchError) as ctx:
                fetch_text("https://example.invalid/feed.json")
        self.assertIn("DNS lookup failed", ctx.exception.detail)
        self.assertNotIn("URLError", ctx.exception.detail)

    def test_json_parse_error_is_user_friendly(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"<html>not json</html>"

        with patch("urllib.request.urlopen", return_value=FakeResponse()):
            with self.assertRaises(SourceParseError) as ctx:
                fetch_json("https://api.example.com/feed")
        self.assertIn("response was not valid JSON", ctx.exception.detail)
        self.assertNotIn("JSONDecodeError", ctx.exception.detail)


if __name__ == "__main__":
    unittest.main()
