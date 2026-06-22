import socket
import unittest
from urllib.request import Request
from unittest.mock import patch

from securitywatchdaily.collectors.http import _NoRedirect, fetch_json, fetch_text
from securitywatchdaily.errors import SourceFetchError, SourceParseError


def public_dns_result(port=443):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]


class FakeResponse:
    def __init__(self, body=b"ok"):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self.body


class HttpErrorTests(unittest.TestCase):
    def test_dns_error_is_user_friendly(self):
        with patch(
            "socket.getaddrinfo",
            side_effect=socket.gaierror(8, "nodename nor servname provided"),
        ):
            with self.assertRaises(SourceFetchError) as ctx:
                fetch_text("https://example.invalid/feed.json")
        self.assertIn("DNS lookup failed", ctx.exception.detail)
        self.assertNotIn("URLError", ctx.exception.detail)

    def test_json_parse_error_is_user_friendly(self):
        with (
            patch("socket.getaddrinfo", return_value=public_dns_result()),
            patch(
                "securitywatchdaily.collectors.http._NO_PROXY_NO_REDIRECT_OPENER.open",
                return_value=FakeResponse(b"<html>not json</html>"),
            ),
        ):
            with self.assertRaises(SourceParseError) as ctx:
                fetch_json("https://api.example.com/feed")
        self.assertIn("response was not valid JSON", ctx.exception.detail)
        self.assertNotIn("JSONDecodeError", ctx.exception.detail)

    def test_loopback_ipv4_is_blocked(self):
        with self.assertRaises(SourceFetchError) as ctx:
            fetch_text("https://127.0.0.1/feed.json")
        self.assertIn("resolved to a local", ctx.exception.detail)

    def test_localhost_is_blocked(self):
        with self.assertRaises(SourceFetchError) as ctx:
            fetch_text("https://localhost/feed.json")
        self.assertIn("resolved to a local", ctx.exception.detail)

    def test_loopback_ipv6_is_blocked(self):
        with self.assertRaises(SourceFetchError) as ctx:
            fetch_text("https://[::1]/feed.json")
        self.assertIn("resolved to a local", ctx.exception.detail)

    def test_rfc1918_private_ipv4_is_blocked(self):
        for url in ("https://10.0.0.5/feed", "https://172.16.0.5/feed", "https://192.168.1.5/feed"):
            with self.subTest(url=url):
                with self.assertRaises(SourceFetchError) as ctx:
                    fetch_text(url)
                self.assertIn("resolved to a local", ctx.exception.detail)

    def test_link_local_and_metadata_addresses_are_blocked(self):
        for url in ("https://169.254.1.1/feed", "https://169.254.169.254/latest/meta-data"):
            with self.subTest(url=url):
                with self.assertRaises(SourceFetchError) as ctx:
                    fetch_text(url)
                self.assertIn("resolved to a local", ctx.exception.detail)

    def test_ipv6_unique_local_and_link_local_addresses_are_blocked(self):
        for url in ("https://[fd00::1]/feed", "https://[fe80::1]/feed"):
            with self.subTest(url=url):
                with self.assertRaises(SourceFetchError) as ctx:
                    fetch_text(url)
                self.assertIn("resolved to a local", ctx.exception.detail)

    def test_dns_name_resolving_to_blocked_range_is_blocked(self):
        with patch(
            "socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.44", 443))],
        ):
            with self.assertRaises(SourceFetchError) as ctx:
                fetch_text("https://feed.example.com/feed.json")
        self.assertIn("resolved to a local", ctx.exception.detail)

    def test_redirects_are_not_followed(self):
        redirect = _NoRedirect()
        request = Request("https://feed.example.com/feed.json")
        self.assertIsNone(
            redirect.redirect_request(
                request,
                None,
                302,
                "Found",
                {"Location": "https://127.0.0.1/feed"},
                "https://127.0.0.1/feed",
            )
        )

    def test_valid_public_https_source_url_still_works(self):
        with (
            patch("socket.getaddrinfo", return_value=public_dns_result()),
            patch(
                "securitywatchdaily.collectors.http._NO_PROXY_NO_REDIRECT_OPENER.open",
                return_value=FakeResponse(b"hello"),
            ),
        ):
            self.assertEqual(fetch_text("https://example.com/feed.txt"), "hello")


if __name__ == "__main__":
    unittest.main()
