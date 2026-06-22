import socket
import unittest
import urllib.error
from urllib.request import Request
from unittest.mock import patch

from securitywatchdaily.collectors.http import _NoRedirect, fetch_json, fetch_text, read_external_response
from securitywatchdaily.errors import SourceFetchError, SourceParseError


def public_dns_result(port=443):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]


class FakeResponse:
    def __init__(self, body=b"ok"):
        self.body = bytearray(body)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size=-1):
        if size is None or size < 0:
            size = len(self.body)
        chunk = self.body[:size]
        del self.body[:size]
        return bytes(chunk)


class ChunkedResponse:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.read_calls = 0

    def read(self, size=-1):
        self.read_calls += 1
        if not self.chunks:
            return b""
        return self.chunks.pop(0)


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

    def test_response_at_cap_is_allowed(self):
        self.assertEqual(read_external_response(FakeResponse(b"12345"), max_bytes=5), b"12345")

    def test_oversized_response_is_rejected_safely(self):
        with self.assertRaises(SourceFetchError) as ctx:
            read_external_response(FakeResponse(b"123456"), max_bytes=5)
        self.assertIn("too large", ctx.exception.message)
        self.assertIn("limit", ctx.exception.detail)

    def test_chunked_read_stops_when_cap_is_exceeded(self):
        response = ChunkedResponse([b"123", b"456", b"789"])
        with self.assertRaises(SourceFetchError):
            read_external_response(response, max_bytes=5)
        self.assertEqual(response.read_calls, 2)

    def test_timeout_error_is_safe_and_actionable(self):
        with (
            patch("socket.getaddrinfo", return_value=public_dns_result()),
            patch(
                "securitywatchdaily.collectors.http._NO_PROXY_NO_REDIRECT_OPENER.open",
                side_effect=urllib.error.URLError(TimeoutError("timed out with api_key=secret")),
            ),
        ):
            with self.assertRaises(SourceFetchError) as ctx:
                fetch_text("https://example.com/feed.txt?api_key=secret", timeout=20)
        self.assertIn("request timed out after 20 seconds", ctx.exception.detail)
        self.assertNotIn("api_key", ctx.exception.detail)
        self.assertNotIn("secret", ctx.exception.detail)

    def test_url_credentials_are_not_echoed_in_error_detail(self):
        with self.assertRaises(SourceFetchError) as ctx:
            fetch_text("https://user:secret@example.com/feed.json")
        self.assertIn("credentials in source URLs are not supported", ctx.exception.detail)
        self.assertNotIn("user:secret", ctx.exception.detail)


if __name__ == "__main__":
    unittest.main()
