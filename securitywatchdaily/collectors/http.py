"""Small HTTP helpers for collector modules."""

from __future__ import annotations

import json
import ipaddress
import socket
import threading
import urllib.error
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from urllib.parse import urlparse
import urllib.request

from securitywatchdaily.errors import SourceFetchError, SourceParseError

USER_AGENT = "SecurityWatchDaily/0.1 local vulnerability watch"
DEFAULT_EXTERNAL_TIMEOUT_SECONDS = 20
EXTERNAL_RESPONSE_MAX_BYTES = 5 * 1024 * 1024
EXTERNAL_RESPONSE_CHUNK_BYTES = 64 * 1024
_DNS_LOCK = threading.Lock()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_PROXY_NO_REDIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _safe_host_label(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.hostname:
        return "source URL"
    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    return f"{host}:{port}" if port else host


def _is_forbidden_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or address == "169.254.169.254"
    )


def _resolved_address(info: tuple) -> str:
    sockaddr = info[4]
    return sockaddr[0]


def _format_byte_limit(max_bytes: int) -> str:
    if max_bytes % (1024 * 1024) == 0:
        return f"{max_bytes // (1024 * 1024)} MB"
    if max_bytes % 1024 == 0:
        return f"{max_bytes // 1024} KB"
    return f"{max_bytes} bytes"


def _validate_external_url(url: str, *, allow_http: bool = False) -> tuple[str, str, list[tuple]]:
    parsed = urlparse(url)
    schemes = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme not in schemes or not parsed.hostname:
        scheme_message = "https" if not allow_http else "http or https"
        raise SourceFetchError(
            "Source URL is not allowed.",
            detail=f"{_safe_host_label(url)}: use a valid {scheme_message} URL.",
        )
    if parsed.username or parsed.password:
        raise SourceFetchError(
            "Source URL is not allowed.",
            detail=f"{_safe_host_label(url)}: credentials in source URLs are not supported.",
        )
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SourceFetchError(
            "Source could not be fetched.",
            detail=f"{_safe_host_label(url)}: DNS lookup failed. Check network access or the source URL.",
        ) from exc
    if not results:
        raise SourceFetchError(
            "Source could not be fetched.",
            detail=f"{_safe_host_label(url)}: DNS lookup returned no usable addresses.",
        )
    addresses = {_resolved_address(info) for info in results}
    if any(_is_forbidden_address(address) for address in addresses):
        raise SourceFetchError(
            "Source URL is not allowed.",
            detail=f"{_safe_host_label(url)}: resolved to a local, private, link-local, multicast, or metadata address.",
        )
    return host, str(port), results


@contextmanager
def _pinned_dns(host: str, port: str, results: list[tuple]) -> Iterator[None]:
    original_getaddrinfo = socket.getaddrinfo

    def guarded_getaddrinfo(query_host, query_port, *args, **kwargs):
        if str(query_host).rstrip(".").casefold() == host.rstrip(".").casefold() and str(query_port) == port:
            return results
        return original_getaddrinfo(query_host, query_port, *args, **kwargs)

    with _DNS_LOCK:
        socket.getaddrinfo = guarded_getaddrinfo
        try:
            yield
        finally:
            socket.getaddrinfo = original_getaddrinfo


def open_external_url(
    url: str,
    *,
    timeout: int = DEFAULT_EXTERNAL_TIMEOUT_SECONDS,
    headers: Mapping[str, str] | None = None,
    allow_http: bool = False,
):
    host, port, results = _validate_external_url(url, allow_http=allow_http)
    request_headers = {"User-Agent": USER_AGENT, **dict(headers or {})}
    req = urllib.request.Request(url, headers=request_headers)
    with _pinned_dns(host, port, results):
        return _NO_PROXY_NO_REDIRECT_OPENER.open(req, timeout=timeout)


def read_external_response(response, *, max_bytes: int = EXTERNAL_RESPONSE_MAX_BYTES) -> bytes:
    body = bytearray()
    while True:
        remaining = max_bytes - len(body)
        chunk = response.read(min(EXTERNAL_RESPONSE_CHUNK_BYTES, remaining + 1))
        if not chunk:
            return bytes(body)
        body.extend(chunk)
        if len(body) > max_bytes:
            raise SourceFetchError(
                "Source response is too large.",
                detail=f"Response exceeded the {_format_byte_limit(max_bytes)} external source limit.",
            )


def fetch_text(url: str, *, timeout: int = DEFAULT_EXTERNAL_TIMEOUT_SECONDS) -> str:
    host = _safe_host_label(url)
    try:
        with open_external_url(url, timeout=timeout) as response:
            return read_external_response(response).decode("utf-8", "replace")
    except SourceFetchError:
        raise
    except urllib.error.HTTPError as exc:
        raise SourceFetchError("Source returned an HTTP error.", detail=f"{host}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, socket.gaierror):
            detail = f"{host}: DNS lookup failed. Check network access or the source URL."
        elif isinstance(reason, TimeoutError):
            detail = f"{host}: request timed out after {timeout} seconds."
        else:
            detail = f"{host}: network request failed. Check network access or the source URL."
        raise SourceFetchError("Source could not be fetched.", detail=detail) from exc
    except TimeoutError as exc:
        raise SourceFetchError("Source request timed out.", detail=f"{host}: request timed out after {timeout} seconds.") from exc
    except Exception as exc:
        raise SourceFetchError("Source could not be fetched.", detail=f"{host}: {type(exc).__name__}") from exc


def fetch_json(url: str, *, timeout: int = DEFAULT_EXTERNAL_TIMEOUT_SECONDS) -> object:
    host = _safe_host_label(url)
    text = fetch_text(url, timeout=timeout)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SourceParseError(
            "Source returned invalid JSON.",
            detail=f"{host}: response was not valid JSON. The feed endpoint may have changed or returned an error page.",
        ) from exc
