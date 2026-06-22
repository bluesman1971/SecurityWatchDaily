"""Small HTTP helpers for collector modules."""

from __future__ import annotations

import json
import socket
import urllib.error
from urllib.parse import urlparse
import urllib.request

from securitywatchdaily.errors import SourceFetchError, SourceParseError

USER_AGENT = "SecurityWatchDaily/0.1 local vulnerability watch"


def fetch_text(url: str, *, timeout: int = 30) -> str:
    host = urlparse(url).netloc or url
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise SourceFetchError("Source returned an HTTP error.", detail=f"{host}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, socket.gaierror):
            detail = f"{host}: DNS lookup failed. Check network access or the source URL."
        elif isinstance(reason, TimeoutError):
            detail = f"{host}: request timed out after {timeout} seconds."
        else:
            detail = f"{host}: network request failed ({reason})."
        raise SourceFetchError("Source could not be fetched.", detail=detail) from exc
    except TimeoutError as exc:
        raise SourceFetchError("Source request timed out.", detail=f"{host}: request timed out after {timeout} seconds.") from exc
    except Exception as exc:
        raise SourceFetchError("Source could not be fetched.", detail=f"{host}: {type(exc).__name__}") from exc


def fetch_json(url: str, *, timeout: int = 30) -> object:
    host = urlparse(url).netloc or url
    text = fetch_text(url, timeout=timeout)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SourceParseError(
            "Source returned invalid JSON.",
            detail=f"{host}: response was not valid JSON. The feed endpoint may have changed or returned an error page.",
        ) from exc
