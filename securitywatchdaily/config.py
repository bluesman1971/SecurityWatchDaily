"""Runtime configuration and path handling."""

from __future__ import annotations

import os
from pathlib import Path


APP_NAME = "SecurityWatchDaily"


def default_base_dir() -> Path:
    env = os.getenv("SECURITYWATCHDAILY_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return Path.cwd().resolve()


def database_path(base_dir: Path | None = None) -> Path:
    root = base_dir or default_base_dir()
    return root / "securitywatchdaily.sqlite3"


def reports_dir(base_dir: Path | None = None) -> Path:
    root = base_dir or default_base_dir()
    return root / "reports"


def legacy_watchlist_path(base_dir: Path | None = None) -> Path:
    root = base_dir or default_base_dir()
    return root / "watchlist.json"
