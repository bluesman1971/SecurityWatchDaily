"""Product normalization and alias support for inventory matching."""

from __future__ import annotations

import re
import sqlite3

from securitywatchdaily.models import ProductAlias
from securitywatchdaily.repositories.assets import get_product_alias, save_product_alias


DEFAULT_ALIASES = [
    ProductAlias(None, "palo alto", "panos", "palo alto networks", "pan-os", "palo_alto_pan_os"),
    ProductAlias(None, "palo alto networks", "pan-os", "palo alto networks", "pan-os", "palo_alto_pan_os"),
    ProductAlias(None, "microsoft", "windows 11 pro", "microsoft", "windows 11", "windows_11"),
    ProductAlias(None, "microsoft", "microsoft windows 11", "microsoft", "windows 11", "windows_11"),
    ProductAlias(None, "canonical", "ubuntu 22.04", "canonical", "ubuntu", "ubuntu_lts"),
    ProductAlias(None, "canonical", "ubuntu 24.04", "canonical", "ubuntu", "ubuntu_lts"),
]


def normalize_token(value: str) -> str:
    text = (value or "").casefold().strip()
    text = re.sub(r"[\u2010-\u2015]", "-", text)
    text = re.sub(r"[^a-z0-9.+-]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def normalize_pair(conn: sqlite3.Connection, vendor: str, product: str, platform: str = "") -> tuple[str, str, str]:
    raw_vendor = normalize_token(vendor)
    raw_product = normalize_token(product)
    alias = get_product_alias(conn, raw_vendor, raw_product)
    if alias:
        return alias.normalized_vendor, alias.normalized_product, alias.platform or normalize_token(platform)
    return raw_vendor, raw_product, normalize_token(platform)


def seed_product_aliases(conn: sqlite3.Connection) -> None:
    for alias in DEFAULT_ALIASES:
        save_product_alias(conn, alias)
    conn.commit()
