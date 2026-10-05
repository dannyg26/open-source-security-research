"""Dependency-free destination validation for the verification harness."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def assert_local_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("verification URL must use http or https")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("verification URL must include a hostname")
    if hostname.casefold() == "localhost":
        return
    try:
        if ipaddress.ip_address(hostname).is_loopback:
            return
    except ValueError:
        pass
    raise ValueError("refusing non-loopback target; use localhost, 127.0.0.0/8, or ::1")
