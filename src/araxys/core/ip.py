"""Shared client-IP extraction with trusted-proxy support.

Every middleware that extracts the client IP from a request should
use ``get_client_ip()`` so that ``X-Forwarded-For`` spoofing is
prevented by a configurable trusted-proxy list.

Usage::

    from araxys.core.ip import get_client_ip

    ip = get_client_ip(request, trusted_proxies=["10.0.0.0/8"])
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request


def get_client_ip(
    request: Request,
    trusted_proxies: list[str] | None = None,
) -> str:
    """Extract the real client IP, respecting a trusted-proxy whitelist.

    Parameters
    ----------
    request:
        The incoming Starlette request.
    trusted_proxies:
        IP addresses or CIDR ranges of trusted reverse proxies.
        When set, ``X-Forwarded-For`` is only honoured when the
        **direct** client (``request.client.host``) belongs to one of
        the trusted ranges.  An empty list or ``None`` means
        ``X-Forwarded-For`` is **never** trusted.

    Returns
    -------
    str
        The extracted IP (IPv4-mapped-IPv6 addresses are normalized to
        plain IPv4), or ``"unknown"`` if no IP can be determined.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and trusted_proxies:
        direct_ip = _direct_client_ip(request)
        if direct_ip and _is_trusted(direct_ip, trusted_proxies):
            # The first entry in X-Forwarded-For is the original client.
            return _normalize_ip(forwarded.split(",")[0].strip())

    if request.client:
        return _normalize_ip(request.client.host)
    return "unknown"


def _normalize_ip(ip: str) -> str:
    """Convert IPv4-mapped-IPv6 addresses (``::ffff:x.x.x.x``) to plain IPv4.

    This ensures that ``::ffff:192.168.1.1`` matches ``192.168.1.1/24``
    in IP access lists and rate-limit keys.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return ip


def _direct_client_ip(request: Request) -> str | None:
    """Return the IP of the host that connected directly to this server."""
    if request.client:
        return request.client.host
    return None


def _is_trusted(ip: str, allowed: list[str]) -> bool:
    """Return ``True`` if *ip* is within any of the *allowed* ranges.

    Supports CIDR notation (e.g. ``10.0.0.0/8``), exact IP addresses,
    and plain hostnames (e.g. ``testclient`` for test environments).
    """
    # Try exact hostname match first (useful for testing / container names).
    if ip in allowed:
        return True

    try:
        client = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for entry in allowed:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if client in net:
            return True
    return False
