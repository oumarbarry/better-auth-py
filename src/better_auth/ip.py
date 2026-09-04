"""Client-IP resolution for rate limiting and session tracking.

Ports better-auth's ``core/utils/ip.ts``. The resolution *logic* mirrors TS exactly —
header precedence, forwarded-chain walking (right-to-left, fail-closed on a malformed
hop), single-value-only trust without ``trusted_proxies``, IPv6 subnet collapsing, and
``disable_ip_tracking``. The low-level IP math (validation, IPv4-mapped unwrapping, CIDR
membership, subnet masking) leans on Python's ``ipaddress`` stdlib instead of TS's
hand-rolled routines (JS has no IP library), so normalized IPv6 keys come out in
stdlib canonical (compressed) form rather than TS's fully-expanded string — the same
address, a different spelling, and keys never cross the TS/Python boundary.

Port adaptation: TS ``getIp`` falls back to ``127.0.0.1`` in dev/test when no header
resolves; here the ASGI integration already supplies ``request.client_ip`` (the socket
peer), so that is the fallback.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import IPAddressOptions
    from .types import AuthRequest


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _canonical_addr(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parsed address with IPv4-mapped IPv6 unwrapped, so a mapped hop compares against
    an IPv4 CIDR. Raises ``ValueError`` for an invalid IP."""
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def normalize_ip(ip: str, ipv6_subnet: int = 64) -> str:
    """Normalize an IP for consistent keying: IPv4 as-is, IPv4-mapped IPv6 unwrapped to
    IPv4, IPv6 collapsed to its ``ipv6_subnet`` network address. Out-of-range subnets are
    clamped (negative -> mask all, > 128 -> no mask), matching TS."""
    try:
        addr = _canonical_addr(ip)
    except ValueError:
        return ip.lower()  # unreachable after prior validation; degrade safely
    if isinstance(addr, ipaddress.IPv4Address):
        return str(addr)
    prefix = max(0, min(128, int(ipv6_subnet)))
    return str(ipaddress.ip_network((addr, prefix), strict=False).network_address)


def _parse_cidr(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """An IP or ``IP/prefix`` as a network, or None if malformed — so a config typo
    drops out of the trusted set instead of matching."""
    prefix = value.rpartition("/")[2] if "/" in value else ""
    if prefix and not prefix.isdigit():
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def get_ip_from_header(
    value: str,
    ipv6_subnet: int = 64,
    trusted_proxies: list[str] | None = None,
) -> str | None:
    """Resolve the client IP from a forwarded header value (a comma list). With
    ``trusted_proxies`` the chain is walked right-to-left, trusted hops skipped, and the
    first untrusted address wins; a malformed hop fails closed. Without trusted proxies
    only a single-value header is trusted. Returns None when unresolvable."""
    forwarded = [ip.strip() for ip in value.split(",") if ip.strip()]
    if not forwarded:
        return None

    proxies = [n for n in (_parse_cidr(p) for p in (trusted_proxies or [])) if n is not None]

    if proxies:
        for ip in reversed(forwarded):
            try:
                addr = _canonical_addr(ip)
            except ValueError:
                return None  # a malformed hop breaks the chain: fail closed
            if any(addr.version == net.version and addr in net for net in proxies):
                continue
            return normalize_ip(ip, ipv6_subnet)
        return None

    # Without valid trusted proxies a multi-hop chain is unresolvable.
    if len(forwarded) != 1 or not is_valid_ip(forwarded[0]):
        return None
    return normalize_ip(forwarded[0], ipv6_subnet)


def get_request_ip(request: AuthRequest, options: IPAddressOptions) -> str | None:
    """Resolve the client IP from the configured headers, honoring
    ``disable_ip_tracking`` and header precedence. Falls back to
    ``request.client_ip`` (the ASGI socket peer). Returns None when tracking is
    disabled or nothing resolves."""
    if options.disable_ip_tracking:
        return None
    for key in options.ip_address_headers:
        value = request.headers.get(key.lower())  # AuthRequest headers are lower-cased
        if isinstance(value, str):
            ip = get_ip_from_header(value, options.ipv6_subnet, options.trusted_proxies)
            if ip:
                return ip
    return request.client_ip
