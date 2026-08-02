"""RFC-6890 host classifier — the SSRF gate for OIDC discovery/endpoint fetches.

Faithful port of ``@better-auth/core/utils/host`` (``classifyHost`` /
``isPublicRoutableHost``). The port leans on Python's stdlib :mod:`ipaddress`,
whose special-purpose-registry properties (``is_global``/``is_private``/
``is_loopback``/...) are derived from the same IANA registries RFC 6890 codifies —
so the standard ranges (loopback, RFC 1918, link-local, ULA, shared-address,
documentation, benchmarking, multicast, reserved) classify identically to the TS
bit-twiddling. The two things stdlib does NOT cover and we port explicitly:

  1. cloud-metadata / ``localhost`` FQDNs (``metadata.google.internal`` etc.), and
  2. 6to4 / NAT64 / Teredo IPv6 forms that embed a private IPv4 behind a
     syntactically-public IPv6 literal — a real SSRF smuggling vector TS closes.

``is_public_routable_host`` is the only load-bearing predicate for the discovery
pipeline (a host is fetchable iff it classifies ``public``); ``classify_host``
additionally reports ``literal`` (ipv4/ipv6/fqdn), consumed by the DNS resolve-check.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# Cloud provider instance-metadata FQDNs (host.ts CLOUD_METADATA_HOSTS). Their IPs
# (usually 169.254.169.254) are already caught as link-local; this set covers the
# FQDN form a naive resolver might follow.
CLOUD_METADATA_HOSTS: frozenset[str] = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
        "instance-data.ec2.internal",
    }
)


@dataclass(frozen=True)
class HostClassification:
    #: coarse RFC-6890 kind; only ``"public"`` is fetchable
    kind: str
    #: syntactic form of the input host
    literal: str  # "ipv4" | "ipv6" | "fqdn"
    #: lowercase, port/bracket/zone/trailing-dot-stripped form
    canonical: str


def _strip_brackets(host: str) -> str:
    if len(host) >= 2 and host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _strip_port(host: str) -> str:
    # Bracketed IPv6 with port: [::1]:8080 -> [::1]
    if host.startswith("["):
        end = host.find("]")
        return host if end == -1 else host[: end + 1]
    first = host.find(":")
    if first == -1:
        return host
    # more than one colon => bare IPv6, not host:port
    if host.find(":", first + 1) != -1:
        return host
    return host[:first]


def _strip_zone_id(host: str) -> str:
    zone = host.find("%")
    return host if zone == -1 else host[:zone]


def _embedded_ipv4_is_private(addr: ipaddress.IPv6Address) -> bool:
    """6to4 (2002::/16), NAT64 (64:ff9b::/96) and Teredo (2001:0000::/32) embed an
    IPv4 that can route into private/loopback space. Return True when the embedded
    IPv4 is non-public — mirrors host.ts ``classifyIPv6`` recursion."""
    packed = addr.packed
    embedded: ipaddress.IPv4Address | None = None
    if addr in ipaddress.ip_network("2002::/16"):  # 6to4: bytes 2..6
        embedded = ipaddress.IPv4Address(packed[2:6])
    elif addr in ipaddress.ip_network("64:ff9b::/96"):  # NAT64: last 4 bytes
        embedded = ipaddress.IPv4Address(packed[12:16])
    elif addr in ipaddress.ip_network("2001::/32"):  # Teredo: last 4 bytes XOR-obfuscated
        embedded = ipaddress.IPv4Address(bytes(b ^ 0xFF for b in packed[12:16]))
    if embedded is None:
        return False
    return not embedded.is_global


def _ip_kind(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "linkLocal"
    if ip.is_private:
        return "private"
    if isinstance(ip, ipaddress.IPv6Address) and _embedded_ipv4_is_private(ip):
        return "reserved"
    if ip.is_global:
        return "public"
    return "reserved"


def classify_host(host: str) -> HostClassification:
    """Classify a host per RFC 6890 / RFC 6761. Never raises — an unparseable
    FQDN is reported ``{kind: "public", literal: "fqdn"}`` (structural validation is
    a separate upstream concern)."""
    stripped = _strip_zone_id(_strip_brackets(_strip_port(host.strip())))
    stripped = stripped.rstrip(".")  # RFC 1034 absolute form
    lowered = stripped.lower()

    if lowered == "":
        return HostClassification("reserved", "fqdn", "")

    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        if lowered == "localhost" or lowered.endswith(".localhost"):
            return HostClassification("localhost", "fqdn", lowered)
        if lowered in CLOUD_METADATA_HOSTS:
            return HostClassification("cloudMetadata", "fqdn", lowered)
        return HostClassification("public", "fqdn", lowered)

    # IPv4-mapped IPv6 (::ffff:a.b.c.d) is unmapped and reported as ipv4.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        mapped = ip.ipv4_mapped
        return HostClassification(_ip_kind(mapped), "ipv4", str(mapped))

    literal = "ipv4" if isinstance(ip, ipaddress.IPv4Address) else "ipv6"
    return HostClassification(_ip_kind(ip), literal, str(ip))


def is_public_routable_host(host: str) -> bool:
    """First-line SSRF gate: True ONLY for hosts that classify ``public``. Every
    RFC-6890 special-purpose range and cloud-metadata/localhost FQDN returns False.

    Syntactic only — a public FQDN that *resolves* to a private IP still passes;
    re-verify resolved addresses before connecting (see discovery resolve-check)."""
    return classify_host(host).kind == "public"
