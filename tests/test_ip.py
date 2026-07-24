"""Client-IP resolution (``advanced.ipAddress``): the ``get_request_ip`` util ported
from TS ``core/utils/ip.ts``, plus its wiring into rate-limit keying and session
tracking. Header precedence, forwarded-chain parsing, IPv6 collapsing, and the
security property that only *configured* headers are trusted."""

from __future__ import annotations

from better_auth import IPAddressOptions
from better_auth.ip import get_ip_from_header, get_request_ip, is_valid_ip, normalize_ip
from better_auth.session import create_session
from better_auth.types import AuthRequest
from conftest import make_auth


def _req(headers=None, client_ip=None):
    return AuthRequest(
        method="POST", path="/x", headers=headers or {}, client_ip=client_ip
    )


# --- normalize_ip / is_valid_ip (normalizeIP parity) --------------------------


def test_is_valid_ip():
    assert is_valid_ip("203.0.113.7")
    assert is_valid_ip("2001:db8::1")
    assert not is_valid_ip("garbage")
    assert not is_valid_ip("999.0.0.1")


def test_ipv4_returned_as_is():
    assert normalize_ip("203.0.113.7") == "203.0.113.7"


def test_ipv4_mapped_ipv6_unwrapped_to_ipv4():
    assert normalize_ip("::ffff:192.0.2.1") == "192.0.2.1"


def test_ipv6_collapsed_to_default_64_subnet():
    # host bits below /64 are masked so a rotating client suffix keys the same bucket
    assert normalize_ip("2001:db8::dead:beef", 64) == "2001:db8::"


def test_ipv6_subnet_128_keeps_full_address():
    assert normalize_ip("2001:db8::1", 128) == "2001:db8::1"


# --- get_ip_from_header (getIPFromHeader parity) ------------------------------


def test_single_value_header_trusted():
    assert get_ip_from_header("203.0.113.7") == "203.0.113.7"


def test_multi_value_without_trusted_proxies_is_unresolvable():
    # leftmost token is spoofable; without trusted proxies a chain returns None
    assert get_ip_from_header("1.1.1.1, 2.2.2.2") is None


def test_invalid_single_value_returns_none():
    assert get_ip_from_header("garbage") is None


def test_trusted_proxies_walk_chain_right_to_left():
    # chain: client, proxy; the trusted proxy hop is skipped, client wins
    ip = get_ip_from_header(
        "203.0.113.7, 10.0.0.5", trusted_proxies=["10.0.0.0/8"]
    )
    assert ip == "203.0.113.7"


def test_trusted_proxies_malformed_hop_fails_closed():
    ip = get_ip_from_header("bogus, 10.0.0.5", trusted_proxies=["10.0.0.0/8"])
    assert ip is None


# --- get_request_ip (getIp parity, port fallback = client_ip) -----------------


def test_default_reads_x_forwarded_for():
    ip = get_request_ip(_req({"x-forwarded-for": "203.0.113.7"}), IPAddressOptions())
    assert ip == "203.0.113.7"


def test_header_precedence_follows_configured_order():
    opts = IPAddressOptions(ip_address_headers=["cf-connecting-ip", "x-forwarded-for"])
    req = _req({"cf-connecting-ip": "203.0.113.9", "x-forwarded-for": "1.1.1.1"})
    assert get_request_ip(req, opts) == "203.0.113.9"


def test_only_configured_headers_are_read():
    # security: a header not in the configured list must be ignored even if present.
    # x-forwarded-for is spoofed but not configured -> falls back to client_ip.
    opts = IPAddressOptions(ip_address_headers=["cf-connecting-ip"])
    req = _req({"x-forwarded-for": "6.6.6.6"}, client_ip="9.9.9.9")
    assert get_request_ip(req, opts) == "9.9.9.9"


def test_falls_back_to_client_ip_when_no_configured_header():
    assert get_request_ip(_req(client_ip="9.9.9.9"), IPAddressOptions()) == "9.9.9.9"


def test_disable_ip_tracking_returns_none():
    opts = IPAddressOptions(disable_ip_tracking=True)
    req = _req({"x-forwarded-for": "203.0.113.7"}, client_ip="9.9.9.9")
    assert get_request_ip(req, opts) is None


# --- rate-limit wiring --------------------------------------------------------


async def test_rate_limit_keys_on_configured_header():
    auth = make_auth(ip_address=IPAddressOptions(ip_address_headers=["x-real-ip"]))
    req = _req({"x-real-ip": "203.0.113.9"}, client_ip="9.9.9.9")
    resolved = await auth._rate_limiter._resolve(req)
    assert resolved is not None and resolved[0] == "203.0.113.9|/x"


async def test_rate_limit_disable_ip_tracking_skips():
    auth = make_auth(ip_address=IPAddressOptions(disable_ip_tracking=True))
    assert await auth._rate_limiter._resolve(_req(client_ip="9.9.9.9")) is None


async def test_rate_limit_no_ip_uses_sentinel():
    auth = make_auth()
    resolved = await auth._rate_limiter._resolve(_req(client_ip=None))
    assert resolved is not None and resolved[0] == "no-trusted-ip|/x"


# --- session wiring -----------------------------------------------------------


async def test_session_stores_resolved_ip():
    auth = make_auth(ip_address=IPAddressOptions(ip_address_headers=["x-real-ip"]))
    req = _req({"x-real-ip": "203.0.113.9"}, client_ip="9.9.9.9")
    session, _ = await create_session(auth, "user-1", req)
    assert session["ipAddress"] == "203.0.113.9"


async def test_session_disable_ip_tracking_stores_empty():
    auth = make_auth(ip_address=IPAddressOptions(disable_ip_tracking=True))
    req = _req({"x-forwarded-for": "203.0.113.7"}, client_ip="9.9.9.9")
    session, _ = await create_session(auth, "user-1", req)
    assert session["ipAddress"] == ""
