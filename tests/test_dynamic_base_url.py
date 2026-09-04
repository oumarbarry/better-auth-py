"""Dynamic ``base_url`` ({allowed_hosts}) — parity with better-auth's
``utils/url.ts`` + ``context/helpers.ts`` dynamic-baseURL resolution."""

from __future__ import annotations

import asyncio
import re

import pytest

from better_auth import BetterAuth, DynamicBaseURL
from better_auth.base_url import (
    bind_base_url,
    get_host_from_source,
    get_protocol_from_source,
    matches_host_pattern,
    resolve_dynamic_base_url,
    validate_proxy_header,
)
from better_auth.origin import is_trusted_origin, resolve_trusted_origins
from better_auth.types import APIError, AuthRequest
from conftest import SECRET, make_auth

# --- construction ---------------------------------------------------------------------


def test_string_base_url_unchanged():
    auth = make_auth(base_url="https://myapp.com/")
    assert auth.base_url == "https://myapp.com"


def test_dynamic_config_accepted():
    auth = make_auth(
        base_url=DynamicBaseURL(allowed_hosts=["myapp.com"], fallback="https://myapp.com")
    )
    assert auth.base_url == "https://myapp.com"


def test_empty_allowed_hosts_raises():
    with pytest.raises(ValueError, match="allowedHosts cannot be empty"):
        BetterAuth(secret=SECRET, base_url=DynamicBaseURL(allowed_hosts=[]))


# --- host pattern matching ------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "pattern", "expected"),
    [
        ("myapp.com", "myapp.com", True),
        ("MyApp.COM", "myapp.com", True),
        ("myapp.com", "MYAPP.com", True),
        ("evil.com", "myapp.com", False),
        ("preview-123.vercel.app", "*.vercel.app", True),
        # wildcard-match default separator is "/", so "*" crosses dots
        ("a.b.vercel.app", "*.vercel.app", True),
        ("vercel.app", "*.vercel.app", False),
        ("preview-123.myapp.com", "preview-*.myapp.com", True),
        ("prod-123.myapp.com", "preview-*.myapp.com", False),
        # protocol / path are stripped before comparing
        ("https://myapp.com/x", "myapp.com", True),
        ("myapp.com", "https://myapp.com", True),
        ("myapp.com:3000", "myapp.com", False),
        ("", "myapp.com", False),
        ("myapp.com", "", False),
    ],
)
def test_matches_host_pattern(host: str, pattern: str, expected: bool):
    assert matches_host_pattern(host, pattern) is expected


# --- proxy header validation ----------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "myapp.com",
        "my-app.co.uk",
        "myapp.com:3000",
        "localhost",
        "localhost:8000",
        "127.0.0.1:8080",
        "192.168.1.1",
        "[::1]",
        "[::1]:8000",
    ],
)
def test_validate_proxy_header_accepts_hosts(header: str):
    assert validate_proxy_header(header, "host") is True


@pytest.mark.parametrize(
    "header",
    [
        "",
        "   ",
        "../etc/passwd",
        "myapp.com/../evil.com",
        "my\x00app.com",
        "my app.com",
        "myapp.com evil.com",
        ".myapp.com",
        "<script>",
        "my'app.com",
        'my"app.com',
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,x",
        "myapp.com:notaport",
        "-myapp.com",
    ],
)
def test_validate_proxy_header_rejects_suspicious_hosts(header: str):
    assert validate_proxy_header(header, "host") is False


@pytest.mark.parametrize(
    ("header", "expected"),
    [("http", True), ("https", True), ("ws", False), ("HTTPS", False), ("", False)],
)
def test_validate_proxy_header_proto(header: str, expected: bool):
    assert validate_proxy_header(header, "proto") is expected


# --- host resolution from headers -----------------------------------------------------


def test_host_header_used_by_default():
    assert get_host_from_source({"host": "myapp.com"}, True) == "myapp.com"


def test_forwarded_host_wins_when_trusted():
    headers = {"host": "internal.local", "x-forwarded-host": "myapp.com"}
    assert get_host_from_source(headers, True) == "myapp.com"


def test_forwarded_host_ignored_when_untrusted():
    headers = {"host": "internal.local", "x-forwarded-host": "evil.com"}
    assert get_host_from_source(headers, False) == "internal.local"


def test_invalid_forwarded_host_falls_back_to_host_header():
    headers = {"host": "myapp.com", "x-forwarded-host": "evil.com/../x"}
    assert get_host_from_source(headers, True) == "myapp.com"


def test_no_usable_host_returns_none():
    assert get_host_from_source({"host": "bad host"}, True) is None
    assert get_host_from_source({}, True) is None


# --- protocol resolution --------------------------------------------------------------


def test_config_protocol_wins():
    headers = {"host": "myapp.com", "x-forwarded-proto": "http"}
    assert get_protocol_from_source(headers, "https", True) == "https"
    assert get_protocol_from_source({"host": "myapp.com"}, "http", True) == "http"


def test_forwarded_proto_used_when_trusted():
    headers = {"host": "myapp.com", "x-forwarded-proto": "http"}
    assert get_protocol_from_source(headers, "auto", True) == "http"
    assert get_protocol_from_source(headers, "auto", False) == "https"


def test_invalid_forwarded_proto_ignored():
    headers = {"host": "myapp.com", "x-forwarded-proto": "gopher"}
    assert get_protocol_from_source(headers, "auto", True) == "https"


@pytest.mark.parametrize(
    # bare "::1" is absent on purpose: validate_proxy_header only accepts bracketed IPv6,
    # so an unbracketed host header never reaches the loopback check (url.ts:124).
    "host",
    ["localhost", "localhost:3000", "app.localhost", "[::1]", "[::1]:8000", "127.0.0.1:8000"],
)
def test_loopback_host_defaults_to_http(host: str):
    assert get_protocol_from_source({"host": host}, None, True) == "http"


def test_non_loopback_defaults_to_https():
    assert get_protocol_from_source({"host": "myapp.com"}, None, True) == "https"


# --- resolve_dynamic_base_url ---------------------------------------------------------


def test_resolve_allowed_host():
    config = DynamicBaseURL(allowed_hosts=["*.vercel.app"])
    assert (
        resolve_dynamic_base_url(config, {"host": "preview-1.vercel.app"}, True)
        == "https://preview-1.vercel.app"
    )


def test_resolve_unknown_host_uses_fallback():
    config = DynamicBaseURL(allowed_hosts=["myapp.com"], fallback="https://myapp.com/")
    assert resolve_dynamic_base_url(config, {"host": "evil.com"}, True) == "https://myapp.com"


def test_resolve_unknown_host_without_fallback_raises():
    config = DynamicBaseURL(allowed_hosts=["myapp.com"])
    with pytest.raises(
        ValueError, match=re.escape('Host "evil.com" is not in the allowed hosts list')
    ):
        resolve_dynamic_base_url(config, {"host": "evil.com"}, True)


def test_resolve_no_host_uses_fallback():
    config = DynamicBaseURL(allowed_hosts=["myapp.com"], fallback="https://myapp.com")
    assert resolve_dynamic_base_url(config, {}, True) == "https://myapp.com"


def test_resolve_no_host_without_fallback_raises():
    config = DynamicBaseURL(allowed_hosts=["myapp.com"])
    with pytest.raises(ValueError, match="Could not determine host"):
        resolve_dynamic_base_url(config, {}, True)


def test_resolve_honours_config_protocol():
    config = DynamicBaseURL(allowed_hosts=["myapp.com"], protocol="http")
    assert resolve_dynamic_base_url(config, {"host": "myapp.com"}, True) == "http://myapp.com"


# --- BetterAuth.base_url property -----------------------------------------------------


def test_direct_call_without_request_uses_fallback():
    auth = make_auth(
        base_url=DynamicBaseURL(allowed_hosts=["*.vercel.app"], fallback="https://myapp.com/")
    )
    assert auth.base_url == "https://myapp.com"


def test_direct_call_without_request_or_fallback_raises():
    auth = make_auth(base_url=DynamicBaseURL(allowed_hosts=["*.vercel.app"]))
    with pytest.raises(APIError) as excinfo:
        _ = auth.base_url
    assert excinfo.value.status == 500
    assert "Dynamic baseURL could not be resolved" in excinfo.value.message


def test_bind_base_url_sets_and_resets():
    auth = make_auth(
        base_url=DynamicBaseURL(allowed_hosts=["*.vercel.app"], fallback="https://myapp.com")
    )
    with bind_base_url(auth._dynamic_base_url, {"host": "a.vercel.app"}, True):
        assert auth.base_url == "https://a.vercel.app"
    assert auth.base_url == "https://myapp.com"


async def test_per_request_isolation():
    """Two concurrent tasks resolving different allowed hosts never see each other's."""
    auth = make_auth(base_url=DynamicBaseURL(allowed_hosts=["*.vercel.app"]))
    seen: list[str] = []

    async def run(host: str) -> None:
        with bind_base_url(auth._dynamic_base_url, {"host": host}, True):
            await asyncio.sleep(0)
            seen.append(auth.base_url)

    await asyncio.gather(run("a.vercel.app"), run("b.vercel.app"))
    assert sorted(seen) == ["https://a.vercel.app", "https://b.vercel.app"]


async def test_handle_resolves_base_url_per_request():
    auth = make_auth(base_url=DynamicBaseURL(allowed_hosts=["*.vercel.app"]))
    captured: list[str] = []

    async def before(ctx):
        captured.append(ctx.auth.base_url)
        return None

    auth.hooks = {"before": before}
    request = AuthRequest(
        method="POST",
        path="/sign-in/email",
        headers={"host": "pr-7.vercel.app", "origin": "https://pr-7.vercel.app"},
        body=b'{"email":"a@b.com","password":"password123"}',
    )
    await auth.handle(request)
    assert captured == ["https://pr-7.vercel.app"]


async def test_handle_rejects_unknown_host_without_fallback():
    auth = make_auth(base_url=DynamicBaseURL(allowed_hosts=["myapp.com"]))
    response = await auth.handle(
        AuthRequest(method="GET", path="/get-session", headers={"host": "evil.com"})
    )
    assert response.status == 500
    assert response.body["code"] == "INTERNAL_SERVER_ERROR"


async def test_spoofed_forwarded_host_ignored_when_untrusted():
    auth = make_auth(
        base_url=DynamicBaseURL(allowed_hosts=["*.vercel.app"], fallback="https://myapp.com"),
        trusted_proxy_headers=False,
    )
    captured: list[str] = []

    async def before(ctx):
        captured.append(ctx.auth.base_url)
        return None

    auth.hooks = {"before": before}
    await auth.handle(
        AuthRequest(
            method="GET",
            path="/get-session",
            headers={"host": "a.vercel.app", "x-forwarded-host": "evil.com"},
        )
    )
    assert captured == ["https://a.vercel.app"]


# --- trusted origins expansion --------------------------------------------------------


async def test_trusted_origins_expand_allowed_hosts():
    auth = make_auth(base_url=DynamicBaseURL(allowed_hosts=["myapp.com", "*.vercel.app"]))
    origins = await resolve_trusted_origins(auth, None)
    assert origins == ["https://myapp.com", "https://*.vercel.app"]


async def test_trusted_origins_auto_protocol_adds_http():
    auth = make_auth(base_url=DynamicBaseURL(allowed_hosts=["myapp.com"], protocol="auto"))
    assert await resolve_trusted_origins(auth, None) == [
        "https://myapp.com",
        "http://myapp.com",
    ]


async def test_trusted_origins_http_protocol_only_http():
    auth = make_auth(base_url=DynamicBaseURL(allowed_hosts=["myapp.com"], protocol="http"))
    assert await resolve_trusted_origins(auth, None) == ["http://myapp.com"]


async def test_trusted_origins_loopback_gets_http():
    auth = make_auth(base_url=DynamicBaseURL(allowed_hosts=["localhost:3000"]))
    assert await resolve_trusted_origins(auth, None) == [
        "https://localhost:3000",
        "http://localhost:3000",
    ]


async def test_trusted_origins_pass_through_scheme_and_fallback():
    auth = make_auth(
        base_url=DynamicBaseURL(
            allowed_hosts=["https://myapp.com"], fallback="https://fallback.com/x"
        )
    )
    assert await resolve_trusted_origins(auth, None) == [
        "https://myapp.com",
        "https://fallback.com",
    ]


async def test_wildcard_allowed_host_origin_is_trusted():
    auth = make_auth(base_url=DynamicBaseURL(allowed_hosts=["*.vercel.app"]))
    assert await is_trusted_origin(auth, None, "https://pr-7.vercel.app", allow_relative=False)
    assert not await is_trusted_origin(auth, None, "https://evil.com", allow_relative=False)


async def test_check_origin_accepts_wildcard_host_end_to_end():
    auth = make_auth(base_url=DynamicBaseURL(allowed_hosts=["*.vercel.app"]))
    response = await auth.handle(
        AuthRequest(
            method="POST",
            path="/sign-in/email",
            headers={
                "host": "pr-7.vercel.app",
                "origin": "https://pr-7.vercel.app",
                "cookie": "x=1",
            },
            body=b'{"email":"a@b.com","password":"password123"}',
        )
    )
    assert response.body.get("code") != "INVALID_ORIGIN"


async def test_check_origin_rejects_unlisted_origin():
    auth = make_auth(
        base_url=DynamicBaseURL(allowed_hosts=["*.vercel.app"], fallback="https://myapp.com")
    )
    response = await auth.handle(
        AuthRequest(
            method="POST",
            path="/sign-in/email",
            headers={
                "host": "pr-7.vercel.app",
                "origin": "https://evil.com",
                "cookie": "x=1",
            },
            body=b'{"email":"a@b.com","password":"password123"}',
        )
    )
    assert response.status == 403
    assert response.body["code"] == "INVALID_ORIGIN"


# --- cookie derivation (item 7) -------------------------------------------------------


def test_secure_cookies_from_dynamic_protocol():
    assert make_auth(
        base_url=DynamicBaseURL(allowed_hosts=["a.com"], protocol="https")
    ).use_secure_cookies
    assert not make_auth(
        base_url=DynamicBaseURL(allowed_hosts=["a.com"], protocol="http")
    ).use_secure_cookies


def test_secure_cookies_auto_is_env_derived(monkeypatch):
    monkeypatch.setenv("BETTER_AUTH_ENV", "production")
    assert make_auth(base_url=DynamicBaseURL(allowed_hosts=["a.com"])).use_secure_cookies
    monkeypatch.setenv("BETTER_AUTH_ENV", "development")
    assert not make_auth(base_url=DynamicBaseURL(allowed_hosts=["a.com"])).use_secure_cookies


def test_cookie_domain_follows_resolved_host():
    from better_auth.config import CrossSubDomainCookies

    auth = make_auth(
        base_url=DynamicBaseURL(allowed_hosts=["*.vercel.app"], fallback="https://myapp.com"),
        cross_sub_domain_cookies=CrossSubDomainCookies(enabled=True),
    )
    assert auth.cookie_domain == "myapp.com"
    with bind_base_url(auth._dynamic_base_url, {"host": "pr-7.vercel.app"}, True):
        assert auth.cookie_domain == "pr-7.vercel.app"
