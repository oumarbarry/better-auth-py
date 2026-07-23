"""Tests for the captcha plugin (verify a CAPTCHA token before protected endpoints run).

Mirrors better-auth's plugins/captcha/captcha.test.ts and the gap spec
(docs/plans/gap/04-plugins-simple.md, "captcha"). TS source verified against:
  packages/better-auth/src/plugins/captcha/index.ts
  packages/better-auth/src/plugins/captcha/constants.ts
  packages/better-auth/src/plugins/captcha/error-codes.ts
  packages/better-auth/src/plugins/captcha/verify-handlers/*.ts

Most cases call ``plugin.on_request(ctx)`` directly — it's the whole contract, and doing
so avoids seeding real users just to prove a 400/403/500 short-circuit. The one behavior
that genuinely depends on core dispatch order (rate limiting before captcha) goes through
a real HTTP round trip via ``conftest.make_client``.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl

import httpx
import pytest

from better_auth import AuthRequest, BetterAuth, Ctx, RateLimit
from better_auth.plugins_ext.captcha import (
    CAPTCHA_VERIFY_TIMEOUT,
    DEFAULT_ENDPOINTS,
    EXTERNAL_ERROR_CODES,
    SITE_VERIFY_MAP,
    CaptchaPlugin,
)
from conftest import make_auth, make_client

PROVIDERS: list[dict[str, Any]] = [
    {"provider": "cloudflare-turnstile", "kwargs": {}},
    {"provider": "google-recaptcha", "kwargs": {}},
    {"provider": "hcaptcha", "kwargs": {"site_key": "xx-site-key"}},
    {"provider": "captchafox", "kwargs": {"site_key": "xx-site-key"}},
]


def mock_http(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def json_handler(status: int, data: dict[str, Any] | None = None) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=data if data is not None else {})

    return handler


def ctx_for(
    auth: BetterAuth,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    client_ip: str | None = None,
) -> Ctx:
    return Ctx(
        auth=auth,
        request=AuthRequest(
            method="POST",
            path=path,
            headers={k.lower(): v for k, v in (headers or {}).items()},
            client_ip=client_ip,
        ),
    )


def form_body(request: httpx.Request) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode()))


# --- error codes / constants (exact TS strings) ----------------------------------------


def test_error_codes_exact_strings():
    assert EXTERNAL_ERROR_CODES == {
        "VERIFICATION_FAILED": "Captcha verification failed",
        "MISSING_RESPONSE": "Missing CAPTCHA response",
        "UNKNOWN_ERROR": "Something went wrong",
    }


def test_error_codes_surface_on_auth_instance():
    auth = make_auth(plugins=[CaptchaPlugin(provider="cloudflare-turnstile", secret_key="sk")])
    assert auth.error_codes["MISSING_RESPONSE"] == "Missing CAPTCHA response"


def test_default_endpoints_and_site_verify_map():
    assert DEFAULT_ENDPOINTS == ["/sign-up/email", "/sign-in/email", "/request-password-reset"]
    assert SITE_VERIFY_MAP == {
        "cloudflare-turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        "google-recaptcha": "https://www.google.com/recaptcha/api/siteverify",
        "hcaptcha": "https://api.hcaptcha.com/siteverify",
        "captchafox": "https://api.captchafox.com/siteverify",
    }


# --- matching / gating -------------------------------------------------------------------


async def test_ignores_non_protected_endpoints():
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"success": False})

    plugin = CaptchaPlugin(
        provider="cloudflare-turnstile", secret_key="xx-secret-key", endpoints=["/sign-up"]
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "invalid-token"})

    result = await plugin.on_request(ctx)

    assert result is None
    assert calls == []  # never dispatched to the provider


@pytest.mark.parametrize("path", ["/sign-up/email", "/sign-in/email", "/request-password-reset"])
async def test_missing_captcha_response_returns_400(path):
    plugin = CaptchaPlugin(provider="cloudflare-turnstile", secret_key="xx-secret-key")
    auth = make_auth(plugins=[plugin])
    ctx = ctx_for(auth, path, headers={})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 400
    assert result.body == {"code": "MISSING_RESPONSE", "message": "Missing CAPTCHA response"}


async def test_missing_secret_key_returns_500():
    plugin = CaptchaPlugin(provider="cloudflare-turnstile", secret_key="")
    auth = make_auth(plugins=[plugin])
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "invalid-token"})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 500
    assert result.body == {"code": "UNKNOWN_ERROR", "message": "Something went wrong"}


async def test_missing_secret_key_wins_over_missing_token():
    """TS checks secretKey before reading the header — a 500, not a 400, when both absent."""
    plugin = CaptchaPlugin(provider="cloudflare-turnstile", secret_key="")
    auth = make_auth(plugins=[plugin])
    ctx = ctx_for(auth, "/sign-in/email", headers={})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 500


async def test_siteverify_transport_error_fails_closed_500():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    plugin = CaptchaPlugin(provider="cloudflare-turnstile", secret_key="xx-secret-key")
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 500
    assert result.body["code"] == "UNKNOWN_ERROR"


async def test_malformed_json_response_fails_closed_500():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    plugin = CaptchaPlugin(provider="cloudflare-turnstile", secret_key="xx-secret-key")
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 500
    assert result.body["code"] == "UNKNOWN_ERROR"


async def test_site_verify_url_override_honored():
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        return httpx.Response(200, json={"success": True, "hostname": "example.com"})

    plugin = CaptchaPlugin(
        provider="cloudflare-turnstile",
        secret_key="xx-secret-key",
        site_verify_url_override="https://custom.example/verify",
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is None
    assert captured == ["https://custom.example/verify"]


# --- per-provider: success / validation-failure / siteverify-failure (parametrized) -----


@pytest.mark.parametrize("config", PROVIDERS, ids=lambda c: c["provider"])
async def test_provider_success_allows_request_through(config):
    handler = json_handler(
        200, {"success": True, "hostname": "example.com", "challenge_ts": "2022-02-28T15:14:30Z"}
    )
    plugin = CaptchaPlugin(
        provider=config["provider"], secret_key="xx-secret-key", **config["kwargs"]
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(
        auth, "/sign-in/email", headers={"x-captcha-response": "token"}, client_ip="127.0.0.1"
    )

    result = await plugin.on_request(ctx)

    assert result is None


@pytest.mark.parametrize("config", PROVIDERS, ids=lambda c: c["provider"])
async def test_provider_validation_failure_returns_403(config):
    handler = json_handler(200, {"success": False, "error-codes": ["invalid-input-response"]})
    plugin = CaptchaPlugin(
        provider=config["provider"], secret_key="xx-secret-key", **config["kwargs"]
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 403
    assert result.body == {"code": "VERIFICATION_FAILED", "message": "Captcha verification failed"}


@pytest.mark.parametrize("config", PROVIDERS, ids=lambda c: c["provider"])
async def test_provider_siteverify_failure_returns_500(config):
    handler = json_handler(503)
    plugin = CaptchaPlugin(
        provider=config["provider"], secret_key="xx-secret-key", **config["kwargs"]
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 500
    assert result.body["code"] == "UNKNOWN_ERROR"


@pytest.mark.parametrize("config", PROVIDERS, ids=lambda c: c["provider"])
async def test_provider_bounds_request_with_shared_timeout(config):
    captured: list[Any] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.extensions.get("timeout"))
        return httpx.Response(200, json={"success": True, "hostname": "x"})

    plugin = CaptchaPlugin(
        provider=config["provider"], secret_key="xx-secret-key", **config["kwargs"]
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    await plugin.on_request(ctx)

    assert captured == [
        {
            "connect": CAPTCHA_VERIFY_TIMEOUT,
            "read": CAPTCHA_VERIFY_TIMEOUT,
            "write": CAPTCHA_VERIFY_TIMEOUT,
            "pool": CAPTCHA_VERIFY_TIMEOUT,
        }
    ]


# --- turnstile specifics -----------------------------------------------------------------


async def test_turnstile_sends_json_body_with_remoteip():
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["content_type"] = request.headers.get("content-type", "")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"success": True, "hostname": "x"})

    plugin = CaptchaPlugin(provider="cloudflare-turnstile", secret_key="xx-secret-key")
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(
        auth, "/sign-in/email", headers={"x-captcha-response": "token"}, client_ip="127.0.0.1"
    )

    await plugin.on_request(ctx)

    assert captured["content_type"].startswith("application/json")
    assert captured["body"] == {
        "secret": "xx-secret-key",
        "response": "token",
        "remoteip": "127.0.0.1",
    }


async def test_turnstile_omits_remoteip_when_no_client_ip():
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"success": True, "hostname": "x"})

    plugin = CaptchaPlugin(provider="cloudflare-turnstile", secret_key="xx-secret-key")
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"}, client_ip=None)

    await plugin.on_request(ctx)

    assert "remoteip" not in captured["body"]


async def test_turnstile_rejects_mismatched_expected_action():
    handler = json_handler(200, {"success": True, "action": "signup", "hostname": "myapp.com"})
    plugin = CaptchaPlugin(
        provider="cloudflare-turnstile", secret_key="xx-secret-key", expected_action="login"
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 403


async def test_turnstile_rejects_hostname_outside_allowlist():
    handler = json_handler(200, {"success": True, "hostname": "untrusted.example"})
    plugin = CaptchaPlugin(
        provider="cloudflare-turnstile", secret_key="xx-secret-key", allowed_hostnames=["myapp.com"]
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 403


async def test_turnstile_accepts_when_action_and_hostname_match():
    handler = json_handler(200, {"success": True, "action": "login", "hostname": "myapp.com"})
    plugin = CaptchaPlugin(
        provider="cloudflare-turnstile",
        secret_key="xx-secret-key",
        expected_action="login",
        allowed_hostnames=["myapp.com"],
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is None


# --- google-recaptcha specifics -----------------------------------------------------------


async def test_recaptcha_sends_form_body_with_remoteip():
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["content_type"] = request.headers.get("content-type", "")
        captured["body"] = form_body(request)
        return httpx.Response(200, json={"success": True, "hostname": "x", "challenge_ts": "t"})

    plugin = CaptchaPlugin(provider="google-recaptcha", secret_key="xx-secret-key")
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(
        auth, "/sign-in/email", headers={"x-captcha-response": "token"}, client_ip="127.0.0.1"
    )

    await plugin.on_request(ctx)

    assert "application/x-www-form-urlencoded" in captured["content_type"]
    assert captured["body"] == {
        "secret": "xx-secret-key",
        "response": "token",
        "remoteip": "127.0.0.1",
    }


async def test_recaptcha_low_score_returns_403_with_default_min_score():
    handler = json_handler(
        200,
        {
            "success": True,
            "score": 0.4,
            "action": "yourAction",
            "hostname": "x",
            "challenge_ts": "t",
        },
    )
    plugin = CaptchaPlugin(provider="google-recaptcha", secret_key="xx-secret-key")
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 403


async def test_recaptcha_custom_min_score_allows_lower_score():
    handler = json_handler(
        200, {"success": True, "score": 0.4, "hostname": "x", "challenge_ts": "t"}
    )
    plugin = CaptchaPlugin(provider="google-recaptcha", secret_key="xx-secret-key", min_score=0.3)
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is None


async def test_recaptcha_rejects_mismatched_expected_action():
    handler = json_handler(
        200,
        {
            "success": True,
            "score": 0.9,
            "action": "signup",
            "hostname": "myapp.com",
            "challenge_ts": "t",
        },
    )
    plugin = CaptchaPlugin(
        provider="google-recaptcha", secret_key="xx-secret-key", expected_action="login"
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 403


async def test_recaptcha_v2_response_without_score_ignores_min_score():
    """A v2 (non-score) response must not be treated as a v3 response with score 0."""
    handler = json_handler(200, {"success": True, "hostname": "x", "challenge_ts": "t"})
    plugin = CaptchaPlugin(provider="google-recaptcha", secret_key="xx-secret-key")
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    result = await plugin.on_request(ctx)

    assert result is None


# --- hcaptcha specifics --------------------------------------------------------------------


async def test_hcaptcha_sends_form_body_with_sitekey_and_remoteip():
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = form_body(request)
        return httpx.Response(200, json={"success": True, "hostname": "x", "challenge_ts": 1})

    plugin = CaptchaPlugin(provider="hcaptcha", secret_key="xx-secret-key", site_key="xx-site-key")
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(
        auth, "/sign-in/email", headers={"x-captcha-response": "token"}, client_ip="127.0.0.1"
    )

    await plugin.on_request(ctx)

    assert captured["body"] == {
        "secret": "xx-secret-key",
        "response": "token",
        "sitekey": "xx-site-key",
        "remoteip": "127.0.0.1",
    }


async def test_hcaptcha_omits_sitekey_when_not_configured():
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = form_body(request)
        return httpx.Response(200, json={"success": True})

    plugin = CaptchaPlugin(provider="hcaptcha", secret_key="xx-secret-key")
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(auth, "/sign-in/email", headers={"x-captcha-response": "token"})

    await plugin.on_request(ctx)

    assert "sitekey" not in captured["body"]


# --- captchafox specifics ------------------------------------------------------------------


async def test_captchafox_sends_form_body_with_sitekey_and_camelcase_remoteip():
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = form_body(request)
        return httpx.Response(200, json={"success": True, "hostname": "x", "challenge_ts": 1})

    plugin = CaptchaPlugin(
        provider="captchafox", secret_key="xx-secret-key", site_key="xx-site-key"
    )
    auth = make_auth(plugins=[plugin], http_client=mock_http(handler))
    ctx = ctx_for(
        auth, "/sign-in/email", headers={"x-captcha-response": "token"}, client_ip="127.0.0.1"
    )

    await plugin.on_request(ctx)

    # NB: captchafox uses "remoteIp" (camelCase) — every other provider uses "remoteip".
    assert captured["body"] == {
        "secret": "xx-secret-key",
        "response": "token",
        "sitekey": "xx-site-key",
        "remoteIp": "127.0.0.1",
    }


# --- /sign-in/email-otp exemption --------------------------------------------------------


async def test_email_otp_sign_in_exempt_by_default():
    plugin = CaptchaPlugin(provider="cloudflare-turnstile", secret_key="xx-secret-key")
    auth = make_auth(plugins=[plugin])
    # no x-captcha-response header — if this were enforced it would 400 immediately.
    ctx = ctx_for(auth, "/sign-in/email-otp", headers={})

    result = await plugin.on_request(ctx)

    assert result is None


async def test_email_otp_sign_in_enforced_when_explicitly_opted_in():
    plugin = CaptchaPlugin(
        provider="cloudflare-turnstile",
        secret_key="xx-secret-key",
        endpoints=["/sign-in/email-otp"],
    )
    auth = make_auth(plugins=[plugin])
    ctx = ctx_for(auth, "/sign-in/email-otp", headers={})

    result = await plugin.on_request(ctx)

    assert result is not None
    assert result.status == 400
    assert result.body["code"] == "MISSING_RESPONSE"


async def test_email_otp_still_exempt_when_custom_endpoints_omit_it():
    """A custom ``endpoints`` list that doesn't literally name the exempt path leaves it
    exempt — matching endpoints substring-matching a *different* protected path doesn't
    revoke the exemption."""
    plugin = CaptchaPlugin(
        provider="cloudflare-turnstile",
        secret_key="xx-secret-key",
        endpoints=["/sign-in/email", "/sign-up/email"],
    )
    auth = make_auth(plugins=[plugin])
    ctx = ctx_for(auth, "/sign-in/email-otp", headers={})

    result = await plugin.on_request(ctx)

    assert result is None


# --- ordering: core rate limiting runs before captcha verification (integration) --------


async def test_rate_limit_applies_before_captcha_verification():
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200, json={"success": False, "error-codes": ["invalid-input-response"]}
        )

    plugin = CaptchaPlugin(provider="cloudflare-turnstile", secret_key="xx-secret-key")
    auth = make_auth(
        plugins=[plugin],
        http_client=mock_http(handler),
        rate_limit=RateLimit(enabled=True, custom_rules={"/sign-in/email": (10, 1)}),
    )
    async with make_client(auth) as client:
        first = await client.post(
            "/api/auth/sign-in/email",
            json={"email": "test@test.com", "password": "test123456"},
            headers={"x-captcha-response": "invalid-captcha-token"},
        )
        second = await client.post(
            "/api/auth/sign-in/email",
            json={"email": "test@test.com", "password": "test123456"},
            headers={"x-captcha-response": "invalid-captcha-token"},
        )

    assert first.status_code == 403
    assert second.status_code == 429
    assert len(calls) == 1  # captcha never re-dispatched once rate-limited
