"""Captcha plugin — verify a CAPTCHA token (``x-captcha-response`` header) against a
provider before protected sign-up/sign-in endpoints run.

Port of better-auth's ``plugins/captcha`` (v1.7.6; index.ts, constants.ts,
error-codes.ts, verify-handlers/*.ts). Runs in ``on_request`` — i.e. after core rate
limiting and before route dispatch (see ``BetterAuth._dispatch``) — so a rejected
captcha never reaches the endpoint handler, and an exhausted rate limit short-circuits
before the provider is ever called (test-verified in TS; core already orders it this
way in the Python port too).

Fails CLOSED: any non-2xx response, transport error, or malformed body from the
provider's siteverify endpoint is treated as an unknown error (500), never as a pass.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from ..ip import get_request_ip
from ..origin import _wildcard_to_regex
from ..plugins import Plugin
from ..types import AuthResponse, Ctx

logger = logging.getLogger("better_auth.captcha")

#: TS ``CAPTCHA_VERIFY_TIMEOUT_MS`` (10_000ms) expressed in httpx's seconds.
CAPTCHA_VERIFY_TIMEOUT = 10.0

DEFAULT_ENDPOINTS: list[str] = ["/sign-up/email", "/sign-in/email", "/request-password-reset"]

SITE_VERIFY_MAP: dict[str, str] = {
    "cloudflare-turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    "google-recaptcha": "https://www.google.com/recaptcha/api/siteverify",
    "hcaptcha": "https://api.hcaptcha.com/siteverify",
    "captchafox": "https://api.captchafox.com/siteverify",
}

#: exact TS strings (captcha/error-codes.ts EXTERNAL_ERROR_CODES) — surfaced to the client.
EXTERNAL_ERROR_CODES: dict[str, str] = {
    "VERIFICATION_FAILED": "Captcha verification failed",
    "MISSING_RESPONSE": "Missing CAPTCHA response",
    "UNKNOWN_ERROR": "Something went wrong",
}
#: exact TS strings (INTERNAL_ERROR_CODES) — logged only, never surfaced to the client.
INTERNAL_ERROR_CODES: dict[str, str] = {
    "MISSING_SECRET_KEY": "Missing secret key",
    "SERVICE_UNAVAILABLE": "CAPTCHA service unavailable",
}


def _normalize_path(path: str) -> str:
    """TS ``normalizeEndpointPath`` (v1.7.6 index.ts:22-34); the base path and a trailing
    slash are already stripped by dispatch, so only duplicate slashes remain."""
    return re.sub(r"/{2,}", "/", path)


def _endpoint_matches(endpoint: str, pathname: str) -> bool:
    """Full-path rule: exact, or a ``*``/``**`` wildcard (TS v1.7.6 index.ts:51-55)."""
    if "*" in endpoint:
        return bool(_wildcard_to_regex(endpoint).match(pathname))
    return endpoint == pathname


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _verification_failed() -> AuthResponse:
    return AuthResponse(
        status=403,
        body={
            "code": "VERIFICATION_FAILED",
            "message": EXTERNAL_ERROR_CODES["VERIFICATION_FAILED"],
        },
    )


def _turnstile_failed(details: dict[str, Any]) -> AuthResponse:
    """cloudflare-turnstile.ts:56 (a17efd7cf): log why siteverify refused the token."""
    logger.warning(
        "Cloudflare Turnstile verification failed: %s",
        {"provider": "cloudflare-turnstile", **details},
    )
    return _verification_failed()


async def _post_json(http: httpx.AsyncClient, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = await http.post(url, json=payload, timeout=CAPTCHA_VERIFY_TIMEOUT)
    if not response.is_success:
        raise RuntimeError(INTERNAL_ERROR_CODES["SERVICE_UNAVAILABLE"])
    return response.json()


async def _post_form(http: httpx.AsyncClient, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = await http.post(url, data=payload, timeout=CAPTCHA_VERIFY_TIMEOUT)
    if not response.is_success:
        raise RuntimeError(INTERNAL_ERROR_CODES["SERVICE_UNAVAILABLE"])
    return response.json()


class CaptchaPlugin(Plugin):
    """Gate protected endpoints behind a CAPTCHA provider (TS ``plugins/captcha``).

    Constructor kwargs mirror the TS ``CaptchaOptions`` union (snake_case) with identical
    defaults, flattened across all providers; only the fields relevant to the configured
    ``provider`` are read. ``provider="vercel-botid"`` needs no secret key: it calls
    ``check_bot_id()`` (returning the BotID verdict dict, ``{"isBot": ...}``) and allows
    the request when ``isBot`` is ``False``, or when ``validate_request({"request",
    "verification"})`` returns true.
    """

    id = "captcha"
    error_codes = EXTERNAL_ERROR_CODES

    def __init__(
        self,
        *,
        provider: str,
        secret_key: str = "",
        endpoints: list[str] | None = None,
        site_verify_url_override: str | None = None,
        min_score: float = 0.5,
        expected_action: str | None = None,
        allowed_hostnames: list[str] | None = None,
        site_key: str | None = None,
        check_bot_id: Callable[[], Awaitable[dict[str, Any]]] | None = None,
        validate_request: Callable[[dict[str, Any]], bool | Awaitable[bool]] | None = None,
    ) -> None:
        self.provider = provider
        self.secret_key = secret_key
        self.endpoints = endpoints
        self.site_verify_url_override = site_verify_url_override
        self.min_score = min_score
        self.expected_action = expected_action
        self.allowed_hostnames = allowed_hostnames
        self.site_key = site_key
        self.check_bot_id = check_bot_id
        self.validate_request = validate_request

    async def on_request(self, ctx: Ctx) -> AuthResponse | None:
        try:
            endpoints = self.endpoints if self.endpoints else DEFAULT_ENDPOINTS
            pathname = _normalize_path(ctx.request.path)
            if not any(_endpoint_matches(endpoint, pathname) for endpoint in endpoints):
                return None

            if self.provider == "vercel-botid":
                return await self._verify_botid(ctx)

            if not self.secret_key:
                raise RuntimeError(INTERNAL_ERROR_CODES["MISSING_SECRET_KEY"])

            captcha_response = ctx.request.headers.get("x-captcha-response")
            # captcha/index.ts:68 — getIp(request, ctx.options), honors advanced.ipAddress
            remote_ip = get_request_ip(ctx.request, ctx.auth.ip_address)

            if not captcha_response:
                return AuthResponse(
                    status=400,
                    body={
                        "code": "MISSING_RESPONSE",
                        "message": EXTERNAL_ERROR_CODES["MISSING_RESPONSE"],
                    },
                )

            site_verify_url = self.site_verify_url_override or SITE_VERIFY_MAP[self.provider]
            http = ctx.auth.http

            if self.provider == "cloudflare-turnstile":
                return await self._verify_turnstile(
                    http, site_verify_url, captcha_response, remote_ip
                )
            if self.provider == "google-recaptcha":
                return await self._verify_recaptcha(
                    http, site_verify_url, captcha_response, remote_ip
                )
            if self.provider == "hcaptcha":
                return await self._verify_hcaptcha(
                    http, site_verify_url, captcha_response, remote_ip
                )
            if self.provider == "captchafox":
                return await self._verify_captchafox(
                    http, site_verify_url, captcha_response, remote_ip
                )
            return None
        except Exception as exc:  # fail closed — mirrors TS's catch-all in onRequest
            logger.error("captcha verification error: %s", exc)
            return AuthResponse(
                status=500,
                body={"code": "UNKNOWN_ERROR", "message": EXTERNAL_ERROR_CODES["UNKNOWN_ERROR"]},
            )

    async def _verify_botid(self, ctx: Ctx) -> AuthResponse | None:
        """TS ``vercelBotId`` (v1.7.6 verify-handlers/vercel-botid.ts): the check and any
        custom validation share the provider timeout and fail closed."""
        check_bot_id = self.check_bot_id
        if check_bot_id is None:
            raise RuntimeError("vercel-botid requires check_bot_id")

        async def decide() -> bool:
            verification = await check_bot_id()
            if self.validate_request is not None:
                return bool(
                    await _maybe_await(
                        self.validate_request(
                            {"request": ctx.request, "verification": verification}
                        )
                    )
                )
            return verification.get("isBot") is False

        try:
            is_valid = await asyncio.wait_for(decide(), CAPTCHA_VERIFY_TIMEOUT)
        except Exception as exc:
            raise RuntimeError(INTERNAL_ERROR_CODES["SERVICE_UNAVAILABLE"]) from exc
        return None if is_valid else _verification_failed()

    async def _verify_turnstile(
        self, http: httpx.AsyncClient, url: str, captcha_response: str, remote_ip: str | None
    ) -> AuthResponse | None:
        payload: dict[str, Any] = {"secret": self.secret_key, "response": captcha_response}
        if remote_ip:
            payload["remoteip"] = remote_ip
        data = await _post_json(http, url, payload)
        if not data.get("success"):
            details: dict[str, Any] = {
                "reason": "siteverify_rejected",
                "errorCodes": data.get("error-codes") or [],
            }
            details.update({k: data[k] for k in ("hostname", "action") if data.get(k)})
            return _turnstile_failed(details)
        # Bind the token to the expected action / hostname allowlist so a token issued
        # for a different action or host can't be replayed against this endpoint.
        if self.expected_action and data.get("action") != self.expected_action:
            return _turnstile_failed(
                {
                    "reason": "action_mismatch",
                    "expectedAction": self.expected_action,
                    "actualAction": data.get("action"),
                }
            )
        if self.allowed_hostnames and data.get("hostname") not in self.allowed_hostnames:
            return _turnstile_failed(
                {
                    "reason": "hostname_mismatch",
                    "allowedHostnames": self.allowed_hostnames,
                    "actualHostname": data.get("hostname"),
                }
            )
        return None

    async def _verify_recaptcha(
        self, http: httpx.AsyncClient, url: str, captcha_response: str, remote_ip: str | None
    ) -> AuthResponse | None:
        payload: dict[str, Any] = {"secret": self.secret_key, "response": captcha_response}
        if remote_ip:
            payload["remoteip"] = remote_ip
        data = await _post_form(http, url, payload)
        if not data.get("success"):
            return _verification_failed()
        # v3 responses carry a numeric `score`; v2 responses omit it entirely.
        score = data.get("score")
        if (
            isinstance(score, int | float)
            and not isinstance(score, bool)
            and score < self.min_score
        ):
            return _verification_failed()
        if self.expected_action and data.get("action") != self.expected_action:
            return _verification_failed()
        if self.allowed_hostnames and data.get("hostname") not in self.allowed_hostnames:
            return _verification_failed()
        return None

    async def _verify_hcaptcha(
        self, http: httpx.AsyncClient, url: str, captcha_response: str, remote_ip: str | None
    ) -> AuthResponse | None:
        payload: dict[str, Any] = {"secret": self.secret_key, "response": captcha_response}
        if self.site_key:
            payload["sitekey"] = self.site_key
        if remote_ip:
            payload["remoteip"] = remote_ip
        data = await _post_form(http, url, payload)
        if not data.get("success"):
            return _verification_failed()
        return None

    async def _verify_captchafox(
        self, http: httpx.AsyncClient, url: str, captcha_response: str, remote_ip: str | None
    ) -> AuthResponse | None:
        payload: dict[str, Any] = {"secret": self.secret_key, "response": captcha_response}
        if self.site_key:
            payload["sitekey"] = self.site_key
        if remote_ip:
            payload["remoteIp"] = remote_ip  # NB: camelCase — every other provider uses "remoteip"
        data = await _post_form(http, url, payload)
        if not data.get("success"):
            return _verification_failed()
        return None
