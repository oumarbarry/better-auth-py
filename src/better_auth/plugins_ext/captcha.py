"""Captcha plugin — verify a CAPTCHA token (``x-captcha-response`` header) against a
provider before protected sign-up/sign-in endpoints run.

Port of better-auth's ``plugins/captcha`` (v1.6.23; index.ts, constants.ts,
error-codes.ts, verify-handlers/*.ts). Runs in ``on_request`` — i.e. after core rate
limiting and before route dispatch (see ``BetterAuth._dispatch``) — so a rejected
captcha never reaches the endpoint handler, and an exhausted rate limit short-circuits
before the provider is ever called (test-verified in TS; core already orders it this
way in the Python port too).

Fails CLOSED: any non-2xx response, transport error, or malformed body from the
provider's siteverify endpoint is treated as an unknown error (500), never as a pass.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ..plugins import Plugin
from ..types import AuthResponse, Ctx

logger = logging.getLogger("better_auth.captcha")

#: TS ``CAPTCHA_VERIFY_TIMEOUT_MS`` (10_000ms) expressed in httpx's seconds.
CAPTCHA_VERIFY_TIMEOUT = 10.0

DEFAULT_ENDPOINTS: list[str] = ["/sign-up/email", "/sign-in/email", "/request-password-reset"]

#: exempt unless the caller's custom ``endpoints`` list names it verbatim (index.ts:42-51).
_EXEMPT_BY_DEFAULT = ["/sign-in/email-otp"]

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


def _verification_failed() -> AuthResponse:
    return AuthResponse(
        status=403,
        body={
            "code": "VERIFICATION_FAILED",
            "message": EXTERNAL_ERROR_CODES["VERIFICATION_FAILED"],
        },
    )


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
    defaults, flattened across all four providers — only the fields relevant to the
    configured ``provider`` are read.
    """

    id = "captcha"
    error_codes = EXTERNAL_ERROR_CODES

    def __init__(
        self,
        *,
        provider: str,
        secret_key: str,
        endpoints: list[str] | None = None,
        site_verify_url_override: str | None = None,
        min_score: float = 0.5,
        expected_action: str | None = None,
        allowed_hostnames: list[str] | None = None,
        site_key: str | None = None,
    ) -> None:
        self.provider = provider
        self.secret_key = secret_key
        self.endpoints = endpoints
        self.site_verify_url_override = site_verify_url_override
        self.min_score = min_score
        self.expected_action = expected_action
        self.allowed_hostnames = allowed_hostnames
        self.site_key = site_key

    def _exempt_paths(self) -> list[str]:
        endpoints = self.endpoints or []
        return [p for p in _EXEMPT_BY_DEFAULT if not (endpoints and p in endpoints)]

    async def on_request(self, ctx: Ctx) -> AuthResponse | None:
        try:
            endpoints = self.endpoints if self.endpoints else DEFAULT_ENDPOINTS
            pathname = ctx.request.path
            exempt_paths = self._exempt_paths()
            matched = any(
                endpoint in pathname and not any(p in pathname for p in exempt_paths)
                for endpoint in endpoints
            )
            if not matched:
                return None

            if not self.secret_key:
                raise RuntimeError(INTERNAL_ERROR_CODES["MISSING_SECRET_KEY"])

            captcha_response = ctx.request.headers.get("x-captcha-response")
            remote_ip = ctx.request.client_ip

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

    async def _verify_turnstile(
        self, http: httpx.AsyncClient, url: str, captcha_response: str, remote_ip: str | None
    ) -> AuthResponse | None:
        payload: dict[str, Any] = {"secret": self.secret_key, "response": captcha_response}
        if remote_ip:
            payload["remoteip"] = remote_ip
        data = await _post_json(http, url, payload)
        if not data.get("success"):
            return _verification_failed()
        # Bind the token to the expected action / hostname allowlist so a token issued
        # for a different action or host can't be replayed against this endpoint.
        if self.expected_action and data.get("action") != self.expected_action:
            return _verification_failed()
        if self.allowed_hostnames and data.get("hostname") not in self.allowed_hostnames:
            return _verification_failed()
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
