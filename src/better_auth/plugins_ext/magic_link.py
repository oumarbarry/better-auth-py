"""magic-link plugin — a faithful port of better-auth's ``plugins/magic-link``.

Passwordless sign-in/sign-up via an emailed one-time link. Wire parity with the TS
plugin (``packages/better-auth/src/plugins/magic-link``):

- ``POST /sign-in/magic-link`` stores a ``verification`` row keyed by the *stored*
  token (``storeToken`` = plain | hashed | custom-hasher) with value
  ``JSON({email, name?})`` and mails the RAW token inside a
  ``<baseURL><basePath>/magic-link/verify?token=…&callbackURL=…`` link;
- ``GET /magic-link/verify`` origin-checks each callback URL, then **atomically
  consumes** the token (single-use regardless of the deprecated ``allowed_attempts``)
  so N racing verifies mint at most one session; on invalid/expired it redirects to
  ``errorCallbackURL?error=INVALID_TOKEN``; adopting an existing UNVERIFIED user
  revokes its unproven credential/sessions *before* marking it verified.

Storage fidelity: the stored ``verification.value`` is compact JSON
(``{"email":…}`` / ``{"email":…,"name":…}``) byte-compatible with TS
``JSON.stringify``; the token in the mail is always the raw token.
"""

from __future__ import annotations

import inspect
import json
import logging
import string
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..adapters.base import Where
from ..crypto import default_key_hasher, generate_random_string
from ..origin import is_trusted_origin
from ..plugins import Plugin, RateLimitRule
from ..session import create_session
from ..types import APIError, AuthResponse, Ctx

logger = logging.getLogger("better_auth")

_ALLOWED_ATTEMPTS_WARNING = (
    "[better-auth/magic-link] `allowedAttempts` is ignored: tokens are consumed "
    "atomically on the first verification call. Any value other than `1` has no "
    "effect; remove the option to silence this warning."
)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _accepts_ctx(fn: Callable[..., Any]) -> bool:
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (ValueError, TypeError):
        return True
    if any(p.kind == p.VAR_POSITIONAL for p in params):
        return True
    return sum(1 for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)) >= 2


def _resolve(origin: str, value: str) -> str:
    """Resolve a callback value against the base origin (TS ``new URL(value, baseURL)``);
    absolute URLs pass through, absolute paths resolve against the origin."""
    return urljoin(origin.rstrip("/") + "/", value)


def _redirect_with_error(absolute_url: str, error: str) -> AuthResponse:
    """302 to ``absolute_url`` with ``error=<code>`` added, preserving existing params."""
    parts = urlsplit(absolute_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["error"] = error
    target = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    return AuthResponse(redirect_to=target)


class MagicLinkPlugin(Plugin):
    id = "magic-link"
    error_codes: ClassVar[dict[str, str]] = {}  # TS exports none; redirect codes are inline

    def __init__(
        self,
        *,
        send_magic_link: Callable[..., Any],
        expires_in: int = 300,
        allowed_attempts: int | float | None = None,
        disable_sign_up: bool = False,
        rate_limit: dict[str, int] | None = None,
        generate_token: Callable[[str], Any] | None = None,
        store_token: str | dict[str, Any] = "plain",
    ) -> None:
        self.send_magic_link = send_magic_link
        self.expires_in = expires_in or 300
        self.disable_sign_up = disable_sign_up
        self.generate_token = generate_token
        self.store_token = store_token
        rl = rate_limit or {}
        self._rl_window = rl.get("window") or 60
        self._rl_max = rl.get("max") or 5
        # `allowed_attempts` is deprecated: single-use is enforced atomically. Any value
        # other than 1 is ignored and warned about at construction (matches TS console.warn).
        if allowed_attempts is not None and allowed_attempts != 1:
            logger.warning(_ALLOWED_ATTEMPTS_WARNING)

    # --- rate limit ---------------------------------------------------------------------

    def rate_limit(self) -> list[RateLimitRule]:
        def matcher(path: str) -> bool:
            return path.startswith("/sign-in/magic-link") or path.startswith("/magic-link/verify")

        return [RateLimitRule(window=self._rl_window, max=self._rl_max, path_matcher=matcher)]

    # --- routes -------------------------------------------------------------------------

    def routes(self) -> list[tuple[str, str, Any]]:
        return [
            ("POST", "/sign-in/magic-link", self._sign_in),
            ("GET", "/magic-link/verify", self._verify),
        ]

    async def _store(self, token: str) -> str:
        if self.store_token == "hashed":
            return default_key_hasher(token)
        if isinstance(self.store_token, dict) and self.store_token.get("type") == "custom-hasher":
            return await _maybe_await(self.store_token["hash"](token))
        return token

    async def _send(self, data: dict[str, Any], ctx: Ctx) -> None:
        result = (
            self.send_magic_link(data, ctx)
            if _accepts_ctx(self.send_magic_link)
            else self.send_magic_link(data)
        )
        await _maybe_await(result)

    async def _sign_in(self, ctx: Ctx) -> dict[str, Any]:
        body = ctx.body()
        email = body.get("email")
        if not isinstance(email, str) or "@" not in email:
            raise APIError(400, "INVALID_EMAIL", "Invalid email")
        metadata = body.get("metadata")

        token = (
            await _maybe_await(self.generate_token(email))
            if self.generate_token is not None
            else generate_random_string(32, string.ascii_letters)
        )
        stored_token = await self._store(token)

        value: dict[str, Any] = {"email": email}
        if body.get("name") is not None:
            value["name"] = body["name"]
        now = datetime.now(timezone.utc)
        await ctx.internal.create_verification_value(
            {
                "identifier": stored_token,
                "value": json.dumps(value, separators=(",", ":")),
                "expiresAt": now + timedelta(seconds=self.expires_in),
            }
        )

        base = f"{ctx.auth.base_url}{ctx.auth.base_path}/magic-link/verify"
        params: dict[str, str] = {"token": token, "callbackURL": body.get("callbackURL") or "/"}
        if body.get("newUserCallbackURL"):
            params["newUserCallbackURL"] = body["newUserCallbackURL"]
        if body.get("errorCallbackURL"):
            params["errorCallbackURL"] = body["errorCallbackURL"]
        url = f"{base}?{urlencode(params)}"

        await self._send({"email": email, "url": url, "token": token, "metadata": metadata}, ctx)
        return {"status": True}

    async def _origin_check(self, ctx: Ctx, value: str | None) -> None:
        # TS wraps each callback URL in originCheck (throws INVALID_CALLBACK_URL /
        # "Invalid callbackURL"); an absent value defaults to "/" which is always trusted.
        if not value:
            return
        if not await is_trusted_origin(ctx.auth, ctx.request, value, allow_relative=True):
            raise APIError(403, "INVALID_CALLBACK_URL", "Invalid callbackURL")

    async def _verify(self, ctx: Ctx) -> AuthResponse:
        query = ctx.request.query
        token = query.get("token")

        # originCheck each callback URL BEFORE consuming the token (TS `use: [...]`)
        await self._origin_check(ctx, query.get("callbackURL"))
        await self._origin_check(ctx, query.get("newUserCallbackURL"))
        await self._origin_check(ctx, query.get("errorCallbackURL"))

        origin = ctx.auth.base_url
        callback_url = _resolve(origin, query.get("callbackURL") or "/")
        error_callback_url = _resolve(origin, query.get("errorCallbackURL") or callback_url)
        new_user_callback_url = _resolve(origin, query.get("newUserCallbackURL") or callback_url)

        stored_token = await self._store(token) if token else None
        token_value = (
            await ctx.internal.consume_verification_value(stored_token) if stored_token else None
        )
        if token_value is None:
            return _redirect_with_error(error_callback_url, "INVALID_TOKEN")

        payload = json.loads(token_value["value"])
        email = payload["email"]
        name = payload.get("name")

        is_new_user = False
        user = await ctx.adapter.find_one("user", [Where("email", email.lower())])
        if user is None:
            if self.disable_sign_up:
                return _redirect_with_error(error_callback_url, "new_user_signup_disabled")
            user = await ctx.internal.create_user(
                {"email": email, "emailVerified": True, "name": name or ""}
            )
            is_new_user = True
            if user is None:
                return _redirect_with_error(error_callback_url, "failed_to_create_user")

        if not user.get("emailVerified"):
            # order matters: strip the unproven credential/sessions BEFORE marking verified
            await ctx.internal.revoke_unproven_account_access(user["id"])
            user = await ctx.internal.update_user(user["id"], {"emailVerified": True}) or user

        session, cookies = await create_session(
            ctx.auth, user["id"], ctx.request, user=user, ctx=ctx
        )
        if session is None:  # unreachable in this port (create_session never fails); parity guard
            return _redirect_with_error(error_callback_url, "failed_to_create_session")

        if not query.get("callbackURL"):
            response = AuthResponse(
                body={
                    "token": session["token"],
                    "user": ctx.auth.parse_user_output(user),
                    "session": ctx.auth.parse_session_output(session),
                }
            )
            for cookie in cookies:
                response.set_cookie(cookie)
            return response

        response = AuthResponse(redirect_to=new_user_callback_url if is_new_user else callback_url)
        for cookie in cookies:
            response.set_cookie(cookie)
        return response
