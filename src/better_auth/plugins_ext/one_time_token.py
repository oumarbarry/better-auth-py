"""one-time-token plugin — mint a short-lived single-use token from a session, then
exchange it for that session (e.g. cross-domain handoff).

Verified against TS ``packages/better-auth/src/plugins/one-time-token/index.ts`` (and
``utils.ts``) at v1.6.23.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from ..crypto import default_key_hasher, generate_random_string
from ..plugins import HookSet, Plugin, PluginHook, add_expose_headers
from ..session import refresh_session_cookie, utcnow
from ..types import APIError, AuthResponse, Ctx

#: TS union ``"plain" | "hashed" | {type:"custom-hasher", hash}``.
StoreToken = str | dict[str, Any]


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


class OneTimeTokenPlugin(Plugin):
    """TS ``oneTimeToken()`` — see module docstring for the source file.

    ``$ERROR_CODES``: TS exports none for this plugin — ``verify`` throws plain
    ``c.error("BAD_REQUEST", {message})`` calls with no distinct ``code``. This port's
    error envelope always carries a ``code``, so (matching the existing
    ``endpoints.change_email`` precedent for the same TS pattern) these three use the
    generic ``"BAD_REQUEST"`` code; the ``message`` text matches TS exactly. A real TS
    deployment's wire body for these is likely ``{"message": ...}`` alone (no ``code``
    key) — this port's body is always ``{"code": "BAD_REQUEST", "message": ...}``.
    """

    id = "one-time-token"

    def __init__(
        self,
        *,
        expires_in: int = 3,
        disable_client_request: bool = False,
        generate_token: Callable[[dict[str, Any], Ctx], Any] | None = None,
        disable_set_session_cookie: bool = False,
        store_token: StoreToken = "plain",
        set_ott_header_on_new_session: bool = False,
    ) -> None:
        self.expires_in = expires_in
        self.disable_client_request = disable_client_request
        self.generate_token_fn = generate_token
        self.disable_set_session_cookie = disable_set_session_cookie
        self.store_token = store_token
        self.set_ott_header_on_new_session = set_ott_header_on_new_session

    def routes(self):
        return [
            ("GET", "/one-time-token/generate", self.generate),
            ("POST", "/one-time-token/verify", self.verify),
        ]

    def hooks(self) -> HookSet:
        return HookSet(after=[PluginHook(lambda ctx: True, self._set_header_on_new_session)])

    # --- helpers ---------------------------------------------------------------------

    async def _stored_token(self, token: str) -> str:
        if self.store_token == "hashed":
            return default_key_hasher(token)
        if isinstance(self.store_token, dict) and self.store_token.get("type") == "custom-hasher":
            return await _maybe_await(self.store_token["hash"](token))
        return token

    async def _generate_token(self, ctx: Ctx, session: dict[str, Any]) -> str:
        if self.generate_token_fn is not None:
            token = await _maybe_await(self.generate_token_fn(session, ctx))
        else:
            token = generate_random_string(32)
        expires_at = utcnow() + timedelta(seconds=self.expires_in * 60)
        stored = await self._stored_token(token)
        await ctx.internal.create_verification_value(
            {
                "value": session["session"]["token"],
                "identifier": f"one-time-token:{stored}",
                "expiresAt": expires_at,
            }
        )
        return token

    # --- endpoints ---------------------------------------------------------------------

    async def generate(self, ctx: Ctx) -> AuthResponse:
        # ponytail: TS gates on `c.request`, present only for calls that arrived
        # over a real HTTP transport and absent for server-side
        # `auth.api.generateOneTimeToken()` calls — so TS can let a server caller
        # through while blocking a client one on the *same* handler. This port has
        # no such server-call surface: `Ctx.request` is a required `AuthRequest`,
        # so every call reaching this HTTP endpoint at all is, by construction, a
        # client call. `disable_client_request` therefore disables the endpoint
        # outright; a first-party server integration mints a token without going
        # through HTTP by calling `_generate_token(ctx, session)` directly (see
        # tests/plugins/test_one_time_token.py), the only "server API" this
        # HTTP-dispatch-only port has.
        if self.disable_client_request:
            raise APIError(400, "BAD_REQUEST", "Client requests are disabled")
        session = await ctx.require_session()
        token = await self._generate_token(ctx, session)
        return AuthResponse(body={"token": token})

    async def verify(self, ctx: Ctx) -> AuthResponse:
        token = ctx.body().get("token")
        if not token:
            raise APIError(400, "BAD_REQUEST", "Invalid token")
        stored = await self._stored_token(token)
        # Atomically burn the single-use record before issuing a session, so two
        # concurrent redemptions of the same token resolve to exactly one success.
        verification = await ctx.internal.consume_verification_value(f"one-time-token:{stored}")
        if verification is None:
            raise APIError(400, "BAD_REQUEST", "Invalid token")

        session = await ctx.internal.find_session(verification["value"])
        if session is None:
            raise APIError(400, "BAD_REQUEST", "Session not found")

        response = AuthResponse(body=session)
        if not self.disable_set_session_cookie:
            response.set_cookie(
                refresh_session_cookie(ctx.auth, ctx.request, session["session"]["token"])
            )
            ctx.new_session = session  # TS setSessionCookie() also calls setNewSession()

        # ponytail: TS checks expiry AFTER already queueing the session cookie (its
        # shared mutable response-header state keeps that queued write regardless of
        # the later throw). This port's APIError always yields a clean {code,message}
        # response with no headers no matter what `response` holds, so the ordering
        # has no observable effect here — kept for parity with the source's flow.
        if session["session"]["expiresAt"] < utcnow():
            raise APIError(400, "BAD_REQUEST", "Session expired")
        return response

    # --- hooks ---------------------------------------------------------------------

    async def _set_header_on_new_session(self, ctx: Ctx) -> None:
        if ctx.new_session is None or not self.set_ott_header_on_new_session:
            return None
        token = await self._generate_token(ctx, ctx.new_session)
        response = ctx.response
        if response is None:
            return None
        response.headers.append(("set-ott", token))
        add_expose_headers(response, "set-ott")
        return None
