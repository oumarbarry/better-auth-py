"""custom-session — wraps ``GET /get-session`` so integrators can shape/augment the
returned session object.

Port of TS ``packages/better-auth/src/plugins/custom-session/index.ts``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ..endpoints import get_session_handler
from ..plugins import HookSet, Plugin, PluginHook, Route
from ..types import AuthResponse, Ctx

Fn = Callable[[dict[str, Any], Ctx], Awaitable[Any]]

_LIST_DEVICE_SESSIONS_PATH = "/multi-session/list-device-sessions"


class CustomSessionPlugin(Plugin):
    id = "custom-session"

    def __init__(
        self, fn: Fn, *, should_mutate_list_device_sessions_endpoint: bool = False
    ) -> None:
        # ponytail: TS's `fn(session, ctx) => Promise<Returns>` also takes a second
        # positional `options: BetterAuthOptions` arg for type inference only (no
        # runtime effect) -- skipped, Python has nothing to infer against it.
        self.fn = fn
        self.should_mutate_list_device_sessions_endpoint = (
            should_mutate_list_device_sessions_endpoint
        )

    def routes(self) -> list[Route]:
        # Shadows the core `("GET", "/get-session", ...)` route (plugin routes are
        # tried first in auth.py's `_match`).
        return [("GET", "/get-session", self._get_session)]

    async def _get_session(self, ctx: Ctx) -> AuthResponse:
        try:
            core_response = await get_session_handler(ctx)
        except Exception:
            core_response = None
        if not isinstance(core_response, AuthResponse) or core_response.body is None:
            return AuthResponse(body=None)

        result = await self.fn(core_response.body, ctx)

        response = AuthResponse(body=result)
        # Forward every header (including each Set-Cookie) as its own separate entry --
        # AuthResponse.headers is already a list of tuples, never comma-joined, so a
        # plain copy preserves each cookie's own attributes (Max-Age, etc.) intact.
        response.headers.extend(core_response.headers)
        return response

    def hooks(self) -> HookSet:
        return HookSet(
            after=[PluginHook(matcher=self._matches_list_device_sessions, handler=self._mutate)]
        )

    def _matches_list_device_sessions(self, ctx: Ctx) -> bool:
        # ponytail: multi-session isn't ported yet (Wave 4) -- no route ever produces
        # this path today, so this matcher never actually fires through real HTTP
        # dispatch. It will start working for free once multi-session lands its
        # `/multi-session/list-device-sessions` endpoint.
        return (
            ctx.request.path == _LIST_DEVICE_SESSIONS_PATH
            and self.should_mutate_list_device_sessions_endpoint
        )

    async def _mutate(self, ctx: Ctx) -> None:
        response = ctx.response
        if isinstance(response, AuthResponse) and isinstance(response.body, list):
            response.body = [await self.fn(item, ctx) for item in response.body]
        return None
