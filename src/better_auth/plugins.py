"""Plugin API — the TS ``BetterAuthPlugin`` contract, pythonic.

A plugin subclasses :class:`Plugin` and overrides the pieces it needs. Every hook
point mirrors better-auth's ``packages/core/src/types/plugin.ts`` and fires at the
same lifecycle position (see :meth:`better_auth.auth.BetterAuth._dispatch`):

    onRequest -> before-hooks (matched) -> endpoint -> after-hooks (matched) -> onResponse

``routes()`` is kept as the ergonomic endpoint form (``(method, path, handler)``);
it is the Python spelling of TS ``endpoints``. ``before()``/``after()`` are global
(always-matched) request hooks; ``hooks()`` adds path/context-gated ones with a
matcher, exactly like TS ``hooks.before[]``/``hooks.after[]``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from .schema import Schema
from .types import AuthResponse, Ctx

if TYPE_CHECKING:
    from .auth import BetterAuth

Handler = Callable[[Ctx], Awaitable[AuthResponse | dict[str, Any] | None]]
Route = tuple[str, str, Handler]  # (method, path, handler) — path like "/my-plugin/action"
Matcher = Callable[[Ctx], bool]


@dataclass
class PluginHook:
    """A matched before/after request hook (TS ``{matcher, handler}``).

    ``matcher(ctx)`` gates the hook per-request; ``handler(ctx)`` runs when it
    matches. A before handler may return an :class:`AuthResponse` to short-circuit;
    an after handler may return one to replace the outgoing response (it reads the
    current response from ``ctx.response``).
    """

    matcher: Matcher
    handler: Handler


@dataclass
class PluginMiddleware:
    """Path-scoped middleware (TS ``{path, middleware}``).

    ``path`` matches exactly, or as a prefix when it ends in ``/**``. Runs after the
    origin check and before the endpoint's before-hooks; may short-circuit by
    returning an :class:`AuthResponse`.
    """

    path: str
    handler: Handler


@dataclass
class RateLimitRule:
    """A plugin rate-limit rule (TS ``{window, max, pathMatcher}``).

    Consulted after the default + special rules and before ``customRules`` — the
    first plugin rule whose ``path_matcher`` matches wins (see the limiter).
    """

    window: int
    max: int
    path_matcher: Callable[[str], bool]


@dataclass
class HookSet:
    """Return type of :meth:`Plugin.hooks` — matched before/after request hooks."""

    before: list[PluginHook] = field(default_factory=list)
    after: list[PluginHook] = field(default_factory=list)


class Plugin:
    """Base class for plugins. Override what you need; everything defaults to a no-op."""

    #: namespace for hooks/logs and endpoint-conflict detection (TS ``id``).
    id: str = "plugin"
    #: optional plugin version (TS ``version``).
    version: str | None = None
    #: extra models/fields merged into the core schema (TS ``schema``; see schema.Field).
    schema: ClassVar[Schema] = {}
    #: plugin error-code table surfaced on ``auth.error_codes`` (TS ``$ERROR_CODES``).
    error_codes: ClassVar[dict[str, str]] = {}

    def init(self, auth: BetterAuth) -> None:
        """Called once after the instance is built (TS ``init(ctx)``).

        May mutate ``auth`` in place (options, providers, extra state). Runs before
        any request is served.
        """

    def routes(self) -> list[Route]:
        """Endpoints to mount (TS ``endpoints``)."""
        return []

    def middlewares(self) -> list[PluginMiddleware]:
        """Path-scoped middlewares (TS ``middlewares``)."""
        return []

    def hooks(self) -> HookSet:
        """Matched before/after request hooks (TS ``hooks``)."""
        return HookSet()

    def rate_limit(self) -> list[RateLimitRule]:
        """Per-path rate-limit rules (TS ``rateLimit``)."""
        return []

    async def on_request(self, ctx: Ctx) -> AuthResponse | None:
        """Runs in the onRequest phase, before routing hooks. Return an
        :class:`AuthResponse` to short-circuit (TS ``onRequest``)."""
        return None

    async def on_response(self, ctx: Ctx, response: AuthResponse) -> AuthResponse | None:
        """Runs in the onResponse phase. Return an :class:`AuthResponse` to replace
        the outgoing one (TS ``onResponse``)."""
        return None

    async def before(self, ctx: Ctx) -> AuthResponse | None:
        """Global before hook (always matched). Return an AuthResponse to short-circuit."""
        return None

    async def after(self, ctx: Ctx, response: AuthResponse) -> AuthResponse | None:
        """Global after hook (always matched). Return an AuthResponse to replace the response."""
        return None
