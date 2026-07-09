"""Plugin API: add routes, extend the schema, and hook around every request."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, ClassVar

from .schema import Schema
from .types import AuthResponse, Ctx

Handler = Callable[[Ctx], Awaitable[AuthResponse | dict[str, Any] | None]]
Route = tuple[str, str, Handler]  # (method, path, handler) — path like "/my-plugin/action"


class Plugin:
    """Base class for plugins. Override what you need."""

    id: str = "plugin"
    #: Extra models/fields merged into the core schema (see better_auth.schema.Field).
    schema: ClassVar[Schema] = {}

    def routes(self) -> list[Route]:
        return []

    async def before(self, ctx: Ctx) -> AuthResponse | None:
        """Runs before every endpoint. Return an AuthResponse to short-circuit."""
        return None

    async def after(self, ctx: Ctx, response: AuthResponse) -> AuthResponse | None:
        """Runs after every endpoint. Return an AuthResponse to replace the outgoing one."""
        return None
