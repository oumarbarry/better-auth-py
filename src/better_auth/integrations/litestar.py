"""Litestar integration: mount the auth router and read sessions via dependencies.

Usage::

    from litestar import Litestar, get
    from litestar.di import NamedDependency, Provide

    from better_auth import BetterAuth
    from better_auth.integrations.litestar import BetterAuthLitestar

    auth = BetterAuth(...)
    ba = BetterAuthLitestar(auth)

    @get("/me", dependencies={"result": Provide(ba.require_session)})
    async def me(result: NamedDependency[dict]) -> dict:
        return result["user"]

    app = Litestar(route_handlers=[ba.router, me])
"""

from __future__ import annotations

from typing import Any

try:
    from litestar import HttpMethod, Request, Router, route
    from litestar.exceptions import NotAuthorizedException
    from litestar.params import FromPath
    from litestar.response.base import ASGIResponse
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "Litestar is not installed; install it with `pip install better-auth-server[litestar]`"
    ) from exc

from ..auth import BetterAuth
from ..types import AuthRequest, AuthResponse, dump_json


def _to_auth_request(request: Request, path: str, body: bytes) -> AuthRequest:
    headers = {k.lower(): v for k, v in request.headers.items()}
    client_ip = request.client.host if request.client else None
    forwarded = headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    return AuthRequest(
        method=request.method,
        path=path,
        headers=headers,
        # last value wins, as with FastAPI's `dict(request.query_params)`
        query={key: values[-1] for key, values in request.query_params.dict().items()},
        body=body,
        client_ip=client_ip,
    )


def _to_response(result: AuthResponse) -> ASGIResponse:
    """AuthResponse → ASGI response (the low-level one: it keeps repeated Set-Cookie headers)."""
    if result.redirect_to is not None:
        # ASGIResponse always defaults a content-type, so a redirect carries an (ignored)
        # `application/json` where the FastAPI layer sends none. Body and status match.
        return ASGIResponse(
            status_code=302,
            headers=[("location", result.redirect_to), *result.headers],
        )
    return ASGIResponse(
        body=result.body if result.media_type else dump_json(result.body),
        status_code=result.status,
        media_type=result.media_type or "application/json",
        headers=list(result.headers),
    )


class BetterAuthLitestar:
    """Binds a BetterAuth instance to Litestar: `.router` plus session dependencies."""

    def __init__(self, auth: BetterAuth, include_in_schema: bool = False):
        self.auth = auth
        base = auth.base_path.rstrip("/")

        @route(
            base + "/{rest:path}",
            http_method=[HttpMethod.GET, HttpMethod.POST],
            include_in_schema=include_in_schema,
            name="better-auth",
        )
        async def handle(request: Request, rest: FromPath[str]) -> ASGIResponse:
            body = await request.body()
            return _to_response(await auth.handle(_to_auth_request(request, rest, body)))

        #: pass to ``Litestar(route_handlers=[...])`` — mirrors FastAPI's ``include_router``
        self.router = Router(path="/", route_handlers=[handle])

    async def session(self, request: Request) -> dict[str, Any] | None:
        """Dependency: ``{"session": ..., "user": ...}`` or None."""
        return await self.auth.load_session(_to_auth_request(request, "/get-session", b""))

    async def require_session(self, request: Request) -> dict[str, Any]:
        """Dependency: like `session` but responds 401 when unauthenticated."""
        result = await self.session(request)
        if result is None:
            raise NotAuthorizedException(detail="Not authenticated")
        return result
