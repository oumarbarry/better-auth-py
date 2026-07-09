"""FastAPI integration: mount the auth router and read sessions via dependencies.

Usage::

    from better_auth import BetterAuth
    from better_auth.integrations.fastapi import BetterAuthFastAPI

    auth = BetterAuth(...)
    ba = BetterAuthFastAPI(auth)
    app.include_router(ba.router)

    @app.get("/me")
    async def me(result: dict = Depends(ba.require_session)):
        return result["user"]
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response

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
        query=dict(request.query_params),
        body=body,
        client_ip=client_ip,
    )


def _to_response(result: AuthResponse) -> Response:
    if result.redirect_to is not None:
        response = Response(status_code=302)
        response.headers["location"] = result.redirect_to
    else:
        response = Response(
            content=result.body if result.media_type else dump_json(result.body),
            status_code=result.status,
            media_type=result.media_type or "application/json",
        )
    for name, value in result.headers:
        response.headers.append(name, value)
    return response


class BetterAuthFastAPI:
    """Binds a BetterAuth instance to FastAPI: `.router` plus session dependencies."""

    def __init__(self, auth: BetterAuth, include_in_schema: bool = False):
        self.auth = auth
        self.router = APIRouter()
        base = auth.base_path.rstrip("/")

        @self.router.api_route(
            base + "/{rest:path}",
            methods=["GET", "POST"],
            include_in_schema=include_in_schema,
            name="better-auth",
        )
        async def handle(request: Request, rest: str) -> Response:
            body = await request.body()
            return _to_response(await auth.handle(_to_auth_request(request, "/" + rest, body)))

    async def session(self, request: Request) -> dict[str, Any] | None:
        """Dependency: ``{"session": ..., "user": ...}`` or None."""
        return await self.auth.load_session(_to_auth_request(request, "/get-session", b""))

    async def require_session(self, request: Request) -> dict[str, Any]:
        """Dependency: like `session` but responds 401 when unauthenticated."""
        result = await self.session(request)
        if result is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return result
