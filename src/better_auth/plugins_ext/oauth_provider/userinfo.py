"""GET|POST /oauth2/userinfo — OIDC UserInfo endpoint.

Port of TS ``packages/oauth-provider/src/userinfo.ts`` (v1.6.23). A Bearer access token from the
``Authorization`` header is validated through the introspection ``validate_access_token`` helper
(JWT or opaque); the request requires an ``openid`` scope and a ``sub``. Claims come from
``user_normal_claims`` (per granted scope), pairwise ``sub`` is resolved when the server + client
opt in, and ``custom_user_info_claims`` are merged last.

Like TS userinfo.ts:46, the 401 carries no ``WWW-Authenticate`` header — only the client-side
``mcp.ts`` (excluded from this port) sets one.
"""

from __future__ import annotations

import inspect
from typing import Any

from ...adapters.base import Where
from ...types import Ctx
from .client_crud import get_client
from .introspect import validate_access_token
from .token import user_normal_claims
from .utils import OAuthError, resolve_subject_identifier


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def userinfo_endpoint(ctx: Ctx, opts: Any) -> dict[str, Any]:
    authorization = ctx.request.headers.get("authorization")
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer ") :]
    else:
        token = authorization
    if not token:
        raise OAuthError(401, "invalid_request", "authorization header not found")

    jwt = await validate_access_token(ctx, opts, token)

    scope = jwt.get("scope")
    scopes = scope.split(" ") if isinstance(scope, str) else None
    if not scopes or "openid" not in scopes:
        raise OAuthError(400, "invalid_scope", "Missing required scope")

    sub = jwt.get("sub")
    if not sub:
        raise OAuthError(400, "invalid_request", "user not found")

    user = await ctx.adapter.find_one("user", [Where("id", sub)])
    if not user:
        raise OAuthError(400, "invalid_request", "user not found")

    base_claims = user_normal_claims(user, scopes)

    # Resolve pairwise sub if the server has it enabled and the client opts in.
    if getattr(opts, "pairwise_secret", None):
        client_id = jwt.get("client_id") or jwt.get("azp")
        if client_id:
            client = await get_client(ctx, opts, client_id)
            if client:
                base_claims["sub"] = resolve_subject_identifier(client, opts, user["id"])

    custom = getattr(opts, "custom_user_info_claims", None)
    extra = (
        await _await(custom({"user": user, "scopes": scopes, "jwt": jwt}))
        if custom and scopes
        else {}
    )
    # Drop None claims to mirror TS JSON.stringify omitting undefined; custom claims win last.
    merged = {k: v for k, v in base_claims.items() if v is not None}
    merged.update(extra or {})
    return merged
