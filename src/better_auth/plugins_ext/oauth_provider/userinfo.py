"""GET|POST /oauth2/userinfo — OIDC UserInfo endpoint.

Port of TS ``packages/oauth-provider/src/userinfo.ts`` (v1.7.6). The access token arrives in the
``Authorization`` header (``Bearer`` or ``DPoP``) or, on POST, as the ``access_token`` form field
(5ac62493e), never both. It is validated through introspection's
``require_active_access_token_with_claims`` (JWT or opaque); a DPoP-bound token also needs a
matching proof (aedcb974f). Standard claims come from the claim registry for every granted scope
and every ``claims.userinfo`` name the token carries (e3125e872); pairwise ``sub`` is resolved
when the server and client opt in; ``custom_user_info_claims`` may override any claim but ``sub``.
Responses are ``no-store`` (2196ea65e).
"""

from __future__ import annotations

import inspect
from typing import Any
from urllib.parse import parse_qsl

from ...adapters.base import Where
from ...types import AuthResponse, Ctx
from . import dpop
from .claims import pick_claims, user_normal_claims
from .client_crud import get_client
from .introspect import require_active_access_token_with_claims
from .token import NO_STORE_HEADERS, no_store
from .utils import OAuthError, resolve_subject_identifier


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _body_access_token(ctx: Ctx) -> str | None:
    """The POST form ``access_token`` (RFC 6750 §2.2); JSON bodies are read for convenience."""
    if ctx.request.method != "POST" or not ctx.request.body:
        return None
    ctype = (ctx.request.headers.get("content-type") or "").lower()
    if "application/x-www-form-urlencoded" in ctype:
        pairs = parse_qsl(ctx.request.body.decode("utf-8", "replace"), keep_blank_values=True)
        values = [v for k, v in pairs if k == "access_token"]
        return values[-1] if values else None
    try:
        value = ctx.body().get("access_token")
    except Exception:
        return None
    return value if isinstance(value, str) else None


def _access_token_authorization(ctx: Ctx) -> dpop.AccessTokenAuthorization | None:
    """TS ``getUserInfoAccessToken`` (userinfo.ts:83)."""
    header = dpop.parse_access_token_authorization(ctx.request.headers.get("authorization"))
    body_token = _body_access_token(ctx)
    if header and body_token:
        raise OAuthError(
            400, "invalid_request", "Multiple access token transport methods are not allowed"
        )
    if header:
        return header
    return dpop.AccessTokenAuthorization("Bearer", body_token) if body_token else None


async def userinfo_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    try:
        claims = await _userinfo(ctx, opts)
    except OAuthError as error:
        raise no_store(error) from None
    return AuthResponse(body=claims, headers=list(NO_STORE_HEADERS))


async def _userinfo(ctx: Ctx, opts: Any) -> dict[str, Any]:
    authorization = _access_token_authorization(ctx)
    if not authorization or not authorization.token:
        raise OAuthError(401, "invalid_request", "access token not found")
    jwt, requested_claims = await require_active_access_token_with_claims(
        ctx, opts, authorization.token
    )

    dpop_opts = getattr(opts, "dpop", None) or {}
    try:
        await dpop.enforce_dpop_binding(
            payload=jwt,
            authorization=authorization,
            proof_jwt=dpop.get_dpop_proof_jwt(ctx),
            method=ctx.request.method or "GET",
            url=dpop.get_endpoint_url(ctx, "/oauth2/userinfo"),
            proof_max_age_seconds=dpop_opts.get("proofMaxAgeSeconds"),
            signing_algorithms=dpop_opts.get("signingAlgorithms"),
            replay_store=dpop.create_dpop_replay_store(ctx.auth.internal),
        )
    except dpop.DpopBindingError as error:
        raise OAuthError(401, error.code, str(error)) from None

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

    base_claims = user_normal_claims(user, scopes, requested_claims)

    # Load the client only when pairwise subjects need it (userinfo.ts:196).
    client_id = jwt.get("client_id") or jwt.get("azp")
    if client_id and getattr(opts, "pairwise_secret", None):
        client = await get_client(ctx, opts, client_id)
        if client:
            base_claims["sub"] = resolve_subject_identifier(client, opts, user["id"])

    custom = getattr(opts, "custom_user_info_claims", None)
    extra = (
        await _await(
            custom(
                {"user": user, "scopes": scopes, "jwt": jwt, "requestedClaims": requested_claims}
            )
        )
        if custom and scopes
        else {}
    )
    # None claims drop out like TS JSON.stringify omitting undefined; sub is re-pinned last.
    return {**pick_claims(base_claims), **pick_claims(extra), "sub": base_claims["sub"]}
