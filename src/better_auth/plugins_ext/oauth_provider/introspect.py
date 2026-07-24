"""POST /oauth2/introspect — RFC 7662 token introspection.

Port of TS ``packages/oauth-provider/src/introspect.ts`` (v1.6.23). Requires client
credentials (Basic or body). Tries the token, honoring ``token_type_hint``, as JWT access ->
opaque access -> refresh, returning the RFC 7662 shape (``{active, scope, client_id, sub, sid,
exp, iat, iss, ...}``) or ``{active: false}``. Security gates: a JWT access token MUST carry an
``azp`` matching an enabled client (a plain jwt-plugin session token is rejected —
token-type confusion), ``sid`` is cleared when its session is gone/expired, and pairwise ``sub``
is resolved at the presentation layer.
"""

from __future__ import annotations

import inspect
import math
from typing import Any

from ...adapters.base import Where
from ...session import utcnow
from ...types import Ctx
from .client_crud import get_client
from .token import (
    decode_refresh_token,
    validate_client_credentials,
)
from .utils import (
    JwsAccessTokenClaimInvalid,
    JwsAccessTokenExpired,
    JwsAccessTokenInvalid,
    OAuthError,
    basic_to_client_credentials,
    get_jwt_plugin,
    parse_client_metadata,
    resolve_subject_identifier,
    store_token,
    verify_jws_access_token,
)

_INACTIVE = {"active": False}


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _base_url(ctx: Ctx) -> str:
    return f"{ctx.auth.base_url}{ctx.auth.base_path}"


def _issuer(ctx: Ctx) -> str:
    jwt_plugin = get_jwt_plugin(ctx.auth)
    return getattr(jwt_plugin, "issuer", None) or _base_url(ctx)


def _epoch(dt: Any) -> int | None:
    if dt is None:
        return None
    return math.floor(dt.timestamp())


async def _session_alive(ctx: Ctx, session_id: str | None) -> bool:
    if not session_id:
        return False
    session = await ctx.adapter.find_one("session", [Where("id", session_id)])
    return bool(session and session["expiresAt"] >= utcnow())


# --- JWT access token (introspect.ts:38) ---------------------------------------------


class _NotAJwt(Exception):
    """Signals validate_access_token to fall through to opaque handling."""


async def _validate_jwt_access_token(
    ctx: Ctx, opts: Any, token: str, client_id: str | None
) -> dict[str, Any]:
    jwt_plugin = get_jwt_plugin(ctx.auth)
    audience = getattr(opts, "valid_audiences", None) or _base_url(ctx)
    try:
        payload = await verify_jws_access_token(
            jwt_plugin, token, audience=audience, issuer=_issuer(ctx)
        )
    except JwsAccessTokenExpired:
        return dict(_INACTIVE)
    except JwsAccessTokenClaimInvalid:
        return dict(_INACTIVE)
    except JwsAccessTokenInvalid:
        raise _NotAJwt() from None

    # A provider-issued access token always carries `azp`; a plain jwt-plugin session token
    # (same keys/issuer/audience) does not, so require it plus a matching enabled client.
    azp = payload.get("azp")
    if not azp:
        return dict(_INACTIVE)
    client = await get_client(ctx, opts, azp)
    if not client or client.get("disabled"):
        return dict(_INACTIVE)
    if client_id and azp != client_id:
        return dict(_INACTIVE)

    if payload.get("sid") and not await _session_alive(ctx, payload.get("sid")):
        payload["sid"] = None

    payload["client_id"] = azp
    payload["active"] = True
    return payload


# --- opaque access token -------------------------------------------------------------


async def _validate_opaque_access_token(
    ctx: Ctx, opts: Any, token: str, client_id: str | None
) -> dict[str, Any]:
    value = token
    prefix = (getattr(opts, "prefix", None) or {}).get("opaqueAccessToken")
    if prefix:
        if value.startswith(prefix):
            value = value[len(prefix) :]
        else:
            raise OAuthError(400, "invalid_request", "opaque access token not found")

    access = await ctx.adapter.find_one(
        "oauthAccessToken",
        [Where("token", await store_token(opts.store_tokens, value, "access_token"))],
    )
    if not access:
        raise OAuthError(400, "invalid_token", "opaque access token not found")
    if not access.get("expiresAt") or access["expiresAt"] < utcnow():
        return dict(_INACTIVE)

    client = None
    if access.get("clientId"):
        client = await get_client(ctx, opts, access["clientId"])
        if not client or client.get("disabled"):
            return dict(_INACTIVE)
        if client_id and access["clientId"] != client_id:
            return dict(_INACTIVE)

    session_id = access.get("sessionId")
    if session_id and not await _session_alive(ctx, session_id):
        session_id = None

    user = None
    if access.get("userId"):
        user = await ctx.adapter.find_one("user", [Where("id", access["userId"])])

    custom = getattr(opts, "custom_access_token_claims", None)
    custom_claims = (
        await _await(
            custom(
                {
                    "user": user,
                    "scopes": access.get("scopes"),
                    "referenceId": access.get("referenceId"),
                    "metadata": parse_client_metadata(client.get("metadata") if client else None),
                }
            )
        )
        if custom
        else {}
    )

    scopes = access.get("scopes")
    return {
        **custom_claims,
        "active": True,
        "iss": _issuer(ctx),
        "client_id": access.get("clientId"),
        "sub": user.get("id") if user else None,
        "sid": session_id,
        "exp": _epoch(access["expiresAt"]),
        "iat": _epoch(access.get("createdAt")),
        "scope": " ".join(scopes) if scopes else None,
    }


# --- refresh token -------------------------------------------------------------------


async def _validate_refresh_token(
    ctx: Ctx, opts: Any, token: str, client_id: str
) -> dict[str, Any]:
    refresh = await ctx.adapter.find_one(
        "oauthRefreshToken",
        [Where("token", await store_token(opts.store_tokens, token, "refresh_token"))],
    )
    if not refresh:
        raise OAuthError(400, "invalid_token", "token not found")
    if not refresh.get("clientId") or refresh["clientId"] != client_id:
        return dict(_INACTIVE)
    if not refresh.get("expiresAt") or refresh["expiresAt"] < utcnow():
        return dict(_INACTIVE)
    if refresh.get("revoked"):
        return dict(_INACTIVE)

    session_id = refresh.get("sessionId")
    if session_id and not await _session_alive(ctx, session_id):
        session_id = None

    user = None
    if refresh.get("userId"):
        user = await ctx.adapter.find_one("user", [Where("id", refresh["userId"])])

    scopes = refresh.get("scopes")
    return {
        "active": True,
        "client_id": client_id,
        "iss": _issuer(ctx),
        "sub": user.get("id") if user else None,
        "sid": session_id,
        "exp": _epoch(refresh["expiresAt"]),
        "iat": _epoch(refresh.get("createdAt")),
        "scope": " ".join(scopes) if scopes else None,
    }


async def validate_access_token(
    ctx: Ctx, opts: Any, token: str, client_id: str | None = None
) -> dict[str, Any]:
    """Try the token as JWT access then opaque access — TS ``validateAccessToken`` (shared with
    userinfo). Raises :class:`OAuthError` when it is neither."""
    try:
        return await _validate_jwt_access_token(ctx, opts, token, client_id)
    except _NotAJwt:
        pass
    try:
        return await _validate_opaque_access_token(ctx, opts, token, client_id)
    except OAuthError:
        pass
    raise OAuthError(400, "invalid_request", "Invalid access token")


# --- pairwise sub at presentation ----------------------------------------------------


def _resolve_introspection_sub(
    opts: Any, payload: dict[str, Any], client: dict[str, Any]
) -> dict[str, Any]:
    if payload.get("active") and payload.get("sub"):
        return {**payload, "sub": resolve_subject_identifier(client, opts, payload["sub"])}
    return payload


# --- endpoint ------------------------------------------------------------------------


async def introspect_endpoint(ctx: Ctx, opts: Any) -> dict[str, Any]:
    from .token import _read_body

    body = _read_body(ctx)
    client_id = body.get("client_id")
    client_secret = body.get("client_secret")
    token = body.get("token")
    token_type_hint = body.get("token_type_hint")

    authorization = ctx.request.headers.get("authorization")
    if authorization and authorization.startswith("Basic "):
        creds = basic_to_client_credentials(authorization)
        if creds:
            client_id = creds["client_id"]
            client_secret = creds["client_secret"]

    if not client_id or not client_secret:
        raise OAuthError(401, "invalid_client", "missing required credentials")

    if token and isinstance(token, str) and token.startswith("Bearer "):
        token = token[len("Bearer ") :]
    if not token:
        raise OAuthError(400, "invalid_request", "missing a required token for introspection")

    client = await validate_client_credentials(ctx, opts, client_id, client_secret)

    try:
        if token_type_hint in (None, "access_token"):
            try:
                payload = await validate_access_token(ctx, opts, token, client["clientId"])
                return _resolve_introspection_sub(opts, payload, client)
            except OAuthError as error:
                if token_type_hint == "access_token":
                    raise
                _pass_through(error)

        if token_type_hint in (None, "refresh_token"):
            try:
                decoded = await decode_refresh_token(opts, token)
                payload = await _validate_refresh_token(
                    ctx, opts, decoded["token"], client["clientId"]
                )
                return _resolve_introspection_sub(opts, payload, client)
            except OAuthError as error:
                if token_type_hint == "refresh_token":
                    raise
                _pass_through(error)

        raise OAuthError(400, "invalid_request", "token not found")
    except OAuthError as error:
        if error.status == 400:
            return dict(_INACTIVE)
        raise


def _pass_through(error: OAuthError) -> None:
    """Continue to the next token type on a swallowable 400; re-raise anything else — TS treats
    a non-``BAD_REQUEST`` APIError as a hard error."""
    if error.status != 400:
        raise error
