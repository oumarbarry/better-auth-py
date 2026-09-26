"""POST /oauth2/introspect — RFC 7662 token introspection.

Port of TS ``packages/oauth-provider/src/introspect.ts`` (v1.7.6). Requires client
authentication (Basic, post, or ``private_key_jwt``). Tries the token, honoring a known
``token_type_hint``, as JWT access -> opaque access -> refresh, returning the RFC 7662 shape
(``{active, scope, client_id, sub, sid, exp, iat, iss, token_type, ...}``) or ``{active: false}``.
Security gates: a JWT access token MUST carry an ``azp`` matching an enabled client (a plain
jwt-plugin session token is rejected: token-type confusion), every ``aud`` value must name an
``oauthResource`` row (deleting the row revokes its tokens), an access token dies with its
session, only the issuing client or a resource server linked to the token's audience may
introspect (2fd3d5850), a DPoP binding is reported as ``cnf`` with ``token_type: DPoP``, and
pairwise ``sub`` is resolved against the issuing client at the presentation layer.
"""

from __future__ import annotations

import inspect
import math
from typing import Any

from ...adapters.base import Where
from ...session import utcnow
from ...types import AuthResponse, Ctx
from .claims import resolve_access_token_claims
from .client_crud import get_client
from .dpop import strip_access_token_authorization_scheme
from .resources import (
    get_resource_custom_claims,
    is_audience_claim_allowed,
    is_client_linked_to_any_resource,
    to_audience_claim,
    user_info_resource,
)
from .token import (
    NO_STORE_HEADERS,
    authenticate_client,
    confirmation_token_type,
    decode_refresh_token,
    no_store,
    validate_client_credentials,
)
from .utils import (
    JwsAccessTokenClaimInvalid,
    JwsAccessTokenExpired,
    JwsAccessTokenInvalid,
    OAuthError,
    get_jwt_plugin,
    parse_client_metadata,
    resolve_subject_identifier,
    resolved_issuer,
    store_token,
    verify_jws_access_token,
)

_INVALID_ACCESS_TOKEN = "Invalid access token"

_INACTIVE = {"active": False}


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _base_url(ctx: Ctx) -> str:
    return f"{ctx.auth.base_url}{ctx.auth.base_path}"


def _issuer(ctx: Ctx, opts: Any) -> str:
    return resolved_issuer(ctx, opts)


def _epoch(dt: Any) -> int | None:
    if dt is None:
        return None
    return math.floor(dt.timestamp())


async def _session_alive(ctx: Ctx, session_id: str | None) -> bool:
    if not session_id:
        return False
    session = await ctx.adapter.find_one("session", [Where("id", session_id)])
    return bool(session and session["expiresAt"] >= utcnow())


# --- introspection authorization (introspect.ts:66-110) -------------------------------


def _audience_resources(aud: Any, userinfo_aud: str) -> list[str]:
    """TS ``audienceResourceIdentifiers``: resource audiences minus the implicit UserInfo one."""
    if aud is None:
        return []
    values = aud if isinstance(aud, list) else [aud]
    return [v for v in values if isinstance(v, str) and v != userinfo_aud]


async def _introspection_authorized(
    ctx: Ctx,
    introspecting_client_id: str | None,
    issuer_client_id: str | None,
    audience_resources: list[str],
) -> bool:
    """TS ``isIntrospectionAuthorized`` (RFC 7662 §2.1/§4): the issuing client, or a resource
    server linked to one of the token's audience resources."""
    if not introspecting_client_id or introspecting_client_id == issuer_client_id:
        return True
    if not audience_resources:
        return False
    return await is_client_linked_to_any_resource(ctx, introspecting_client_id, audience_resources)


# --- JWT access token (introspect.ts:116) --------------------------------------------


class _NotAJwt(Exception):
    """Signals validate_access_token to fall through to opaque handling."""


async def _validate_jwt_access_token(
    ctx: Ctx, opts: Any, token: str, client_id: str | None
) -> dict[str, Any]:
    # Disabled mode issues no JWT access tokens (opaque only) and installs no JWKS to verify
    # against, so skip straight to opaque handling — TS introspect.ts:44 (jwtPlugin undefined).
    if getattr(opts, "disable_jwt_plugin", False):
        raise _NotAJwt() from None
    jwt_plugin = get_jwt_plugin(ctx.auth)
    try:
        # Signature + issuer here; ``aud`` is checked against the resource model below.
        payload = await verify_jws_access_token(
            jwt_plugin, token, audience=None, issuer=_issuer(ctx, opts)
        )
    except (JwsAccessTokenExpired, JwsAccessTokenClaimInvalid):
        return dict(_INACTIVE)
    except JwsAccessTokenInvalid:
        raise _NotAJwt() from None

    # Every aud value must resolve to a resource row or the UserInfo audience; a deleted
    # resource revokes its tokens (introspect.ts:189).
    userinfo_aud = user_info_resource(ctx)
    if not await is_audience_claim_allowed(ctx, opts, payload.get("aud"), [userinfo_aud]):
        return dict(_INACTIVE)
    # A provider-issued access token always carries `azp`; a plain jwt-plugin session token
    # (same keys/issuer/audience) does not, so require it plus a matching enabled client.
    azp = payload.get("azp")
    if not azp:
        return dict(_INACTIVE)
    client = await get_client(ctx, opts, azp)
    if not client or client.get("disabled"):
        return dict(_INACTIVE)
    if not await _introspection_authorized(
        ctx, client_id, azp, _audience_resources(payload.get("aud"), userinfo_aud)
    ):
        return dict(_INACTIVE)
    # A session-bound JWT dies with its session (introspect.ts:226).
    if payload.get("sid") and not await _session_alive(ctx, payload.get("sid")):
        return dict(_INACTIVE)

    payload["client_id"] = azp
    payload["active"] = True
    payload["token_type"] = confirmation_token_type(payload.get("cnf"))
    return payload


# --- opaque access token (introspect.ts:258) -----------------------------------------


async def _validate_opaque_access_token(
    ctx: Ctx, opts: Any, token: str, client_id: str | None
) -> tuple[dict[str, Any], list[str]]:
    """Returns the introspection payload and the persisted ``claims.userinfo`` names."""
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
        return dict(_INACTIVE), []
    if access.get("revoked"):
        return dict(_INACTIVE), []

    resources = access.get("resources") if isinstance(access.get("resources"), list) else None

    client = None
    if access.get("clientId"):
        client = await get_client(ctx, opts, access["clientId"])
        if not client or client.get("disabled"):
            return dict(_INACTIVE), []
        if not await _introspection_authorized(ctx, client_id, access["clientId"], resources or []):
            return dict(_INACTIVE), []

    # An opaque token bound to a session dies with it (introspect.ts:325).
    session_id = access.get("sessionId")
    if session_id and not await _session_alive(ctx, session_id):
        return dict(_INACTIVE), []

    user = None
    if access.get("userId"):
        user = await ctx.adapter.find_one("user", [Where("id", access["userId"])])
    userinfo_aud = user_info_resource(ctx)

    # Deleting a resource row revokes the tokens bound to it (introspect.ts:351).
    if resources and not await is_audience_claim_allowed(ctx, opts, resources, [userinfo_aud]):
        return dict(_INACTIVE), []

    scopes = access.get("scopes") or []
    audience = list(resources) if resources is not None else None
    if audience and "openid" in scopes and userinfo_aud not in audience:
        audience.append(userinfo_aud)

    # Re-derive the enriched claims through the JWT mint's authority (introspect.ts:376).
    access_token_claims = (
        await resolve_access_token_claims(
            ctx,
            opts,
            user=user,
            scopes=scopes,
            resources=resources,
            reference_id=access.get("referenceId"),
            metadata=parse_client_metadata(client.get("metadata")),
            resource_policy_claims=(
                await get_resource_custom_claims(ctx, resources) if resources else {}
            ),
        )
        if client
        else {}
    )
    confirmation = access.get("confirmation")
    payload = {
        **access_token_claims,
        "active": True,
        "iss": _issuer(ctx, opts),
        "aud": to_audience_claim(audience),
        "client_id": access.get("clientId"),
        "azp": access.get("clientId"),
        "sub": user.get("id") if user else None,
        "sid": session_id,
        "exp": _epoch(access["expiresAt"]),
        "iat": _epoch(access.get("createdAt")),
        "scope": " ".join(scopes) if access.get("scopes") else None,
        "token_type": confirmation_token_type(confirmation),
        **({"cnf": confirmation} if confirmation else {}),
    }
    return payload, list(access.get("requestedUserInfoClaims") or [])


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
        "iss": _issuer(ctx, opts),
        "sub": user.get("id") if user else None,
        "sid": session_id,
        "exp": _epoch(refresh["expiresAt"]),
        "iat": _epoch(refresh.get("createdAt")),
        "scope": " ".join(scopes) if scopes else None,
        "token_type": confirmation_token_type(refresh.get("confirmation")),
        **({"cnf": refresh["confirmation"]} if refresh.get("confirmation") else {}),
    }


async def resolve_access_token_validation(
    ctx: Ctx, opts: Any, token: str, client_id: str | None = None
) -> tuple[dict[str, Any], list[str]]:
    """Try the token as JWT access then opaque access, TS ``resolveAccessTokenValidation``
    (introspect.ts:540). Returns the payload and the opaque row's ``claims.userinfo`` names
    (empty for a JWT). Neither: a 401 ``invalid_token`` Bearer challenge."""
    try:
        return await _validate_jwt_access_token(ctx, opts, token, client_id), []
    except _NotAJwt:
        pass
    try:
        return await _validate_opaque_access_token(ctx, opts, token, client_id)
    except OAuthError:
        pass
    raise invalid_access_token_error()


async def validate_access_token(
    ctx: Ctx, opts: Any, token: str, client_id: str | None = None
) -> dict[str, Any]:
    """TS ``validateAccessToken``: the RFC 7662 payload only."""
    return (await resolve_access_token_validation(ctx, opts, token, client_id))[0]


async def require_active_access_token_with_claims(
    ctx: Ctx, opts: Any, token: str, client_id: str | None = None
) -> tuple[dict[str, Any], list[str]]:
    """TS ``requireActiveAccessTokenWithClaims`` (introspect.ts:604), the UserInfo entry."""
    payload, claims = await resolve_access_token_validation(ctx, opts, token, client_id)
    if payload.get("active"):
        return payload, claims
    raise invalid_access_token_error()


def invalid_access_token_error() -> OAuthError:
    """TS ``createInvalidAccessTokenError`` (introspect.ts:514): 401 with a Bearer challenge."""
    return OAuthError(
        401,
        "invalid_token",
        _INVALID_ACCESS_TOKEN,
        headers=[
            (
                "WWW-Authenticate",
                f'Bearer error="invalid_token", error_description="{_INVALID_ACCESS_TOKEN}"',
            )
        ],
    )


# --- pairwise sub at presentation ----------------------------------------------------


async def _resolve_introspection_sub(
    ctx: Ctx, opts: Any, payload: dict[str, Any], client: dict[str, Any]
) -> dict[str, Any]:
    """Pairwise ``sub`` scoped to the TOKEN's client (its sector), not the caller, TS
    ``resolveIntrospectionSub`` (introspect.ts:629)."""
    if not payload.get("active") or not payload.get("sub"):
        return payload
    issuer_id = payload.get("client_id") or payload.get("azp")
    if not issuer_id:
        return payload
    issuing = client if issuer_id == client["clientId"] else await get_client(ctx, opts, issuer_id)
    if not issuing:
        return payload
    return {**payload, "sub": resolve_subject_identifier(issuing, opts, payload["sub"])}


# --- endpoint ------------------------------------------------------------------------


async def introspect_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    """POST /oauth2/introspect. Handler responses and errors carry no-store headers."""
    from .token import _read_body

    body = _read_body(ctx)
    if body.get("token") is None:  # body schema (oauth.ts:1071) -> RFC envelope
        raise OAuthError(400, "invalid_request", "token is required")
    try:
        payload = await _introspect(ctx, opts, body)
    except OAuthError as error:
        raise no_store(error) from None
    return AuthResponse(body=payload, headers=list(NO_STORE_HEADERS))


async def _introspect(ctx: Ctx, opts: Any, body: dict[str, Any]) -> dict[str, Any]:
    token = body.get("token")
    token_type_hint = body.get("token_type_hint")
    # RFC 7662 §2.1: unknown hints are ignored; detection tries both token types.
    if token_type_hint not in ("access_token", "refresh_token"):
        token_type_hint = None

    creds = await authenticate_client(ctx, opts, body, "/oauth2/introspect")
    if not creds["client_id"] or (not creds["client_secret"] and not creds["pre_verified"]):
        raise OAuthError(401, "invalid_client", "missing required credentials")

    if token and isinstance(token, str):
        token = strip_access_token_authorization_scheme(token)
    if not token:
        raise OAuthError(400, "invalid_request", "missing a required token for introspection")

    client = await validate_client_credentials(
        ctx,
        opts,
        creds["client_id"],
        creds["client_secret"],
        pre_verified=creds["pre_verified"],
        auth_method=creds["auth_method"],
    )

    try:
        if token_type_hint in (None, "access_token"):
            try:
                payload = await validate_access_token(ctx, opts, token, client["clientId"])
                return await _resolve_introspection_sub(ctx, opts, payload, client)
            except OAuthError:
                if token_type_hint == "access_token":
                    raise

        if token_type_hint in (None, "refresh_token"):
            try:
                decoded = await decode_refresh_token(opts, token)
                payload = await _validate_refresh_token(
                    ctx, opts, decoded["token"], client["clientId"]
                )
                return await _resolve_introspection_sub(ctx, opts, payload, client)
            except OAuthError:
                if token_type_hint == "refresh_token":
                    raise

        raise OAuthError(400, "invalid_request", "token not found")
    except OAuthError as error:
        # TS isInactiveTokenError: a 400 or an invalid_token error reads as inactive.
        if error.status == 400 or error.error == "invalid_token":
            return dict(_INACTIVE)
        raise
