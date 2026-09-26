"""POST /oauth2/revoke — RFC 7009 token revocation.

Port of TS ``packages/oauth-provider/src/revoke.ts`` (v1.7.6). Form-urlencoded. The client
authenticates like at the token endpoint (Basic, post, ``private_key_jwt``); the token is tried,
honoring a known ``token_type_hint``, as JWT access (a verified one is ``unsupported_token_type``:
nothing is stored to revoke) -> opaque access (**delete the row**) -> refresh (atomic CAS
``revoked=null -> now`` via ``increment_one``; a loser or an already-revoked token tears down the
whole ``(client, user)`` family per RFC 9700 §4.14, then the access tokens with that
``refreshId`` are deleted). Revocation is idempotent: any other swallowable ``BAD_REQUEST``
collapses to a ``null``/empty 200 (RFC 7009 §2.2).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...adapters.base import Where
from ...session import utcnow
from ...types import Ctx
from .dpop import strip_access_token_authorization_scheme
from .resources import is_audience_claim_allowed, user_info_resource
from .token import (
    authenticate_client,
    decode_refresh_token,
    invalidate_refresh_family,
    validate_client_credentials,
)
from .utils import (
    JwsAccessTokenClaimInvalid,
    JwsAccessTokenExpired,
    JwsAccessTokenInvalid,
    OAuthError,
    get_jwt_plugin,
    resolved_issuer,
    store_token,
    verify_jws_access_token,
)


def _base_url(ctx: Ctx) -> str:
    return f"{ctx.auth.base_url}{ctx.auth.base_path}"


def _issuer(ctx: Ctx, opts: Any) -> str:
    return resolved_issuer(ctx, opts)


async def _revoke_jwt_access_token(ctx: Ctx, opts: Any, token: str) -> None:
    """Verify a JWT access token (signature + issuer, then ``azp`` and audience). A verified one
    is reported as ``unsupported_token_type`` (RFC 7009 §2.2.1): it is self-contained and never
    stored. Expired or foreign-audience JWTs are already inactive: a no-op. TS
    ``revokeJwtAccessToken`` (revoke.ts:46, 3e852a265)."""
    # Disabled mode issues no JWT access tokens and has no JWKS — fall through to opaque.
    if getattr(opts, "disable_jwt_plugin", False):
        raise OAuthError(400, "invalid_request", "invalid JWT signature")
    jwt_plugin = get_jwt_plugin(ctx.auth)
    try:
        payload = await verify_jws_access_token(
            jwt_plugin, token, audience=None, issuer=_issuer(ctx, opts)
        )
    except JwsAccessTokenInvalid:
        # Likely an opaque token — fall through to opaque handling.
        raise OAuthError(400, "invalid_request", "invalid JWT signature") from None
    except (JwsAccessTokenExpired, JwsAccessTokenClaimInvalid):
        return None
    if not payload.get("azp") or not await is_audience_claim_allowed(
        ctx, opts, payload.get("aud"), [user_info_resource(ctx)]
    ):
        return None
    raise OAuthError(
        400,
        "unsupported_token_type",
        "JWT access tokens are self-contained and cannot be revoked server-side",
    )


async def _revoke_opaque_access_token(ctx: Ctx, opts: Any, token: str, client_id: str) -> None:
    """Find and delete the opaque access-token row — TS ``revokeOpaqueAccessToken``."""
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
        raise OAuthError(400, "invalid_request", "opaque access token not found")
    if not access.get("clientId") or access["clientId"] != client_id:
        return None

    where = [Where("id", access["id"])] if access.get("id") else [Where("token", access["token"])]
    await ctx.adapter.delete("oauthAccessToken", where)
    return None


async def _revoke_refresh_token(ctx: Ctx, opts: Any, token: str, client_id: str) -> None:
    """CAS-revoke a refresh token + cascade access-token deletion — TS ``revokeRefreshToken``. An
    already-revoked token or a lost CAS tears down the whole ``(client, user)`` family."""
    refresh = await ctx.adapter.find_one(
        "oauthRefreshToken",
        [Where("token", await store_token(opts.store_tokens, token, "refresh_token"))],
    )
    if not refresh:
        raise OAuthError(400, "invalid_request", "token not found")
    if refresh.get("revoked"):
        await invalidate_refresh_family(ctx, client_id, refresh["userId"])
        raise OAuthError(400, "invalid_request", "refresh token revoked")
    if not refresh.get("clientId") or refresh["clientId"] != client_id:
        return None

    revoked_at = datetime.fromtimestamp(int(utcnow().timestamp()), tz=timezone.utc)
    # Atomic compare-and-swap: if a concurrent rotation already revoked (and re-minted) this row,
    # fail closed and tear down the whole family so the rotation's offspring cannot be used either.
    won = await ctx.adapter.increment_one(
        "oauthRefreshToken",
        [Where("id", refresh["id"]), Where("revoked", None, operator="eq")],
        set={"revoked": revoked_at},
    )
    if not won:
        await invalidate_refresh_family(ctx, client_id, refresh["userId"])
        raise OAuthError(400, "invalid_request", "refresh token revoked")
    await ctx.adapter.delete_many("oauthAccessToken", [Where("refreshId", refresh["id"])])
    return None


async def _revoke_access_token(ctx: Ctx, opts: Any, client_id: str, token: str) -> None:
    """Try the token as JWT access, then opaque access — TS ``revokeAccessToken``."""
    try:
        return await _revoke_jwt_access_token(ctx, opts, token)
    except OAuthError as error:
        if error.error == "unsupported_token_type":
            raise  # a confirmed JWT access token cannot be revoked
        # otherwise not a JWT, continue to opaque
    try:
        return await _revoke_opaque_access_token(ctx, opts, token, client_id)
    except OAuthError:
        pass
    raise OAuthError(400, "invalid_request", "Invalid access token")


async def revoke_endpoint(ctx: Ctx, opts: Any) -> None:
    from .token import _read_body

    body = _read_body(ctx)
    token = body.get("token")
    if token is None:  # body schema (oauth.ts:1212) -> RFC envelope
        raise OAuthError(400, "invalid_request", "token is required")
    token_type_hint = body.get("token_type_hint")
    # RFC 7009 §2.2.1: unknown hints are ignored and every token type is searched.
    if token_type_hint not in ("access_token", "refresh_token"):
        token_type_hint = None

    creds = await authenticate_client(ctx, opts, body, "/oauth2/revoke")
    if not creds["client_id"]:
        raise OAuthError(401, "invalid_client", "missing required credentials")

    if isinstance(token, str):
        token = strip_access_token_authorization_scheme(token)
    if not token:
        # TS revoke.ts:333 reuses the introspection wording.
        raise OAuthError(400, "invalid_request", "missing a required token for introspection")

    # A wrong/missing secret raises here (outside the swallow) — a hard error, not idempotent.
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
                return await _revoke_access_token(ctx, opts, client["clientId"], token)
            except OAuthError as error:
                if token_type_hint == "access_token" or error.error == "unsupported_token_type":
                    raise
                # else continue to refresh handling

        if token_type_hint in (None, "refresh_token"):
            try:
                decoded = await decode_refresh_token(opts, token)
                return await _revoke_refresh_token(ctx, opts, decoded["token"], client["clientId"])
            except OAuthError:
                if token_type_hint == "refresh_token":
                    raise

        raise OAuthError(400, "invalid_request", "token not found")
    except OAuthError as error:
        # RFC 7009 §2.2.1: unsupported_token_type surfaces; any other client error collapses to
        # an idempotent empty 200 (§2.2).
        if error.error == "unsupported_token_type":
            raise
        if error.status == 400:
            return None
        raise
