"""POST /oauth2/token — the three grants, token minting, and refresh rotation.

Port of TS ``packages/oauth-provider/src/token.ts`` (v1.6.23). Form-urlencoded only. Handles
``authorization_code`` (single-use code redemption + PKCE consistency), ``client_credentials``
(M2M, OIDC-scope rejection), and ``refresh_token`` (rotation via a ``revoked=null`` CAS +
RFC 9700 §4.14 family teardown on replay). Access tokens are JWT when a validated ``resource``
audience is present (signed on the jwt plugin's EdDSA keys), otherwise opaque and stored hashed;
id tokens carry pinned OIDC claims that custom claims can never override.

The JWT-disabled / HS256 path is not ported (rejected at plugin init) — EdDSA-first.
"""

from __future__ import annotations

import inspect
import math
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl

from ...adapters.base import Where
from ...crypto import generate_random_string
from ...session import utcnow
from ...types import Ctx
from ..jwt import to_exp_jwt
from .client_crud import get_client
from .utils import (
    OAuthError,
    basic_to_client_credentials,
    client_allows_grant,
    get_jwt_plugin,
    is_pkce_required,
    normalize_timestamp_value,
    parse_client_metadata,
    resolve_subject_identifier,
    store_token,
    verify_client_secret,
)

#: TS ``generateRandomString(32, "A-Z", "a-z")`` — opaque access / refresh token charset.
_TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

_ACR_BRONZE = "urn:mace:incommon:iap:bronze"


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _now_s() -> int:
    return int(utcnow().timestamp())


def _base_url(ctx: Ctx) -> str:
    return f"{ctx.auth.base_url}{ctx.auth.base_path}"


def _token_issuer(ctx: Ctx) -> str:
    """id_token / access-token ``iss`` — TS ``jwtPluginOptions?.jwt?.issuer ?? ctx.context.baseURL``
    (unvalidated, unlike the discovery issuer)."""
    jwt_plugin = get_jwt_plugin(ctx.auth)
    return getattr(jwt_plugin, "issuer", None) or _base_url(ctx)


def _read_body(ctx: Ctx) -> dict[str, Any]:
    """Form-urlencoded body (the only allowed media type), falling back to JSON for callers
    that send JSON (test/convenience). Mirrors TS content-type body parsing."""
    request = ctx.request
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype == "application/x-www-form-urlencoded":
        return dict(parse_qsl(request.body.decode("utf-8", "replace")))
    try:
        return ctx.body()
    except Exception:
        return {}


def _strip_none(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop ``None`` values — TS relies on ``JSON.stringify`` omitting ``undefined`` claims."""
    return {k: v for k, v in payload.items() if v is not None}


# --- client credential validation (utils/index.ts:450) -------------------------------


async def validate_client_credentials(
    ctx: Ctx,
    opts: Any,
    client_id: str,
    client_secret: str | None = None,
    scopes: list[str] | None = None,
    grant_type: str | None = None,
) -> dict[str, Any]:
    """Validate a client + optional secret + scope subset + grant allowance — TS
    ``validateClientCredentials``. Raises OAuth-shaped errors on any mismatch."""
    client = await get_client(ctx, opts, client_id)
    if not client:
        raise OAuthError(400, "invalid_client", "missing client")
    if client.get("disabled"):
        raise OAuthError(400, "invalid_client", "client is disabled")
    if not client.get("public") and not client_secret:
        raise OAuthError(400, "invalid_client", "client secret must be provided")
    if client_secret and not client.get("clientSecret"):
        raise OAuthError(
            400, "invalid_client", "public client, client secret should not be received"
        )
    if client_secret and not await verify_client_secret(
        opts, client["clientSecret"], client_secret
    ):
        raise OAuthError(401, "invalid_client", "invalid client_secret")
    if scopes and client.get("scopes"):
        valid = set(client["scopes"])
        for sc in scopes:
            if sc not in valid:
                raise OAuthError(400, "invalid_scope", f"client does not allow scope {sc}")
    if grant_type and not client_allows_grant(client, grant_type):
        raise OAuthError(
            400, "unauthorized_client", f"client is not authorized to use grant type {grant_type}"
        )
    return client


# --- shared OIDC/user claims (userinfo.ts:13) ----------------------------------------


def user_normal_claims(user: dict[str, Any], scopes: list[str]) -> dict[str, Any]:
    """OIDC normal claims for the id_token / userinfo — TS ``userNormalClaims`` (``sub`` plus
    profile/email claim groups). ``None`` values are dropped downstream."""
    name = [v for v in (user.get("name") or "").split(" ") if v]
    claims: dict[str, Any] = {"sub": user.get("id")}
    if "profile" in scopes:
        claims["name"] = user.get("name")
        claims["picture"] = user.get("image")
        claims["given_name"] = " ".join(name[:-1]) if len(name) > 1 else None
        claims["family_name"] = name[-1] if len(name) > 1 else None
    if "email" in scopes:
        claims["email"] = user.get("email")
        claims["email_verified"] = user.get("emailVerified") or False
    return claims


# --- refresh token encode/decode (prefix + formatRefreshToken hooks) ------------------


async def encode_refresh_token(opts: Any, tok: str, session_id: str | None = None) -> str:
    prefix = (getattr(opts, "prefix", None) or {}).get("refreshToken", "")
    fmt = getattr(opts, "format_refresh_token", None)
    if fmt and fmt.get("encrypt"):
        tok = await _await(fmt["encrypt"](tok, session_id))
    return prefix + tok


async def decode_refresh_token(opts: Any, tok: str) -> dict[str, Any]:
    prefix = (getattr(opts, "prefix", None) or {}).get("refreshToken")
    if prefix:
        if tok.startswith(prefix):
            tok = tok[len(prefix) :]
        else:
            raise OAuthError(400, "invalid_token", "refresh token not found")
    fmt = getattr(opts, "format_refresh_token", None)
    if fmt and fmt.get("decrypt"):
        return await _await(fmt["decrypt"](tok))
    return {"token": tok}


# --- token minters -------------------------------------------------------------------


async def _create_jwt_access_token(
    ctx: Ctx,
    opts: Any,
    body: dict[str, Any],
    user: dict[str, Any] | None,
    client: dict[str, Any],
    audience: str | list[str],
    scopes: list[str],
    reference_id: str | None,
    iat: int,
    exp: int,
    sid: str | None,
) -> str:
    """Signed EdDSA JWT access token — TS ``createJwtAccessToken``. ``sub`` stays the real
    user id (never pairwise); ``azp`` binds the token to its client."""
    custom = getattr(opts, "custom_access_token_claims", None)
    custom_claims = (
        await _await(
            custom(
                {
                    "user": user,
                    "scopes": scopes,
                    "resource": body.get("resource"),
                    "referenceId": reference_id,
                    "metadata": parse_client_metadata(client.get("metadata")),
                }
            )
        )
        if custom
        else {}
    )
    aud = audience[0] if isinstance(audience, list) and len(audience) == 1 else audience
    payload = _strip_none(
        {
            **custom_claims,
            "sub": user.get("id") if user else None,
            "aud": aud,
            "azp": client.get("clientId"),
            "scope": " ".join(scopes),
            "sid": sid,
            "iss": _token_issuer(ctx),
            "iat": iat,
            "exp": exp,
        }
    )
    jwt_plugin = get_jwt_plugin(ctx.auth)
    return await jwt_plugin.sign_jwt(payload=payload)


async def _create_opaque_access_token(
    ctx: Ctx,
    opts: Any,
    user: dict[str, Any] | None,
    client: dict[str, Any],
    scopes: list[str],
    iat: int,
    exp: int,
    sid: str | None,
    reference_id: str | None,
    refresh_id: str | None,
) -> str:
    """Opaque access token stored hashed in ``oauthAccessToken`` — TS ``createOpaqueAccessToken``."""  # noqa: E501
    gen = getattr(opts, "generate_opaque_access_token", None)
    tok = await _await(gen()) if gen else generate_random_string(32, _TOKEN_ALPHABET)
    await ctx.adapter.create(
        "oauthAccessToken",
        {
            "token": await store_token(opts.store_tokens, tok, "access_token"),
            "clientId": client.get("clientId"),
            "sessionId": sid,
            "userId": user.get("id") if user else None,
            "referenceId": reference_id,
            "refreshId": refresh_id,
            "scopes": scopes,
            "createdAt": datetime.fromtimestamp(iat, tz=timezone.utc),
            "expiresAt": datetime.fromtimestamp(exp, tz=timezone.utc),
        },
    )
    prefix = (getattr(opts, "prefix", None) or {}).get("opaqueAccessToken", "")
    return prefix + tok


async def _create_id_token(
    ctx: Ctx,
    opts: Any,
    user: dict[str, Any],
    client: dict[str, Any],
    scopes: list[str],
    nonce: str | None,
    session_id: str | None,
    auth_time: datetime | None,
) -> str:
    """OIDC id_token — TS ``createIdToken``. Custom claims may override ``acr``/``auth_time`` and
    user claims, but the pinned security claims (iss/sub/aud/nonce/iat/exp/sid) always win."""
    iat = _now_s()
    exp = iat + (getattr(opts, "id_token_expires_in", None) or 36000)
    user_claims = user_normal_claims(user, scopes)
    resolved_sub = resolve_subject_identifier(client, opts, user["id"])
    auth_time_sec = math.floor(auth_time.timestamp()) if auth_time is not None else None

    custom = getattr(opts, "custom_id_token_claims", None)
    custom_claims = (
        await _await(
            custom(
                {
                    "user": user,
                    "scopes": scopes,
                    "metadata": parse_client_metadata(client.get("metadata")),
                }
            )
        )
        if custom
        else {}
    )

    payload: dict[str, Any] = {
        **user_claims,
        "auth_time": auth_time_sec,
        "acr": _ACR_BRONZE,
        **custom_claims,
    }
    # Pinned claims override any custom-supplied value.
    payload["iss"] = _token_issuer(ctx)
    payload["sub"] = resolved_sub
    payload["aud"] = client.get("clientId")
    payload["nonce"] = nonce
    payload["iat"] = iat
    payload["exp"] = exp
    payload["sid"] = session_id if client.get("enableEndSession") else None

    jwt_plugin = get_jwt_plugin(ctx.auth)
    return await jwt_plugin.sign_jwt(payload=_strip_none(payload))


# --- refresh family teardown (RFC 9700 §4.14) ----------------------------------------


async def invalidate_refresh_family(ctx: Ctx, client_id: str, user_id: str) -> None:
    """Tear down the whole ``(client, user)`` refresh family plus the access tokens that
    reference those rows — TS ``invalidateRefreshFamily``. Access tokens are deleted first so
    their FK parents can be removed.

    ponytail: the two deletes are not a single transaction, matching TS
    ``TODO(invalidate-family-race)``; a concurrent rotation between them can re-seed the family.
    Close it with a transactional mint chain when the adapter contract exposes one."""
    refresh_rows = await ctx.adapter.find_many(
        "oauthRefreshToken",
        [Where("clientId", client_id), Where("userId", user_id)],
    )
    if refresh_rows:
        await ctx.adapter.delete_many(
            "oauthAccessToken",
            [Where("refreshId", [r["id"] for r in refresh_rows], operator="in")],
        )
    await ctx.adapter.delete_many(
        "oauthRefreshToken",
        [Where("clientId", client_id), Where("userId", user_id)],
    )


async def _create_refresh_token(
    ctx: Ctx,
    opts: Any,
    user: dict[str, Any],
    reference_id: str | None,
    client: dict[str, Any],
    scopes: list[str],
    iat: int,
    session_id: str | None,
    original_refresh: dict[str, Any] | None,
    auth_time: datetime | None,
) -> dict[str, Any]:
    """Mint a refresh row. Initial issuance is a single insert; rotation is an atomic CAS on the
    parent's ``revoked=null`` guard (loser -> ``invalid_grant``) followed by a fresh insert — TS
    ``createRefreshToken``."""
    exp = iat + (getattr(opts, "refresh_token_expires_in", None) or 2592000)
    gen = getattr(opts, "generate_refresh_token", None)
    tok = await _await(gen()) if gen else generate_random_string(32, _TOKEN_ALPHABET)
    new_row = {
        "token": await store_token(opts.store_tokens, tok, "refresh_token"),
        "clientId": client.get("clientId"),
        "sessionId": session_id,
        "userId": user["id"],
        "referenceId": reference_id,
        "authTime": auth_time,
        "scopes": scopes,
        "createdAt": datetime.fromtimestamp(iat, tz=timezone.utc),
        "expiresAt": datetime.fromtimestamp(exp, tz=timezone.utc),
    }

    if not (original_refresh and original_refresh.get("id")):
        created = await ctx.adapter.create("oauthRefreshToken", new_row)
        return {"id": created["id"], "token": await encode_refresh_token(opts, tok, session_id)}

    # Rotation: atomic compare-and-swap on revoked=null. Concurrent rotations both observed the
    # parent unrevoked at the grant-side read; only one wins this update, the loser fails closed.
    won = await ctx.adapter.increment_one(
        "oauthRefreshToken",
        [Where("id", original_refresh["id"]), Where("revoked", None, operator="eq")],
        set={"revoked": datetime.fromtimestamp(iat, tz=timezone.utc)},
    )
    if not won:
        raise OAuthError(400, "invalid_grant", "invalid refresh token")

    created = await ctx.adapter.create("oauthRefreshToken", new_row)
    return {"id": created["id"], "token": await encode_refresh_token(opts, tok, session_id)}


async def _check_resource(ctx: Ctx, opts: Any, body: dict[str, Any], scopes: list[str]):
    """Resolve + validate the requested ``resource`` audience against ``validAudiences`` — TS
    ``checkResource``. Returns the audience (str / list) or ``None`` when no resource requested."""
    resource = body.get("resource")
    if resource is None:
        return None
    audience = [resource] if isinstance(resource, str) else list(resource)
    base = _base_url(ctx)
    if "openid" in scopes:
        audience.append(f"{base}/oauth2/userinfo")
    valid = set(getattr(opts, "valid_audiences", None) or [base])
    if "openid" in scopes:
        valid.add(f"{base}/oauth2/userinfo")
    for aud in audience:
        if aud not in valid:
            raise OAuthError(400, "invalid_request", "requested resource invalid")
    return audience[0] if len(audience) == 1 else audience


async def create_user_tokens(
    ctx: Ctx,
    opts: Any,
    *,
    body: dict[str, Any],
    client: dict[str, Any],
    scopes: list[str],
    grant_type: str,
    user: dict[str, Any] | None = None,
    reference_id: str | None = None,
    session_id: str | None = None,
    nonce: str | None = None,
    refresh_token: dict[str, Any] | None = None,
    auth_time: datetime | None = None,
    verification_value: dict[str, Any] | None = None,
):
    """Assemble the token response — TS ``createUserTokens``. JWT access when an audience is
    present else opaque; refresh only when the client may use it and ``offline_access`` is
    granted; id_token only for a user with ``openid`` scope."""
    iat = _now_s()
    base_expiry = (
        (getattr(opts, "access_token_expires_in", None) or 3600)
        if user
        else (getattr(opts, "m2m_access_token_expires_in", None) or 3600)
    )
    default_exp = iat + base_expiry
    exp = default_exp
    scope_expirations = getattr(opts, "scope_expirations", None)
    if scope_expirations:
        for sc in scopes:
            cand = (
                to_exp_jwt(scope_expirations[sc], iat)
                if sc in scope_expirations
                else default_exp
            )
            exp = min(exp, cand)
    exp = int(exp)

    audience = await _check_resource(ctx, opts, body, scopes)

    is_refresh_token = bool(
        user
        and client_allows_grant(client, "refresh_token")
        and (
            (refresh_token and "offline_access" in (refresh_token.get("scopes") or []))
            or "offline_access" in scopes
        )
    )
    is_jwt_access_token = audience is not None  # disable_jwt_plugin rejected at init
    is_id_token = bool(user and "openid" in scopes)

    custom_fields_fn = getattr(opts, "custom_token_response_fields", None)
    custom_fields = (
        await _await(
            custom_fields_fn(
                {
                    "grantType": grant_type,
                    "user": user,
                    "scopes": scopes,
                    "metadata": parse_client_metadata(client.get("metadata")),
                    "verificationValue": verification_value,
                }
            )
        )
        if custom_fields_fn
        else {}
    ) or {}

    # An opaque access token references the refresh row's id, so mint the refresh first in that
    # case; the JWT path stores nothing and needs no back-reference.
    early_refresh = None
    if is_refresh_token and user and not is_jwt_access_token:
        early_refresh = await _create_refresh_token(
            ctx, opts, user, reference_id, client, scopes, iat, session_id, refresh_token, auth_time
        )

    if is_jwt_access_token:
        access_token = await _create_jwt_access_token(
            ctx, opts, body, user, client, audience, scopes, reference_id, iat, exp, session_id
        )
    else:
        access_token = await _create_opaque_access_token(
            ctx,
            opts,
            user,
            client,
            scopes,
            iat,
            exp,
            session_id,
            reference_id,
            early_refresh["id"] if early_refresh else None,
        )

    if early_refresh:
        refresh = early_refresh
    elif is_refresh_token and user:
        refresh = await _create_refresh_token(
            ctx, opts, user, reference_id, client, scopes, iat, session_id, refresh_token, auth_time
        )
    else:
        refresh = None

    id_token = (
        await _create_id_token(ctx, opts, user, client, scopes, nonce, session_id, auth_time)
        if is_id_token and user
        else None
    )

    body_out: dict[str, Any] = dict(custom_fields)
    body_out["access_token"] = access_token
    body_out["expires_in"] = exp - iat
    body_out["expires_at"] = exp
    body_out["token_type"] = "Bearer"
    body_out["scope"] = " ".join(scopes)
    if refresh:
        body_out["refresh_token"] = refresh["token"]
    if id_token:
        body_out["id_token"] = id_token

    from ...types import AuthResponse

    return AuthResponse(
        body=body_out,
        headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
    )


# --- authorization_code grant --------------------------------------------------------


async def _check_verification_value(
    ctx: Ctx, opts: Any, code: str, client_id: str, redirect_uri: str | None
) -> dict[str, Any]:
    """Atomic single-use code redemption + verification-value validation — TS
    ``checkVerificationValue``."""
    import json as _json

    verification = await ctx.internal.consume_verification_value(
        await store_token(opts.store_tokens, code, "authorization_code")
    )
    if not verification:
        raise OAuthError(401, "invalid_grant", "invalid code")

    try:
        value = _json.loads(verification["value"])
    except ValueError:
        raise OAuthError(401, "invalid_grant", "malformed verification value") from None
    if not isinstance(value, dict) or not isinstance(value.get("query"), dict):
        raise OAuthError(401, "invalid_grant", "malformed verification value")

    if value["query"].get("client_id") != client_id:
        raise OAuthError(401, "invalid_client", "invalid client_id")
    stored_redirect = value["query"].get("redirect_uri")
    if stored_redirect and stored_redirect != redirect_uri:
        raise OAuthError(400, "invalid_request", "redirect_uri mismatch")
    return value


async def handle_authorization_code_grant(ctx: Ctx, opts: Any, body: dict[str, Any]):
    client_id = body.get("client_id")
    client_secret = body.get("client_secret")
    code = body.get("code")
    code_verifier = body.get("code_verifier")
    redirect_uri = body.get("redirect_uri")

    authorization = ctx.request.headers.get("authorization")
    if authorization and authorization.startswith("Basic "):
        creds = basic_to_client_credentials(authorization)
        if creds:
            client_id = creds["client_id"]
            client_secret = creds["client_secret"]

    if not client_id:
        raise OAuthError(400, "invalid_request", "client_id is required")
    if not code:
        raise OAuthError(400, "invalid_request", "code is required")
    if not redirect_uri:
        raise OAuthError(400, "invalid_request", "redirect_uri is required")

    is_auth_code_with_secret = bool(client_id and client_secret)
    is_auth_code_with_pkce = bool(client_id and code and code_verifier)
    if not is_auth_code_with_secret and not is_auth_code_with_pkce:
        raise OAuthError(
            400, "invalid_request", "Either code_verifier or client_secret is required"
        )

    value = await _check_verification_value(ctx, opts, code, client_id, redirect_uri)
    query = value["query"]
    scope_str = query.get("scope")
    scopes = scope_str.split(" ") if scope_str else None
    if not scopes:
        raise OAuthError(500, "invalid_scope", "verification scope unset")

    client = await validate_client_credentials(
        ctx, opts, client_id, client_secret, scopes, "authorization_code"
    )

    requested_scopes = scope_str.split(" ") if scope_str else []
    pkce_required = is_pkce_required(client, requested_scopes)

    if pkce_required:
        if not is_auth_code_with_pkce:
            raise OAuthError(400, "invalid_request", "PKCE is required for this client")
    elif not (is_auth_code_with_pkce or is_auth_code_with_secret):
        raise OAuthError(
            400,
            "invalid_request",
            "Either PKCE (code_verifier) or client authentication (client_secret) is required",
        )

    pkce_used_in_auth = bool(query.get("code_challenge"))
    pkce_used_in_token = bool(code_verifier)
    if pkce_used_in_auth or pkce_used_in_token:
        if pkce_used_in_auth and not pkce_used_in_token:
            raise OAuthError(
                401,
                "invalid_request",
                "code_verifier required because PKCE was used in authorization",
            )
        if not pkce_used_in_auth and pkce_used_in_token:
            raise OAuthError(
                401,
                "invalid_request",
                "code_verifier provided but PKCE was not used in authorization",
            )
        from ...oauth.machinery import code_challenge as _code_challenge

        challenge = (
            _code_challenge(code_verifier or "")
            if query.get("code_challenge_method") == "S256"
            else None
        )
        if challenge != query.get("code_challenge"):
            raise OAuthError(401, "invalid_request", "code verification failed")

    if not value.get("userId"):
        raise OAuthError(400, "invalid_user", "missing user, user may have been deleted")
    user = await ctx.adapter.find_one("user", [Where("id", value["userId"])])
    if not user:
        raise OAuthError(400, "invalid_user", "missing user, user may have been deleted")

    session = await ctx.adapter.find_one("session", [Where("id", value.get("sessionId"))])
    if not session or session["expiresAt"] < utcnow():
        raise OAuthError(400, "invalid_request", "session no longer exists")

    if value.get("authTime") is not None:
        auth_time = normalize_timestamp_value(value["authTime"])
    else:
        auth_time = normalize_timestamp_value(session.get("createdAt"))

    return await create_user_tokens(
        ctx,
        opts,
        body=body,
        client=client,
        scopes=scopes,
        user=user,
        grant_type="authorization_code",
        reference_id=value.get("referenceId"),
        session_id=session["id"],
        nonce=query.get("nonce"),
        auth_time=auth_time,
        verification_value=value,
    )


# --- client_credentials grant --------------------------------------------------------

_OIDC_SCOPES = {"openid", "profile", "email", "offline_access"}


async def handle_client_credentials_grant(ctx: Ctx, opts: Any, body: dict[str, Any]):
    client_id = body.get("client_id")
    client_secret = body.get("client_secret")
    scope = body.get("scope")

    authorization = ctx.request.headers.get("authorization")
    if authorization and authorization.startswith("Basic "):
        creds = basic_to_client_credentials(authorization)
        if creds:
            client_id = creds["client_id"]
            client_secret = creds["client_secret"]

    if not client_id:
        raise OAuthError(400, "invalid_grant", "Missing required client_id")
    if not client_secret:
        raise OAuthError(400, "invalid_grant", "Missing a required client_secret")

    client = await validate_client_credentials(
        ctx, opts, client_id, client_secret, None, "client_credentials"
    )

    requested_scopes = scope.split(" ") if scope else None
    if requested_scopes:
        valid = set(client.get("scopes") or getattr(opts, "scopes", None) or [])
        invalid = [s for s in requested_scopes if s not in valid or s in _OIDC_SCOPES]
        if invalid:
            raise OAuthError(
                400, "invalid_scope", f"The following scopes are invalid: {', '.join(invalid)}"
            )
    if not requested_scopes:
        requested_scopes = (
            client.get("scopes")
            or getattr(opts, "client_credential_grant_default_scopes", None)
            or getattr(opts, "scopes", None)
            or []
        )

    return await create_user_tokens(
        ctx,
        opts,
        body=body,
        client=client,
        scopes=requested_scopes,
        grant_type="client_credentials",
    )


# --- refresh_token grant -------------------------------------------------------------


async def handle_refresh_token_grant(ctx: Ctx, opts: Any, body: dict[str, Any]):
    client_id = body.get("client_id")
    client_secret = body.get("client_secret")
    refresh_token_value = body.get("refresh_token")
    scope = body.get("scope")

    authorization = ctx.request.headers.get("authorization")
    if authorization and authorization.startswith("Basic "):
        creds = basic_to_client_credentials(authorization)
        if creds:
            client_id = creds["client_id"]
            client_secret = creds["client_secret"]

    if not client_id:
        raise OAuthError(400, "invalid_grant", "Missing required client_id")
    if not refresh_token_value:
        raise OAuthError(
            400, "invalid_grant", "Missing a required refresh_token for refresh_token grant"
        )

    decoded = await decode_refresh_token(opts, refresh_token_value)
    refresh_token = await ctx.adapter.find_one(
        "oauthRefreshToken",
        [Where("token", await store_token(opts.store_tokens, decoded["token"], "refresh_token"))],
    )

    if not refresh_token:
        raise OAuthError(400, "invalid_grant", "session not found")
    if refresh_token["clientId"] != client_id:
        raise OAuthError(400, "invalid_client", "invalid client_id")
    if refresh_token["expiresAt"] < utcnow():
        raise OAuthError(400, "invalid_grant", "invalid refresh token")
    if refresh_token.get("revoked"):
        await invalidate_refresh_family(ctx, client_id, refresh_token["userId"])
        raise OAuthError(400, "invalid_grant", "invalid refresh token")

    scopes = refresh_token.get("scopes")
    requested_scopes = scope.split(" ") if scope else None
    if requested_scopes:
        valid = set(scopes or [])
        for sc in requested_scopes:
            if sc not in valid:
                raise OAuthError(400, "invalid_scope", f"unable to issue scope {sc}")

    client = await validate_client_credentials(
        ctx, opts, client_id, client_secret, requested_scopes or scopes, "refresh_token"
    )

    user = await ctx.adapter.find_one("user", [Where("id", refresh_token["userId"])])
    if not user:
        raise OAuthError(400, "invalid_request", "user not found")

    auth_time = (
        normalize_timestamp_value(refresh_token["authTime"])
        if refresh_token.get("authTime") is not None
        else None
    )

    return await create_user_tokens(
        ctx,
        opts,
        body=body,
        client=client,
        scopes=requested_scopes or scopes,
        user=user,
        grant_type="refresh_token",
        reference_id=refresh_token.get("referenceId"),
        session_id=refresh_token.get("sessionId"),
        refresh_token=refresh_token,
        auth_time=auth_time,
    )


# --- endpoint ------------------------------------------------------------------------


async def token_endpoint(ctx: Ctx, opts: Any):
    """POST /oauth2/token — dispatch by ``grant_type`` (TS ``tokenEndpoint``)."""
    body = _read_body(ctx)
    grant_type = body.get("grant_type")

    allowed = getattr(opts, "grant_types", None)
    if allowed and grant_type and grant_type not in allowed:
        raise OAuthError(400, "unsupported_grant_type", f"unsupported grant_type {grant_type}")

    if grant_type == "authorization_code":
        return await handle_authorization_code_grant(ctx, opts, body)
    if grant_type == "client_credentials":
        return await handle_client_credentials_grant(ctx, opts, body)
    if grant_type == "refresh_token":
        return await handle_refresh_token_grant(ctx, opts, body)
    if grant_type is None:
        raise OAuthError(400, "unsupported_grant_type", "missing required grant_type")
    raise OAuthError(400, "unsupported_grant_type", f"unsupported grant_type {grant_type}")
