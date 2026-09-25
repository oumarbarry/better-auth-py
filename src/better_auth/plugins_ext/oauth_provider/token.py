"""POST /oauth2/token — the three grants, token minting, and refresh rotation.

Port of TS ``packages/oauth-provider/src/token.ts`` (v1.7.6). Form-urlencoded only. Clients
authenticate with ``client_secret_basic``, ``client_secret_post``, ``private_key_jwt`` or as a
public client, and must use the method they registered. Handles ``authorization_code``
(single-use code redemption; a replayed code revokes the tokens already issued for it),
``client_credentials`` (machine scopes from ``clientCredentialsScopes``), and ``refresh_token``
(rotation via a ``revoked=null`` CAS, an optional reuse window that replays the stored response,
and RFC 9700 §4.14 family teardown on replay). Access tokens are ``at+jwt`` JWTs when a validated
``resource`` audience is present (signed on the jwt plugin's keys), otherwise opaque and stored
hashed; id tokens carry pinned OIDC claims plus ``at_hash``.

When ``disable_jwt_plugin`` is set, access tokens are always opaque and id tokens are HS256-signed
with the client's decrypted secret (TS token.ts:180); public clients without a secret get none.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import logging
import math
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl

import jwt as pyjwt

from ...adapters.base import Where
from ...crypto import generate_random_string, symmetric_decrypt, symmetric_encrypt
from ...session import utcnow
from ...types import AuthResponse, Ctx
from ..jwt import to_exp_jwt
from .client_crud import get_client
from .utils import (
    OAuthError,
    _decrypt_stored_client_secret,
    client_allows_grant,
    destructure_credentials,
    extract_client_credentials,
    get_jwt_plugin,
    is_pkce_required,
    normalize_timestamp_value,
    parse_client_metadata,
    resolve_ctx_secret_config,
    resolve_subject_identifier,
    resolved_issuer,
    safe_url_issue,
    store_token,
    throw_invalid_client,
    verify_client_secret,
)

logger = logging.getLogger("better_auth")

#: TS core ``NO_STORE_HEADERS`` (api/index.ts:29), set on token and introspection responses.
NO_STORE_HEADERS = [("Cache-Control", "no-store"), ("Pragma", "no-cache")]

#: Scopes that only a resource owner can delegate (oauthClient/client-credentials.ts:5).
USER_DELEGATED_SCOPES = frozenset({"openid", "profile", "email", "offline_access"})

#: Claim names the AS owns on a JWT access token (claims.ts:19).
_RESERVED_ACCESS_TOKEN_CLAIMS = frozenset(
    {"iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope", "auth_time", "acr", "amr"}
    | {"cnf"}
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


def _token_issuer(ctx: Ctx, opts: Any) -> str:
    """id_token / access-token ``iss`` — TS ``jwtPluginOptions?.jwt?.issuer ?? ctx.context.baseURL``
    (unvalidated, unlike the discovery issuer). Base URL when the jwt plugin is disabled."""
    return resolved_issuer(ctx, opts)


def _read_body(ctx: Ctx) -> dict[str, Any]:
    """Form-urlencoded body (the only allowed media type), falling back to JSON for callers
    that send JSON (test/convenience). Mirrors TS content-type body parsing."""
    request = ctx.request
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype == "application/x-www-form-urlencoded":
        return dict(parse_qsl(request.body.decode("utf-8", "replace"), keep_blank_values=True))
    try:
        return ctx.body()
    except Exception:
        return {}


def _strip_none(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop ``None`` values — TS relies on ``JSON.stringify`` omitting ``undefined`` claims."""
    return {k: v for k, v in payload.items() if v is not None}


# --- client credential validation (utils/index.ts:719) -------------------------------

_SECRET_METHODS = frozenset({"client_secret_basic", "client_secret_post"})


async def validate_client_credentials(
    ctx: Ctx,
    opts: Any,
    client_id: str,
    client_secret: str | None = None,
    scopes: list[str] | None = None,
    grant_type: str | None = None,
    *,
    pre_verified: bool = False,
    auth_method: str | None = None,
) -> dict[str, Any]:
    """Resolve and authorize the client, TS ``validateClientCredentials``: existence, disabled
    state, registered authentication method, secret, scope subset, and grant allowance.
    ``pre_verified`` means an assertion already proved control of ``client_id``."""
    client = await get_client(ctx, opts, client_id)
    if not client:
        raise throw_invalid_client("missing client", method=auth_method)
    if client.get("disabled"):
        raise throw_invalid_client("client is disabled", method=auth_method)

    registered = client.get("tokenEndpointAuthMethod")
    if registered is None:
        registered = "client_secret_basic"
    # bind_client_auth_method=False (port-only) keeps the 1.0 leniency between the two secret
    # methods; TS always binds (3ca2c08dc).
    lenient = (
        not getattr(opts, "bind_client_auth_method", True)
        and {
            registered,
            auth_method,
        }
        <= _SECRET_METHODS
    )
    if auth_method and registered != auth_method and not lenient:
        raise throw_invalid_client(
            f"client registered for {registered} cannot use {auth_method}", method=auth_method
        )
    if client.get("tokenEndpointAuthMethod") == "private_key_jwt" and not pre_verified:
        raise OAuthError(
            400, "invalid_client", "client registered for private_key_jwt must use client_assertion"
        )

    if not pre_verified:
        # Only token_endpoint_auth_method=none identifies a public client.
        if client.get("tokenEndpointAuthMethod") != "none" and not client_secret:
            raise throw_invalid_client("client secret must be provided", method=auth_method)
        if client_secret and not client.get("clientSecret"):
            raise throw_invalid_client(
                "public client, client secret should not be received", method=auth_method
            )
        if client_secret and not await verify_client_secret(
            opts, client["clientSecret"], client_secret, resolve_ctx_secret_config(ctx)
        ):
            raise throw_invalid_client("invalid client_secret", method=auth_method)

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


async def authenticate_client(
    ctx: Ctx, opts: Any, body: dict[str, Any], endpoint: str
) -> dict[str, Any]:
    """``extractClientCredentials`` + ``destructureCredentials`` bound to ``endpoint`` (the RFC
    7523 assertion audience)."""
    base = f"{ctx.auth.base_url}{ctx.auth.base_path}"
    creds = await extract_client_credentials(ctx, opts, body, f"{base}{endpoint}")
    return destructure_credentials(creds)


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


def _strip_reserved_access_claims(claims: dict[str, Any] | None) -> dict[str, Any]:
    """TS ``stripReservedClaims`` (claims.ts:40): the AS owns the RFC 9068 names."""
    claims = claims or {}
    stripped = [k for k in claims if k in _RESERVED_ACCESS_TOKEN_CLAIMS]
    if stripped:
        logger.warning(
            "oauth-provider: stripped reserved access-token claim name(s): %s. "
            "The AS owns these claim values.",
            ", ".join(stripped),
        )
    return {k: v for k, v in claims.items() if k not in _RESERVED_ACCESS_TOKEN_CLAIMS}


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
    """Signed ``at+jwt`` access token, TS ``createJwtAccessToken`` (token.ts:223). ``sub`` is
    the real user id (never pairwise) or the client itself for ``client_credentials`` (RFC 9068
    §2.2); ``client_id``/``azp`` bind it to its client; ``jti`` is a fresh 32-char id."""
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
            **_strip_reserved_access_claims(custom_claims),
            "sub": user.get("id") if user else client.get("clientId"),
            "aud": aud,
            "client_id": client.get("clientId"),
            "azp": client.get("clientId"),
            "scope": " ".join(scopes),
            "sid": sid,
            "iss": _token_issuer(ctx, opts),
            "iat": iat,
            "exp": exp,
            "jti": generate_random_string(32),
        }
    )
    jwt_plugin = get_jwt_plugin(ctx.auth)
    return await jwt_plugin.sign_jwt(payload=payload, header={"typ": "at+jwt"})


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
    authorization_code_id: str | None = None,
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
            "authorizationCodeId": authorization_code_id,
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
    access_token: str | None = None,
) -> str | None:
    """OIDC id_token — TS ``createIdToken``. Custom claims may override ``acr``/``auth_time`` and
    user claims, but the pinned security claims (iss/sub/aud/nonce/iat/exp/sid) always win.

    Signed on the jwt plugin's keys, or HS256 with the client's decrypted secret when
    ``disable_jwt_plugin``. A public client without a secret gets no id_token (it could not be
    verified) — returns ``None``."""
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
    payload["iss"] = _token_issuer(ctx, opts)
    payload["sub"] = resolved_sub
    payload["aud"] = client.get("clientId")
    payload["nonce"] = nonce
    payload["iat"] = iat
    payload["exp"] = exp
    payload["sid"] = session_id if client.get("enableEndSession") else None
    if access_token:
        disabled = getattr(opts, "disable_jwt_plugin", False)
        alg = "HS256" if disabled else get_jwt_plugin(ctx.auth)._alg()
        payload["at_hash"] = _oidc_hash(access_token, alg)

    if getattr(opts, "disable_jwt_plugin", False):
        # HS256 with the client's decrypted secret — TS token.ts:176-191.
        client_secret = client.get("clientSecret")
        if not client_secret:  # public client, cannot be verified -> no id_token
            return None
        secret = await _decrypt_stored_client_secret(
            opts.store_client_secret, client_secret, resolve_ctx_secret_config(ctx)
        )
        return pyjwt.encode(_strip_none(payload), secret, algorithm="HS256")

    jwt_plugin = get_jwt_plugin(ctx.auth)
    return await jwt_plugin.sign_jwt(payload=_strip_none(payload))


def _oidc_hash(token: str, signing_alg: str) -> str:
    """OIDC Core §3.1.3.6 ``at_hash``: left half of the alg's hash, base64url, TS
    ``computeOidcHash`` (token.ts:300). EdDSA hashes with SHA-512.

    ponytail: a custom ``jwt.sign`` is not re-checked against the hashed alg (TS token.ts:420);
    the port hashes with the configured ``keyPairConfig.alg`` it also signs with."""
    if signing_alg == "EdDSA" or signing_alg.endswith("512"):
        digest = hashlib.sha512(token.encode()).digest()
    elif signing_alg.endswith("384"):
        digest = hashlib.sha384(token.encode()).digest()
    else:
        digest = hashlib.sha256(token.encode()).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()


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


async def revoke_tokens_issued_for_authorization_code(ctx: Ctx, code_id: str) -> None:
    """A missing or replayed code revokes every token issued for it (RFC 6749 §4.1.2), TS
    ``revokeTokensIssuedForAuthorizationCode`` (token.ts:569). Cleanup failures are logged."""
    for model in ("oauthAccessToken", "oauthRefreshToken"):
        try:
            await ctx.adapter.delete_many(model, [Where("authorizationCodeId", code_id)])
        except Exception:
            logger.exception("authorization code replay cleanup failed")


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
    authorization_code_id: str | None = None,
) -> dict[str, Any]:
    """Mint a refresh row. Initial issuance is a single insert; rotation is an atomic CAS on the
    parent's ``revoked=null`` guard (loser -> ``invalid_grant``) that also stamps ``rotatedAt``
    and, with a reuse interval, ``rotationReplayExpiresAt``, TS ``createRefreshToken``
    (token.ts:593)."""
    exp = iat + (getattr(opts, "refresh_token_expires_in", None) or 2592000)
    gen = getattr(opts, "generate_refresh_token", None)
    tok = await _await(gen()) if gen else generate_random_string(32, _TOKEN_ALPHABET)
    new_row = {
        "token": await store_token(opts.store_tokens, tok, "refresh_token"),
        "clientId": client.get("clientId"),
        "sessionId": session_id,
        "userId": user["id"],
        "referenceId": reference_id,
        "authorizationCodeId": authorization_code_id,
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
    rotated_at = datetime.fromtimestamp(iat, tz=timezone.utc)
    update: dict[str, Any] = {"revoked": rotated_at, "rotatedAt": rotated_at}
    reuse_interval = getattr(opts, "refresh_token_reuse_interval", 0) or 0
    if reuse_interval > 0:
        update["rotationReplayExpiresAt"] = datetime.fromtimestamp(
            iat + reuse_interval, tz=timezone.utc
        )
    won = await ctx.adapter.increment_one(
        "oauthRefreshToken",
        [Where("id", original_refresh["id"]), Where("revoked", None, operator="eq")],
        set=update,
    )
    if not won:
        raise OAuthError(400, "invalid_grant", "invalid refresh token")

    created = await ctx.adapter.create("oauthRefreshToken", new_row)
    return {"id": created["id"], "token": await encode_refresh_token(opts, tok, session_id)}


# --- refresh rotation replay (token.ts:835-1092, 5838df2f4) --------------------------


def _replay_request(scopes: list[str], resources: Any) -> dict[str, Any]:
    """TS ``buildRefreshTokenRotationReplayRequest``: deduplicated, sorted scopes (and
    resources when present). The replay only answers an identical request."""
    request: dict[str, Any] = {"effectiveScopes": sorted(set(scopes))}
    if resources:
        request["requestedResources"] = sorted(
            set([resources] if isinstance(resources, str) else resources)
        )
    return request


def _within_reuse_interval(refresh: dict[str, Any]) -> bool:
    expires = normalize_timestamp_value(refresh.get("rotationReplayExpiresAt"))
    return bool(refresh.get("rotatedAt")) and expires is not None and expires >= utcnow()


def _is_token_response(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("access_token"), str)
        and isinstance(value.get("expires_in"), (int, float))
        and isinstance(value.get("expires_at"), (int, float))
        and value.get("token_type") in ("Bearer", "DPoP")
        and isinstance(value.get("scope"), str)
    )


def _stored_replay(ctx: Ctx, refresh: dict[str, Any], request: dict[str, Any]) -> Any:
    """TS ``getRefreshTokenRotationReplay``: decrypt the stored ``{request, response}`` and
    return the response when the request matches; any failure is logged and ignored."""
    stored = refresh.get("rotationReplayResponse")
    if not _within_reuse_interval(refresh) or not stored:
        return None
    try:
        replay = json.loads(symmetric_decrypt(resolve_ctx_secret_config(ctx), stored))
    except Exception:
        logger.exception("refresh token rotation replay failed")
        return None
    if not isinstance(replay, dict) or not _is_token_response(replay.get("response")):
        return None
    if replay.get("request") != request:
        return None
    return replay["response"]


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
    authorization_code_id: str | None = None,
):
    """Assemble the token response, TS ``createUserTokens`` (token.ts:1094). JWT access when an
    audience is present else opaque; refresh only when the client may use it and
    ``offline_access`` is granted; id_token (with ``at_hash``) only for a user with ``openid``."""
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
                to_exp_jwt(scope_expirations[sc], iat) if sc in scope_expirations else default_exp
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
    # JWT access tokens require the jwt plugin: disabled mode is always opaque (TS token.ts:1150).
    is_jwt_access_token = audience is not None and not getattr(opts, "disable_jwt_plugin", False)
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
    refresh = None
    if is_refresh_token and user and not is_jwt_access_token:
        refresh = await _create_refresh_token(
            ctx,
            opts,
            user,
            reference_id,
            client,
            scopes,
            iat,
            session_id,
            refresh_token,
            auth_time,
            authorization_code_id,
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
            refresh["id"] if refresh else None,
            authorization_code_id,
        )

    if refresh is None and is_refresh_token and user:
        refresh = await _create_refresh_token(
            ctx,
            opts,
            user,
            reference_id,
            client,
            scopes,
            iat,
            session_id,
            refresh_token,
            auth_time,
            authorization_code_id,
        )

    id_token = (
        await _create_id_token(
            ctx, opts, user, client, scopes, nonce, session_id, auth_time, access_token
        )
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

    if refresh_token and refresh_token.get("id") and refresh:
        await _store_replay(
            ctx, opts, refresh_token, _replay_request(scopes, body.get("resource")), body_out
        )

    return AuthResponse(body=body_out, headers=list(NO_STORE_HEADERS))


async def _store_replay(
    ctx: Ctx, opts: Any, parent: dict[str, Any], request: dict[str, Any], response: dict
) -> None:
    """TS ``storeRefreshTokenRotationReplay``: keep the encrypted ``{request, response}`` on the
    rotated parent so a retry inside the reuse window gets the same answer. Best effort."""
    if (getattr(opts, "refresh_token_reuse_interval", 0) or 0) <= 0:
        return
    try:
        data = json.dumps({"request": request, "response": response}, separators=(",", ":"))
        await ctx.adapter.update(
            "oauthRefreshToken",
            [Where("id", parent["id"])],
            {"rotationReplayResponse": symmetric_encrypt(resolve_ctx_secret_config(ctx), data)},
        )
    except Exception:
        logger.exception("failed to store refresh token rotation replay")


# --- authorization_code grant (token.ts:1360-1688) -----------------------------------


def _is_verification_value(value: Any) -> bool:
    """The shape TS ``verificationValueSchema`` requires (types/zod.ts:166).

    ponytail: checks the envelope and field types, not every authorization-query field."""
    return (
        isinstance(value, dict)
        and value.get("type") == "authorization_code"
        and isinstance(value.get("query"), dict)
        and isinstance(value.get("sessionId"), str)
        and isinstance(value.get("userId"), str)
        and isinstance(value.get("referenceId"), (str, type(None)))
        and (value.get("authTime") is None or isinstance(value["authTime"], (int, float)))
    )


async def _check_verification_value(
    ctx: Ctx, opts: Any, code: str, client_id: str, redirect_uri: str | None
) -> tuple[dict[str, Any], str]:
    """Atomic single-use code redemption + verification-value validation — TS
    ``checkVerificationValue`` (token.ts:1361). Returns the value and the stored code id."""
    code_id = await store_token(opts.store_tokens, code, "authorization_code")
    verification = await ctx.internal.consume_verification_value(code_id)
    if not verification:
        await revoke_tokens_issued_for_authorization_code(ctx, code_id)
        raise OAuthError(400, "invalid_grant", "invalid code")

    try:
        value: Any = json.loads(verification["value"])
    except ValueError:
        value = None
    if value is None or not _is_verification_value(value):
        raise OAuthError(400, "invalid_grant", "malformed verification value")

    if value["query"].get("client_id") != client_id:
        raise OAuthError(400, "invalid_grant", "invalid client_id")
    # RFC 6749 §4.1.3: redirect_uri is bound only when the authorization request carried one,
    # and then must match exactly; a code minted without one must be redeemed without one.
    bound = value["query"].get("redirect_uri")
    if bound:
        if not redirect_uri:
            raise OAuthError(400, "invalid_request", "redirect_uri is required")
        if bound != redirect_uri:
            raise OAuthError(400, "invalid_grant", "redirect_uri mismatch")
    elif redirect_uri:
        raise OAuthError(400, "invalid_grant", "redirect_uri mismatch")
    return value, code_id


async def handle_authorization_code_grant(ctx: Ctx, opts: Any, body: dict[str, Any]):
    creds = await authenticate_client(ctx, opts, body, "/oauth2/token")
    client_id = creds["client_id"]
    client_secret = creds["client_secret"]
    pre_verified = creds["pre_verified"]
    code = body.get("code")
    code_verifier = body.get("code_verifier")
    redirect_uri = body.get("redirect_uri")

    if not client_id:
        raise OAuthError(400, "invalid_request", "client_id is required")
    if not code:
        raise OAuthError(400, "invalid_request", "code is required")

    is_auth_code_with_secret = bool(client_id and client_secret)
    is_auth_code_with_pkce = bool(client_id and code and code_verifier)
    if not is_auth_code_with_secret and not is_auth_code_with_pkce and not pre_verified:
        raise OAuthError(
            400, "invalid_request", "Either code_verifier or client_secret is required"
        )

    value, code_id = await _check_verification_value(ctx, opts, code, client_id, redirect_uri)
    query = value["query"]
    scope_str = query.get("scope")
    scopes = scope_str.split(" ") if scope_str else None
    if not scopes:
        raise OAuthError(500, "invalid_scope", "verification scope unset")

    client = await validate_client_credentials(
        ctx,
        opts,
        client_id,
        client_secret,
        scopes,
        "authorization_code",
        pre_verified=pre_verified,
        auth_method=creds["auth_method"],
    )

    if is_pkce_required(client, scopes, query.get("nonce")):
        if not is_auth_code_with_pkce:
            raise OAuthError(400, "invalid_request", "PKCE is required for this client")
    elif not (is_auth_code_with_pkce or is_auth_code_with_secret or pre_verified):
        raise OAuthError(
            400,
            "invalid_request",
            "Either PKCE (code_verifier) or client authentication (client_secret or "
            "client_assertion) is required",
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

    user = await ctx.adapter.find_one("user", [Where("id", value["userId"])])
    if not user:
        raise OAuthError(400, "invalid_user", "missing user, user may have been deleted")

    session = await ctx.adapter.find_one("session", [Where("id", value["sessionId"])])
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
        authorization_code_id=code_id,
    )


# --- client_credentials grant (token.ts:1696) ----------------------------------------


def _legacy_client_credentials_scopes(client: dict[str, Any], opts: Any) -> tuple[set, list]:
    """1.0 behavior kept while ``client_credential_grant_default_scopes`` is configured and the
    client has no ``clientCredentialsScopes``: any client (or provider) scope minus the
    user-delegated ones, defaulting to the client scopes, then the configured defaults."""
    valid = set(client.get("scopes") or getattr(opts, "scopes", None) or [])
    default = (
        client.get("scopes")
        or getattr(opts, "client_credential_grant_default_scopes", None)
        or getattr(opts, "scopes", None)
        or []
    )
    return valid, list(default)


async def handle_client_credentials_grant(ctx: Ctx, opts: Any, body: dict[str, Any]):
    creds = await authenticate_client(ctx, opts, body, "/oauth2/token")
    client_id = creds["client_id"]
    scope = body.get("scope")

    if not client_id:
        raise OAuthError(400, "invalid_request", "Missing required client_id")

    client = await validate_client_credentials(
        ctx,
        opts,
        client_id,
        creds["client_secret"],
        None,
        "client_credentials",
        pre_verified=creds["pre_verified"],
        auth_method=creds["auth_method"],
    )
    if client.get("tokenEndpointAuthMethod") == "none":
        raise OAuthError(
            400, "unauthorized_client", "public clients cannot use the client_credentials grant"
        )
    machine_scopes = client.get("clientCredentialsScopes") or []
    if machine_scopes:
        valid, default = set(machine_scopes), list(machine_scopes)
    elif getattr(opts, "client_credential_grant_default_scopes", None):
        valid, default = _legacy_client_credentials_scopes(client, opts)
    else:
        raise OAuthError(
            400, "unauthorized_client", "client has no authorized client_credentials scopes"
        )

    requested_scopes = scope.split(" ") if scope else None
    if requested_scopes:
        invalid = [s for s in requested_scopes if s not in valid or s in USER_DELEGATED_SCOPES]
        if invalid:
            raise OAuthError(
                400, "invalid_scope", f"The following scopes are invalid: {', '.join(invalid)}"
            )
    if not requested_scopes:
        requested_scopes = default

    return await create_user_tokens(
        ctx,
        opts,
        body=body,
        client=client,
        scopes=requested_scopes,
        grant_type="client_credentials",
    )


# --- refresh_token grant (token.ts:1782) ---------------------------------------------


async def handle_refresh_token_grant(ctx: Ctx, opts: Any, body: dict[str, Any]):
    creds = await authenticate_client(ctx, opts, body, "/oauth2/token")
    client_id = creds["client_id"]
    refresh_token_value = body.get("refresh_token")
    scope = body.get("scope")

    if not client_id:
        raise OAuthError(400, "invalid_request", "Missing required client_id")
    if not refresh_token_value:
        raise OAuthError(
            400, "invalid_request", "Missing a required refresh_token for refresh_token grant"
        )

    decoded = await decode_refresh_token(opts, refresh_token_value)
    refresh_token = await ctx.adapter.find_one(
        "oauthRefreshToken",
        [Where("token", await store_token(opts.store_tokens, decoded["token"], "refresh_token"))],
    )

    if not refresh_token:
        raise OAuthError(400, "invalid_grant", "session not found")
    if refresh_token["clientId"] != client_id:
        raise OAuthError(400, "invalid_grant", "invalid refresh token")
    if refresh_token["expiresAt"] < utcnow():
        raise OAuthError(400, "invalid_grant", "invalid refresh token")

    scopes = refresh_token.get("scopes")
    requested_scopes = scope.split(" ") if scope else None
    if requested_scopes:
        valid = set(scopes or [])
        for sc in requested_scopes:
            if sc not in valid:
                raise OAuthError(400, "invalid_scope", f"unable to issue scope {sc}")

    client = await validate_client_credentials(
        ctx,
        opts,
        client_id,
        creds["client_secret"],
        requested_scopes or scopes,
        "refresh_token",
        pre_verified=creds["pre_verified"],
        auth_method=creds["auth_method"],
    )

    if refresh_token.get("revoked"):
        if _within_reuse_interval(refresh_token):
            request = _replay_request(requested_scopes or scopes or [], body.get("resource"))
            replay = _stored_replay(ctx, refresh_token, request)
            if replay:
                replay = {**replay, "expires_in": max(0, replay["expires_at"] - _now_s())}
                return AuthResponse(body=replay, headers=list(NO_STORE_HEADERS))
            raise OAuthError(400, "invalid_grant", "invalid refresh token")
        await invalidate_refresh_family(ctx, client_id, refresh_token["userId"])
        raise OAuthError(400, "invalid_grant", "invalid refresh token")

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
        authorization_code_id=refresh_token.get("authorizationCodeId"),
    )


# --- endpoint ------------------------------------------------------------------------

_DEFAULT_GRANT_TYPES = ["authorization_code", "client_credentials", "refresh_token"]


def _type_issue(field: str, value: Any) -> str:
    """TS ``describeIssue`` for a present value of the wrong type (oauth-endpoint.ts:272)."""
    if isinstance(value, list):
        return f"{field} must not appear more than once"
    return f"{field} must be a string"


def validate_token_body(body: dict[str, Any]) -> None:
    """The ``/oauth2/token`` body schema as RFC 6749 §5.2 envelopes, TS oauth.ts:875
    (``grant_type: z.string().trim().min(1)``, ``redirect_uri: SafeUrlSchema``) mapped by
    ``mapIssuesToOAuthError``. Trims ``grant_type`` in place, like zod's transform.

    ponytail: ``resource`` URI validation (``invalid_target``) belongs to the resource model."""
    grant_type = body.get("grant_type")
    if grant_type is None:
        raise OAuthError(400, "invalid_request", "grant_type is required")
    if not isinstance(grant_type, str):
        raise OAuthError(400, "invalid_request", _type_issue("grant_type", grant_type))
    body["grant_type"] = grant_type = grant_type.strip()
    if not grant_type:
        raise OAuthError(
            400,
            "invalid_request",
            "grant_type: Too small: expected string to have >=1 characters",
        )
    redirect_uri = body.get("redirect_uri")
    if redirect_uri is not None:
        if not isinstance(redirect_uri, str):
            raise OAuthError(400, "invalid_request", _type_issue("redirect_uri", redirect_uri))
        issue = safe_url_issue(redirect_uri)
        if issue:
            raise OAuthError(400, "invalid_request", f"redirect_uri: {issue}")


def no_store(error: OAuthError) -> OAuthError:
    """Attach :data:`NO_STORE_HEADERS` to an error the handler raised (TS noStore metadata
    covers handler errors, not schema failures)."""
    error.headers = [*(error.headers or []), *NO_STORE_HEADERS]
    return error


async def token_endpoint(ctx: Ctx, opts: Any):
    """POST /oauth2/token: validate the body, then dispatch by ``grant_type`` (TS
    ``tokenEndpoint``, token.ts:96).

    ponytail: extension grant handlers (TS ``extensions.ts``) are not ported."""
    body = _read_body(ctx)
    validate_token_body(body)
    try:
        return await _dispatch_grant(ctx, opts, body)
    except OAuthError as error:
        raise no_store(error) from None


async def _dispatch_grant(ctx: Ctx, opts: Any, body: dict[str, Any]):
    grant_type = body["grant_type"]
    supported = getattr(opts, "grant_types", None) or _DEFAULT_GRANT_TYPES
    if grant_type not in supported:
        raise OAuthError(400, "unsupported_grant_type", f"unsupported grant_type {grant_type}")
    if grant_type == "authorization_code":
        return await handle_authorization_code_grant(ctx, opts, body)
    if grant_type == "client_credentials":
        return await handle_client_credentials_grant(ctx, opts, body)
    if grant_type == "refresh_token":
        return await handle_refresh_token_grant(ctx, opts, body)
    raise OAuthError(400, "unsupported_grant_type", f"unsupported grant_type {grant_type}")
