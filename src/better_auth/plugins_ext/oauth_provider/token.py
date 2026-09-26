"""POST /oauth2/token — the three grants, token minting, and refresh rotation.

Port of TS ``packages/oauth-provider/src/token.ts`` (v1.7.6). Form-urlencoded only. Clients
authenticate with ``client_secret_basic``, ``client_secret_post``, ``private_key_jwt`` or as a
public client, and must use the method they registered. Handles ``authorization_code``
(single-use code redemption; a replayed code revokes the tokens already issued for it),
``client_credentials`` (machine scopes from ``clientCredentialsScopes``), and ``refresh_token``
(rotation via a ``revoked=null`` CAS, an optional reuse window that replays the stored response,
and RFC 9700 §4.14 family teardown on replay). RFC 8707 ``resource`` values must name
``oauthResource`` rows whose policy narrows scopes and lifetimes; a request may narrow, never
widen, the resources bound to the grant. Access tokens are ``at+jwt`` JWTs when a resource
audience is present (signed on the jwt plugin's keys), otherwise opaque and stored hashed; a DPoP
proof binds them to a key (``cnf.jkt``, ``token_type: DPoP``). ID tokens carry pinned OIDC
claims plus ``at_hash``; profile and email claims are served by UserInfo.

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
from . import dpop
from .claims import (
    LEVEL_0_ACR,
    STANDARD_CLAIM_NAMES,
    get_requested_user_info_claims,
    get_supported_claims,
    is_claims_request_input,
    is_valid_oidc_claims_request,
    resolve_access_token_claims,
    strip_reserved_id_token_claims,
    user_normal_claims,
)
from .client_crud import get_client
from .resources import (
    extract_repeated_resource_from_form,
    resolve_resource_policy,
    resource_uri_issue,
    to_audience_claim,
    to_resource_list,
)
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

#: TS ``generateRandomString(32, "A-Z", "a-z")`` — opaque access / refresh token charset.
_TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


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
    user: dict[str, Any] | None,
    client: dict[str, Any],
    audience: str | list[str],
    scopes: list[str],
    *,
    iat: int,
    exp: int,
    sid: str | None,
    signing_key_id: str | None = None,
    signing_algorithm: str | None = None,
    access_token_claims: dict[str, Any] | None = None,
    confirmation: dict[str, Any] | None = None,
) -> str:
    """Signed ``at+jwt`` access token, TS ``createJwtAccessToken`` (token.ts:223). ``sub`` is
    the real user id (never pairwise) or the client itself for ``client_credentials`` (RFC 9068
    §2.2); the enriched claims come first so every AS-owned claim, ``cnf`` last, wins."""
    payload = _strip_none(
        {
            **(access_token_claims or {}),
            "sub": user.get("id") if user else client.get("clientId"),
            "aud": to_audience_claim(audience),
            "client_id": client.get("clientId"),
            "azp": client.get("clientId"),
            "scope": " ".join(scopes),
            "sid": sid,
            "iss": _token_issuer(ctx, opts),
            "iat": iat,
            "exp": exp,
            "jti": generate_random_string(32),
            "cnf": confirmation,
        }
    )
    jwt_plugin = get_jwt_plugin(ctx.auth)
    if signing_algorithm and signing_algorithm != jwt_plugin._alg():
        # ponytail: the jwt plugin signs with one algorithm (no multi-alg keyring yet), so a
        # resource pinned to another alg fails like TS resolveSigningKey does when no key with
        # that alg exists and none may be minted. Lift this with jwks keyPairConfigs.
        raise ValueError(
            f'signJWT: no key with alg "{signing_algorithm}" found in JWKS. The plugin '
            f'auto-mints only one key matching keyPairConfig.alg="{jwt_plugin._alg()}".'
        )
    return await jwt_plugin.sign_jwt(
        payload=payload, header={"typ": "at+jwt"}, signing_key_id=signing_key_id
    )


async def _create_opaque_access_token(
    ctx: Ctx,
    opts: Any,
    user: dict[str, Any] | None,
    client: dict[str, Any],
    scopes: list[str],
    *,
    iat: int,
    exp: int,
    sid: str | None,
    resources: list[str] | None,
    reference_id: str | None,
    authorization_code_id: str | None,
    refresh_id: str | None,
    confirmation: dict[str, Any] | None,
    requested_user_info_claims: list[str] | None,
) -> str:
    """Opaque access token stored hashed in ``oauthAccessToken``, TS
    ``createOpaqueAccessToken`` (token.ts:473)."""
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
            "resources": resources,
            "refreshId": refresh_id,
            "confirmation": confirmation,
            "requestedUserInfoClaims": requested_user_info_claims or None,
            "scopes": scopes,
            "createdAt": datetime.fromtimestamp(iat, tz=timezone.utc),
            "expiresAt": datetime.fromtimestamp(exp, tz=timezone.utc),
        },
    )
    prefix = (getattr(opts, "prefix", None) or {}).get("opaqueAccessToken", "")
    return prefix + tok


#: TS ``ID_TOKEN_SCOPE_CLAIM_GUARDS`` (token.ts:75): the standard UserInfo claim names seeded
#: unset so they reach the ID token only through ``custom_id_token_claims``.
_ID_TOKEN_SCOPE_CLAIM_GUARDS = dict.fromkeys(STANDARD_CLAIM_NAMES)


def _legacy_profile_claims(opts: Any, user: dict[str, Any], scopes: list[str]) -> dict[str, Any]:
    """Port-only, deprecated: the 1.0 scope-based profile and email claims for the ID token,
    behind ``legacy_id_token_profile_claims`` (default off, TS behavior)."""
    if not getattr(opts, "legacy_id_token_profile_claims", False):
        return {}
    claims = user_normal_claims(user, scopes)
    claims.pop("sub", None)  # always the pinned, possibly pairwise, subject
    return claims


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
    """OIDC id_token, TS ``createIdToken`` (token.ts:324). Standard profile/email claims live
    at UserInfo only (d368217ef); ``custom_id_token_claims`` may add claims but never replace
    the protocol claims it owns (335cda702), and ``acr`` is ``"0"`` (a966815b1).

    Signed on the jwt plugin's keys, or HS256 with the client's decrypted secret when
    ``disable_jwt_plugin``. A public client without a secret gets no id_token (it could not be
    verified): returns ``None``."""
    iat = _now_s()
    exp = iat + (getattr(opts, "id_token_expires_in", None) or 36000)
    resolved_sub = resolve_subject_identifier(client, opts, user["id"])
    auth_time_sec = math.floor(auth_time.timestamp()) if auth_time is not None else None

    custom = getattr(opts, "custom_id_token_claims", None)
    custom_claims = strip_reserved_id_token_claims(
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
        else None
    )
    disabled = getattr(opts, "disable_jwt_plugin", False)
    alg = "HS256" if disabled else get_jwt_plugin(ctx.auth)._alg()
    emit_sid = bool(client.get("enableEndSession") or client.get("backchannelLogoutUri"))
    payload: dict[str, Any] = {
        **_ID_TOKEN_SCOPE_CLAIM_GUARDS,
        **_legacy_profile_claims(opts, user, scopes),
        "auth_time": auth_time_sec,
        "acr": LEVEL_0_ACR,
        **custom_claims,
        "at_hash": _oidc_hash(access_token, alg) if access_token else None,
        "iss": _token_issuer(ctx, opts),
        "sub": resolved_sub,
        "aud": client.get("clientId"),
        "nonce": nonce,
        "iat": iat,
        "exp": exp,
        "sid": session_id if emit_sid else None,
    }

    if disabled:
        # HS256 with the client's decrypted secret, TS token.ts:398.
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
    client: dict[str, Any],
    scopes: list[str],
    *,
    iat: int,
    exp: int,
    session_id: str | None,
    reference_id: str | None,
    authorization_code_id: str | None,
    original_refresh: dict[str, Any] | None,
    auth_time: datetime | None,
    resources: list[str] | None,
    confirmation: dict[str, Any] | None,
    requested_user_info_claims: list[str] | None,
) -> dict[str, Any]:
    """Mint a refresh row. Initial issuance is a single insert; rotation is an atomic CAS on the
    parent's ``revoked=null`` guard (loser -> ``invalid_grant``) that also stamps ``rotatedAt``
    and, with a reuse interval, ``rotationReplayExpiresAt``, TS ``createRefreshToken``
    (token.ts:593)."""
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
        "confirmation": confirmation,
        "requestedUserInfoClaims": requested_user_info_claims or None,
        "scopes": scopes,
        "resources": resources,
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


# --- resource grant issuance (token.ts:710-770) --------------------------------------


async def _resolve_resource_grant_issuance(
    ctx: Ctx,
    opts: Any,
    *,
    client_id: str,
    requested_scopes: list[str],
    resources: list[str] | None,
    original_resources: list[str] | None,
    refresh_token: dict[str, Any] | None,
    iat: int,
    scope_expires_at: int,
) -> dict[str, Any]:
    """TS ``resolveResourceGrantIssuance``: the resource policy plus the effective access and
    refresh expiry (a resource may shorten, never extend, the plugin refresh lifetime)."""
    policy = await resolve_resource_policy(
        ctx, opts, resource=resources, client_id=client_id, requested_scopes=requested_scopes
    )
    resource_expires_at = (
        iat + policy["accessTokenTtl"] if policy["accessTokenTtl"] is not None else scope_expires_at
    )
    default_refresh_ttl = getattr(opts, "refresh_token_expires_in", None) or 2592000
    refresh_ttl = (
        min(policy["refreshTokenTtl"], default_refresh_ttl)
        if policy["refreshTokenTtl"] is not None
        else default_refresh_ttl
    )
    return {
        **policy,
        "accessTokenExpiresAt": min(scope_expires_at, resource_expires_at),
        "refreshTokenExpiresAt": iat + refresh_ttl,
        "refreshResources": (refresh_token or {}).get("resources")
        or original_resources
        or resources,
    }


# --- DPoP binding (token.ts:771-834, aedcb974f) --------------------------------------


def _client_requires_dpop(client: dict[str, Any]) -> bool:
    """TS ``clientRequiresDpopBoundAccessTokens``. ``dpopBoundAccessTokens`` is an oauthClient
    column added with the client model; read it when present."""
    metadata = parse_client_metadata(client.get("metadata")) or {}
    return (
        client.get("dpopBoundAccessTokens") is True
        or metadata.get("dpop_bound_access_tokens") is True
    )


async def _resolve_dpop_token_binding(
    ctx: Ctx,
    opts: Any,
    *,
    client: dict[str, Any],
    grant_issuance: dict[str, Any],
    verification_value: dict[str, Any] | None = None,
    refresh_token: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """TS ``resolveDpopTokenBinding``: verify a DPoP proof on the token request and return the
    ``{jkt}`` confirmation to bind; a proof is required when the client, a resource, the
    authorization request (``dpop_jkt``) or the refresh family asks for DPoP."""
    auth_code_jkt = ((verification_value or {}).get("query") or {}).get("dpop_jkt")
    refresh_jkt = dpop.get_confirmation_jkt((refresh_token or {}).get("confirmation"))
    expected_jkt = refresh_jkt or auth_code_jkt
    proof_jwt = dpop.get_dpop_proof_jwt(ctx)
    required = (
        _client_requires_dpop(client)
        or grant_issuance["dpopBoundAccessTokensRequired"]
        or bool(auth_code_jkt)
        or bool(refresh_jkt)
    )
    if not proof_jwt:
        if required:
            raise OAuthError(400, "invalid_dpop_proof", "DPoP proof header is required")
        return None
    dpop_opts = getattr(opts, "dpop", None) or {}
    try:
        proof = await dpop.verify_dpop_proof(
            proof_jwt=proof_jwt,
            method="POST",
            url=dpop.get_endpoint_url(ctx, "/oauth2/token"),
            expected_jkt=expected_jkt,
            proof_max_age_seconds=dpop_opts.get("proofMaxAgeSeconds"),
            signing_algorithms=dpop_opts.get("signingAlgorithms"),
            replay_store=dpop.create_dpop_replay_store(ctx.auth.internal),
        )
    except dpop.DpopProofError as error:
        raise OAuthError(400, "invalid_dpop_proof", str(error)) from None
    return {"jkt": proof.jkt}


def confirmation_token_type(confirmation: Any) -> str:
    """TS ``confirmationTokenType`` (token.ts:86): a DPoP ``jkt`` makes the token ``DPoP``."""
    return "DPoP" if dpop.get_confirmation_jkt(confirmation) else "Bearer"


# --- refresh rotation replay (token.ts:835-1092, 5838df2f4) --------------------------


def _normalize_replay_values(values: Any) -> list[str] | None:
    return sorted(set(values)) if values is not None else None


def _confirmation_replay_key(confirmation: Any) -> str | None:
    if not confirmation:
        return None
    if "jkt" in confirmation:
        return f"jkt:{confirmation['jkt']}"
    return f"x5t#S256:{confirmation.get('x5t#S256')}"


def _is_confirmation(value: Any) -> bool:
    return isinstance(value, dict) and (
        (isinstance(value.get("jkt"), str) and "x5t#S256" not in value)
        or (isinstance(value.get("x5t#S256"), str) and "jkt" not in value)
    )


def _replay_request(
    effective_scopes: list[str], resources: list[str] | None, confirmation: Any
) -> dict[str, Any]:
    """TS ``buildRefreshTokenRotationReplayRequest``: the replay only answers the same
    effective scopes, requested resources and sender constraint."""
    request: dict[str, Any] = {"effectiveScopes": _normalize_replay_values(effective_scopes) or []}
    requested = _normalize_replay_values(resources)
    if requested:
        request["requestedResources"] = requested
    if confirmation:
        request["confirmation"] = confirmation
    return request


def _same_replay_request(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """TS ``sameRefreshTokenRotationReplayRequest``."""
    return (
        _normalize_replay_values(left.get("effectiveScopes"))
        == _normalize_replay_values(right.get("effectiveScopes"))
        and _normalize_replay_values(left.get("requestedResources"))
        == _normalize_replay_values(right.get("requestedResources"))
        and _confirmation_replay_key(left.get("confirmation"))
        == _confirmation_replay_key(right.get("confirmation"))
    )


def _is_replay(value: Any) -> bool:
    """TS ``isRefreshTokenRotationReplay``."""
    if not isinstance(value, dict) or not isinstance(value.get("request"), dict):
        return False
    request = value["request"]
    scopes = request.get("effectiveScopes")
    resources = request.get("requestedResources")
    return (
        isinstance(scopes, list)
        and all(isinstance(s, str) for s in scopes)
        and (
            resources is None
            or (isinstance(resources, list) and all(isinstance(r, str) for r in resources))
        )
        and ("confirmation" not in request or _is_confirmation(request["confirmation"]))
        and _is_token_response(value.get("response"))
    )


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
        and (value.get("refresh_token") is None or isinstance(value["refresh_token"], str))
        and (value.get("id_token") is None or isinstance(value["id_token"], str))
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
    if not _is_replay(replay) or not _same_replay_request(replay["request"], request):
        return None
    return replay["response"]


async def _resolve_replay_request(
    ctx: Ctx,
    opts: Any,
    *,
    client: dict[str, Any],
    refresh_token: dict[str, Any],
    scopes: list[str],
    resources: list[str] | None,
) -> dict[str, Any]:
    """TS ``resolveRefreshTokenRotationReplayRequest``: the request a retry must match, with
    the resource policy and DPoP binding recomputed for this request."""
    iat = _now_s()
    grant_issuance = await _resolve_resource_grant_issuance(
        ctx,
        opts,
        client_id=client["clientId"],
        requested_scopes=scopes,
        resources=resources,
        original_resources=None,
        refresh_token=refresh_token,
        iat=iat,
        scope_expires_at=iat + (getattr(opts, "access_token_expires_in", None) or 3600),
    )
    confirmation = await _resolve_dpop_token_binding(
        ctx, opts, client=client, grant_issuance=grant_issuance, refresh_token=refresh_token
    )
    return _replay_request(grant_issuance["effectiveScopes"], resources, confirmation)


async def create_user_tokens(
    ctx: Ctx,
    opts: Any,
    *,
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
    resources: list[str] | None = None,
    original_resources: list[str] | None = None,
    requested_user_info_claims: list[str] | None = None,
):
    """Assemble the token response, TS ``createUserTokens`` (token.ts:1094). The resource policy
    narrows scopes and lifetimes; JWT access when an audience is present else opaque; refresh
    only when the client may use it and ``offline_access`` is granted; id_token (with
    ``at_hash``) only for a user with ``openid``."""
    iat = _now_s()
    base_expiry = (
        (getattr(opts, "access_token_expires_in", None) or 3600)
        if user
        else (getattr(opts, "m2m_access_token_expires_in", None) or 3600)
    )
    default_exp = iat + base_expiry
    scope_exp = default_exp
    scope_expirations = getattr(opts, "scope_expirations", None)
    if scope_expirations:
        for sc in scopes:
            cand = (
                to_exp_jwt(scope_expirations[sc], iat) if scope_expirations.get(sc) else default_exp
            )
            scope_exp = min(scope_exp, cand)
    scope_exp = int(scope_exp)

    grant_issuance = await _resolve_resource_grant_issuance(
        ctx,
        opts,
        client_id=client["clientId"],
        requested_scopes=scopes,
        resources=resources,
        original_resources=original_resources,
        refresh_token=refresh_token,
        iat=iat,
        scope_expires_at=scope_exp,
    )
    audience = grant_issuance["audienceClaim"]
    effective_scopes = grant_issuance["effectiveScopes"]
    exp = int(grant_issuance["accessTokenExpiresAt"])
    refresh_exp = int(grant_issuance["refreshTokenExpiresAt"])

    is_refresh_token = bool(
        user
        and client_allows_grant(client, "refresh_token")
        and (
            (refresh_token and "offline_access" in (refresh_token.get("scopes") or []))
            or "offline_access" in scopes
        )
    )
    # JWT access tokens require the jwt plugin: disabled mode is always opaque (TS token.ts:1150).
    is_jwt_access_token = bool(audience) and not getattr(opts, "disable_jwt_plugin", False)
    is_id_token = bool(user and "openid" in effective_scopes)
    metadata = parse_client_metadata(client.get("metadata"))

    custom_fields_fn = getattr(opts, "custom_token_response_fields", None)
    custom_fields = (
        await _await(
            custom_fields_fn(
                {
                    "grantType": grant_type,
                    "user": user,
                    "scopes": effective_scopes,
                    "metadata": metadata,
                    "verificationValue": verification_value,
                }
            )
        )
        if custom_fields_fn
        else {}
    ) or {}

    confirmation = await _resolve_dpop_token_binding(
        ctx,
        opts,
        client=client,
        grant_issuance=grant_issuance,
        verification_value=verification_value,
        refresh_token=refresh_token,
    )
    user_info_claims = (
        requested_user_info_claims
        if requested_user_info_claims is not None
        else ((refresh_token or {}).get("requestedUserInfoClaims") or [])
    )

    async def mint_refresh() -> dict[str, Any]:
        assert user is not None
        return await _create_refresh_token(
            ctx,
            opts,
            user,
            client,
            effective_scopes,
            iat=iat,
            exp=refresh_exp,
            session_id=session_id,
            reference_id=reference_id,
            authorization_code_id=authorization_code_id,
            original_refresh=refresh_token,
            auth_time=auth_time,
            resources=grant_issuance["refreshResources"],
            confirmation=confirmation,
            requested_user_info_claims=user_info_claims,
        )

    # An opaque access token references the refresh row's id, so mint the refresh first in that
    # case; the JWT path stores nothing and needs no back-reference.
    refresh = await mint_refresh() if is_refresh_token and not is_jwt_access_token else None

    if is_jwt_access_token:
        access_token_claims = await resolve_access_token_claims(
            ctx,
            opts,
            user=user,
            scopes=effective_scopes,
            resources=resources,
            reference_id=reference_id,
            metadata=metadata,
            resource_policy_claims=grant_issuance["rawCustomClaims"],
        )
        access_token = await _create_jwt_access_token(
            ctx,
            opts,
            user,
            client,
            audience,
            effective_scopes,
            iat=iat,
            exp=exp,
            sid=session_id,
            signing_key_id=grant_issuance["signingKeyId"],
            signing_algorithm=grant_issuance["signingAlgorithm"],
            access_token_claims=access_token_claims,
            confirmation=confirmation,
        )
    else:
        access_token = await _create_opaque_access_token(
            ctx,
            opts,
            user,
            client,
            effective_scopes,
            iat=iat,
            exp=exp,
            sid=session_id,
            resources=resources,
            reference_id=reference_id,
            authorization_code_id=authorization_code_id,
            refresh_id=refresh["id"] if refresh else None,
            confirmation=confirmation,
            requested_user_info_claims=user_info_claims,
        )

    if refresh is None and is_refresh_token:
        refresh = await mint_refresh()

    id_token = (
        await _create_id_token(
            ctx, opts, user, client, effective_scopes, nonce, session_id, auth_time, access_token
        )
        if is_id_token and user
        else None
    )

    body_out: dict[str, Any] = dict(custom_fields)
    body_out["access_token"] = access_token
    body_out["expires_in"] = exp - iat
    body_out["expires_at"] = exp
    body_out["token_type"] = confirmation_token_type(confirmation)
    if refresh:
        body_out["refresh_token"] = refresh["token"]
    body_out["scope"] = " ".join(effective_scopes)
    if id_token:
        body_out["id_token"] = id_token

    if refresh_token and refresh_token.get("id") and refresh:
        await _store_replay(
            ctx,
            opts,
            refresh_token,
            _replay_request(effective_scopes, resources, confirmation),
            body_out,
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

    ponytail: checks the envelope, field types, the bound resources and the claims request, not
    every authorization-query field."""
    if not (
        isinstance(value, dict)
        and value.get("type") == "authorization_code"
        and isinstance(value.get("query"), dict)
        and isinstance(value.get("sessionId"), str)
        and isinstance(value.get("userId"), str)
        and isinstance(value.get("referenceId"), (str, type(None)))
        and (value.get("authTime") is None or isinstance(value["authTime"], (int, float)))
    ):
        return False
    resource = value.get("resource")
    if resource is not None and not (
        isinstance(resource, list) and all(isinstance(r, str) for r in resource)
    ):
        return False
    claims = value["query"].get("claims")
    return claims is None or (
        is_claims_request_input(claims) and is_valid_oidc_claims_request(claims)
    )


async def _check_verification_value(
    ctx: Ctx,
    opts: Any,
    code: str,
    client_id: str,
    redirect_uri: str | None,
    resources: list[str] | None,
) -> tuple[dict[str, Any], str, list[str] | None, list[str] | None]:
    """Atomic single-use code redemption + verification-value validation, TS
    ``checkVerificationValue`` (token.ts:1361). Returns the value, the stored code id, the
    effective resources and the resources the grant authorized."""
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
    # RFC 8707: the token request may narrow the resources bound at /authorize, never widen
    # them (b4b086722). The top-level field wins over the legacy query.resource.
    stored = to_resource_list(value.get("resource")) or to_resource_list(
        value["query"].get("resource")
    )
    if resources and stored:
        for resource in resources:
            if resource not in stored:
                raise OAuthError(400, "invalid_target", "requested resource not authorized")
    return value, code_id, resources or stored, stored


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

    resources = to_resource_list(body.get("resource"))
    value, code_id, effective_resources, authorized_resources = await _check_verification_value(
        ctx, opts, code, client_id, redirect_uri, resources
    )
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
        requested_user_info_claims=get_requested_user_info_claims(
            query.get("claims"), get_supported_claims(opts)
        ),
        resources=effective_resources,
        original_resources=authorized_resources,
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
        client=client,
        scopes=requested_scopes,
        grant_type="client_credentials",
        resources=to_resource_list(body.get("resource")),
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
    # A refresh request may narrow the grant's resources, never widen them (token.ts:1868).
    resources = to_resource_list(body.get("resource"))
    stored_resources = refresh_token.get("resources")
    if resources and stored_resources and not all(r in stored_resources for r in resources):
        raise OAuthError(400, "invalid_target", "requested resource invalid")

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
            request = await _resolve_replay_request(
                ctx,
                opts,
                client=client,
                refresh_token=refresh_token,
                scopes=requested_scopes or scopes or [],
                resources=resources or stored_resources,
            )
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
        client=client,
        scopes=requested_scopes or scopes,
        user=user,
        grant_type="refresh_token",
        reference_id=refresh_token.get("referenceId"),
        session_id=refresh_token.get("sessionId"),
        refresh_token=refresh_token,
        auth_time=auth_time,
        authorization_code_id=refresh_token.get("authorizationCodeId"),
        resources=resources or stored_resources,
        requested_user_info_claims=refresh_token.get("requestedUserInfoClaims"),
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
    # ``resource: ResourceUriSchema | ResourceUriSchema[]`` (oauth.ts:919). A malformed or
    # wrong-typed value fails the zod union ("Invalid input"); the refinements that pass the
    # absolute-URI gate report their own message. Neither maps to invalid_target there.
    resource = body.get("resource")
    if resource is not None:
        issue = _resource_issue(resource)
        if issue:
            raise OAuthError(400, "invalid_request", f"resource: {issue}")


def _resource_issue(resource: Any) -> str | None:
    if isinstance(resource, str):
        issue = resource_uri_issue(resource)
        return "Invalid input" if issue == "resource must be an absolute URI" else issue
    if isinstance(resource, list):
        if not resource:
            return "Too small: expected array to have >=1 items"
        if all(isinstance(r, str) for r in resource):
            issues = [resource_uri_issue(r) for r in resource]
            if "resource must be an absolute URI" in issues:
                return "Invalid input"
            first = next((i for i in issues if i), None)
            return first
    return "Invalid input"


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
    # RFC 8707 §2: keep every repeated form ``resource`` (oauth.ts:1063).
    repeated = extract_repeated_resource_from_form(ctx)
    if repeated and len(repeated) > 1:
        body["resource"] = repeated
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
