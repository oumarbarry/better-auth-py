"""``private_key_jwt`` client authentication (RFC 7523).

Port of TS ``packages/oauth-provider/src/utils/client-assertion.ts`` and the JWK-set check of
``client-jwks.ts`` at v1.7.6. The assertion is verified against the client's registered ``jwks``
(inline JSON) or ``jwksUri`` (fetched behind an SSRF gate, cached five minutes), then its ``jti``
is consumed through a single insert into ``oauthClientAssertion`` whose primary key is a digest
of ``private_key_jwt:{clientId}:{jti}``: a replay collides on the key on every real database.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt as pyjwt

from ...adapters.base import Where
from ...crypto import b64url_encode_nopad
from ...origin import is_trusted_origin
from ...types import Ctx
from ..sso.host import is_public_routable_host
from .authorize import get_issuer
from .client_crud import get_client
from .utils import CLIENT_ASSERTION_TYPE, PRIVATE_KEY_JWT_SIGNING_ALGORITHMS, OAuthError

_JWKS_CACHE_TTL_S = 5 * 60
_JWKS_CACHE_MAX_ENTRIES = 500
_JWKS_FETCH_TIMEOUT_S = 5
_MAX_JWKS_RESPONSE_BYTES = 64 * 1024
_JSON_CONTENT_TYPE = re.compile(r"^application/(?:[-\w.]+\+)?json\s*(?:;|$)", re.IGNORECASE)

#: ``{cache key: (jwks, fetched_at)}`` shared per process.
#: ponytail: one module-level cache (TS keys it per provider options object); fine while one
#: provider runs per process, key by plugin instance if several ever share one.
_jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}


def _invalid_client(description: str, status: int = 400) -> OAuthError:
    return OAuthError(status, "invalid_client", description)


# --- public JWK set validation (client-jwks.ts) --------------------------------------

_EC_ALG_BY_CURVE = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
_PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth")


def _has_str(key: dict[str, Any], name: str) -> bool:
    return isinstance(key.get(name), str) and len(key[name]) > 0


def _is_supported_public_jwk(key: dict[str, Any]) -> bool:
    kty = key.get("kty")
    if kty == "RSA":
        return _has_str(key, "n") and _has_str(key, "e")
    if kty == "EC":
        return key.get("crv") in _EC_ALG_BY_CURVE and _has_str(key, "x") and _has_str(key, "y")
    if kty == "OKP":
        return key.get("crv") == "Ed25519" and _has_str(key, "x")
    return False


def _has_supported_alg(key: dict[str, Any]) -> bool:
    if "alg" not in key:
        return True
    alg = key["alg"]
    if not isinstance(alg, str) or alg not in PRIVATE_KEY_JWT_SIGNING_ALGORITHMS:
        return False
    kty = key.get("kty")
    if kty == "RSA":
        return alg.startswith(("RS", "PS"))
    if kty == "EC":
        return _EC_ALG_BY_CURVE.get(key.get("crv")) == alg
    if kty == "OKP":
        return key.get("crv") == "Ed25519" and alg == "EdDSA"
    return False


def validate_public_client_jwks(value: Any) -> dict[str, Any]:
    """TS ``validatePublicClientJwks`` (client-jwks.ts:128): an RFC 7517 set of public asymmetric
    keys usable for ``private_key_jwt``. Returns ``{valid, jwks}`` or ``{valid, error}``."""
    keys = value.get("keys") if isinstance(value, dict) else None
    if not isinstance(keys, list) or not keys:
        return {
            "valid": False,
            "error": "jwks must be an RFC 7517 JWK Set object with a non-empty keys array",
        }
    for key in keys:
        if not isinstance(key, dict):
            return {
                "valid": False,
                "error": "jwks keys must be supported public JWKs with required key parameters",
            }
        if key.get("kty") == "oct" or "k" in key or any(m in key for m in _PRIVATE_JWK_MEMBERS):
            return {"valid": False, "error": "jwks must contain only public asymmetric keys"}
        if not _is_supported_public_jwk(key):
            return {
                "valid": False,
                "error": "jwks keys must be supported public JWKs with required key parameters",
            }
        if not _has_supported_alg(key):
            return {
                "valid": False,
                "error": "jwks key alg must be supported for private_key_jwt and compatible "
                "with its key type and signing curve",
            }
    return {"valid": True, "jwks": {"keys": keys}}


# --- JWKS resolution (client-assertion.ts:85-323) ------------------------------------


async def _validate_jwks_uri(ctx: Ctx, jwks_uri: str) -> None:
    """TS ``validateJwksUri``: HTTPS, no credentials, no fragment, a publicly routable host,
    and a trusted origin.

    ponytail: the CIMD same-origin exemption (``clientDiscoveryId``) is not ported; it arrives
    with client discovery."""
    parts = urlsplit(jwks_uri)
    if parts.scheme != "https":
        raise _invalid_client("jwks_uri must use HTTPS")
    if parts.username or parts.password:
        raise _invalid_client("jwks_uri must not contain credentials")
    if "#" in jwks_uri:
        raise _invalid_client("jwks_uri must not include a fragment component")
    if not is_public_routable_host(parts.hostname or ""):
        raise _invalid_client("jwks_uri must not point to a private or reserved address")
    if not await is_trusted_origin(ctx.auth, ctx.request, jwks_uri, allow_relative=False):
        raise _invalid_client("client jwks_uri is not trusted")


async def _fetch_jwks_from_uri(jwks_uri: str) -> dict[str, Any] | None:
    """TS ``fetchJwksFromUri``: 200 only, no redirects, JSON media type, 64 KiB cap, 5 s timeout.
    Returns the validated set, ``None`` when the body is not a usable key set, and raises on a
    transport failure (so the caller may fall back to a stale cache entry)."""
    async with (
        httpx.AsyncClient(timeout=_JWKS_FETCH_TIMEOUT_S, follow_redirects=False) as client,
        client.stream("GET", jwks_uri, headers={"accept": "application/json"}) as response,
    ):
        if response.status_code != 200:
            raise RuntimeError(f"JWKS fetch returned {response.status_code}")
        if not _JSON_CONTENT_TYPE.match(response.headers.get("content-type") or ""):
            raise RuntimeError("JWKS response must use a JSON media type")
        length = response.headers.get("content-length")
        if length and length.isdigit() and int(length) > _MAX_JWKS_RESPONSE_BYTES:
            raise RuntimeError("JWKS response exceeds 64 KiB")
        body = b""
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) > _MAX_JWKS_RESPONSE_BYTES:
                raise RuntimeError("JWKS response exceeds 64 KiB")
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    result = validate_public_client_jwks(parsed)
    return result["jwks"] if result["valid"] else None


def _cache_set(key: str, jwks: dict[str, Any], now: float) -> None:
    _jwks_cache.pop(key, None)
    _jwks_cache[key] = (jwks, now)
    if len(_jwks_cache) > _JWKS_CACHE_MAX_ENTRIES:
        _jwks_cache.pop(next(iter(_jwks_cache)))


def _cache_key(client: dict[str, Any]) -> str:
    return f"{client.get('clientDiscoveryId') or 'managed'}:{client.get('jwksUri') or ''}"


async def _fetch_client_jwks(ctx: Ctx, client: dict[str, Any]) -> dict[str, Any]:
    """TS ``fetchClientJwks``: inline ``jwks`` first, else the cached ``jwksUri`` set. A failed
    refresh serves a stale entry for up to twice the TTL, then fails closed."""
    if client.get("jwks"):
        jwks = client["jwks"]
        return json.loads(jwks) if isinstance(jwks, str) else jwks
    jwks_uri = client.get("jwksUri")
    if not jwks_uri:
        raise _invalid_client("client has no JWKS configured")
    await _validate_jwks_uri(ctx, jwks_uri)

    now = time.time()
    key = _cache_key(client)
    cached = _jwks_cache.get(key)
    if cached and now - cached[1] < _JWKS_CACHE_TTL_S:
        return cached[0]
    try:
        jwks = await _fetch_jwks_from_uri(jwks_uri)
    except Exception:
        if cached and now - cached[1] < _JWKS_CACHE_TTL_S * 2:
            return cached[0]
        raise _invalid_client("failed to fetch client JWKS") from None
    if jwks is None:
        raise _invalid_client("failed to fetch client JWKS")
    _cache_set(key, jwks, now)
    return jwks


async def _refetch_client_jwks(client: dict[str, Any]) -> dict[str, Any] | None:
    """TS ``refetchClientJwks``: bypass the cache once after a key miss (client key rotation)."""
    if not client.get("jwksUri"):
        return None
    try:
        jwks = await _fetch_jwks_from_uri(client["jwksUri"])
    except Exception:
        return None
    if jwks is not None:
        _cache_set(_cache_key(client), jwks, time.time())
    return jwks


class _NoMatchingKey(Exception):
    pass


def _verify_with_jwks(
    token: str, jwks: dict[str, Any], header: dict[str, Any], options: dict[str, Any]
) -> dict[str, Any]:
    """jose ``createLocalJWKSet`` + ``jwtVerify``: select keys by ``kid``, ``alg``, key type
    and ``use``, then try each candidate. Raises :class:`_NoMatchingKey` when none applies."""
    alg = header["alg"]
    kty = "RSA" if alg.startswith(("RS", "PS")) else "EC" if alg.startswith("ES") else "OKP"
    candidates = [
        k
        for k in jwks.get("keys") or []
        if isinstance(k, dict)
        and k.get("kty") == kty
        and (header.get("kid") is None or k.get("kid") == header.get("kid"))
        and (k.get("alg") is None or k.get("alg") == alg)
        and (k.get("use") is None or k.get("use") == "sig")
    ]
    if not candidates:
        raise _NoMatchingKey()
    last: Exception = _NoMatchingKey()
    for jwk in candidates:
        try:
            key = pyjwt.PyJWK.from_dict(jwk, algorithm=alg).key
            return pyjwt.decode(
                token,
                key,
                algorithms=[alg],
                audience=options["audience"],
                issuer=options["issuer"],
                subject=options["subject"],
                # jose leaves a future iat alone; consume_client_assertion bounds it instead.
                options={"verify_iat": False},
            )
        except Exception as exc:  # try the next candidate, like jose's multi-key iterator
            last = exc
    raise last


# --- assertion hygiene + jti replay (client-assertion.ts:346) -------------------------


async def consume_client_assertion(
    ctx: Ctx, opts: Any, *, namespace: str, payload: dict[str, Any], expected_audience: str
) -> None:
    """TS ``consumeClientAssertion``: ``aud`` includes the endpoint, ``exp`` present, unexpired
    and at most ``assertion_max_lifetime`` away, ``iat`` not older than that, and a ``jti``
    consumed by one insert keyed by ``b64url(sha256(f"{namespace}:{jti}")[:24])``."""
    aud = payload.get("aud")
    audiences = aud if isinstance(aud, list) else [] if aud is None else [aud]
    if expected_audience not in audiences:
        raise _invalid_client("client assertion aud does not match the endpoint")

    max_lifetime = getattr(opts, "assertion_max_lifetime", None) or 300
    now = math.floor(time.time())
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise _invalid_client("client assertion must include exp claim")
    if exp <= now:
        raise _invalid_client("client assertion has expired")
    if exp - now > max_lifetime:
        raise _invalid_client(
            f"client assertion exp is too far in the future (max {max_lifetime}s)"
        )
    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and not isinstance(iat, bool) and now - iat > max_lifetime:
        raise _invalid_client(f"client assertion iat is too far in the past (max {max_lifetime}s)")
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise _invalid_client("client assertion must include jti claim")

    jti_id = b64url_encode_nopad(hashlib.sha256(f"{namespace}:{jti}".encode()).digest()[:24])
    try:
        await ctx.adapter.create(
            "oauthClientAssertion",
            {"id": jti_id, "expiresAt": datetime.fromtimestamp(exp, tz=timezone.utc)},
            force_allow_id=True,
        )
    except Exception:
        try:
            used = bool(await ctx.adapter.find_one("oauthClientAssertion", [Where("id", jti_id)]))
        except Exception:
            used = False  # lookup failed: a replay cannot be confirmed, surface the insert error
        if used:
            raise _invalid_client("client assertion jti has already been used") from None
        raise


async def verify_client_assertion(
    ctx: Ctx,
    opts: Any,
    client_assertion: str,
    client_assertion_type: str,
    client_id_hint: str | None,
    expected_audience: str | None,
) -> str:
    """TS ``verifyClientAssertion`` (client-assertion.ts:455). Returns the authenticated
    ``client_id``. ``aud`` may name the serving endpoint or the issuer (801968e35)."""
    if client_assertion_type != CLIENT_ASSERTION_TYPE:
        raise _invalid_client("unsupported client_assertion_type")
    try:
        header = pyjwt.get_unverified_header(client_assertion)
    except Exception:
        raise _invalid_client("malformed client assertion: invalid JWT header") from None
    alg = header.get("alg")
    if not alg or alg not in PRIVATE_KEY_JWT_SIGNING_ALGORITHMS:
        raise _invalid_client(f"unsupported assertion signing algorithm: {alg}")
    try:
        unverified = pyjwt.decode(client_assertion, options={"verify_signature": False})
    except Exception:
        raise _invalid_client("malformed client assertion: invalid JWT payload") from None
    client_id = unverified.get("sub") or unverified.get("iss")
    if not client_id:
        raise _invalid_client(
            "client assertion must contain sub or iss claim identifying the client"
        )
    if client_id_hint and client_id_hint != client_id:
        raise _invalid_client("client_id in body does not match assertion sub/iss")

    client = await get_client(ctx, opts, client_id)
    if not client:
        raise _invalid_client("unknown client")
    if client.get("disabled"):
        raise _invalid_client("client is disabled")
    if client.get("tokenEndpointAuthMethod") != "private_key_jwt":
        raise _invalid_client("client is not registered for private_key_jwt authentication")

    jwks = await _fetch_client_jwks(ctx, client)
    base = f"{ctx.auth.base_url}{ctx.auth.base_path}"
    endpoint_audience = expected_audience or f"{base}/oauth2/token"
    accepted = list(dict.fromkeys([endpoint_audience, get_issuer(ctx, opts)]))
    options = {"issuer": client_id, "subject": client_id, "audience": accepted}
    failed = _invalid_client("client assertion signature verification failed", 401)
    try:
        payload = _verify_with_jwks(client_assertion, jwks, header, options)
    except _NoMatchingKey:
        refreshed = await _refetch_client_jwks(client)
        if refreshed is None:
            raise failed from None
        try:
            payload = _verify_with_jwks(client_assertion, refreshed, header, options)
        except Exception:
            raise failed from None
    except Exception:
        raise failed from None

    aud = payload.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    matched = next(a for a in audiences if isinstance(a, str) and a in accepted)
    await consume_client_assertion(
        ctx,
        opts,
        namespace=f"private_key_jwt:{client_id}",
        payload=payload,
        expected_audience=matched,
    )
    return client_id
