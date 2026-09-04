"""JWKS fetch/cache + id-token verification (ports ``verify.ts`` / provider ``verifyIdToken``).

Needs ``cryptography`` (pyjwt's RS256/ES256 backend) — a pre-decided dependency. The JWKS
response is cached with a short TTL; on a ``kid`` cache-miss the set is refetched once so a
key rotation is picked up. The JWKS fetch goes through :func:`oauth_fetch` (SSRF guard).
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt
from jwt import PyJWK

from .machinery import oauth_fetch

_JWKS_TTL = 300  # seconds, like verify.ts
_NO_KID_COOLDOWN = 30  # seconds


class _JWKSCache:
    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._last_miss: dict[str, float] = {}

    async def keys(self, http: httpx.AsyncClient, uri: str, *, force: bool = False) -> list[dict]:
        now = time.monotonic()
        cached = self._cache.get(uri)
        if not force and cached is not None and now - cached[0] < _JWKS_TTL:
            return cached[1]
        response = await oauth_fetch(http, "GET", uri, headers={"accept": "application/json"})
        keys = response.json().get("keys", [])
        self._cache[uri] = (now, keys)
        return keys

    async def find(self, http: httpx.AsyncClient, uri: str, kid: str | None) -> dict | None:
        keys = await self.keys(http, uri)
        match = _match_kid(keys, kid)
        if match is not None:
            return match
        # kid miss: refetch once (rotation), rate-limited so we don't hammer the endpoint.
        now = time.monotonic()
        if now - self._last_miss.get(uri, 0.0) < _NO_KID_COOLDOWN:
            return None
        self._last_miss[uri] = now
        keys = await self.keys(http, uri, force=True)
        return _match_kid(keys, kid)


def _match_kid(keys: list[dict], kid: str | None) -> dict | None:
    if not keys:
        return None
    if kid is None:
        return keys[0]
    return next((k for k in keys if k.get("kid") == kid), None)


_cache = _JWKSCache()


async def verify_id_token(
    http: httpx.AsyncClient,
    token: str,
    *,
    jwks_uri: str,
    audience: str | list[str],
    issuers: list[str],
    nonce: str | None = None,
    max_age: int | None = None,
) -> dict[str, Any] | None:
    """Verify an OIDC id token's signature/issuer/audience (and optional nonce/max-age).

    Returns the decoded claims on success, ``None`` on any failure (mirrors the TS
    providers' ``verifyIdToken`` which swallows errors and returns ``null``/``false``).
    Supports RS256/ES256 (whatever ``alg`` the token header declares, resolved via JWKS).
    """
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        if not alg:
            return None
        jwk = await _cache.find(http, jwks_uri, header.get("kid"))
        if jwk is None:
            return None
        key = PyJWK.from_dict(jwk).key
        claims = jwt.decode(
            token,
            key,
            algorithms=[alg],
            audience=audience,
            issuer=issuers if len(issuers) > 1 else issuers[0],
        )
    except jwt.PyJWTError:
        return None
    if nonce is not None and claims.get("nonce") != nonce:
        return None
    if max_age is not None:
        iat = claims.get("iat")
        if iat is None or time.time() - int(iat) > max_age:
            return None
    return claims
