"""JWKS fetch/cache + id-token verification (ports ``verify.ts`` / provider ``verifyIdToken``).

Needs ``cryptography`` (pyjwt's RS256/ES256 backend) — a pre-decided dependency. The JWKS
response is cached with a short TTL; on a ``kid`` cache-miss the set is refetched once so a
key rotation is picked up. The JWKS fetch goes through :func:`oauth_fetch` (SSRF guard).
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
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

    async def find(self, http: httpx.AsyncClient, uri: str, kid: str | None) -> list[dict]:
        keys = await self.keys(http, uri)
        match = _match_kid(keys, kid)
        if match:
            return match
        # kid miss: refetch once (rotation), rate-limited so we don't hammer the endpoint.
        now = time.monotonic()
        if now - self._last_miss.get(uri, 0.0) < _NO_KID_COOLDOWN:
            return []
        self._last_miss[uri] = now
        keys = await self.keys(http, uri, force=True)
        return _match_kid(keys, kid)


def _match_kid(keys: list[dict], kid: str | None) -> list[dict]:
    """Every key sharing the ``kid`` (TS v1.7.6 google.ts:107-125 tries each one); no
    ``kid`` leaves every key as a candidate."""
    if kid is None:
        return list(keys)
    return [k for k in keys if k.get("kid") == kid]


def _nonce_matches(claim: Any, nonce: str, comparison: str) -> bool:
    """TS v1.7.6 verify-id-token.ts:15-30 ``nonceMatches``."""
    if not isinstance(claim, str):
        return False
    if claim == nonce:
        return True
    return comparison == "exact-or-sha256" and claim == hashlib.sha256(nonce.encode()).hexdigest()


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
    algorithms: list[str] | None = None,
    nonce_comparison: str = "exact",
    verify_claims: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any] | None:
    """The shared id-token verifier (TS v1.7.6 verify-id-token.ts ``verifyProviderIdToken``):
    signature via JWKS, issuer (skipped when ``issuers`` is empty), audience, optional
    max-age, nonce and a provider claim check.

    Returns the decoded claims on success, ``None`` on any failure (fail closed).
    ``algorithms`` pins the accepted JWS algorithms; unset, the token header's ``alg`` is
    accepted. Every JWKS key sharing the token's ``kid`` is tried in turn.
    """
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        if not alg or (algorithms is not None and alg not in algorithms):
            return None
        candidates = await _cache.find(http, jwks_uri, header.get("kid"))
    except (jwt.PyJWTError, httpx.HTTPError, ValueError):
        return None
    claims: dict[str, Any] | None = None
    issuer: str | list[str] | None = (
        None if not issuers else issuers if len(issuers) > 1 else issuers[0]
    )
    for jwk in candidates:
        try:
            key = PyJWK.from_dict(jwk).key
            claims = jwt.decode(
                token, key, algorithms=algorithms or [alg], audience=audience, issuer=issuer
            )
            break
        except (jwt.PyJWTError, ValueError):
            continue
    if claims is None:
        return None
    if nonce and not _nonce_matches(claims.get("nonce"), nonce, nonce_comparison):
        return None
    if max_age is not None:
        iat = claims.get("iat")
        if iat is None or time.time() - int(iat) > max_age:
            return None
    if verify_claims is not None and not verify_claims(claims):
        return None
    return claims
