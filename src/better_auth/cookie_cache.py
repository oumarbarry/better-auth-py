"""Signed ``session_data`` cookie cache (better-auth ``cookies/index.ts``, ``cache.ts``,
``jwt.ts``).

Two strategies are ported. ``compact`` (the TS default): the payload
``{session, user, updatedAt, version}`` is HMAC-SHA256 signed (base64urlnopad) and the
whole envelope ``{session, expiresAt, signature}`` is base64url-encoded. ``jwt``: the
payload is an HS256 JWT signed with the secret, or, when the JWT plugin runs with
``session_cookie_cache=True``, a JWT signed with the plugin's JWKS keys that other
services can check with :func:`verify_session_cookie_jwt_with_jwks`. A cache hit on
``/get-session`` returns without touching the DB.

ponytail: the jwe strategy and cookie chunking are not ported; compact or jwt and small
payloads cover the common case. Add chunking if a session's cached payload nears 4 KB.
"""

from __future__ import annotations

import hmac
import json
import logging
import math
import re
import time
from collections.abc import Awaitable
from typing import TYPE_CHECKING, Any, Protocol

import jwt as pyjwt

from .crypto import b64url_decode_nopad, b64url_encode_nopad, sign_hmac_b64url
from .session import build_cookie, cookie_name
from .types import AuthRequest, json_default

if TYPE_CHECKING:
    from .auth import BetterAuth

logger = logging.getLogger("better_auth")

#: cookies/jwt.ts:6-8
SESSION_COOKIE_JWT_TYPE = "better-auth.session-cache+jwt"
SESSION_COOKIE_JWT_AUDIENCE = "better-auth:session-cache"
SESSION_COOKIE_JWT_ISSUER = "better-auth:session-cache"

#: A decoded cache: ``(payload, expires_at_ms)``.
Decoded = tuple[dict[str, Any], float]


class CookieCacheSigner(Protocol):
    """TS ``CookieCacheSigner`` (core types/cookie.ts): set by the JWT plugin on
    ``auth.cookie_cache_signer`` to sign ``jwt``-strategy caches with its JWKS keys."""

    def sign(self, auth: BetterAuth, payload: dict[str, Any], expires_in: int) -> Awaitable[str]:
        """The cookie value for ``payload``, valid ``expires_in`` seconds."""
        ...

    def verify(self, auth: BetterAuth, token: str) -> Awaitable[Decoded | None]:
        """The payload and its expiry, or None when the value does not verify."""
        ...


def _dumps(value: Any) -> str:
    return json.dumps(value, default=json_default, separators=(",", ":"))


# --- payload schema (cookies/cache.ts:7-39) ----------------------------------------------

_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def _is_date(value: Any) -> bool:
    return isinstance(value, str) and bool(_ISO_DATE.match(value))


def _payload_issues(payload: Any) -> list[dict[str, Any]]:
    """Mirror of the zod ``cookieCachePayloadSchema`` checks, as ``{code, path}`` issues."""
    if not isinstance(payload, dict):
        return [{"code": "invalid_type", "path": []}]
    issues: list[dict[str, Any]] = []

    def check(path: list[str], ok: bool) -> None:
        if not ok:
            issues.append({"code": "invalid_type", "path": path})

    session, user = payload.get("session"), payload.get("user")
    check(["session"], isinstance(session, dict))
    check(["user"], isinstance(user, dict))
    if isinstance(session, dict):
        check(["session", "id"], isinstance(session.get("id"), str))
        check(["session", "userId"], session.get("userId") is not None)
        check(["session", "expiresAt"], _is_date(session.get("expiresAt")))
        check(["session", "token"], isinstance(session.get("token"), str))
        for key in ("ipAddress", "userAgent"):
            check(["session", key], session.get(key) is None or isinstance(session[key], str))
        for key in ("createdAt", "updatedAt"):
            check(["session", key], key not in session or _is_date(session[key]))
    if isinstance(user, dict):
        for key in ("id", "email", "name"):
            check(["user", key], isinstance(user.get(key), str))
        check(["user", "emailVerified"], isinstance(user.get("emailVerified", False), bool))
        check(["user", "image"], user.get("image") is None or isinstance(user["image"], str))
        for key in ("createdAt", "updatedAt"):
            check(["user", key], key not in user or _is_date(user[key]))
    updated_at = payload.get("updatedAt")
    check(["updatedAt"], isinstance(updated_at, (int, float)) and not isinstance(updated_at, bool))
    check(["version"], payload.get("version") is None or isinstance(payload["version"], str))
    return issues


def parse_cookie_cache_payload(payload: Any) -> dict[str, Any] | None:
    """The payload when it has the cache shape, else None with a warning (c7a5c1a7e)."""
    if payload is None:
        return None
    issues = _payload_issues(payload)
    if not issues:
        return payload
    logger.warning("Cookie cache payload failed schema validation", extra={"issues": issues})
    return None


def parse_session_cookie_jwt_payload(claims: dict[str, Any]) -> dict[str, Any] | None:
    """cookies/jwt.ts:34-50: the cache payload of a JWKS-signed cookie JWT, bound to its
    ``sub`` (user id) and ``sid`` (session token) claims."""
    data = parse_cookie_cache_payload(claims)
    if data is None or not isinstance(claims.get("iss"), str) or not claims["iss"]:
        return None
    if claims.get("sub") != data["user"]["id"] or claims.get("sid") != data["session"]["token"]:
        return None
    return data


def verify_session_cookie_jwt_with_jwks(
    token: str,
    jwks: dict[str, Any],
    *,
    issuer: str | None = None,
    audience: str | None = None,
) -> dict[str, Any] | None:
    """Check a JWKS-signed ``session_data`` cookie against a published key set, for a
    service that shares the cookie but not the database (cookies/jwt.ts:52-87)."""
    from .plugins_ext.jwt import key_from_jwk

    try:
        header = pyjwt.get_unverified_header(token)
        if header.get("typ") != SESSION_COOKIE_JWT_TYPE or not header.get("kid"):
            return None
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == header["kid"]), None)
        alg = (key or {}).get("alg") or header.get("alg")
        if key is None or not alg:
            return None
        claims = pyjwt.decode(
            token,
            key_from_jwk(key),
            algorithms=[alg],
            audience=audience or SESSION_COOKIE_JWT_AUDIENCE,
            issuer=issuer,
            leeway=15,
        )
    except Exception:
        return None
    return parse_session_cookie_jwt_payload(claims)


# --- encode ------------------------------------------------------------------------------


def _cache_payload(auth: BetterAuth, session: dict[str, Any], user: dict[str, Any]) -> dict:
    """The payload with dates as JS ``toISOString`` strings, as ``JSON.stringify`` writes
    them (so naive or non-UTC datetimes still pass the schema on the way back)."""
    from .internal_adapter import _dumps as _js_dumps

    return json.loads(
        _js_dumps(
            {
                "session": auth.parse_session_output(session),
                "user": auth.parse_user_output(user),
                "updatedAt": int(time.time() * 1000),
                "version": auth.session_options.cookie_cache.version,
            }
        )
    )


def _encode(auth: BetterAuth, payload: dict[str, Any], max_age: int | None) -> str:
    """``max_age`` is None for a browser-session cookie: the compact window is then 60s
    and a JWT lives 300s (cookies/index.ts:184-236)."""
    if auth.session_options.cookie_cache.strategy == "jwt":
        # crypto/jwt.ts:14-26 signJWT: HS256 over the secret, header {alg} only
        now = math.floor(time.time())
        claims = {**payload, "iat": now, "exp": now + (max_age or 60 * 5)}
        return pyjwt.encode(claims, auth.secret, algorithm="HS256", headers={"typ": None})
    expires_at = int(time.time() * 1000) + (max_age or 60) * 1000
    signature = sign_hmac_b64url(auth.secret, _dumps({**payload, "expiresAt": expires_at}))
    envelope = {"session": payload, "expiresAt": expires_at, "signature": signature}
    return b64url_encode_nopad(_dumps(envelope).encode())


def make_cache_value(auth: BetterAuth, session: dict[str, Any], user: dict[str, Any]) -> str:
    cache = auth.session_options.cookie_cache
    return _encode(auth, _cache_payload(auth, session, user), cache.max_age)


def _signer(auth: BetterAuth) -> CookieCacheSigner | None:
    """The JWT plugin's signer when it owns a ``jwt``-strategy cache."""
    if auth.session_options.cookie_cache.strategy != "jwt":
        return None
    return getattr(auth, "cookie_cache_signer", None)


def set_cookie_cache(
    auth: BetterAuth, session: dict[str, Any], user: dict[str, Any], dont_remember: bool
) -> str | None:
    """The ``Set-Cookie`` for the session_data cache, or None when caching is off.

    ponytail: with a JWKS signer the value needs an async key lookup, so this sync
    entry point skips the cache (a DB read serves the next request). Core session
    paths call :func:`set_cookie_cache_async`; move plugin callers to it as needed.
    """
    if not auth.session_options.cookie_cache.enabled or _signer(auth) is not None:
        return None
    max_age = None if dont_remember else auth.session_options.cookie_cache.max_age
    value = _encode(auth, _cache_payload(auth, session, user), max_age)
    return build_cookie(auth, value, max_age, "session_data")


async def set_cookie_cache_async(
    auth: BetterAuth, session: dict[str, Any], user: dict[str, Any], dont_remember: bool
) -> str | None:
    """:func:`set_cookie_cache`, signing through the JWT plugin when it owns the cache
    (cookies/index.ts:202-210)."""
    cache = auth.session_options.cookie_cache
    if not cache.enabled:
        return None
    signer = _signer(auth)
    if signer is None:
        return set_cookie_cache(auth, session, user, dont_remember)
    payload = _cache_payload(auth, session, user)
    max_age = None if dont_remember else cache.max_age
    value = await signer.sign(auth, payload, max_age or 60 * 5)
    return build_cookie(auth, value, max_age, "session_data")


def clear_cookie_cache(auth: BetterAuth) -> str | None:
    if not auth.session_options.cookie_cache.enabled:
        return None
    return expire_cookie_cache(auth)


def expire_cookie_cache(auth: BetterAuth) -> str:
    """``expireCookie(sessionData)``: always emitted, whatever the cache setting."""
    return build_cookie(auth, "", 0, "session_data")


# --- decode ------------------------------------------------------------------------------


def _decode_sync(auth: BetterAuth, value: str) -> Decoded | None:
    if auth.session_options.cookie_cache.strategy == "jwt":
        try:
            claims = pyjwt.decode(value, auth.secret, algorithms=["HS256"])
        except Exception:
            return None
        payload = parse_cookie_cache_payload(claims)
        if payload is None:
            return None
        exp = claims.get("exp")
        return payload, exp * 1000 if exp else time.time() * 1000
    try:
        envelope = json.loads(b64url_decode_nopad(value))
    except (ValueError, TypeError):
        return None
    if not isinstance(envelope, dict):
        return None
    payload, signature, expires_at = (
        envelope.get("session"),
        envelope.get("signature"),
        envelope.get("expiresAt"),
    )
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return None
    if not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool):
        return None
    expected = sign_hmac_b64url(auth.secret, _dumps({**payload, "expiresAt": expires_at}))
    if not hmac.compare_digest(signature, expected):
        return None
    parsed = parse_cookie_cache_payload(payload)
    return (parsed, expires_at) if parsed is not None else None


async def decode_cookie_cache(auth: BetterAuth, value: str) -> Decoded | None:
    """cookies/index.ts:271-348 ``decodeCookieCache``."""
    signer = _signer(auth)
    if signer is not None:
        return await signer.verify(auth, value)
    return _decode_sync(auth, value)


def cache_is_current(auth: BetterAuth, decoded: Decoded) -> bool:
    """Version match, then neither the cache window nor the cached session has ended
    (session.ts:138-167)."""
    payload, expires_at = decoded
    if (payload.get("version") or "1") != auth.session_options.cookie_cache.version:
        return False
    now_ms = time.time() * 1000
    session_expiry = _to_ms(payload["session"].get("expiresAt"))
    return expires_at >= now_ms and math.isfinite(session_expiry) and session_expiry >= now_ms


def get_cookie_cache(auth: BetterAuth, request: AuthRequest) -> dict[str, Any] | None:
    """Decode+verify the session_data cookie, or None if absent/invalid/stale."""
    if not auth.session_options.cookie_cache.enabled or _signer(auth) is not None:
        return None
    raw = request.cookies().get(cookie_name(auth, "session_data"))
    decoded = _decode_sync(auth, raw) if raw else None
    if decoded is None or not cache_is_current(auth, decoded):
        return None
    return {"session": decoded[0]["session"], "user": decoded[0]["user"]}


def _to_ms(value: Any) -> float:
    """Epoch ms from an ISO string; NaN when it does not parse (``new Date`` semantics)."""
    from datetime import datetime

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() * 1000
    except ValueError:
        return float("nan")
