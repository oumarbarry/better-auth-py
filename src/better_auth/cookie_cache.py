"""Signed ``session_data`` cookie cache (better-auth ``cookies/index.ts``).

Only the ``compact`` strategy is ported (the TS default): the payload
``{session, user, updatedAt, version}`` is HMAC-SHA256 signed (base64urlnopad) and the
whole envelope ``{session, expiresAt, signature}`` is base64url-encoded. A cache hit on
``/get-session`` returns without touching the DB.

ponytail: jwt/jwe strategies and cookie chunking are not ported — compact + small
payloads cover the common case; add chunking if a session's cached payload nears 4 KB.
"""

from __future__ import annotations

import hmac
import json
import time
from typing import TYPE_CHECKING, Any

from .crypto import b64url_decode_nopad, b64url_encode_nopad, sign_hmac_b64url
from .session import build_cookie, cookie_name
from .types import AuthRequest, json_default

if TYPE_CHECKING:
    from .auth import BetterAuth


def _dumps(value: Any) -> str:
    return json.dumps(value, default=json_default, separators=(",", ":"))


def make_cache_value(auth: BetterAuth, session: dict[str, Any], user: dict[str, Any]) -> str:
    cache = auth.session_options.cookie_cache
    now_ms = int(time.time() * 1000)
    payload = {
        "session": auth.parse_session_output(session),
        "user": auth.parse_user_output(user),
        "updatedAt": now_ms,
        "version": cache.version,
    }
    expires_at = now_ms + cache.max_age * 1000
    signature = sign_hmac_b64url(auth.secret, _dumps({**payload, "expiresAt": expires_at}))
    envelope = {"session": payload, "expiresAt": expires_at, "signature": signature}
    return b64url_encode_nopad(_dumps(envelope).encode())


def set_cookie_cache(
    auth: BetterAuth, session: dict[str, Any], user: dict[str, Any], dont_remember: bool
) -> str | None:
    """The ``Set-Cookie`` for the session_data cache, or None when caching is off."""
    if not auth.session_options.cookie_cache.enabled:
        return None
    value = make_cache_value(auth, session, user)
    max_age = None if dont_remember else auth.session_options.cookie_cache.max_age
    return build_cookie(auth, value, max_age, "session_data")


def clear_cookie_cache(auth: BetterAuth) -> str | None:
    if not auth.session_options.cookie_cache.enabled:
        return None
    return build_cookie(auth, "", 0, "session_data")


def get_cookie_cache(auth: BetterAuth, request: AuthRequest) -> dict[str, Any] | None:
    """Decode+verify the session_data cookie, or None if absent/invalid/stale."""
    cache = auth.session_options.cookie_cache
    if not cache.enabled:
        return None
    raw = request.cookies().get(cookie_name(auth, "session_data"))
    if not raw:
        return None
    try:
        envelope = json.loads(b64url_decode_nopad(raw))
    except (ValueError, TypeError):
        return None
    payload = envelope.get("session")
    signature = envelope.get("signature")
    expires_at = envelope.get("expiresAt")
    if not isinstance(payload, dict) or not payload.get("session") or not payload.get("user"):
        return None
    expected = sign_hmac_b64url(auth.secret, _dumps({**payload, "expiresAt": expires_at}))
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        return None
    if payload.get("version", "1") != cache.version:
        return None
    now_ms = time.time() * 1000
    if isinstance(expires_at, (int, float)) and expires_at < now_ms:
        return None
    session_expiry = payload["session"].get("expiresAt")
    if session_expiry is not None and _to_ms(session_expiry) < now_ms:
        return None
    return {"session": payload["session"], "user": payload["user"]}


def _to_ms(value: Any) -> float:
    """Epoch ms from an ISO string (dates round-trip through JSON as strings)."""
    if isinstance(value, (int, float)):
        return float(value)
    from datetime import datetime

    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp() * 1000
    except ValueError:
        return float("inf")  # unparseable → treat as not-expired, DB read will settle it
