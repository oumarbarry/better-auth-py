"""Session lifecycle and cookies, following better-auth semantics exactly.

Default cookie: ``better-auth.session_token`` (``__Secure-`` prefixed over HTTPS),
value = URI-encoded ``{token}.{base64(hmac_sha256(secret, token))}``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from .adapters.base import Where
from .crypto import generate_id, sign_value, unsign_value
from .ip import get_request_ip
from .types import AuthRequest

if TYPE_CHECKING:
    from .auth import BetterAuth
    from .types import Ctx

DONT_REMEMBER_EXPIRES_IN = 60 * 60 * 24  # 1 day, like better-auth


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def cookie_name(auth: BetterAuth, base: str = "session_token") -> str:
    name = f"{auth.cookie_prefix}.{base}"
    return f"__Secure-{name}" if auth.use_secure_cookies else name


def build_cookie(
    auth: BetterAuth,
    value: str,
    max_age: int | None,
    base: str = "session_token",
    *,
    http_only: bool = True,
) -> str:
    """Build a Set-Cookie value inheriting the session cookie's derived attributes
    (SameSite/Secure/Domain/prefix). ``http_only=False`` emits a JS-readable cookie
    (e.g. last-login-method) that still inherits those attributes."""
    parts = [f"{cookie_name(auth, base)}={value}", "Path=/"]
    if http_only:
        parts.append("HttpOnly")
    parts.append("SameSite=Lax")
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    if auth.use_secure_cookies:
        parts.append("Secure")
    if auth.cookie_domain:
        parts.append(f"Domain={auth.cookie_domain}")
    return "; ".join(parts)


def clear_cookie(auth: BetterAuth, base: str = "session_token") -> str:
    return build_cookie(auth, "", 0, base)


def delete_session_cookies(auth: BetterAuth) -> list[str]:
    """``deleteSessionCookie`` (cookies/index.ts:517-555): the session token, the cookie
    cache and the dont-remember marker all expire."""
    return [
        clear_cookie(auth),
        clear_cookie(auth, "session_data"),
        clear_cookie(auth, "dont_remember"),
    ]


def read_token(auth: BetterAuth, request: AuthRequest) -> str | None:
    """Signed token from the session cookie, or an `Authorization: Bearer` header
    (bearer is a plugin in better-auth TS; built in here for API-first apps).

    The cookie value must carry a valid signature; a bearer header may be either the
    signed value or the raw session token returned by sign-in/sign-up.
    """
    raw = request.cookies().get(cookie_name(auth))
    if raw is not None:
        return unsign_value(auth.secret, raw)
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        bearer = authorization[7:].strip()
        return unsign_value(auth.secret, bearer) or bearer
    return None


async def create_session(
    auth: BetterAuth,
    user_id: str,
    request: AuthRequest,
    remember_me: bool = True,
    user: dict[str, Any] | None = None,
    ctx: Ctx | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Create a DB session and return ``(session, set_cookie_values)``.

    When the cookie cache is enabled, also emits the signed ``session_data`` cache
    cookie (reading the user when not given) so the next ``/get-session`` can skip the DB.

    When ``ctx`` is given, records ``ctx.new_session = {"session", "user"}`` so
    after-hooks can detect this request created a session (TS ``setNewSession``).
    Every core session-creation path funnels through here, so the signal fires on
    all of them.
    """
    now = utcnow()
    expires_in = auth.session_options.expires_in if remember_me else DONT_REMEMBER_EXPIRES_IN
    session = {
        "id": generate_id(),
        "token": generate_id(32),
        "userId": user_id,
        "expiresAt": now + timedelta(seconds=expires_in),
        "ipAddress": get_request_ip(request, auth.ip_address) or "",
        "userAgent": request.headers.get("user-agent", ""),
        "createdAt": now,
        "updatedAt": now,
    }
    await auth.internal.create("session", session)  # routes through databaseHooks
    signed = sign_value(auth.secret, session["token"])
    if remember_me:
        cookies = [
            build_cookie(auth, signed, auth.session_options.expires_in),
            clear_cookie(auth, "dont_remember"),
        ]
    else:
        # browser-session cookie + marker so the session is never refreshed
        cookies = [
            build_cookie(auth, signed, None),
            build_cookie(auth, "true", None, "dont_remember"),
        ]
    # setSessionCookie always writes the cache next to the token (cookies/index.ts:350-392)
    cache_on = auth.session_options.cookie_cache.enabled
    if user is None and (ctx is not None or cache_on):
        user = await auth.adapter.find_one("user", [Where("id", user_id)])
    if user is not None and cache_on:
        from .cookie_cache import set_cookie_cache_async

        cache_cookie = await set_cookie_cache_async(auth, session, user, not remember_me)
        if cache_cookie is not None:
            cookies.append(cache_cookie)
    if ctx is not None:
        ctx.new_session = {"session": session, "user": user}
    return session, cookies


def refresh_session_cookie(auth: BetterAuth, request: AuthRequest, token: str) -> str:
    """Re-issue the ``session_token`` cookie for an already-valid session, honouring
    the existing `dont_remember` (browser-session) marker. :func:`set_session_cookies`
    also refreshes the cookie cache."""
    dont_remember = cookie_name(auth, "dont_remember") in request.cookies()
    max_age = None if dont_remember else auth.session_options.expires_in
    return build_cookie(auth, sign_value(auth.secret, token), max_age)


async def set_session_cookies(
    auth: BetterAuth, request: AuthRequest, session: dict[str, Any], user: dict[str, Any]
) -> list[str]:
    """TS ``setSessionCookie`` for an existing session (cookies/index.ts:350-392): the
    token cookie plus the cookie cache rebuilt from the current session and user."""
    from .cookie_cache import set_cookie_cache_async

    cookies = [refresh_session_cookie(auth, request, session["token"])]
    dont_remember = cookie_name(auth, "dont_remember") in request.cookies()
    cache_cookie = await set_cookie_cache_async(auth, session, user, dont_remember)
    if cache_cookie is not None:
        cookies.append(cache_cookie)
    return cookies


async def get_session(
    auth: BetterAuth,
    request: AuthRequest,
    disable_cache: bool = False,
    disable_refresh: bool = False,
    is_post_request: bool = False,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate the request's session.

    Returns ``({"session": ..., "user": ...} | None, set_cookie_values)``.
    Expired sessions are deleted (and the cookie cleared); `expiresAt` slides forward
    by `expires_in` once the session is older than `update_age` (better-auth's formula).

    When ``session.cookieCache`` is enabled and a valid ``session_data`` cookie is
    present, the cached ``{session, user}`` is returned without a DB read (unless
    ``disable_cache``). On a real DB read the cache is refreshed.

    ``session.deferSessionRefresh`` moves every write to POST /get-session: unless
    ``is_post_request``, no row is refreshed or deleted and the result carries
    ``needsRefresh`` (session.ts:385-389, 437-455). Only that POST handler passes
    ``is_post_request=True`` — TS pins ``method: "GET"`` for every other session read
    (getSessionFromCtx, session.ts:563).
    """
    from .cookie_cache import cache_is_current, decode_cookie_cache, expire_cookie_cache

    cookies: list[str] = []
    cache_enabled = auth.session_options.cookie_cache.enabled
    token = read_token(auth, request)
    if token is None and cache_enabled:
        return None, []
    # session.ts:84-171 (v1.7.6): a session_data cookie is only honoured while the cache
    # is on, for the session_token it was issued with; any other one is expired.
    cache_value = request.cookies().get(cookie_name(auth, "session_data"))
    if cache_value and not cache_enabled:
        cookies.append(expire_cookie_cache(auth))  # 7ec71461f
    if token is None:
        return None, cookies
    if cache_enabled and not disable_cache and cache_value:
        decoded = await decode_cookie_cache(auth, cache_value)
        if (
            decoded is not None
            and decoded[0]["session"]["token"] == token
            and cache_is_current(auth, decoded)
        ):
            return {"session": decoded[0]["session"], "user": decoded[0]["user"]}, []
        cookies.append(expire_cookie_cache(auth))

    session = await auth.adapter.find_one("session", [Where("token", token)])
    if session is None:
        return None, [*cookies, *delete_session_cookies(auth)]

    now = utcnow()
    options = auth.session_options
    # writes are deferred to POST /get-session (session.ts:80, 387)
    defer = options.defer_session_refresh and not is_post_request
    if session["expiresAt"] <= now:
        if not defer:
            await auth.internal.delete_many("session", [Where("token", token)])
        return None, [*cookies, *delete_session_cookies(auth)]

    dont_remember = cookie_name(auth, "dont_remember") in request.cookies()
    due_at = (
        session["expiresAt"]
        - timedelta(seconds=options.expires_in)
        + timedelta(seconds=options.update_age)
    )
    # TS folds `session.disableSessionRefresh` into the query flag for this decision only
    # (session.ts:429-435); the flag then gates both the write and `needsRefresh`.
    needs_refresh = due_at <= now and not (disable_refresh or options.disable_session_refresh)
    if needs_refresh and not dont_remember and not defer:
        session = (
            await auth.internal.update(
                "session",
                [Where("token", token)],
                {"expiresAt": now + timedelta(seconds=options.expires_in), "updatedAt": now},
            )
            or session
        )
        cookies.append(build_cookie(auth, sign_value(auth.secret, token), options.expires_in))

    user = await auth.adapter.find_one("user", [Where("id", session["userId"])])
    if user is None:
        return None, [*cookies, *delete_session_cookies(auth)]

    if options.cookie_cache.enabled:
        from .cookie_cache import set_cookie_cache_async

        cache_cookie = await set_cookie_cache_async(auth, session, user, dont_remember)
        if cache_cookie is not None:
            cookies.append(cache_cookie)

    result = {"session": session, "user": user}
    if defer and not dont_remember and not disable_refresh:
        # TS returns early — without the flag — when the *request* opted out of refreshing
        # (session.ts:397-410, query-only), so `needsRefresh` only exists on the deferred read.
        result["needsRefresh"] = needs_refresh
    return result, cookies
