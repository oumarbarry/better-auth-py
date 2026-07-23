"""Session lifecycle and cookies, following better-auth semantics exactly.

Default cookie: ``better-auth.session_token`` (``__Secure-`` prefixed over HTTPS),
value = URI-encoded ``{token}.{base64(hmac_sha256(secret, token))}``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from .adapters.base import Where
from .crypto import generate_id, sign_value, unsign_value
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

    When ``user`` is given and the cookie cache is enabled, also emits the signed
    ``session_data`` cache cookie so the next ``/get-session`` can skip the DB.

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
        "ipAddress": request.client_ip or "",
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
    if user is not None:
        from .cookie_cache import set_cookie_cache

        cache_cookie = set_cookie_cache(auth, session, user, not remember_me)
        if cache_cookie is not None:
            cookies.append(cache_cookie)
    if ctx is not None:
        resolved_user = user
        if resolved_user is None:
            resolved_user = await auth.adapter.find_one("user", [Where("id", user_id)])
        ctx.new_session = {"session": session, "user": resolved_user}
    return session, cookies


def refresh_session_cookie(auth: BetterAuth, request: AuthRequest, token: str) -> str:
    """Re-issue the ``session_token`` cookie for an already-valid session.

    better-auth's TS `setSessionCookie` also refreshes the (session_data) cookie
    cache with the new user payload; that cache isn't implemented here (see gap
    item 15), so this only re-signs/re-sets the plain session cookie, honouring
    the existing `dont_remember` (browser-session) marker.
    """
    dont_remember = cookie_name(auth, "dont_remember") in request.cookies()
    max_age = None if dont_remember else auth.session_options.expires_in
    return build_cookie(auth, sign_value(auth.secret, token), max_age)


async def get_session(
    auth: BetterAuth,
    request: AuthRequest,
    disable_cache: bool = False,
    disable_refresh: bool = False,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate the request's session.

    Returns ``({"session": ..., "user": ...} | None, set_cookie_values)``.
    Expired sessions are deleted (and the cookie cleared); `expiresAt` slides forward
    by `expires_in` once the session is older than `update_age` (better-auth's formula).

    When ``session.cookieCache`` is enabled and a valid ``session_data`` cookie is
    present, the cached ``{session, user}`` is returned without a DB read (unless
    ``disable_cache``). On a real DB read the cache is refreshed.
    """
    if not disable_cache:
        from .cookie_cache import get_cookie_cache

        cached = get_cookie_cache(auth, request)
        if cached is not None:
            return cached, []

    token = read_token(auth, request)
    if token is None:
        return None, []
    session = await auth.adapter.find_one("session", [Where("token", token)])
    if session is None:
        return None, [clear_cookie(auth)]

    now = utcnow()
    if session["expiresAt"] <= now:
        await auth.internal.delete_many("session", [Where("token", token)])
        return None, [clear_cookie(auth), clear_cookie(auth, "dont_remember")]

    cookies: list[str] = []
    options = auth.session_options
    dont_remember = cookie_name(auth, "dont_remember") in request.cookies()
    due_at = (
        session["expiresAt"]
        - timedelta(seconds=options.expires_in)
        + timedelta(seconds=options.update_age)
    )
    if due_at <= now and not dont_remember and not disable_refresh:
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
        return None, [clear_cookie(auth)]

    if options.cookie_cache.enabled:
        from .cookie_cache import set_cookie_cache

        cache_cookie = set_cookie_cache(auth, session, user, dont_remember)
        if cache_cookie is not None:
            cookies.append(cache_cookie)

    return {"session": session, "user": user}, cookies
