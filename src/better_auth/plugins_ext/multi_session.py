"""multi-session — keep several device sessions signed in at once and switch/revoke
between them via per-session cookies.

Port of TS `packages/better-auth/src/plugins/multi-session/index.ts` (+
`error-codes.ts`). See `docs/plans/gap/05-plugins-core.md` "multi-session".

Cookie scheme: alongside the main session cookie, this plugin sets one ADDITIONAL
signed cookie per device session, named ``"<sessionCookieName>_multi-<token.lower()>"``
(value = ``sign_value(secret, token)``, same attributes/max-age as the main session
cookie). A cookie is "a multi-session cookie" iff its name contains ``"_multi-"`` (TS
``isMultiSessionCookie``). Capped at ``maximum_sessions`` (default 5): once the count
of distinct device-session cookies would exceed the cap, a fresh sign-in still gets its
*main* session cookie but no additional per-device slot (TS: silently skipped, not an
error).

Security: `set-active`/`revoke` act on the token proven by the *signed cookie value*
found at the name built from the request body's `sessionToken`, never on the body
value itself — the signature covers the value, not the cookie's name, so a request
can't pair a validly-signed cookie with an unrelated token to act on a session it
holds no cookie for.
"""

from __future__ import annotations

from typing import Any, ClassVar

from ..cookie_cache import set_cookie_cache
from ..crypto import sign_value, unsign_value
from ..endpoints import require_fields
from ..plugins import HookSet, Plugin, PluginHook, Route
from ..session import build_cookie, clear_cookie, cookie_name, refresh_session_cookie, utcnow
from ..types import APIError, AuthResponse, Ctx

#: TS `MULTI_SESSION_ERROR_CODES` (error-codes.ts).
ERROR_CODES: dict[str, str] = {"INVALID_SESSION_TOKEN": "Invalid session token"}


def _err(status: int, code: str) -> APIError:
    return APIError(status, code, ERROR_CODES[code])


def _is_multi_session_cookie(key: str) -> bool:
    return "_multi-" in key


def _multi_base(token: str) -> str:
    """The `build_cookie`/`clear_cookie` ``base`` for `token`'s per-device cookie.

    TS names the cookie ``${sessionCookieName}_multi-${token.toLowerCase()}``;
    ``cookie_name(auth, _multi_base(token))`` reproduces that exact string, since
    `cookie_name` already wraps ``{prefix}.{base}`` in the secure prefix the same way
    TS wraps its whole computed name.
    """
    return f"session_token_multi-{token.lower()}"


async def _activate(ctx: Ctx, response: AuthResponse, item: dict[str, Any]) -> None:
    """Point the main session cookie at `item` (TS `setSessionCookie`): refresh the
    signed session_token cookie, refresh the cookie cache, and record
    `ctx.new_session` so this plugin's own (and other plugins') after-hooks see it."""
    token = item["session"]["token"]
    response.set_cookie(refresh_session_cookie(ctx.auth, ctx.request, token))
    dont_remember = cookie_name(ctx.auth, "dont_remember") in ctx.request.cookies()
    cache_cookie = set_cookie_cache(ctx.auth, item["session"], item["user"], dont_remember)
    if cache_cookie is not None:
        response.set_cookie(cache_cookie)
    ctx.new_session = {"session": item["session"], "user": item["user"]}


class MultiSessionPlugin(Plugin):
    """TS `multiSession()` — see module docstring for the source file."""

    id = "multi-session"
    error_codes: ClassVar[dict[str, str]] = ERROR_CODES

    def __init__(self, *, maximum_sessions: int = 5) -> None:
        self.maximum_sessions = maximum_sessions

    def routes(self) -> list[Route]:
        return [
            ("GET", "/multi-session/list-device-sessions", self.list_device_sessions),
            ("POST", "/multi-session/set-active", self.set_active_session),
            ("POST", "/multi-session/revoke", self.revoke_device_session),
        ]

    def hooks(self) -> HookSet:
        return HookSet(
            after=[
                PluginHook(matcher=lambda ctx: True, handler=self._after_new_session),
                PluginHook(
                    matcher=lambda ctx: ctx.request.path == "/sign-out",
                    handler=self._after_sign_out,
                ),
            ]
        )

    # --- endpoints -----------------------------------------------------------------

    async def list_device_sessions(self, ctx: Ctx) -> AuthResponse:
        """GET /multi-session/list-device-sessions — every still-valid session named
        by a `_multi-` cookie on the request, de-duped to one entry per user id."""
        request_cookies = ctx.request.cookies()
        tokens: list[str] = []
        for key, raw in request_cookies.items():
            if not _is_multi_session_cookie(key):
                continue
            token = unsign_value(ctx.auth.secret, raw)
            if token:
                tokens.append(token)
        if not tokens:
            return AuthResponse(body=[])

        now = utcnow()
        seen_users: set[str] = set()
        body: list[dict[str, Any]] = []
        for token in tokens:
            item = await ctx.internal.find_session(token)
            if item is None or item["session"]["expiresAt"] <= now:
                continue
            user_id = item["user"]["id"]
            if user_id in seen_users:
                continue
            seen_users.add(user_id)
            body.append(
                {
                    "session": ctx.auth.parse_session_output(item["session"]),
                    "user": ctx.auth.parse_user_output(item["user"]),
                }
            )
        return AuthResponse(body=body)

    async def set_active_session(self, ctx: Ctx) -> AuthResponse:
        """POST /multi-session/set-active — switch the main session cookie to the
        session proven by the signed `_multi-` cookie named after `sessionToken`."""
        body = ctx.body()
        require_fields(body, "sessionToken")
        multi_base = _multi_base(body["sessionToken"])
        raw = ctx.request.cookies().get(cookie_name(ctx.auth, multi_base))
        token = unsign_value(ctx.auth.secret, raw) if raw is not None else None
        if token is None:
            raise _err(401, "INVALID_SESSION_TOKEN")

        item = await ctx.internal.find_session(token)
        if item is None or item["session"]["expiresAt"] < utcnow():
            response = AuthResponse(
                status=401,
                body={
                    "code": "INVALID_SESSION_TOKEN",
                    "message": ERROR_CODES["INVALID_SESSION_TOKEN"],
                },
            )
            response.set_cookie(clear_cookie(ctx.auth, multi_base))
            return response

        response = AuthResponse(
            body={
                "session": ctx.auth.parse_session_output(item["session"]),
                "user": ctx.auth.parse_user_output(item["user"]),
            }
        )
        await _activate(ctx, response, item)
        return response

    async def revoke_device_session(self, ctx: Ctx) -> AuthResponse:
        """POST /multi-session/revoke — delete the session proven by the signed
        `_multi-` cookie named after `sessionToken` and clear that cookie. If it was
        the active session, promote the next still-valid device session (or clear the
        main cookie entirely when none remain). Requires an active session (TS
        `sessionMiddleware`)."""
        active = await ctx.require_session()
        body = ctx.body()
        require_fields(body, "sessionToken")
        multi_base = _multi_base(body["sessionToken"])
        raw = ctx.request.cookies().get(cookie_name(ctx.auth, multi_base))
        token = unsign_value(ctx.auth.secret, raw) if raw is not None else None
        if token is None:
            raise _err(401, "INVALID_SESSION_TOKEN")

        # Revoke the session proven by the signed cookie value, not the
        # request-named token (see module docstring).
        await ctx.internal.delete_session(token)
        response = AuthResponse(body={"status": True})
        response.set_cookie(clear_cookie(ctx.auth, multi_base))

        if active["session"]["token"] != token:
            return response

        request_cookies = ctx.request.cookies()
        now = utcnow()
        valid_sessions: list[dict[str, Any]] = []
        for key, raw_value in request_cookies.items():
            if not _is_multi_session_cookie(key):
                continue
            candidate = unsign_value(ctx.auth.secret, raw_value)
            if not candidate:
                continue
            item = await ctx.internal.find_session(candidate)
            if item is not None and item["session"]["expiresAt"] > now:
                valid_sessions.append(item)

        if valid_sessions:
            await _activate(ctx, response, valid_sessions[0])
        else:
            response.set_cookie(clear_cookie(ctx.auth))
            response.set_cookie(clear_cookie(ctx.auth, "dont_remember"))
        return response

    # --- hooks -----------------------------------------------------------------

    async def _after_new_session(self, ctx: Ctx) -> None:
        """TS `hooks.after[0]` (matcher `() => true`): when this response set a
        session cookie for a freshly-created/switched session, add its per-device
        cookie (unless at `maximum_sessions`) and drop any stale device cookie
        already held for the same user."""
        response = ctx.response
        if not isinstance(response, AuthResponse):
            return None
        initial_cookies = [v for k, v in response.headers if k.lower() == "set-cookie"]
        if not initial_cookies:
            return None
        new_session = ctx.new_session
        if new_session is None:
            return None

        session_token = new_session["session"]["token"]
        target_base = _multi_base(session_token)
        target_name = cookie_name(ctx.auth, target_base)

        set_cookie_names = {v.split(";", 1)[0].split("=", 1)[0].strip() for v in initial_cookies}
        request_cookies = ctx.request.cookies()
        if target_name in set_cookie_names or target_name in request_cookies:
            return None

        multi_keys = [k for k in request_cookies if _is_multi_session_cookie(k)]
        tokens_to_delete: list[str] = []
        for key in multi_keys:
            token = unsign_value(ctx.auth.secret, request_cookies[key])
            if not token:
                continue
            existing = await ctx.internal.find_session(token)
            if existing is not None and existing["user"]["id"] == new_session["user"]["id"]:
                tokens_to_delete.append(token)
                response.set_cookie(clear_cookie(ctx.auth, _multi_base(token)))
        # ponytail: singular delete_session in a loop, not the batch delete_sessions
        # ("in" operator) -- MemoryAdapter's "in" comparison unconditionally
        # lowercases the row value (adapters/memory.py _eval), so it never matches
        # mixed-case session tokens. Out of this file's ownership to fix; delete_session
        # (singular, "eq") is confirmed correct and is what the task's foundation list
        # names anyway.
        for token in tokens_to_delete:
            await ctx.internal.delete_session(token)

        main_name = cookie_name(ctx.auth)
        main_cookie_present = any(main_name in v for v in initial_cookies)
        current_count = len(multi_keys) - len(tokens_to_delete) + (1 if main_cookie_present else 0)
        if current_count > self.maximum_sessions:
            return None

        signed = sign_value(ctx.auth.secret, session_token)
        response.set_cookie(
            build_cookie(ctx.auth, signed, ctx.auth.session_options.expires_in, target_base)
        )
        return None

    async def _after_sign_out(self, ctx: Ctx) -> None:
        """TS `hooks.after[1]` (matcher `path === "/sign-out"`): revoke every device
        session named by a *validly signed* `_multi-` cookie and clear those cookies.
        An unverifiable (forged/tampered) cookie is left untouched entirely."""
        response = ctx.response
        if not isinstance(response, AuthResponse):
            return None
        request_cookies = ctx.request.cookies()
        multi_keys = [k for k in request_cookies if _is_multi_session_cookie(k)]
        if not multi_keys:
            return None

        verified_tokens: list[str] = []
        for key in multi_keys:
            token = unsign_value(ctx.auth.secret, request_cookies[key])
            if not token:
                continue
            response.set_cookie(clear_cookie(ctx.auth, _multi_base(token)))
            verified_tokens.append(token)
        # ponytail: see _after_new_session -- delete_sessions' "in" query is broken
        # in MemoryAdapter, so delete one at a time via the confirmed-good singular op.
        for token in verified_tokens:
            await ctx.internal.delete_session(token)
        return None
