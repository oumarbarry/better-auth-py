"""last-login-method — records the auth method used on the most recent successful
login, in a cookie and optionally in the DB.

Port of TS ``packages/better-auth/src/plugins/last-login-method/index.ts``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ..plugins import HookSet, Plugin, PluginHook
from ..schema import Field, Schema
from ..session import cookie_name
from ..types import AuthResponse, Ctx

if TYPE_CHECKING:
    from ..auth import BetterAuth

DEFAULT_COOKIE_NAME = "better-auth.last_used_login_method"
DEFAULT_MAX_AGE = 60 * 60 * 24 * 30  # 30 days


def _default_resolve_method(path: str, params: dict[str, str]) -> str | None:
    """TS ``defaultResolveMethod`` (index.ts:61-79)."""
    if path.startswith("/callback/") or path.startswith("/oauth2/callback/"):
        return (
            params.get("id")
            or params.get("providerId")
            or params.get("provider")
            or path.rstrip("/").rsplit("/", 1)[-1]
        )
    if path in ("/sign-in/email", "/sign-up/email"):
        return "email"
    if "siwe" in path:
        return "siwe"
    if "/passkey/verify-authentication" in path:
        return "passkey"
    if path.startswith("/magic-link/verify"):
        return "magic-link"
    return None


class LastLoginMethodPlugin(Plugin):
    id = "last-login-method"

    def __init__(
        self,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        max_age: int = DEFAULT_MAX_AGE,
        custom_resolve_method: Callable[[Ctx], str | None] | None = None,
        store_in_database: bool = False,
        schema: dict[str, Any] | None = None,
    ) -> None:
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.custom_resolve_method = custom_resolve_method
        self.store_in_database = store_in_database
        if store_in_database:
            field_name = ((schema or {}).get("user") or {}).get("lastLoginMethod") or (
                "lastLoginMethod"
            )
            # Shadows the Plugin.schema ClassVar on this instance only — the DB column
            # exists only when opted into (auth.py merges each plugin's `.schema`).
            self.schema: Schema = {
                "user": {
                    "lastLoginMethod": Field(
                        "string", input=False, required=False, field_name=field_name
                    )
                }
            }

    def init(self, auth: BetterAuth) -> None:
        if not self.store_in_database:
            return
        # ponytail: contributed via the internal-adapter's raw hooks list (not a
        # dedicated "add database hook" API) -- that's the seam plugins have for this
        # in the current port; see internal_adapter._normalize_hooks/_hook.
        auth.internal.hooks.append({"user": {"create": {"before": self._user_create_before}}})

    def hooks(self) -> HookSet:
        return HookSet(after=[PluginHook(matcher=lambda ctx: True, handler=self._after)])

    def _resolve_method(self, ctx: Ctx | None) -> str | None:
        # ponytail: TS normalizes a missing ctx.path to "" and still calls a custom
        # resolver with it; Ctx here always carries a real (possibly empty) path once
        # it exists at all, so the only "missing" case is ctx itself being None (an
        # internal caller that didn't thread it) -- treated as "no method" since there
        # is no Ctx to hand a custom resolver. Every real HTTP-dispatched request
        # (before-hooks, after-hooks, and every core user-creation call site) always
        # supplies a real ctx, so this is unreachable outside direct/internal calls.
        if ctx is None:
            return None
        if self.custom_resolve_method is not None:
            return self.custom_resolve_method(ctx)
        return _default_resolve_method(ctx.request.path, ctx.params)

    def _has_session_token(self, response: AuthResponse, auth: BetterAuth) -> bool:
        # TS: `setCookieHeaders.some(cookie => cookie.includes(sessionTokenName))` --
        # a plain substring check (not name-exact, not Max-Age aware, unlike bearer's).
        name = cookie_name(auth)
        return any(key.lower() == "set-cookie" and name in value for key, value in response.headers)

    def _build_cookie(self, auth: BetterAuth, value: str) -> str:
        """Non-httpOnly cookie inheriting the session cookie's derived SameSite/
        Secure/Domain attributes, with this plugin's own Max-Age -- but the
        configured ``cookie_name`` used verbatim as the cookie NAME. TS's
        ``ctx.setCookie`` bypasses ``createCookieGetter``/the cookie-prefix machinery
        entirely (that seam only runs for better-auth's OWN named cookies via
        ``authCookies``), so the configured name is never re-prefixed -- verified via
        custom-prefix.test.ts ("Uses exact cookie name from config, not affected by
        cookiePrefix") and cookies/index.ts's ``createCookie``/``ctx.setCookie`` split.
        """
        parts = [f"{self.cookie_name}={value}", "Path=/", "SameSite=Lax", f"Max-Age={self.max_age}"]
        if auth.use_secure_cookies:
            parts.append("Secure")
        if auth.cookie_domain:
            parts.append(f"Domain={auth.cookie_domain}")
        return "; ".join(parts)

    async def _after(self, ctx: Ctx) -> None:
        method = self._resolve_method(ctx)
        if not method:
            return None
        response = ctx.response
        if isinstance(response, AuthResponse) and self._has_session_token(response, ctx.auth):
            response.set_cookie(self._build_cookie(ctx.auth, method))
        if self.store_in_database and ctx.new_session is not None:
            user_id = ctx.new_session["user"]["id"]
            await ctx.internal.update_user(user_id, {"lastLoginMethod": method})
        return None

    async def _user_create_before(
        self, user: dict[str, Any], ctx: Ctx | None
    ) -> dict[str, Any] | None:
        method = self._resolve_method(ctx)
        if not method:
            return None
        return {"data": {**user, "lastLoginMethod": method}}
