"""anonymous plugin — throwaway anonymous user + session, auto-linked and cleaned up
once the visitor signs in for real.

Verified against TS ``packages/better-auth/src/plugins/anonymous/index.ts`` (and
``schema.ts``, ``error-codes.ts``, ``types.ts``) at v1.6.23.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any, ClassVar

from ..crypto import generate_id
from ..endpoints import EMAIL_RE
from ..plugins import HookSet, Plugin, PluginHook
from ..schema import Field, Schema
from ..session import clear_cookie, cookie_name, create_session, get_session
from ..types import APIError, AuthResponse, Ctx

#: TS ``ANONYMOUS_ERROR_CODES`` (error-codes.ts) — the dict KEY is the wire ``code``
#: (TS ``defineErrorCodes`` turns each entry into ``{code: key, message: value}``,
#: and ``APIError.from(status, entry)`` puts both on the response body).
ERROR_CODES: dict[str, str] = {
    "INVALID_EMAIL_FORMAT": "Email was not generated in a valid format",
    "FAILED_TO_CREATE_USER": "Failed to create user",
    "COULD_NOT_CREATE_SESSION": "Could not create session",
    "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY": (
        "Anonymous users cannot sign in again anonymously"
    ),
    "FAILED_TO_DELETE_ANONYMOUS_USER": "Failed to delete anonymous user",
    "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS": "Failed to delete anonymous user sessions",
    "USER_IS_NOT_ANONYMOUS": "User is not anonymous",
    "DELETE_ANONYMOUS_USER_DISABLED": "Deleting anonymous users is disabled",
}

#: TS ``schema.ts`` — ``required:false`` (nullable), ``input:false`` (never taken from
#: client input), ``defaultValue:false`` (every user gets it, anonymous or not).
_SCHEMA: Schema = {
    "user": {"isAnonymous": Field("boolean", required=False, input=False, default=False)},
}

#: TS ``hooks.after[0].matcher`` — path prefixes that can plausibly turn an anonymous
#: visitor into a real one (sign-in/up, oauth callbacks, and every plugin's own
#: verify/callback endpoint). Plugins not yet ported (passkey, one-tap, ...) are
#: listed too: matching a path nobody serves yet is harmless.
_LINK_OR_VERIFY_PREFIXES = (
    "/sign-in",
    "/sign-up",
    "/callback",
    "/oauth2/callback",
    "/magic-link/verify",
    "/email-otp/verify-email",
    "/one-tap/callback",
    "/passkey/verify-authentication",
    "/phone-number/verify",
    "/verify-email",
)


def _err(status: int, code: str) -> APIError:
    return APIError(status, code, ERROR_CODES[code])


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _peek_session(ctx: Ctx) -> dict[str, Any] | None:
    """The request's *current* session without sliding its expiry (TS
    ``getSessionFromCtx(ctx, {disableRefresh:true})``). Reads whatever the client's
    incoming ``Cookie`` header names — decoupled from any session this same request
    is in the middle of creating."""
    result, _cookies = await get_session(ctx.auth, ctx.request, disable_refresh=True)
    return result


def _matches_link_or_verify_path(ctx: Ctx) -> bool:
    return ctx.request.path.startswith(_LINK_OR_VERIFY_PREFIXES)


def _response_set_session_cookie(ctx: Ctx) -> bool:
    response = ctx.response
    if response is None:
        return False
    prefix = f"{cookie_name(ctx.auth)}="
    return any(
        header.lower() == "set-cookie" and value.startswith(prefix)
        for header, value in response.headers
    )


class AnonymousPlugin(Plugin):
    """TS ``anonymous()`` — see module docstring for the source file."""

    id = "anonymous"
    schema: ClassVar[Schema] = _SCHEMA
    error_codes: ClassVar[dict[str, str]] = ERROR_CODES

    def __init__(
        self,
        *,
        email_domain_name: str | None = None,
        on_link_account: Callable[[dict[str, Any]], Any] | None = None,
        disable_delete_anonymous_user: bool = False,
        generate_name: Callable[[Ctx], Any] | None = None,
        generate_random_email: Callable[[], Any] | None = None,
    ) -> None:
        # ponytail: TS also accepts a per-instance `schema` override (field-name
        # remapping only). `Plugin.schema` is a ClassVar on the shared base, so an
        # instance override isn't type-safe here; skipped — no behavior depends on
        # it, only the fixed `isAnonymous` column shape below. Add a subclass-level
        # `schema` override if a caller ever needs a custom column name.
        self.email_domain_name = email_domain_name
        self.on_link_account = on_link_account
        self.disable_delete_anonymous_user = disable_delete_anonymous_user
        self.generate_name = generate_name
        self.generate_random_email = generate_random_email

    def routes(self):
        return [
            ("POST", "/sign-in/anonymous", self.sign_in_anonymous),
            ("POST", "/delete-anonymous-user", self.delete_anonymous_user),
        ]

    def hooks(self) -> HookSet:
        return HookSet(after=[PluginHook(_matches_link_or_verify_path, self._after_link_or_verify)])

    # --- helpers ---------------------------------------------------------------------

    async def _anon_email(self) -> str:
        if self.generate_random_email is not None:
            custom = await _maybe_await(self.generate_random_email())
            if custom:
                if not EMAIL_RE.match(custom):
                    raise _err(400, "INVALID_EMAIL_FORMAT")
                return custom
        new_id = generate_id()
        if self.email_domain_name:
            return f"temp-{new_id}@{self.email_domain_name}"
        return f"temp@{new_id}.com"

    async def _require_sensitive_session(self, ctx: Ctx) -> dict[str, Any]:
        """TS ``sensitiveSessionMiddleware`` (api/routes/session.ts:644): an
        authoritative, cookie-cache-BYPASSING session read — no freshness gate."""
        result, _cookies = await get_session(ctx.auth, ctx.request, disable_cache=True)
        if result is None:
            raise APIError(401, "UNAUTHORIZED", "Not authenticated")
        return result

    # --- endpoints ---------------------------------------------------------------------

    async def sign_in_anonymous(self, ctx: Ctx) -> AuthResponse:
        existing = await _peek_session(ctx)
        if existing is not None and existing["user"].get("isAnonymous"):
            raise _err(400, "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY")

        email = await self._anon_email()
        name = await _maybe_await(self.generate_name(ctx)) if self.generate_name else None
        name = name or "Anonymous"
        new_user = await ctx.internal.create_user(
            {"email": email, "emailVerified": False, "isAnonymous": True, "name": name}
        )
        if new_user is None:
            raise _err(500, "FAILED_TO_CREATE_USER")

        session, cookies = await create_session(
            ctx.auth, new_user["id"], ctx.request, user=new_user, ctx=ctx
        )
        response = AuthResponse(
            body={"token": session["token"], "user": ctx.auth.parse_user_output(new_user)}
        )
        for cookie in cookies:
            response.set_cookie(cookie)
        return response

    async def delete_anonymous_user(self, ctx: Ctx) -> AuthResponse:
        result = await self._require_sensitive_session(ctx)
        user = result["user"]
        if self.disable_delete_anonymous_user:
            raise _err(400, "DELETE_ANONYMOUS_USER_DISABLED")
        if not user.get("isAnonymous"):
            raise _err(403, "USER_IS_NOT_ANONYMOUS")

        try:
            await ctx.internal.delete_user_sessions(user["id"])
        except Exception:
            raise _err(500, "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS") from None
        try:
            await ctx.internal.delete_user(user["id"])
        except Exception:
            raise _err(500, "FAILED_TO_DELETE_ANONYMOUS_USER") from None

        response = AuthResponse(body={"success": True})
        response.set_cookie(clear_cookie(ctx.auth))
        response.set_cookie(clear_cookie(ctx.auth, "dont_remember"))
        return response

    # --- hooks ---------------------------------------------------------------------

    async def _after_link_or_verify(self, ctx: Ctx) -> None:
        if not _response_set_session_cookie(ctx):
            return None
        existing = await _peek_session(ctx)
        if existing is None or not existing["user"].get("isAnonymous"):
            return None

        if ctx.request.path == "/sign-in/anonymous" and ctx.new_session is None:
            raise _err(400, "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY")
        new_session = ctx.new_session
        if new_session is None:
            return None

        if self.on_link_account is not None:
            await _maybe_await(
                self.on_link_account(
                    {
                        "anonymous_user": {
                            "session": existing["session"],
                            "user": existing["user"],
                        },
                        "new_user": new_session,
                        "ctx": ctx,
                    }
                )
            )

        new_user = new_session.get("user") or {}
        is_same_user = new_user.get("id") == existing["user"].get("id")
        new_session_is_anonymous = bool(new_user.get("isAnonymous"))
        if self.disable_delete_anonymous_user or is_same_user or new_session_is_anonymous:
            return None
        try:
            await ctx.internal.delete_user_sessions(existing["user"]["id"])
            await ctx.internal.delete_user(existing["user"]["id"])
        except Exception:
            # TS: logs and swallows — best-effort post-link cleanup, not fatal to
            # the response that already succeeded.
            pass
        return None
