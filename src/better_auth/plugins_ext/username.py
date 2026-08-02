"""username plugin — a faithful port of better-auth's ``plugins/username``.

Sign in with a username instead of an email, and enforce uniqueness/format on
sign-up and update. Wire parity with the TS plugin
(``packages/better-auth/src/plugins/username``):

- schema adds ``user.username`` (unique, sortable, ``transform.input`` = normalizer)
  and ``user.displayUsername`` (``transform.input`` = display normalizer);
- ``/sign-in/username`` equalizes timing (a wrong username still runs a dummy hash)
  and never leaks ``EMAIL_NOT_VERIFIED`` before a correct password;
- validation lives in the HTTP before-hooks for ``/sign-up/email`` + ``/update-user``
  (400s) and in the endpoints for ``/sign-in/username`` + ``/is-username-available``
  (422s); the ``databaseHooks`` normalize + persist and *skip* re-validating those
  two paths, exactly like TS ``pathsWithHttpHookValidation``.

Persistence note: this port's core ``sign_up_email`` does not fold arbitrary body
fields into the user row, so the ``user.create.before`` databaseHook sources
``username``/``displayUsername`` from ``ctx.body()`` (the request body the HTTP
hooks already finalized) and injects them; ``transform.input`` then normalizes on
write. On ``/update-user`` the core already carries the fields through
``parse_user_input``, so the update hook is a validated pass-through.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from ..adapters.base import Where
from ..crypto import dummy_verify, sign_email_verification_token, verify_password
from ..plugins import HookSet, Plugin, PluginHook
from ..schema import Field, Schema
from ..session import create_session
from ..types import APIError, AuthResponse, Ctx

if TYPE_CHECKING:
    from ..auth import BetterAuth

#: exact TS strings (username/error-codes.ts). Surfaced on ``auth.error_codes``.
ERROR_CODES: dict[str, str] = {
    "INVALID_USERNAME_OR_PASSWORD": "Invalid username or password",
    "EMAIL_NOT_VERIFIED": "Email not verified",
    "UNEXPECTED_ERROR": "Unexpected error",
    "USERNAME_IS_ALREADY_TAKEN": "Username is already taken. Please try another.",
    "USERNAME_TOO_SHORT": "Username is too short",
    "USERNAME_TOO_LONG": "Username is too long",
    "INVALID_USERNAME": "Username is invalid",
    "INVALID_DISPLAY_USERNAME": "Display username is invalid",
}

# TS validates + normalizes in the HTTP before-hooks for these paths, so the
# databaseHooks skip validation there to avoid double work (index.ts:145).
_HTTP_HOOK_PATHS = ("/sign-up/email", "/update-user")
_DEFAULT_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.]+$")


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


class UsernamePlugin(Plugin):
    id = "username"
    error_codes = ERROR_CODES

    def __init__(
        self,
        *,
        min_username_length: int = 3,
        max_username_length: int = 30,
        username_validator: Callable[[str], Any] | None = None,
        display_username_validator: Callable[[str], Any] | None = None,
        username_normalization: Callable[[str], str] | bool | None = None,
        display_username_normalization: Callable[[str], str] | bool = False,
        validation_order: dict[str, str] | None = None,
        schema: dict[str, Any] | None = None,
    ) -> None:
        self.min_username_length = min_username_length or 3
        self.max_username_length = max_username_length or 30
        self.username_validator = username_validator
        self.display_username_validator = display_username_validator
        self.username_normalization = username_normalization
        self.display_username_normalization = display_username_normalization
        self.validation_order = validation_order
        self._auth: BetterAuth | None = None

        # Instance-level schema: transform.input closes over this instance's normalizers.
        user_fields: dict[str, Field] = {
            "username": Field(
                "string",
                required=False,
                unique=True,
                sortable=True,
                returned=True,
                transform_input=self._normalize,
            ),
            "displayUsername": Field(
                "string", required=False, transform_input=self._display_normalize
            ),
        }
        if schema and isinstance(schema.get("user"), dict):
            # minimal override: merge caller field overrides (no model/field renaming)
            for name, override in schema["user"].items():
                if isinstance(override, Field):
                    user_fields[name] = override
        self.schema: Schema = {"user": user_fields}

    # --- normalizers (also the schema transform.input; guard non-strings like TS) --------

    def _normalize(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        norm = self.username_normalization
        if norm is False:
            return value
        if callable(norm):
            return norm(value)
        return value.lower()

    def _display_normalize(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        norm = self.display_username_normalization
        if callable(norm):
            return norm(value)
        return value

    def _vo(self, key: str) -> str | None:
        return (self.validation_order or {}).get(key)

    def _run_validator(self, username: str) -> Any:
        if self.username_validator is not None:
            return self.username_validator(username)
        return bool(_DEFAULT_USERNAME_RE.match(username))

    async def _validate_value(self, username: str) -> tuple[int, str, str] | None:
        """Return ``(status, code, message)`` on failure, else ``None`` — status is the
        HTTP-hook 400; sign-in/is-available re-raise these codes as 422."""
        to_validate = (
            self._normalize(username)
            if self._vo("username") == "post-normalization"
            else username
        )
        if len(to_validate) < self.min_username_length:
            return (400, "USERNAME_TOO_SHORT", ERROR_CODES["USERNAME_TOO_SHORT"])
        if len(to_validate) > self.max_username_length:
            return (400, "USERNAME_TOO_LONG", ERROR_CODES["USERNAME_TOO_LONG"])
        if not await _maybe_await(self._run_validator(to_validate)):
            return (400, "INVALID_USERNAME", ERROR_CODES["INVALID_USERNAME"])
        return None

    async def _validate_full(
        self, username: str, display: Any, adapter: Any, current_user_id: str | None
    ) -> None:
        err = await self._validate_value(username)
        if err is not None:
            raise APIError(400, err[1], err[2])
        normalized = self._normalize(username)
        existing = await adapter.find_one("user", [Where("username", normalized)])
        if existing is not None and (not current_user_id or existing["id"] != current_user_id):
            raise APIError(
                400, "USERNAME_IS_ALREADY_TAKEN", ERROR_CODES["USERNAME_IS_ALREADY_TAKEN"]
            )
        if display and self.display_username_validator is not None:
            to_validate = (
                self._display_normalize(display)
                if self._vo("displayUsername") == "post-normalization"
                else display
            )
            if not await _maybe_await(self.display_username_validator(to_validate)):
                raise APIError(
                    400, "INVALID_DISPLAY_USERNAME", ERROR_CODES["INVALID_DISPLAY_USERNAME"]
                )

    # --- init: register databaseHooks ---------------------------------------------------

    def init(self, auth: BetterAuth) -> None:
        self._auth = auth
        auth.internal.hooks.append(
            {
                "user": {
                    "create": {"before": self._user_create_before},
                    "update": {"before": self._user_update_before},
                }
            }
        )

    async def _user_create_before(self, data: dict[str, Any], ctx: Ctx | None = None) -> Any:
        return await self._db_before(data, ctx, is_update=False)

    async def _user_update_before(self, data: dict[str, Any], ctx: Ctx | None = None) -> Any:
        return await self._db_before(data, ctx, is_update=True)

    async def _db_before(self, data: dict[str, Any], ctx: Ctx | None, *, is_update: bool) -> Any:
        body = ctx.body() if ctx is not None else {}
        username = data["username"] if "username" in data else body.get("username")
        display = (
            data["displayUsername"] if "displayUsername" in data else body.get("displayUsername")
        )
        skip = ctx is not None and ctx.request.path in _HTTP_HOOK_PATHS

        if isinstance(username, str) and username:
            if not skip:
                current_user_id: str | None = None
                if is_update:
                    session = await ctx.get_session() if ctx is not None else None
                    current_user_id = (session["user"]["id"] if session else None) or data.get("id")
                if ctx is not None:
                    adapter = ctx.adapter
                else:
                    assert self._auth is not None
                    adapter = self._auth.adapter
                await self._validate_full(username, display, adapter, current_user_id)
            merged = {**data, "username": username}
            if is_update:
                if display:
                    merged["displayUsername"] = display
            else:
                merged["displayUsername"] = display if display else username
            return {"data": merged}

        if display:
            return {"data": {**data, "displayUsername": display}}
        return {"data": data}

    # --- HTTP before-hooks (mutate ctx.body / raise; TS hooks.before matchers) -----------

    def hooks(self) -> HookSet:
        def on_signup(ctx: Ctx) -> bool:
            return ctx.request.path == "/sign-up/email"

        def on_signup_or_update(ctx: Ctx) -> bool:
            return ctx.request.path in _HTTP_HOOK_PATHS

        return HookSet(
            before=[
                PluginHook(on_signup, self._hook_infer_display),
                PluginHook(on_signup_or_update, self._hook_validate),
                PluginHook(on_signup, self._hook_default_display),
            ]
        )

    async def _hook_infer_display(self, ctx: Ctx) -> None:
        # (a) copy a valid displayUsername into username when only displayUsername is given
        body = ctx.body()
        if not isinstance(body.get("displayUsername"), str) or "username" in body:
            return None
        if await self._validate_value(body["displayUsername"]) is None:
            body["username"] = body["displayUsername"]
        return None

    async def _hook_validate(self, ctx: Ctx) -> None:
        # (b) validate username value + uniqueness (own row allowed on update) + display
        body = ctx.body()
        username = body.get("username")
        if isinstance(username, str):
            err = await self._validate_value(username)
            if err is not None:
                raise APIError(400, err[1], err[2])
            normalized = self._normalize(username)
            existing = await ctx.adapter.find_one("user", [Where("username", normalized)])
            if ctx.request.path == "/sign-up/email" and existing is not None:
                raise APIError(
                    400, "USERNAME_IS_ALREADY_TAKEN", ERROR_CODES["USERNAME_IS_ALREADY_TAKEN"]
                )
            if ctx.request.path == "/update-user" and existing is not None:
                session = await ctx.get_session()
                if session is None or existing["id"] != session["user"]["id"]:
                    raise APIError(
                        400, "USERNAME_IS_ALREADY_TAKEN", ERROR_CODES["USERNAME_IS_ALREADY_TAKEN"]
                    )

        display = body.get("displayUsername")
        if isinstance(display, str) and self._vo("displayUsername") == "post-normalization":
            display = self._display_normalize(display)
        if (
            isinstance(display, str)
            and self.display_username_validator is not None
            and not await _maybe_await(self.display_username_validator(display))
        ):
            raise APIError(400, "INVALID_DISPLAY_USERNAME", ERROR_CODES["INVALID_DISPLAY_USERNAME"])
        return None

    async def _hook_default_display(self, ctx: Ctx) -> None:
        # (c) default displayUsername to username when username is set and display omitted
        body = ctx.body()
        if body.get("username") and not body.get("displayUsername"):
            body["displayUsername"] = body["username"]
        return None

    # --- endpoints ----------------------------------------------------------------------

    def routes(self) -> list[tuple[str, str, Any]]:
        return [
            ("POST", "/sign-in/username", self._sign_in),
            ("POST", "/is-username-available", self._is_available),
        ]

    async def _sign_in(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        if not body.get("username") or not body.get("password"):
            raise APIError(
                401, "INVALID_USERNAME_OR_PASSWORD", ERROR_CODES["INVALID_USERNAME_OR_PASSWORD"]
            )
        password = body["password"]
        username = (
            self._normalize(body["username"])
            if self._vo("username") == "pre-normalization"
            else body["username"]
        )
        if len(username) < self.min_username_length:
            raise APIError(422, "USERNAME_TOO_SHORT", ERROR_CODES["USERNAME_TOO_SHORT"])
        if len(username) > self.max_username_length:
            raise APIError(422, "USERNAME_TOO_LONG", ERROR_CODES["USERNAME_TOO_LONG"])
        if not await _maybe_await(self._run_validator(username)):
            raise APIError(422, "INVALID_USERNAME", ERROR_CODES["INVALID_USERNAME"])

        user = await ctx.adapter.find_one("user", [Where("username", self._normalize(username))])
        if user is None:
            # hash a dummy password so the response time doesn't reveal valid usernames
            dummy_verify(password)
            raise APIError(
                401, "INVALID_USERNAME_OR_PASSWORD", ERROR_CODES["INVALID_USERNAME_OR_PASSWORD"]
            )
        account = await ctx.adapter.find_one(
            "account", [Where("userId", user["id"]), Where("providerId", "credential")]
        )
        if account is None or not account.get("password"):
            raise APIError(
                401, "INVALID_USERNAME_OR_PASSWORD", ERROR_CODES["INVALID_USERNAME_OR_PASSWORD"]
            )
        if not verify_password(account["password"], password):
            raise APIError(
                401, "INVALID_USERNAME_OR_PASSWORD", ERROR_CODES["INVALID_USERNAME_OR_PASSWORD"]
            )

        cfg = ctx.auth.email_and_password
        if cfg.require_email_verification and not user.get("emailVerified"):
            ev = ctx.auth.email_verification
            if ev.send_verification_email is None:
                raise APIError(403, "EMAIL_NOT_VERIFIED", ERROR_CODES["EMAIL_NOT_VERIFIED"])
            # ponytail: `send_on_sign_in` isn't a field on this port's EmailVerification
            # dataclass; read it defensively so the behavior activates when present
            # (set as a runtime attr / a future config field) and no-ops otherwise.
            if getattr(ev, "send_on_sign_in", False):
                token = sign_email_verification_token(
                    ctx.auth.secret, user["email"], expires_in=ev.expires_in
                )
                cb = quote(body.get("callbackURL") or "/", safe="")
                url = (
                    f"{ctx.auth.base_url}{ctx.auth.base_path}/verify-email"
                    f"?token={token}&callbackURL={cb}"
                )
                await ev.send_verification_email(user, url, token)
            raise APIError(403, "EMAIL_NOT_VERIFIED", ERROR_CODES["EMAIL_NOT_VERIFIED"])

        callback_url = body.get("callbackURL")
        remember_me = body.get("rememberMe") is not False
        session, cookies = await create_session(
            ctx.auth, user["id"], ctx.request, remember_me, user=user, ctx=ctx
        )
        response = AuthResponse(
            body={
                "redirect": bool(callback_url),
                "token": session["token"],
                "url": callback_url,
                "user": ctx.auth.parse_user_output(user),
            }
        )
        for cookie in cookies:
            response.set_cookie(cookie)
        if callback_url:
            response.headers.append(("location", callback_url))
        return response

    async def _is_available(self, ctx: Ctx) -> dict[str, Any]:
        body = ctx.body()
        username = body.get("username")
        if not username:
            raise APIError(422, "INVALID_USERNAME", ERROR_CODES["INVALID_USERNAME"])
        if len(username) < self.min_username_length:
            raise APIError(422, "USERNAME_TOO_SHORT", ERROR_CODES["USERNAME_TOO_SHORT"])
        if len(username) > self.max_username_length:
            raise APIError(422, "USERNAME_TOO_LONG", ERROR_CODES["USERNAME_TOO_LONG"])
        if not await _maybe_await(self._run_validator(username)):
            raise APIError(422, "INVALID_USERNAME", ERROR_CODES["INVALID_USERNAME"])
        user = await ctx.adapter.find_one("user", [Where("username", self._normalize(username))])
        return {"available": user is None}
