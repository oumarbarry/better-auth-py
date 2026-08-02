"""Phone-number plugin — SMS-OTP sign-in, verification, and password reset.

Port of better-auth's ``plugins/phone-number`` (v1.6.23). Wire/storage fidelity is the
contract: a Python app and a TS app share one DB, so the verification-value format
(``"<code>:<attempts>"`` under the raw phone number; reset OTPs under
``"<phoneNumber>-request-password-reset"``), the camelCase ``phoneNumber`` /
``phoneNumberVerified`` user columns, the JSON response shapes, and every error string
match the TS source exactly (routes.ts / index.ts / error-codes.ts / schema.ts).

The single-use guarantee rests on ``internalAdapter.consumeVerificationValue`` (atomic,
expiry-gated) exactly as in TS: the first concurrent caller wins the row, every racer
gets ``None`` and is rejected — so one code can never satisfy two verifications.
"""

from __future__ import annotations

import inspect
import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from ..adapters.base import Where
from ..crypto import generate_otp, verify_password
from ..endpoints import validate_password
from ..plugins import HookSet, Plugin, PluginHook, RateLimitRule, Route
from ..schema import Field, Schema
from ..session import create_session, utcnow
from ..types import APIError, AuthResponse, Ctx

if TYPE_CHECKING:
    from ..auth import BetterAuth

logger = logging.getLogger("better_auth.phone_number")

#: exact TS strings (phone-number/error-codes.ts) — surfaced on ``auth.error_codes``.
ERROR_CODES: dict[str, str] = {
    "INVALID_PHONE_NUMBER": "Invalid phone number",
    "PHONE_NUMBER_EXIST": "Phone number already exists",
    "PHONE_NUMBER_NOT_EXIST": "phone number isn't registered",
    "INVALID_PHONE_NUMBER_OR_PASSWORD": "Invalid phone number or password",
    "UNEXPECTED_ERROR": "Unexpected error",
    "OTP_NOT_FOUND": "OTP not found",
    "OTP_EXPIRED": "OTP expired",
    "INVALID_OTP": "Invalid OTP",
    "PHONE_NUMBER_NOT_VERIFIED": "Phone number not verified",
    "PHONE_NUMBER_CANNOT_BE_UPDATED": "Phone number cannot be updated",
    "SEND_OTP_NOT_IMPLEMENTED": "sendOTP not implemented",
    "TOO_MANY_ATTEMPTS": "Too many attempts",
}

_PHONE_FIELD = "phoneNumber"
_VERIFIED_FIELD = "phoneNumberVerified"
# body keys the verify endpoint consumes itself; everything else is an additionalField
_VERIFY_RESERVED = ("phoneNumber", "code", "disableSession", "updatePhoneNumber")


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _err(code: str, status: int) -> APIError:
    return APIError(status, code, ERROR_CODES[code])


def _required_str(body: dict[str, Any], key: str) -> str:
    """A required string body field. Plugin routes carry no body schema, so this is the
    presence/type gate (400 on missing) and the seam that types the value as ``str``."""
    value = body.get(key)
    if not isinstance(value, str):
        raise APIError(400, "INVALID_BODY", f"'{key}' is required")
    return value


class PhoneNumberPlugin(Plugin):
    """SMS-OTP sign-in / verification / password reset via phone number.

    Constructor kwargs mirror the TS ``PhoneNumberOptions`` (snake_case) with identical
    defaults. ``send_otp`` is required in practice (endpoints raise
    ``SEND_OTP_NOT_IMPLEMENTED`` 501 when it is missing).
    """

    id = "phone-number"
    error_codes: ClassVar[dict[str, str]] = ERROR_CODES
    # user.phoneNumber (unique, sortable, returned) + user.phoneNumberVerified
    # (returned, input:false) — camelCase columns shared with the TS schema (schema.ts).
    # ponytail: the TS `schema` field-name override isn't exposed — it needs fieldName
    # plumbing this port lacks and no behaviour depends on it; add when that lands.
    schema: ClassVar[Schema] = {
        "user": {
            _PHONE_FIELD: Field(
                "string", required=False, unique=True, sortable=True, returned=True
            ),
            _VERIFIED_FIELD: Field("boolean", required=False, returned=True, input=False),
        }
    }

    def __init__(
        self,
        *,
        otp_length: int = 6,
        expires_in: int = 300,
        allowed_attempts: int = 3,
        send_otp: Any = None,
        verify_otp: Any = None,
        send_password_reset_otp: Any = None,
        phone_number_validator: Any = None,
        require_verification: bool = False,
        callback_on_verification: Any = None,
        # {"get_temp_email": fn(phone)->str, "get_temp_name"?: fn(phone)->str}
        sign_up_on_verification: dict[str, Any] | None = None,
    ) -> None:
        self.otp_length = otp_length
        self.expires_in = expires_in
        self.allowed_attempts = allowed_attempts
        self.send_otp = send_otp
        self.verify_otp = verify_otp
        self.send_password_reset_otp = send_password_reset_otp
        self.phone_number_validator = phone_number_validator
        self.require_verification = require_verification
        self.callback_on_verification = callback_on_verification
        self.sign_up_on_verification = sign_up_on_verification

    # --- init: contribute the disassociation databaseHook -----------------------------

    def init(self, auth: BetterAuth) -> None:
        """Register the user.update.before hook that keeps ``phoneNumberVerified`` in
        lock-step with a cleared ``phoneNumber`` (TS ``init().options.databaseHooks``).

        ponytail: contribute the hook by appending to the live ``auth.internal.hooks``
        list — the internal adapter is built before ``init()`` runs, so mutating its
        normalized hook list is the one seam that takes effect (mirrors how
        haveibeenpwned appends to ``auth.password_checks``).
        """

        async def before_update(data: dict[str, Any], ctx: Any = None) -> Any:
            # Atomically reset the verified flag when the number is cleared, in the
            # SAME write — so a released number is never left flagged verified.
            if _PHONE_FIELD in data and data[_PHONE_FIELD] is None:
                return {"data": {**data, _VERIFIED_FIELD: False}}
            return None

        auth.internal.hooks.append({"user": {"update": {"before": before_update}}})

    # --- TS BetterAuthPlugin surface --------------------------------------------------

    def rate_limit(self) -> list[RateLimitRule]:
        return [
            RateLimitRule(
                window=60, max=10, path_matcher=lambda path: path.startswith("/phone-number")
            )
        ]

    def hooks(self) -> HookSet:
        def blocks_phone_change(ctx: Ctx) -> bool:
            # Block any phoneNumber change on /update-user except disassociation (null).
            if ctx.request.path != "/update-user":
                return False
            body = ctx.body()
            return _PHONE_FIELD in body and body[_PHONE_FIELD] is not None

        async def reject(ctx: Ctx) -> AuthResponse | None:
            raise _err("PHONE_NUMBER_CANNOT_BE_UPDATED", 400)

        return HookSet(before=[PluginHook(blocks_phone_change, reject)])

    def routes(self) -> list[Route]:
        return [
            ("POST", "/sign-in/phone-number", self._sign_in),
            ("POST", "/phone-number/send-otp", self._send_otp),
            ("POST", "/phone-number/verify", self._verify),
            ("POST", "/phone-number/request-password-reset", self._request_password_reset),
            ("POST", "/phone-number/reset-password", self._reset_password),
        ]

    # --- helpers ----------------------------------------------------------------------

    async def _validate_phone(self, phone: str) -> None:
        if self.phone_number_validator is not None and not await _maybe_await(
            self.phone_number_validator(phone)
        ):
            raise _err("INVALID_PHONE_NUMBER", 400)

    def _expires_at(self) -> Any:
        return utcnow() + timedelta(seconds=self.expires_in)

    async def _run_send(self, send: Any, phone: str, code: str, ctx: Ctx) -> None:
        """Run a send callback so its failure never fails the request.

        ponytail: TS isolates SMS-send failures via ``advanced.backgroundTasks.handler``
        (``runInBackgroundOrAwait``); this port has no such config seam, so the closest
        mechanism is await-then-suppress — the code is still delivered/recorded before we
        respond (tests read it synchronously), but a provider error can't 500 the request.
        """
        try:
            await _maybe_await(send({"phoneNumber": phone, "code": code}, ctx))
        except Exception:
            logger.exception("phone-number send callback failed")

    async def _consume_otp(self, ctx: Ctx, identifier: str, provided_code: str) -> None:
        """Atomic OTP verification against the stored ``"<code>:<attempts>"`` row.

        Mirrors TS ``verifyPhoneNumberOTP`` (routes.ts:849): expiry gate, attempt-budget
        peek, then the atomic consume that is the race gate. On a wrong code still within
        budget the row is recreated with the same value/expiry and ``attempts+1``; once
        the budget is spent the row is deleted and not recreated (locked out).
        """
        internal = ctx.internal
        existing = await internal.find_verification_value(identifier)
        if existing is None:
            raise _err("OTP_NOT_FOUND", 400)
        if existing["expiresAt"] < utcnow():
            await internal.delete_verification_by_identifier(identifier)
            raise _err("OTP_EXPIRED", 400)

        allowed = self.allowed_attempts or 3
        peeked = _attempts_of(existing["value"])
        if peeked and int(peeked) >= allowed:
            await internal.delete_verification_by_identifier(identifier)
            raise _err("TOO_MANY_ATTEMPTS", 403)

        consumed = await internal.consume_verification_value(identifier)
        if consumed is None:
            raise _err("INVALID_OTP", 400)

        otp_value, _, raw_attempts = consumed["value"].partition(":")
        if raw_attempts and int(raw_attempts) >= allowed:
            raise _err("TOO_MANY_ATTEMPTS", 403)
        if otp_value != provided_code:
            await internal.create_verification_value(
                {
                    "value": f"{otp_value}:{int(raw_attempts or '0') + 1}",
                    "identifier": identifier,
                    "expiresAt": consumed["expiresAt"],
                }
            )
            raise _err("INVALID_OTP", 400)

    async def _credential_account(self, ctx: Ctx, user_id: str) -> dict[str, Any] | None:
        return await ctx.adapter.find_one(
            "account", [Where("userId", user_id), Where("providerId", "credential")]
        )

    # --- endpoints --------------------------------------------------------------------

    async def _sign_in(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        phone = _required_str(body, "phoneNumber")
        password = _required_str(body, "password")
        await self._validate_phone(phone)

        user = await ctx.adapter.find_one("user", [Where("phoneNumber", phone)])
        if user is None:
            raise _err("INVALID_PHONE_NUMBER_OR_PASSWORD", 401)

        if self.require_verification and not user.get(_VERIFIED_FIELD):
            # Send a fresh OTP and refuse the sign-in (value has NO ":0" suffix, exactly
            # like TS — the verify path tolerates the colon-less form).
            code = generate_otp(self.otp_length)
            await ctx.internal.create_verification_value(
                {"value": code, "identifier": phone, "expiresAt": self._expires_at()}
            )
            if self.send_otp is not None:
                await self._run_send(self.send_otp, phone, code, ctx)
            raise _err("PHONE_NUMBER_NOT_VERIFIED", 401)

        account = await self._credential_account(ctx, user["id"])
        if account is None:
            raise _err("INVALID_PHONE_NUMBER_OR_PASSWORD", 401)
        if not account.get("password"):
            raise _err("UNEXPECTED_ERROR", 401)
        if not verify_password(account["password"], password):
            raise _err("INVALID_PHONE_NUMBER_OR_PASSWORD", 401)

        remember_me = body.get("rememberMe") is not False
        session, cookies = await create_session(
            ctx.auth, user["id"], ctx.request, remember_me, ctx=ctx
        )
        response = AuthResponse(
            body={"token": session["token"], "user": ctx.auth.parse_user_output(user)}
        )
        for cookie in cookies:
            response.set_cookie(cookie)
        return response

    async def _send_otp(self, ctx: Ctx) -> AuthResponse:
        if self.send_otp is None:
            raise _err("SEND_OTP_NOT_IMPLEMENTED", 501)
        body = ctx.body()
        phone = _required_str(body, "phoneNumber")
        await self._validate_phone(phone)

        code = generate_otp(self.otp_length)
        await ctx.internal.create_verification_value(
            {"value": f"{code}:0", "identifier": phone, "expiresAt": self._expires_at()}
        )
        await self._run_send(self.send_otp, phone, code, ctx)
        return AuthResponse(body={"message": "code sent"})

    async def _verify(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        phone = _required_str(body, "phoneNumber")
        code = _required_str(body, "code")

        if self.verify_otp is not None:
            # Custom verifier bypasses the internal store but still cleans up any row.
            if not await _maybe_await(self.verify_otp({"phoneNumber": phone, "code": code}, ctx)):
                raise _err("INVALID_OTP", 400)
            if await ctx.internal.find_verification_value(phone) is not None:
                await ctx.internal.delete_verification_by_identifier(phone)
        else:
            await self._consume_otp(ctx, phone, code)

        if body.get("updatePhoneNumber"):
            return await self._verify_update_phone(ctx, phone)

        user = await ctx.adapter.find_one("user", [Where("phoneNumber", phone)])
        if user is None:
            if self.sign_up_on_verification is not None:
                user = await self._sign_up(ctx, phone, body)
        else:
            user = await ctx.internal.update_user(user["id"], {_VERIFIED_FIELD: True})
        if user is None:
            raise APIError(500, "FAILED_TO_UPDATE_USER", "Failed to update user")

        await self._fire_callback(ctx, phone, user)

        if not body.get("disableSession"):
            session, cookies = await create_session(ctx.auth, user["id"], ctx.request, ctx=ctx)
            response = AuthResponse(
                body={
                    "status": True,
                    "token": session["token"],
                    "user": ctx.auth.parse_user_output(user),
                }
            )
            for cookie in cookies:
                response.set_cookie(cookie)
            return response
        return AuthResponse(
            body={"status": True, "token": None, "user": ctx.auth.parse_user_output(user)}
        )

    async def _verify_update_phone(self, ctx: Ctx, phone: str) -> AuthResponse:
        session = await ctx.get_session()
        if session is None:
            raise APIError(401, "USER_NOT_FOUND", "User not found")
        existing = await ctx.adapter.find_many("user", [Where("phoneNumber", phone)])
        if existing:
            raise _err("PHONE_NUMBER_EXIST", 400)
        user = await ctx.internal.update_user(
            session["user"]["id"], {_PHONE_FIELD: phone, _VERIFIED_FIELD: True}
        )
        if user is None:
            raise APIError(500, "FAILED_TO_UPDATE_USER", "Failed to update user")
        await self._fire_callback(ctx, phone, user)
        return AuthResponse(
            body={
                "status": True,
                "token": session["session"]["token"],
                "user": ctx.auth.parse_user_output(user),
            }
        )

    async def _sign_up(self, ctx: Ctx, phone: str, body: dict[str, Any]) -> dict[str, Any]:
        rest = {k: v for k, v in body.items() if k not in _VERIFY_RESERVED}
        additional = ctx.auth.parse_user_input(rest, "create")
        cfg = self.sign_up_on_verification or {}
        get_temp_name = cfg.get("get_temp_name")
        user = await ctx.internal.create_user(
            {
                **additional,
                "email": cfg["get_temp_email"](phone),
                "name": get_temp_name(phone) if get_temp_name else phone,
                _PHONE_FIELD: phone,
                _VERIFIED_FIELD: True,
            }
        )
        if user is None:
            raise APIError(500, "FAILED_TO_CREATE_USER", "Failed to create user")
        return user

    async def _fire_callback(self, ctx: Ctx, phone: str, user: dict[str, Any]) -> None:
        if self.callback_on_verification is not None:
            await _maybe_await(
                self.callback_on_verification({"phoneNumber": phone, "user": user}, ctx)
            )

    async def _request_password_reset(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        phone = _required_str(body, "phoneNumber")
        user = await ctx.adapter.find_one("user", [Where("phoneNumber", phone)])
        # The OTP row is written regardless of user existence (TS order), under the
        # reset-scoped identifier, as "<code>:0".
        code = generate_otp(self.otp_length)
        await ctx.internal.create_verification_value(
            {
                "value": f"{code}:0",
                "identifier": f"{phone}-request-password-reset",
                "expiresAt": self._expires_at(),
            }
        )
        # No enumeration: only send when the user actually exists; response is constant.
        if user is None:
            return AuthResponse(body={"status": True})
        if self.send_password_reset_otp is not None:
            await self._run_send(self.send_password_reset_otp, phone, code, ctx)
        return AuthResponse(body={"status": True})

    async def _reset_password(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        phone = _required_str(body, "phoneNumber")
        new_password = _required_str(body, "newPassword")
        identifier = f"{phone}-request-password-reset"
        await self._consume_otp(ctx, identifier, _required_str(body, "otp"))

        user = await ctx.adapter.find_one("user", [Where("phoneNumber", phone)])
        if user is None:
            raise _err("UNEXPECTED_ERROR", 400)
        validate_password(ctx, new_password)  # PASSWORD_TOO_SHORT / PASSWORD_TOO_LONG

        hashed = await ctx.auth.hash_password_checked(new_password, ctx.request.path)
        account = await self._credential_account(ctx, user["id"])
        if account is None:
            await ctx.internal.create_account(
                {"userId": user["id"], "providerId": "credential", "accountId": user["id"],
                 "password": hashed}
            )
        else:
            await ctx.internal.update(
                "account",
                [Where("id", account["id"])],
                {"password": hashed, "updatedAt": utcnow()},
                ctx=ctx,
            )

        on_reset = ctx.auth.email_and_password.on_password_reset
        if on_reset is not None:
            await on_reset({"user": user}, ctx.request)
        if ctx.auth.email_and_password.revoke_sessions_on_password_reset:
            await ctx.internal.delete_user_sessions(user["id"])
        return AuthResponse(body={"status": True})


def _attempts_of(value: str) -> str | None:
    """Second half of a ``"<code>:<attempts>"`` value, or ``None`` when colon-less
    (the requireVerification sign-in path stores the bare code)."""
    _, sep, attempts = value.partition(":")
    return attempts if sep else None
