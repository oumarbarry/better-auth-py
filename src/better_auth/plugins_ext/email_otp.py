"""better-auth ``email-otp`` plugin, ported to Python.

Email one-time-code sign-in, email verification, password reset, and email change.
Wire/storage fidelity with the TS plugin (``plugins/email-otp/``): identifier scheme
``<type>-otp-<email>`` (``change-email`` keyed on ``<current>-<new>``), value
``"<storedOTP>:<attempts>"``, emails lowercased, exact error strings, and the same
atomic single-use guarantee via ``internalAdapter.consume_verification_value``.

Server-only endpoints (``create-verification-otp`` / ``get-verification-otp``) mirror
TS ``createAuthEndpoint.serverOnly``: they are NOT mounted on the HTTP router (a POST/GET
to their path 404s, since no route matches) and are exposed as plain async methods on the
plugin for in-process/server use.
"""

from __future__ import annotations

import hmac
import inspect
import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from ..adapters.base import Where
from ..cookie_cache import set_cookie_cache
from ..crypto import default_key_hasher, generate_otp, symmetric_decrypt, symmetric_encrypt
from ..endpoints import require_fields, validate_email, validate_password
from ..plugins import HookSet, Plugin, PluginHook, RateLimitRule
from ..session import cookie_name, create_session, get_session, refresh_session_cookie, utcnow
from ..types import APIError, AuthResponse, Ctx

if TYPE_CHECKING:
    from ..auth import BetterAuth

logger = logging.getLogger("better_auth")

#: TS ``EMAIL_OTP_ERROR_CODES`` — exact strings (a shared client keys on these).
ERROR_CODES: dict[str, str] = {
    "OTP_EXPIRED": "OTP expired",
    "INVALID_OTP": "Invalid OTP",
    "TOO_MANY_ATTEMPTS": "Too many attempts",
}

_TYPES = ("email-verification", "sign-in", "forget-password", "change-email")

_DEPRECATION_MSG = (
    'The "/forget-password/email-otp" endpoint is deprecated. '
    'Please use "/email-otp/request-password-reset" instead. '
    "This endpoint will be removed in the next major version."
)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _to_identifier(otp_type: str, email: str) -> str:
    """TS ``toOTPIdentifier`` — ``<type>-otp-<email>``."""
    return f"{otp_type}-otp-{email}"


def _split_at_last_colon(value: str) -> tuple[str, str]:
    """TS ``splitAtLastColon`` — split ``<storedOTP>:<attempts>`` at the final colon."""
    idx = value.rfind(":")
    if idx == -1:
        return value, ""
    return value[:idx], value[idx + 1 :]


class EmailOTPPlugin(Plugin):
    """Port of TS ``emailOTP(options)``. Constructor kwargs mirror the TS options
    (snake_case) with identical defaults."""

    id: str = "email-otp"
    error_codes: ClassVar[dict[str, str]] = ERROR_CODES

    def __init__(
        self,
        *,
        send_verification_otp: Any,
        otp_length: int = 6,
        expires_in: int = 5 * 60,
        generate_otp: Any = None,
        send_verification_on_sign_up: bool = False,
        disable_sign_up: bool = False,
        allowed_attempts: int = 3,
        store_otp: str | dict[str, Any] = "plain",
        resend_strategy: str = "rotate",
        change_email: dict[str, Any] | None = None,
        override_default_email_verification: bool = False,
        rate_limit: dict[str, int] | None = None,
    ) -> None:
        self._send_fn = send_verification_otp
        self.otp_length = otp_length
        self.expires_in = expires_in
        self._generate_otp_fn = generate_otp
        self.send_verification_on_sign_up = send_verification_on_sign_up
        self.disable_sign_up = disable_sign_up
        self.allowed_attempts = allowed_attempts
        self.store_otp = store_otp
        self.resend_strategy = resend_strategy
        self._change_email = change_email or {}
        self.override_default_email_verification = override_default_email_verification
        self._rate_limit = rate_limit or {}
        self._auth: BetterAuth | None = None
        self._deprecation_warned = False

    @property
    def auth(self) -> BetterAuth:
        assert self._auth is not None, "plugin.init() has not run yet"
        return self._auth

    # --- lifecycle --------------------------------------------------------------------

    def init(self, auth: BetterAuth) -> None:
        self._auth = auth
        # TS init(): override the core email-verification sender with an OTP sender.
        # endpoints._send_verification_email reads cfg.send_verification_email at call
        # time, so replacing it here reroutes every core verification email to an OTP.
        if self.override_default_email_verification:
            auth.email_verification.send_verification_email = self._override_email_sender

    def routes(self) -> list[tuple[str, str, Any]]:
        return [
            ("POST", "/email-otp/send-verification-otp", self._route_send_verification_otp),
            ("POST", "/email-otp/check-verification-otp", self._route_check_verification_otp),
            ("POST", "/email-otp/verify-email", self._route_verify_email),
            ("POST", "/sign-in/email-otp", self._route_sign_in),
            ("POST", "/email-otp/request-password-reset", self._route_request_password_reset),
            ("POST", "/forget-password/email-otp", self._route_forget_password),
            ("POST", "/email-otp/reset-password", self._route_reset_password),
            ("POST", "/email-otp/request-email-change", self._route_request_email_change),
            ("POST", "/email-otp/change-email", self._route_change_email),
        ]

    def hooks(self) -> HookSet:
        hook = PluginHook(matcher=self._sign_up_matcher, handler=self._after_sign_up)
        return HookSet(after=[hook])

    def rate_limit(self) -> list[RateLimitRule]:
        window = self._rate_limit.get("window") or 60
        maximum = self._rate_limit.get("max") or 3
        paths = [
            "/email-otp/send-verification-otp",
            "/email-otp/check-verification-otp",
            "/email-otp/verify-email",
            "/sign-in/email-otp",
            "/email-otp/request-password-reset",
            "/email-otp/reset-password",
            "/forget-password/email-otp",
            "/email-otp/request-email-change",
            "/email-otp/change-email",
        ]
        return [
            RateLimitRule(window=window, max=maximum, path_matcher=lambda p, path=path: p == path)
            for path in paths
        ]

    # --- OTP storage / verification helpers -------------------------------------------

    async def _generate(self, email: str, otp_type: str, ctx: Ctx | None) -> str:
        if self._generate_otp_fn is not None:
            data = {"email": email, "type": otp_type}
            result = await _maybe_await(self._generate_otp_fn(data, ctx))
            if result:
                return result
        return generate_otp(self.otp_length)

    async def _store(self, otp: str) -> str:
        store = self.store_otp
        if store == "encrypted":
            # ponytail: symmetric_encrypt is the interim $bap$ AES-GCM envelope, NOT
            # byte-compatible with TS XChaCha20 — encrypted OTPs won't decrypt
            # cross-runtime until Wave 4 swaps the crypto impl.
            return symmetric_encrypt(self.auth.secret, otp)
        if store == "hashed":
            return default_key_hasher(otp)
        if isinstance(store, dict) and "hash" in store:
            return await _maybe_await(store["hash"](otp))
        if isinstance(store, dict) and "encrypt" in store:
            return await _maybe_await(store["encrypt"](otp))
        return otp

    async def _verify_stored(self, stored: str, otp: str) -> bool:
        store = self.store_otp
        if store == "encrypted":
            return hmac.compare_digest(symmetric_decrypt(self.auth.secret, stored), otp)
        if store == "hashed":
            return hmac.compare_digest(default_key_hasher(otp), stored)
        if isinstance(store, dict) and "hash" in store:
            return hmac.compare_digest(await _maybe_await(store["hash"](otp)), stored)
        if isinstance(store, dict) and "decrypt" in store:
            return hmac.compare_digest(await _maybe_await(store["decrypt"](stored)), otp)
        return hmac.compare_digest(otp, stored)

    async def _retrieve(self, stored: str) -> str | None:
        """Plain-text OTP from a stored value, or None if unrecoverable (hashed/custom-hash)."""
        store = self.store_otp
        if store == "plain":
            return stored
        if store == "encrypted":
            return symmetric_decrypt(self.auth.secret, stored)
        if isinstance(store, dict) and "decrypt" in store:
            return await _maybe_await(store["decrypt"](stored))
        return None

    def _expires_at(self) -> Any:
        return utcnow() + timedelta(seconds=self.expires_in)

    async def _create_value(self, identifier: str, stored: str) -> None:
        await self.auth.internal.create_verification_value(
            {"value": f"{stored}:0", "identifier": identifier, "expiresAt": self._expires_at()}
        )

    async def _resolve_otp(self, email: str, otp_type: str, ctx: Ctx | None) -> str:
        """TS ``resolveOTP`` — reuse an existing recoverable OTP (resendStrategy "reuse")
        or generate, store, and return a fresh one."""
        identifier = _to_identifier(otp_type, email)
        if self.resend_strategy == "reuse":
            reused = await self._try_reuse_otp(identifier)
            if reused is not None:
                return reused
        otp = await self._generate(email, otp_type, ctx)
        await self._create_value(identifier, await self._store(otp))
        return otp

    async def _try_reuse_otp(self, identifier: str) -> str | None:
        existing = await self.auth.internal.find_verification_value(identifier)
        if not existing or existing["expiresAt"] < utcnow():
            return None
        stored_value, attempts = _split_at_last_colon(existing["value"])
        if attempts and int(attempts) >= self.allowed_attempts:
            return None
        plain = await self._retrieve(stored_value)
        if not plain:
            return None
        await self.auth.internal.update_verification_by_identifier(
            identifier, {"expiresAt": self._expires_at()}
        )
        return plain

    async def _atomic_verify(self, identifier: str, provided: str) -> None:
        """TS ``atomicVerifyOTP`` — single-use consume with the attempt budget.

        The consume is the race gate: the first concurrent caller receives the row,
        every later racer receives ``None`` (rejected as INVALID_OTP), so a correct OTP
        is accepted at most once. A wrong code recreates the row with an incremented
        attempt count (same expiry); an exhausted budget leaves it consumed (locked).
        """
        existing = await self.auth.internal.find_verification_value(identifier)
        if existing and existing["expiresAt"] < utcnow():
            await self.auth.internal.delete_verification_by_identifier(identifier)
            raise APIError(400, "OTP_EXPIRED", ERROR_CODES["OTP_EXPIRED"])
        consumed = await self.auth.internal.consume_verification_value(identifier)
        if consumed is None:
            raise APIError(400, "INVALID_OTP", ERROR_CODES["INVALID_OTP"])
        otp_value, attempts = _split_at_last_colon(consumed["value"])
        used = int(attempts) if attempts else 0
        if used >= self.allowed_attempts:
            raise APIError(403, "TOO_MANY_ATTEMPTS", ERROR_CODES["TOO_MANY_ATTEMPTS"])
        if not await self._verify_stored(otp_value, provided):
            await self.auth.internal.create_verification_value(
                {
                    "value": f"{otp_value}:{used + 1}",
                    "identifier": identifier,
                    "expiresAt": consumed["expiresAt"],
                }
            )
            raise APIError(400, "INVALID_OTP", ERROR_CODES["INVALID_OTP"])

    async def _find_user(self, email: str) -> dict[str, Any] | None:
        return await self.auth.adapter.find_one("user", [Where("email", email)])

    async def _send(self, email: str, otp: str, otp_type: str, ctx: Ctx | None) -> None:
        await _maybe_await(self._send_fn({"email": email, "otp": otp, "type": otp_type}, ctx))

    async def _send_verification_otp_impl(self, email: str, otp_type: str, ctx: Ctx | None) -> None:
        """Shared body of send-verification-otp (used by the HTTP route and the
        overrideDefaultEmailVerification sender)."""
        identifier = _to_identifier(otp_type, email)
        otp = await self._resolve_otp(email, otp_type, ctx)
        should_send = otp_type == "sign-in" and not self.disable_sign_up
        user = await self._find_user(email)
        if user is None and not should_send:
            # no enumeration: drop the row and report success without sending
            await self.auth.internal.delete_verification_by_identifier(identifier)
            return
        await self._send(email, otp, otp_type, ctx)

    async def _override_email_sender(self, user: dict[str, Any], url: str, token: str) -> None:
        await self._send_verification_otp_impl(user["email"].lower(), "email-verification", None)

    # --- server-only endpoints (not HTTP-dispatchable) --------------------------------

    async def create_verification_otp(self, email: str, otp_type: str) -> str:
        """TS server-only ``createVerificationOTP`` — create a row and return the OTP."""
        email = email.lower()
        otp = await self._generate(email, otp_type, None)
        await self._create_value(_to_identifier(otp_type, email), await self._store(otp))
        return otp

    async def get_verification_otp(self, email: str, otp_type: str) -> str | None:
        """TS server-only ``getVerificationOTP`` — recover the plain OTP, or None if
        missing/expired. Raises 400 when the OTP is hashed/custom-hash (unrecoverable)."""
        email = email.lower()
        vv = await self.auth.internal.find_verification_value(_to_identifier(otp_type, email))
        if not vv or vv["expiresAt"] < utcnow():
            return None
        store = self.store_otp
        if store == "hashed" or (isinstance(store, dict) and "hash" in store):
            raise APIError(400, "BAD_REQUEST", "OTP is hashed, cannot return the plain text OTP")
        stored, _attempts = _split_at_last_colon(vv["value"])
        if store == "encrypted":
            return symmetric_decrypt(self.auth.secret, stored)
        if isinstance(store, dict) and "decrypt" in store:
            return await _maybe_await(store["decrypt"](stored))
        return stored

    # --- sign-up after-hook (send an email-verification OTP) --------------------------

    def _sign_up_matcher(self, ctx: Ctx) -> bool:
        return (
            ctx.request.path.startswith("/sign-up")
            and self.send_verification_on_sign_up
            and not self.override_default_email_verification
        )

    async def _after_sign_up(self, ctx: Ctx) -> None:
        body = ctx.response.body if ctx.response is not None else None
        email = None
        if isinstance(body, dict) and isinstance(body.get("user"), dict):
            email = body["user"].get("email")
        if not email:
            return
        otp = await self._generate(email, "email-verification", ctx)
        stored = await self._store(otp)
        await self._create_value(_to_identifier("email-verification", email), stored)
        await self._send(email, otp, "email-verification", ctx)

    # --- HTTP routes ------------------------------------------------------------------

    async def _route_send_verification_otp(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        require_fields(body, "email", "type")
        email = validate_email(body["email"])  # INVALID_EMAIL
        otp_type = body["type"]
        if otp_type == "change-email":
            logger.error(
                "Use the /email-otp/request-email-change endpoint to send OTP for changing email"
            )
            raise APIError(400, "BAD_REQUEST", "Invalid OTP type")
        if otp_type not in _TYPES:
            raise APIError(400, "BAD_REQUEST", "Invalid OTP type")
        await self._send_verification_otp_impl(email, otp_type, ctx)
        return AuthResponse(body={"success": True})

    async def _route_check_verification_otp(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        require_fields(body, "email", "type", "otp")
        email = validate_email(body["email"])  # INVALID_EMAIL
        if body["type"] not in _TYPES:
            raise APIError(400, "BAD_REQUEST", "Invalid OTP type")
        if await self._find_user(email) is None:
            raise APIError(400, "USER_NOT_FOUND", "User not found")
        identifier = _to_identifier(body["type"], email)
        vv = await self.auth.internal.find_verification_value(identifier)
        if not vv:
            raise APIError(400, "INVALID_OTP", ERROR_CODES["INVALID_OTP"])
        if vv["expiresAt"] < utcnow():
            await self.auth.internal.delete_verification_by_identifier(identifier)
            raise APIError(400, "OTP_EXPIRED", ERROR_CODES["OTP_EXPIRED"])
        otp_value, attempts = _split_at_last_colon(vv["value"])
        if attempts and int(attempts) >= self.allowed_attempts:
            await self.auth.internal.delete_verification_by_identifier(identifier)
            raise APIError(403, "TOO_MANY_ATTEMPTS", ERROR_CODES["TOO_MANY_ATTEMPTS"])
        if not await self._verify_stored(otp_value, body["otp"]):
            # non-consuming: bump attempts, keep the (valid) OTP alive
            await self.auth.internal.update_verification_by_identifier(
                identifier, {"value": f"{otp_value}:{int(attempts or '0') + 1}"}
            )
            raise APIError(400, "INVALID_OTP", ERROR_CODES["INVALID_OTP"])
        return AuthResponse(body={"success": True})

    async def _route_verify_email(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        require_fields(body, "email", "otp")
        email = validate_email(body["email"])  # INVALID_EMAIL
        await self._atomic_verify(_to_identifier("email-verification", email), body["otp"])
        user = await self._find_user(email)
        if user is None:
            # safe to leak existence: the caller already holds a valid OTP
            raise APIError(400, "USER_NOT_FOUND", "User not found")
        cfg = self.auth.email_verification
        before = getattr(cfg, "before_email_verification", None)
        if before is not None:
            await _maybe_await(before(user, ctx.request))
        updated = await self.auth.internal.update_user(
            user["id"], {"email": email, "emailVerified": True}
        )
        updated = updated or {**user, "email": email, "emailVerified": True}
        after = getattr(cfg, "after_email_verification", None)
        if after is not None:
            await _maybe_await(after(updated, ctx.request))

        if cfg.auto_sign_in_after_verification:
            session, cookies = await create_session(
                self.auth, updated["id"], ctx.request, user=updated, ctx=ctx
            )
            response = AuthResponse(
                body={
                    "status": True,
                    "token": session["token"],
                    "user": self.auth.parse_user_output(updated),
                }
            )
            for cookie in cookies:
                response.set_cookie(cookie)
            return response

        response = AuthResponse(
            body={"status": True, "token": None, "user": self.auth.parse_user_output(updated)}
        )
        current, _cookies = await get_session(self.auth, ctx.request)
        same_user = current is not None and current["user"]["id"] == updated["id"]
        if same_user and updated["emailVerified"]:
            assert current is not None
            # only update THIS session's cache, and only when it's the verified user
            dont_remember = cookie_name(self.auth, "dont_remember") in ctx.request.cookies()
            cache_cookie = set_cookie_cache(
                self.auth,
                current["session"],
                {**current["user"], "emailVerified": True},
                dont_remember,
            )
            if cache_cookie is not None:
                response.set_cookie(cache_cookie)
        return response

    async def _route_sign_in(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        require_fields(body, "email", "otp")
        email = body["email"].lower()
        await self._atomic_verify(_to_identifier("sign-in", email), body["otp"])
        user = await self._find_user(email)

        if user is None:
            if self.disable_sign_up:
                # enumeration prevention: indistinguishable from a wrong OTP
                raise APIError(400, "INVALID_OTP", ERROR_CODES["INVALID_OTP"])
            rest = {k: v for k, v in body.items() if k not in ("email", "otp", "name", "image")}
            additional = self.auth.parse_user_input(rest, "create")
            new_user = await self.auth.internal.create_user(
                {
                    **additional,
                    "email": email,
                    "emailVerified": True,
                    "name": body.get("name") or "",
                    "image": body.get("image"),
                }
            )
            assert new_user is not None
            return await self._session_response(new_user, ctx)

        if not user["emailVerified"]:
            await self.auth.internal.revoke_unproven_account_access(user["id"])
            await self.auth.internal.update_user(user["id"], {"emailVerified": True})
        return await self._session_response(user, ctx)

    async def _session_response(self, user: dict[str, Any], ctx: Ctx) -> AuthResponse:
        session, cookies = await create_session(
            self.auth, user["id"], ctx.request, user=user, ctx=ctx
        )
        response = AuthResponse(
            body={"token": session["token"], "user": self.auth.parse_user_output(user)}
        )
        for cookie in cookies:
            response.set_cookie(cookie)
        return response

    async def _route_request_password_reset(self, ctx: Ctx) -> AuthResponse:
        return await self._request_password_reset(ctx)

    async def _route_forget_password(self, ctx: Ctx) -> AuthResponse:
        """Deprecated alias of ``/email-otp/request-password-reset``."""
        if not self._deprecation_warned:
            logger.warning(_DEPRECATION_MSG)
            self._deprecation_warned = True
        return await self._request_password_reset(ctx)

    async def _request_password_reset(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        require_fields(body, "email")
        email = body["email"].lower()
        identifier = _to_identifier("forget-password", email)
        otp = await self._resolve_otp(email, "forget-password", ctx)
        user = await self._find_user(email)
        if user is None:
            await self.auth.internal.delete_verification_by_identifier(identifier)
            return AuthResponse(body={"success": True})
        await self._send(email, otp, "forget-password", ctx)
        return AuthResponse(body={"success": True})

    async def _route_reset_password(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        require_fields(body, "email", "otp", "password")
        email = body["email"].lower()
        await self._atomic_verify(_to_identifier("forget-password", email), body["otp"])
        user = await self._find_user(email)
        if user is None:
            raise APIError(400, "USER_NOT_FOUND", "User not found")
        validate_password(ctx, body["password"])  # PASSWORD_TOO_SHORT / PASSWORD_TOO_LONG
        password_hash = await self.auth.hash_password_checked(body["password"], ctx.request.path)
        account = await self.auth.adapter.find_one(
            "account", [Where("userId", user["id"]), Where("providerId", "credential")]
        )
        if account is None:
            await self.auth.internal.create_account(
                {
                    "userId": user["id"],
                    "providerId": "credential",
                    "accountId": user["id"],
                    "password": password_hash,
                }
            )
        else:
            await self.auth.internal.update_account(account["id"], {"password": password_hash})

        cfg = self.auth.email_and_password
        if cfg.on_password_reset is not None:
            await cfg.on_password_reset({"user": user}, ctx.request)
        if not user["emailVerified"]:
            await self.auth.internal.update_user(user["id"], {"emailVerified": True})
        if cfg.revoke_sessions_on_password_reset:
            await self.auth.internal.delete_user_sessions(user["id"])
        return AuthResponse(body={"success": True})

    # --- change email (sensitive: authoritative, cache-bypassing session read) --------

    async def _sensitive_session(self, ctx: Ctx) -> dict[str, Any]:
        result, _cookies = await get_session(self.auth, ctx.request, disable_cache=True)
        if result is None or not result.get("session"):
            raise APIError(401, "UNAUTHORIZED", "Unauthorized")
        return result

    async def _route_request_email_change(self, ctx: Ctx) -> AuthResponse:
        session = await self._sensitive_session(ctx)
        if not self._change_email.get("enabled"):
            logger.error("Change email with OTP is disabled.")
            raise APIError(400, "BAD_REQUEST", "Change email with OTP is disabled")
        email = session["user"]["email"].lower()
        body = ctx.body()
        require_fields(body, "newEmail")
        new_email = validate_email(body["newEmail"])  # INVALID_EMAIL
        if new_email == email:
            logger.error("Email is the same")
            raise APIError(400, "BAD_REQUEST", "Email is the same")

        if self._change_email.get("verify_current_email"):
            if not body.get("otp"):
                raise APIError(400, "BAD_REQUEST", "OTP is required to verify current email")
            await self._atomic_verify(_to_identifier("email-verification", email), body["otp"])
        elif body.get("otp"):
            logger.warning(
                "OTP provided but not required for verifying current email. Set "
                "changeEmail.verifyCurrentEmail to true to require it."
            )

        otp = await self._generate(new_email, "change-email", ctx)
        identifier = _to_identifier("change-email", f"{email}-{new_email}")
        await self._create_value(identifier, await self._store(otp))

        if await self._find_user(new_email) is not None:
            # no enumeration when the new email is taken
            await self.auth.internal.delete_verification_by_identifier(identifier)
            return AuthResponse(body={"success": True})
        await self._send(new_email, otp, "change-email", ctx)
        return AuthResponse(body={"success": True})

    async def _route_change_email(self, ctx: Ctx) -> AuthResponse:
        session = await self._sensitive_session(ctx)
        if not self._change_email.get("enabled"):
            logger.error("Change email with OTP is disabled.")
            raise APIError(400, "BAD_REQUEST", "Change email with OTP is disabled")
        session_user = session["user"]
        session_obj = session["session"]
        email = session_user["email"].lower()
        body = ctx.body()
        require_fields(body, "newEmail", "otp")
        new_email = validate_email(body["newEmail"])  # INVALID_EMAIL
        if new_email == email:
            logger.error("Email is the same")
            raise APIError(400, "BAD_REQUEST", "Email is the same")

        identifier = _to_identifier("change-email", f"{email}-{new_email}")
        await self._atomic_verify(identifier, body["otp"])

        current_user = await self._find_user(email)
        if current_user is None:
            raise APIError(400, "USER_NOT_FOUND", "User not found")
        if await self._find_user(new_email) is not None:
            raise APIError(400, "BAD_REQUEST", "Email already in use")

        cfg = self.auth.email_verification
        before = getattr(cfg, "before_email_verification", None)
        if before is not None:
            await _maybe_await(before(current_user, ctx.request))
        updated = await self.auth.internal.update_user(
            current_user["id"], {"email": new_email, "emailVerified": True}
        )
        updated = updated or {**current_user, "email": new_email, "emailVerified": True}
        after = getattr(cfg, "after_email_verification", None)
        if after is not None:
            await _maybe_await(after(updated, ctx.request))

        response = AuthResponse(body={"success": True})
        response.set_cookie(refresh_session_cookie(self.auth, ctx.request, session_obj["token"]))
        if self.auth.session_options.cookie_cache.enabled:
            dont_remember = cookie_name(self.auth, "dont_remember") in ctx.request.cookies()
            cache_cookie = set_cookie_cache(
                self.auth,
                session_obj,
                {**session_user, "email": new_email, "emailVerified": True},
                dont_remember,
            )
            if cache_cookie is not None:
                response.set_cookie(cache_cookie)
        return response
