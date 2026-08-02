"""better-auth ``two-factor`` plugin, ported to Python.

Second-factor auth via TOTP, emailed/SMS OTP, and backup codes, with a trusted-device
cookie, per-challenge attempt budget and per-account lockout. Verified against TS
``packages/better-auth/src/plugins/two-factor/`` at v1.6.23.

Cross-runtime fidelity is a hard requirement: a ``twoFactor`` row written by the TS library
(XChaCha20-encrypted TOTP secret in ``secret``; XChaCha20-encrypted JSON array of backup
codes in ``backupCodes``) is read/written identically here — the crypto lives in
``crypto.py`` (TS-byte-verified).

Storage / identifier schemes (must match TS exactly):
- TOTP secret: ``generate_random_string(32)`` (charset ``a-z0-9A-Z-_``), ``symmetric_encrypt``-ed.
- Sign-in challenge: signed ``two_factor`` cookie whose value is the verification identifier
  ``2fa-<random20>``; a companion counter row ``2fa-attempts-<identifier>`` gates the budget.
- OTP: verification row ``2fa-otp-<challengeKey>`` with value ``"<storedOTP>:<attempts>"``.
- Trust device: HMAC ``createHMAC("SHA-256","base64urlnopad").sign(secret,"<userId>!<trustId>")``;
  cookie value ``"<token>!<trustId>"`` signed with the standard cookie signer; a verification
  row maps ``trustId -> userId``.

The ``/totp/generate`` and ``/two-factor/view-backup-codes`` server-only endpoints are exposed
as plain async methods (``generate_totp_code`` / ``view_backup_codes``) and are NOT mounted on
the HTTP router (a POST to their path 404s), mirroring TS ``createAuthEndpoint.serverOnly``.
"""

from __future__ import annotations

import contextlib
import hmac
import inspect
import json
import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from ..adapters.base import Where
from ..crypto import (
    default_key_hasher,
    generate_random_string,
    generate_totp,
    otpauth_url,
    sign_hmac_b64url,
    sign_value,
    symmetric_decrypt,
    symmetric_encrypt,
    unsign_value,
    verify_password,
    verify_totp,
)
from ..endpoints import require_fields
from ..plugins import HookSet, Plugin, PluginHook, RateLimitRule
from ..schema import Field, Reference, Schema
from ..session import build_cookie, clear_cookie, cookie_name, create_session, get_session, utcnow
from ..types import APIError, AuthResponse, Ctx

if TYPE_CHECKING:
    from ..auth import BetterAuth

logger = logging.getLogger("better_auth")

# --- constants (TS constant.ts) -------------------------------------------------------

TWO_FACTOR_COOKIE_NAME = "two_factor"
TRUST_DEVICE_COOKIE_NAME = "trust_device"
TRUST_DEVICE_COOKIE_MAX_AGE = 30 * 24 * 60 * 60  # 30 days
DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS = 5
DEFAULT_ACCOUNT_LOCKOUT_MAX_FAILED_ATTEMPTS = 10
DEFAULT_ACCOUNT_LOCKOUT_DURATION_SECONDS = 15 * 60
#: TS ``ctx.context.appName`` default (used as the fallback TOTP issuer).
DEFAULT_APP_NAME = "Better Auth"

#: charset for backup codes — TS ``generateRandomString(len, "a-z","A-Z","0-9")``.
_BACKUP_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

#: TS ``TWO_FACTOR_ERROR_CODES`` — exact strings (a shared client keys on these). The dict
#: KEY is the wire ``code``; the value is the ``message``.
ERROR_CODES: dict[str, str] = {
    "OTP_NOT_ENABLED": "OTP not enabled",
    "OTP_HAS_EXPIRED": "OTP has expired",
    "TOTP_NOT_ENABLED": "TOTP not enabled",
    "TWO_FACTOR_NOT_ENABLED": "Two factor isn't enabled",
    "BACKUP_CODES_NOT_ENABLED": "Backup codes aren't enabled",
    "INVALID_BACKUP_CODE": "Invalid backup code",
    "INVALID_CODE": "Invalid code",
    "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE": "Too many attempts. Please request a new code.",
    "ACCOUNT_TEMPORARILY_LOCKED": (
        "Too many failed verification attempts. Your account is temporarily locked. "
        "Please try again later."
    ),
    "INVALID_TWO_FACTOR_COOKIE": "Invalid two factor cookie",
}
#: TS naming alias.
TWO_FACTOR_ERROR_CODES = ERROR_CODES


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _err(status: int, key: str) -> APIError:
    return APIError(status, key, ERROR_CODES[key])


def _as_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None


async def _find_credential_account(auth: BetterAuth, user_id: str) -> dict[str, Any] | None:
    return await auth.adapter.find_one(
        "account", [Where("userId", user_id), Where("providerId", "credential")]
    )


async def _should_require_password(
    auth: BetterAuth, user_id: str, allow_passwordless: bool
) -> bool:
    """TS ``shouldRequirePassword`` — always require unless ``allow_passwordless`` and the
    user has no credential account with a password."""
    if not allow_passwordless:
        return True
    account = await _find_credential_account(auth, user_id)
    return bool(account and account.get("password"))


async def _password_valid(auth: BetterAuth, user_id: str, password: str) -> bool:
    account = await _find_credential_account(auth, user_id)
    if not account or not account.get("password"):
        return False
    return verify_password(account["password"], password)


class _Challenge:
    """The result of :meth:`TwoFactorPlugin._verify_two_factor` — a sign-in 2FA challenge
    (cookie present, no session) or an authenticated re-verification. Mirrors TS
    ``verifyTwoFactor(ctx)``'s ``{valid, invalid, session, key, beginAttempt}``."""

    def __init__(
        self,
        plugin: TwoFactorPlugin,
        *,
        is_sign_in: bool,
        user: dict[str, Any],
        session: dict[str, Any],
        identifier: str | None,
        key: str,
        dont_remember: bool,
        expires_at: datetime | None,
    ) -> None:
        self.plugin = plugin
        self.is_sign_in = is_sign_in
        self.user = user
        self.session = session
        self.identifier = identifier
        self.key = key
        self.dont_remember = dont_remember
        self.expires_at = expires_at

    def invalid(self, error_key: str) -> None:
        raise _err(401, error_key)

    async def begin_attempt(self, allowed: int) -> _Attempt:
        """Consume the per-challenge counter as the atomic race gate; a spent budget
        cancels the whole challenge (TS ``beginAttempt``). Re-verify is uncapped."""
        if not self.is_sign_in:
            return _Attempt(_noop, _noop)
        assert self.identifier is not None  # sign-in challenge always has an identifier
        auth = self.plugin.auth
        counter_id = f"2fa-attempts-{self.identifier}"
        try:
            consumed = await auth.internal.consume_verification_value(counter_id)
        except Exception:
            consumed = None
        if not consumed:
            raise _err(401, "INVALID_TWO_FACTOR_COOKIE")
        try:
            parsed = int(consumed["value"])
        except (TypeError, ValueError):
            parsed = -1
        attempts = parsed if parsed >= 0 else allowed
        if attempts >= allowed:
            # Budget spent: cancel the whole challenge so every factor must restart.
            with contextlib.suppress(Exception):
                await auth.internal.consume_verification_value(self.identifier)
            raise _err(400, "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE")
        expires_at = self.expires_at

        async def rearm(count: int) -> None:
            with contextlib.suppress(Exception):
                await auth.internal.create_verification_value(
                    {"value": str(count), "identifier": counter_id, "expiresAt": expires_at}
                )

        async def record_failure() -> None:
            await rearm(attempts + 1)

        async def restore() -> None:
            await rearm(attempts)

        return _Attempt(record_failure, restore)

    async def valid(
        self, ctx: Ctx, *, trust_device: bool = False, extra_cookies: list[str] | None = None
    ) -> AuthResponse:
        """Mint the session (sign-in) or return ``{token, user}`` (re-verify)."""
        auth = self.plugin.auth
        if not self.is_sign_in:
            resp = AuthResponse(
                body={
                    "token": self.session["session"]["token"],
                    "user": auth.parse_user_output(self.user),
                }
            )
            for cookie in extra_cookies or []:
                resp.set_cookie(cookie)
            return resp

        # The 2FA challenge is single-use and time-bounded: burn it atomically before
        # issuing a session so a stale replay or a concurrent second use cannot each mint
        # one. The consume returns None for an expired/already-consumed row.
        assert self.identifier is not None  # sign-in challenge always has an identifier
        consumed = await auth.internal.consume_verification_value(self.identifier)
        if not consumed or consumed["value"] != self.user["id"]:
            # ponytail: the consumed row is deleted, so the cookie is now inert; we skip an
            # active clear because APIError responses don't carry cookies in this port.
            raise _err(401, "INVALID_TWO_FACTOR_COOKIE")
        session, cookies = await create_session(
            auth,
            consumed["value"],
            ctx.request,
            remember_me=not self.dont_remember,
            user=self.user,
            ctx=ctx,
        )
        resp = AuthResponse(
            body={"token": session["token"], "user": auth.parse_user_output(self.user)}
        )
        for cookie in cookies:
            resp.set_cookie(cookie)
        resp.set_cookie(clear_cookie(auth, TWO_FACTOR_COOKIE_NAME))
        if trust_device:
            resp.set_cookie(await self.plugin._make_trust_cookie(self.user["id"]))
            resp.set_cookie(clear_cookie(auth, "dont_remember"))
        return resp


async def _noop() -> None:
    return None


class _Attempt:
    def __init__(self, record_failure: Any, restore: Any) -> None:
        self.record_failure = record_failure
        self.restore = restore


class TwoFactorPlugin(Plugin):
    """Port of TS ``twoFactor(options)``. Sub-options are snake_case dicts mirroring the TS
    option groups (``totp_options``, ``otp_options``, ``backup_code_options``,
    ``account_lockout``)."""

    id = "two-factor"
    error_codes: ClassVar[dict[str, str]] = ERROR_CODES

    def __init__(
        self,
        *,
        issuer: str | None = None,
        two_factor_table: str = "twoFactor",
        totp_options: dict[str, Any] | None = None,
        otp_options: dict[str, Any] | None = None,
        backup_code_options: dict[str, Any] | None = None,
        skip_verification_on_enable: bool = False,
        allow_passwordless: bool = False,
        two_factor_cookie_max_age: int = 600,
        trust_device_max_age: int = TRUST_DEVICE_COOKIE_MAX_AGE,
        account_lockout: dict[str, Any] | None = None,
    ) -> None:
        self.issuer = issuer
        self.table = two_factor_table
        self.skip_verification_on_enable = skip_verification_on_enable
        self.allow_passwordless = allow_passwordless
        self.two_factor_cookie_max_age = two_factor_cookie_max_age
        self.trust_device_max_age = trust_device_max_age
        self.account_lockout = account_lockout or {}

        totp = totp_options or {}
        self._totp_digits = totp.get("digits") or 6
        self._totp_period = totp.get("period") or 30
        self._totp_disable = bool(totp.get("disable"))
        self._totp_allow_passwordless = totp.get("allow_passwordless", allow_passwordless)

        otp = otp_options or {}
        self._otp_digits = otp.get("digits") or 6
        self._otp_period_seconds = (otp.get("period") or 3) * 60
        self._otp_allowed_attempts = otp.get("allowed_attempts") or 5
        self._otp_store: Any = otp.get("store_otp", "plain")
        self._otp_send = otp.get("send_otp")

        backup = backup_code_options or {}
        self._backup_amount = backup.get("amount", 10)
        self._backup_length = backup.get("length", 10)
        self._backup_store: Any = backup.get("store_backup_codes", "encrypted")
        self._backup_custom_generate = backup.get("custom_backup_codes_generate")
        self._backup_allow_passwordless = backup.get("allow_passwordless", allow_passwordless)

        # Instance schema (overrides the base ClassVar) — the table name is configurable, so
        # the model key must match ``self.table`` (TS ``mergeSchema`` with ``modelName``).
        self.schema: Schema = {
            "user": {
                "twoFactorEnabled": Field("boolean", required=False, default=False, input=False),
            },
            self.table: {
                "secret": Field("string", required=True, returned=False, index=True),
                "backupCodes": Field("string", required=True, returned=False),
                "userId": Field(
                    "string",
                    required=True,
                    returned=False,
                    references=Reference("user", "id"),
                    index=True,
                ),
                "verified": Field("boolean", required=False, default=True, input=False),
                "failedVerificationCount": Field(
                    "number", required=False, default=0, input=False, returned=False
                ),
                "lockedUntil": Field("datetime", required=False, input=False, returned=False),
            },
        }
        self._auth: BetterAuth | None = None

    @property
    def auth(self) -> BetterAuth:
        assert self._auth is not None, "plugin.init() has not run yet"
        return self._auth

    # --- lifecycle --------------------------------------------------------------------

    def init(self, auth: BetterAuth) -> None:
        self._auth = auth

    def routes(self) -> list[tuple[str, str, Any]]:
        return [
            ("POST", "/two-factor/enable", self._route_enable),
            ("POST", "/two-factor/disable", self._route_disable),
            ("POST", "/two-factor/get-totp-uri", self._route_get_totp_uri),
            ("POST", "/two-factor/verify-totp", self._route_verify_totp),
            ("POST", "/two-factor/send-otp", self._route_send_otp),
            ("POST", "/two-factor/verify-otp", self._route_verify_otp),
            ("POST", "/two-factor/verify-backup-code", self._route_verify_backup_code),
            ("POST", "/two-factor/generate-backup-codes", self._route_generate_backup_codes),
        ]

    def hooks(self) -> HookSet:
        return HookSet(after=[PluginHook(self._sign_in_matcher, self._after_sign_in)])

    def rate_limit(self) -> list[RateLimitRule]:
        return [
            RateLimitRule(
                window=10, max=3, path_matcher=lambda p: p.startswith("/two-factor/")
            )
        ]

    # --- password gate ----------------------------------------------------------------

    async def _require_password(
        self, user_id: str, password: str | None, allow_passwordless: bool
    ) -> None:
        if not await _should_require_password(self.auth, user_id, allow_passwordless):
            return
        if not password:
            raise APIError(400, "INVALID_PASSWORD", "Invalid password")
        if not await _password_valid(self.auth, user_id, password):
            raise APIError(400, "INVALID_PASSWORD", "Invalid password")

    async def _session(self, ctx: Ctx, *, disable_cache: bool = False) -> dict[str, Any]:
        result, _cookies = await get_session(self.auth, ctx.request, disable_cache=disable_cache)
        if result is None or not result.get("session"):
            raise APIError(401, "UNAUTHORIZED", "Unauthorized")
        return result

    # --- backup codes -----------------------------------------------------------------

    def _generate_backup_codes(self) -> list[str]:
        if self._backup_custom_generate is not None:
            return list(self._backup_custom_generate())
        codes = []
        for _ in range(self._backup_amount):
            code = generate_random_string(self._backup_length, _BACKUP_ALPHABET)
            codes.append(f"{code[:5]}-{code[5:]}")
        return codes

    async def _encode_backup_codes(self, codes: list[str]) -> str:
        payload = json.dumps(codes)
        store = self._backup_store
        if store == "encrypted":
            return symmetric_encrypt(self.auth.secret, payload)
        if isinstance(store, dict) and "encrypt" in store:
            return await _maybe_await(store["encrypt"](payload))
        return payload

    async def _decode_backup_codes(self, stored: str) -> list[str] | None:
        store = self._backup_store
        if store == "encrypted":
            decrypted = symmetric_decrypt(self.auth.secret, stored)
        elif isinstance(store, dict) and "decrypt" in store:
            decrypted = await _maybe_await(store["decrypt"](stored))
        else:
            decrypted = stored
        try:
            result = json.loads(decrypted)
        except (ValueError, TypeError):
            return None
        return result if isinstance(result, list) else None

    # --- OTP storage ------------------------------------------------------------------

    async def _store_otp(self, code: str) -> str:
        store = self._otp_store
        if store == "hashed":
            return default_key_hasher(code)
        if isinstance(store, dict) and "hash" in store:
            return await _maybe_await(store["hash"](code))
        if isinstance(store, dict) and "encrypt" in store:
            return await _maybe_await(store["encrypt"](code))
        if store == "encrypted":
            return symmetric_encrypt(self.auth.secret, code)
        return code

    async def _compare_otp(self, stored: str, provided: str) -> bool:
        store = self._otp_store
        if store == "hashed":
            return hmac.compare_digest(stored, default_key_hasher(provided))
        if isinstance(store, dict) and "hash" in store:
            return hmac.compare_digest(stored, await _maybe_await(store["hash"](provided)))
        if isinstance(store, dict) and "decrypt" in store:
            plain = await _maybe_await(store["decrypt"](stored))
            return hmac.compare_digest(plain.encode(), provided.encode())
        if store == "encrypted":
            plain = symmetric_decrypt(self.auth.secret, stored)
            return hmac.compare_digest(plain.encode(), provided.encode())
        return hmac.compare_digest(stored.encode(), provided.encode())

    # --- account lockout --------------------------------------------------------------

    def _lockout(self) -> tuple[bool, int, int]:
        cfg = self.account_lockout
        return (
            cfg.get("enabled", True),
            cfg.get("max_failed_attempts", DEFAULT_ACCOUNT_LOCKOUT_MAX_FAILED_ATTEMPTS),
            cfg.get("duration_seconds", DEFAULT_ACCOUNT_LOCKOUT_DURATION_SECONDS),
        )

    async def _assert_not_locked(self, tf: dict[str, Any]) -> None:
        enabled, _max, _dur = self._lockout()
        locked_until = _as_datetime(tf.get("lockedUntil"))
        if not enabled or locked_until is None:
            return
        if locked_until > utcnow():
            raise _err(429, "ACCOUNT_TEMPORARILY_LOCKED")
        # Clear the expired lock, guarded so a concurrently-set lock is not wiped.
        await self.auth.adapter.increment_one(
            self.table,
            [Where("id", tf["id"]), Where("lockedUntil", utcnow(), "lte")],
            increment={},
            set={"failedVerificationCount": 0, "lockedUntil": None},
        )

    async def _record_failure(self, tf: dict[str, Any]) -> None:
        enabled, max_failed, duration = self._lockout()
        if not enabled:
            return
        updated = await self.auth.adapter.increment_one(
            self.table, [Where("id", tf["id"])], increment={"failedVerificationCount": 1}
        )
        if (updated or {}).get("failedVerificationCount", 0) >= max_failed:
            await self.auth.adapter.update(
                self.table,
                [Where("id", tf["id"])],
                {"lockedUntil": utcnow() + timedelta(seconds=duration)},
            )

    async def _reset_failures(self, tf: dict[str, Any]) -> None:
        enabled, _max, _dur = self._lockout()
        if not enabled:
            return
        await self.auth.adapter.update(
            self.table, [Where("id", tf["id"])], {"failedVerificationCount": 0, "lockedUntil": None}
        )

    # --- verify-two-factor challenge --------------------------------------------------

    async def _verify_two_factor(self, ctx: Ctx) -> _Challenge:
        auth = self.auth
        result, _cookies = await get_session(auth, ctx.request)
        if result is not None and result.get("session"):
            user = result["user"]
            key = f"{user['id']}!{result['session']['id']}"
            return _Challenge(
                self,
                is_sign_in=False,
                user=user,
                session=result,
                identifier=None,
                key=key,
                dont_remember=False,
                expires_at=None,
            )
        # sign-in challenge: read the signed two_factor cookie (its value is the identifier)
        raw = ctx.request.cookies().get(cookie_name(auth, TWO_FACTOR_COOKIE_NAME))
        identifier = unsign_value(auth.secret, raw) if raw else None
        if not identifier:
            raise _err(401, "INVALID_TWO_FACTOR_COOKIE")
        verification = await auth.internal.find_verification_value(identifier)
        if not verification:
            raise _err(401, "INVALID_TWO_FACTOR_COOKIE")
        user = await auth.adapter.find_one("user", [Where("id", verification["value"])])
        if not user:
            raise _err(401, "INVALID_TWO_FACTOR_COOKIE")
        dont_remember = cookie_name(auth, "dont_remember") in ctx.request.cookies()
        return _Challenge(
            self,
            is_sign_in=True,
            user=user,
            session={"session": None, "user": user},
            identifier=identifier,
            key=identifier,
            dont_remember=dont_remember,
            expires_at=verification["expiresAt"],
        )

    # --- enable / disable -------------------------------------------------------------

    async def _route_enable(self, ctx: Ctx) -> AuthResponse:
        result = await self._session(ctx)
        user = result["user"]
        body = ctx.body()
        await self._require_password(user["id"], body.get("password"), self.allow_passwordless)

        secret = generate_random_string(32)
        encrypted_secret = symmetric_encrypt(self.auth.secret, secret)
        codes = self._generate_backup_codes()
        encrypted_codes = await self._encode_backup_codes(codes)

        cookies: list[str] = []
        if self.skip_verification_on_enable:
            updated = await self.auth.internal.update_user(user["id"], {"twoFactorEnabled": True})
            assert updated is not None
            _new_session, cookies = await create_session(
                self.auth, updated["id"], ctx.request, remember_me=True, user=updated, ctx=ctx
            )
            await self.auth.internal.delete_session(result["session"]["token"])

        existing = await self.auth.adapter.find_one(self.table, [Where("userId", user["id"])])
        await self.auth.adapter.delete_many(self.table, [Where("userId", user["id"])])
        verified = (
            existing is not None and existing.get("verified") is not False
        ) or self.skip_verification_on_enable
        await self.auth.adapter.create(
            self.table,
            {
                "secret": encrypted_secret,
                "backupCodes": encrypted_codes,
                "userId": user["id"],
                "verified": verified,
            },
        )
        issuer = body.get("issuer") or self.issuer or DEFAULT_APP_NAME
        uri = otpauth_url(
            secret, issuer, user["email"], digits=self._totp_digits, period=self._totp_period
        )
        resp = AuthResponse(body={"totpURI": uri, "backupCodes": codes})
        for cookie in cookies:
            resp.set_cookie(cookie)
        return resp

    async def _route_disable(self, ctx: Ctx) -> AuthResponse:
        # Sensitive: a DB-backed (cache-bypassing) session so a replayed cookie-cache
        # payload cannot authorize it.
        result = await self._session(ctx, disable_cache=True)
        user = result["user"]
        body = ctx.body()
        await self._require_password(user["id"], body.get("password"), self.allow_passwordless)

        updated = await self.auth.internal.update_user(user["id"], {"twoFactorEnabled": False})
        assert updated is not None
        await self.auth.adapter.delete_many(self.table, [Where("userId", updated["id"])])
        _new_session, cookies = await create_session(
            self.auth, updated["id"], ctx.request, remember_me=True, user=updated, ctx=ctx
        )
        await self.auth.internal.delete_session(result["session"]["token"])

        resp = AuthResponse(body={"status": True})
        for cookie in cookies:
            resp.set_cookie(cookie)
        # revoke the trust-device record + cookie
        raw = ctx.request.cookies().get(cookie_name(self.auth, TRUST_DEVICE_COOKIE_NAME))
        trust = unsign_value(self.auth.secret, raw) if raw else None
        if trust:
            _token, _sep, trust_id = trust.partition("!")
            if trust_id:
                await self.auth.internal.delete_verification_by_identifier(trust_id)
            resp.set_cookie(clear_cookie(self.auth, TRUST_DEVICE_COOKIE_NAME))
        return resp

    # --- TOTP -------------------------------------------------------------------------

    async def _route_get_totp_uri(self, ctx: Ctx) -> AuthResponse:
        if self._totp_disable:
            raise APIError(400, "TOTP_NOT_CONFIGURED", "totp isn't configured")
        result = await self._session(ctx)
        user = result["user"]
        tf = await self.auth.adapter.find_one(self.table, [Where("userId", user["id"])])
        if not tf:
            raise _err(400, "TOTP_NOT_ENABLED")
        secret = symmetric_decrypt(self.auth.secret, tf["secret"])
        await self._require_password(
            user["id"], ctx.body().get("password"), self._totp_allow_passwordless
        )
        uri = otpauth_url(
            secret,
            self.issuer or DEFAULT_APP_NAME,
            user["email"],
            digits=self._totp_digits,
            period=self._totp_period,
        )
        return AuthResponse(body={"totpURI": uri})

    async def _route_verify_totp(self, ctx: Ctx) -> AuthResponse:
        if self._totp_disable:
            raise APIError(400, "TOTP_NOT_CONFIGURED", "totp isn't configured")
        body = ctx.body()
        require_fields(body, "code")
        challenge = await self._verify_two_factor(ctx)
        user = challenge.user
        is_sign_in = challenge.is_sign_in
        tf = await self.auth.adapter.find_one(self.table, [Where("userId", user["id"])])
        if not tf:
            raise _err(400, "TOTP_NOT_ENABLED")
        # During sign-in, reject explicitly-unverified rows (abandoned enrollments); use
        # ``is False`` (not falsy) so null/absent pre-migration rows stay valid.
        if is_sign_in and tf.get("verified") is False:
            raise _err(400, "TOTP_NOT_ENABLED")
        if is_sign_in:
            await self._assert_not_locked(tf)
        attempt = (
            await challenge.begin_attempt(DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS)
            if is_sign_in
            else None
        )
        try:
            decrypted = symmetric_decrypt(self.auth.secret, tf["secret"])
            status = verify_totp(
                body["code"], secret=decrypted, digits=self._totp_digits, period=self._totp_period
            )
        except Exception:
            if attempt:
                await attempt.restore()
            raise
        if not status:
            if attempt:
                await attempt.record_failure()
            if is_sign_in:
                await self._record_failure(tf)
            challenge.invalid("INVALID_CODE")
        if is_sign_in:
            await self._reset_failures(tf)

        # Enrollment mode: row exists but isn't verified yet.
        if tf.get("verified") is not True:
            if not user.get("twoFactorEnabled"):
                active = challenge.session["session"]
                updated = await self.auth.internal.update_user(
                    user["id"], {"twoFactorEnabled": True}
                )
                assert updated is not None
                new_session, cookies = await create_session(
                    self.auth, user["id"], ctx.request, remember_me=True, user=updated, ctx=ctx
                )
                await self.auth.internal.delete_session(active["token"])
                # Mark verified only after all session ops succeed (retry-safe).
                await self.auth.adapter.update(
                    self.table, [Where("id", tf["id"])], {"verified": True}
                )
                resp = AuthResponse(
                    body={
                        "token": new_session["token"],
                        "user": self.auth.parse_user_output(updated),
                    }
                )
                for cookie in cookies:
                    resp.set_cookie(cookie)
                return resp
            await self.auth.adapter.update(self.table, [Where("id", tf["id"])], {"verified": True})
        return await challenge.valid(ctx, trust_device=bool(body.get("trustDevice")))

    # --- OTP --------------------------------------------------------------------------

    async def _route_send_otp(self, ctx: Ctx) -> AuthResponse:
        if not self._otp_send:
            logger.error("send otp isn't configured. Please configure otpOptions.sendOTP.")
            raise APIError(400, "OTP_NOT_CONFIGURED", "otp isn't configured")
        challenge = await self._verify_two_factor(ctx)
        code = generate_random_string(self._otp_digits, "0123456789")
        stored = await self._store_otp(code)
        await self.auth.internal.create_verification_value(
            {
                "value": f"{stored}:0",
                "identifier": f"2fa-otp-{challenge.key}",
                "expiresAt": utcnow() + timedelta(seconds=self._otp_period_seconds),
            }
        )
        await _maybe_await(self._otp_send({"user": challenge.user, "otp": code}, ctx))
        return AuthResponse(body={"status": True})

    async def _route_verify_otp(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        require_fields(body, "code")
        challenge = await self._verify_two_factor(ctx)
        is_sign_in = challenge.is_sign_in
        tf: dict[str, Any] | None = None
        if is_sign_in:
            tf = await self.auth.adapter.find_one(
                self.table, [Where("userId", challenge.user["id"])]
            )
            if not tf:
                raise _err(400, "TWO_FACTOR_NOT_ENABLED")
            await self._assert_not_locked(tf)
        # Consume the OTP row atomically as the race gate.
        otp_identifier = f"2fa-otp-{challenge.key}"
        consumed = await self.auth.internal.consume_verification_value(otp_identifier)
        if not consumed:
            raise _err(400, "OTP_HAS_EXPIRED")
        stored_otp, _sep, counter = consumed["value"].partition(":")
        try:
            attempts = int(counter)
        except (TypeError, ValueError):
            attempts = 0
        if attempts >= self._otp_allowed_attempts:
            raise _err(400, "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE")
        if await self._compare_otp(stored_otp, body["code"]):
            if tf:
                await self._reset_failures(tf)
            if not challenge.user.get("twoFactorEnabled"):
                active = challenge.session["session"]
                if not active:
                    raise APIError(400, "FAILED_TO_CREATE_SESSION", "failed to create session")
                updated = await self.auth.internal.update_user(
                    challenge.user["id"], {"twoFactorEnabled": True}
                )
                assert updated is not None
                new_session, cookies = await create_session(
                    self.auth,
                    challenge.user["id"],
                    ctx.request,
                    remember_me=True,
                    user=updated,
                    ctx=ctx,
                )
                await self.auth.internal.delete_session(active["token"])
                resp = AuthResponse(
                    body={
                        "token": new_session["token"],
                        "user": self.auth.parse_user_output(updated),
                    }
                )
                for cookie in cookies:
                    resp.set_cookie(cookie)
                return resp
            return await challenge.valid(ctx, trust_device=bool(body.get("trustDevice")))
        # Wrong code within budget: re-arm the row with the incremented counter + same expiry.
        await self.auth.internal.create_verification_value(
            {
                "value": f"{stored_otp}:{attempts + 1}",
                "identifier": otp_identifier,
                "expiresAt": consumed["expiresAt"],
            }
        )
        if tf:
            await self._record_failure(tf)
        challenge.invalid("INVALID_CODE")
        raise AssertionError("unreachable")  # invalid() always raises

    # --- backup codes -----------------------------------------------------------------

    async def _route_verify_backup_code(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        require_fields(body, "code")
        challenge = await self._verify_two_factor(ctx)
        user = challenge.user
        is_sign_in = challenge.is_sign_in
        tf = await self.auth.adapter.find_one(self.table, [Where("userId", user["id"])])
        if not tf:
            raise _err(400, "BACKUP_CODES_NOT_ENABLED")
        if is_sign_in:
            await self._assert_not_locked(tf)
        attempt = (
            await challenge.begin_attempt(DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS)
            if is_sign_in
            else None
        )
        try:
            codes = await self._decode_backup_codes(tf["backupCodes"])
        except Exception:
            if attempt:
                await attempt.restore()
            raise
        code = body["code"]
        matched = codes is not None and code in codes
        updated_codes = [c for c in codes if c != code] if codes is not None else None
        if not matched or updated_codes is None:
            if attempt:
                await attempt.record_failure()
            if is_sign_in:
                await self._record_failure(tf)
            raise _err(401, "INVALID_BACKUP_CODE")

        encoded = await self._encode_backup_codes(updated_codes)
        # Rewrite the set minus the used code via a CAS guarded on the old value: a lost
        # race (concurrent use of the same code) → 409, so a code is single-use.
        updated = await self.auth.adapter.increment_one(
            self.table,
            [Where("id", tf["id"]), Where("backupCodes", tf["backupCodes"])],
            increment={},
            set={"backupCodes": encoded},
        )
        if not updated:
            raise APIError(409, "CONFLICT", "Failed to verify backup code. Please try again.")
        if is_sign_in:
            await self._reset_failures(tf)
        if not body.get("disableSession"):
            return await challenge.valid(ctx, trust_device=bool(body.get("trustDevice")))
        session = challenge.session["session"]
        return AuthResponse(
            body={
                "token": session["token"] if session else None,
                "user": self.auth.parse_user_output(user),
            }
        )

    async def _route_generate_backup_codes(self, ctx: Ctx) -> AuthResponse:
        result = await self._session(ctx)
        user = result["user"]
        if not user.get("twoFactorEnabled"):
            raise _err(400, "TWO_FACTOR_NOT_ENABLED")
        await self._require_password(
            user["id"], ctx.body().get("password"), self._backup_allow_passwordless
        )
        tf = await self.auth.adapter.find_one(self.table, [Where("userId", user["id"])])
        if not tf:
            raise _err(400, "TWO_FACTOR_NOT_ENABLED")
        codes = self._generate_backup_codes()
        encoded = await self._encode_backup_codes(codes)
        await self.auth.adapter.update(
            self.table, [Where("id", tf["id"])], {"backupCodes": encoded}
        )
        return AuthResponse(body={"status": True, "backupCodes": codes})

    # --- server-only (not HTTP-dispatchable) ------------------------------------------

    async def view_backup_codes(self, user_id: str) -> dict[str, Any]:
        """TS server-only ``viewBackupCodes`` — the user's decrypted backup codes."""
        tf = await self.auth.adapter.find_one(self.table, [Where("userId", user_id)])
        if not tf:
            raise _err(400, "BACKUP_CODES_NOT_ENABLED")
        codes = await self._decode_backup_codes(tf["backupCodes"])
        if codes is None:
            raise _err(400, "INVALID_BACKUP_CODE")
        return {"status": True, "backupCodes": codes}

    async def generate_totp_code(self, secret: str) -> dict[str, str]:
        """TS server-only ``generateTOTP`` — a current TOTP code for ``secret``."""
        if self._totp_disable:
            raise APIError(400, "TOTP_NOT_CONFIGURED", "totp isn't configured")
        return {"code": generate_totp(secret, digits=self._totp_digits, period=self._totp_period)}

    # --- trust device / sign-in gate --------------------------------------------------

    async def _make_trust_cookie(self, user_id: str) -> str:
        auth = self.auth
        max_age = self.trust_device_max_age
        trust_id = f"trust-device-{generate_random_string(32)}"
        token = sign_hmac_b64url(auth.secret, f"{user_id}!{trust_id}")
        await auth.internal.create_verification_value(
            {
                "value": user_id,
                "identifier": trust_id,
                "expiresAt": utcnow() + timedelta(seconds=max_age),
            }
        )
        return build_cookie(
            auth,
            sign_value(auth.secret, f"{token}!{trust_id}"),
            max_age,
            TRUST_DEVICE_COOKIE_NAME,
        )

    def _sign_in_matcher(self, ctx: Ctx) -> bool:
        return ctx.request.path in (
            "/sign-in/email",
            "/sign-in/username",
            "/sign-in/phone-number",
        )

    def _scrub_session_cookies(self, response: AuthResponse) -> None:
        """Drop the credential sign-in's session_token/session_data Set-Cookie headers and
        replace them with explicit clears, so no valid signed session cookie leaks on a
        2FA-required sign-in."""
        auth = self.auth
        session_name = cookie_name(auth, "session_token")
        data_name = cookie_name(auth, "session_data")
        kept: list[tuple[str, str]] = []
        for header, value in response.headers:
            if header.lower() == "set-cookie":
                name = value.split("=", 1)[0]
                if name in (session_name, data_name) or name.startswith(data_name + "."):
                    continue
            kept.append((header, value))
        response.headers = kept
        response.set_cookie(clear_cookie(auth, "session_token"))
        response.set_cookie(clear_cookie(auth, "session_data"))

    async def _after_sign_in(self, ctx: Ctx) -> AuthResponse | None:
        data = ctx.new_session
        if data is None:
            return None
        user = data.get("user") or {}
        if not user.get("twoFactorEnabled"):
            return None
        auth = self.auth

        # Trust-device check: a valid HMAC + live server record rotates the cookie and lets
        # sign-in proceed; anything else clears the cookie and falls through to a challenge.
        raw = ctx.request.cookies().get(cookie_name(auth, TRUST_DEVICE_COOKIE_NAME))
        trust_cookie = unsign_value(auth.secret, raw) if raw else None
        if trust_cookie:
            token, _sep, trust_id = trust_cookie.partition("!")
            if token and trust_id:
                expected = sign_hmac_b64url(auth.secret, f"{user['id']}!{trust_id}")
                if hmac.compare_digest(token, expected):
                    record = await auth.internal.find_verification_value(trust_id)
                    expires = _as_datetime(record["expiresAt"]) if record else None
                    if (
                        record
                        and record["value"] == user["id"]
                        and expires is not None
                        and expires > utcnow()
                    ):
                        await auth.internal.delete_verification_by_identifier(trust_id)
                        ctx.response.set_cookie(await self._make_trust_cookie(user["id"]))
                        return None  # trusted device: let sign-in proceed
            ctx.response.set_cookie(clear_cookie(auth, TRUST_DEVICE_COOKIE_NAME))

        # Delete the just-created session and reset newSession so downstream hooks don't see
        # a session that no longer exists, then arm the 2FA challenge.
        await auth.internal.delete_session(data["session"]["token"])
        ctx.new_session = None

        max_age = self.two_factor_cookie_max_age
        identifier = f"2fa-{generate_random_string(20)}"
        expires_at = utcnow() + timedelta(seconds=max_age)
        await auth.internal.create_verification_value(
            {"value": user["id"], "identifier": identifier, "expiresAt": expires_at}
        )
        await auth.internal.create_verification_value(
            {"value": "0", "identifier": f"2fa-attempts-{identifier}", "expiresAt": expires_at}
        )

        self._scrub_session_cookies(ctx.response)
        ctx.response.set_cookie(
            build_cookie(
                auth, sign_value(auth.secret, identifier), max_age, TWO_FACTOR_COOKIE_NAME
            )
        )

        methods: list[str] = []
        if not self._totp_disable:
            tf = await auth.adapter.find_one(self.table, [Where("userId", user["id"])])
            if tf and tf.get("verified") is not False:
                methods.append("totp")
        if self._otp_send:
            methods.append("otp")

        ctx.response.status = 200
        ctx.response.body = {"twoFactorRedirect": True, "twoFactorMethods": methods}
        ctx.response.media_type = None
        return ctx.response


__all__ = ["ERROR_CODES", "TWO_FACTOR_ERROR_CODES", "TwoFactorPlugin"]
