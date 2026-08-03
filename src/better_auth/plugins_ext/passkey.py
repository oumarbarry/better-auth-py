"""passkey plugin (WebAuthn/FIDO2) — a faithful port of ``@better-auth/passkey``.

A thin wrapper over ``webauthn`` (py_webauthn) that generates registration/authentication
ceremony options, verifies authenticator responses, persists one ``passkey`` row per
credential, and mints a session on a verified authentication. Wire + storage parity with
the TS plugin (``packages/passkey/src/{index,routes,schema,utils,error-codes,types}.ts``).

Cross-runtime storage contract (a TS-written row must verify under Python and vice-versa):

- ``publicKey`` = **standard base64, PADDED** of the raw COSE bytes (``routes.ts:686``) — NOT
  base64url.
- ``credentialID`` = **base64url, no padding** (``credential.id``).
- ``deviceType`` = camelCase ``"singleDevice"``/``"multiDevice"`` — py_webauthn returns
  snake_case, mapped here (``_device_type``).
- ``transports`` = comma-joined raw WebAuthn tokens (``"internal"``, ``"usb,nfc"``, ``""``).
- ``counter``/``aaguid``/``backedUp`` = plain int / UUID string / bool.

Challenge flow: ``generate_random_string(32)`` token → signed cookie
(``<prefix>.better-auth-passkey``, maxAge 300) → verification row keyed by the RAW token,
value ``JSON({type, expectedChallenge, userData, context})``, ``expiresAt`` now+300s. Verify:
unsign cookie → ``consume_verification_value`` (atomic single-use) → ceremony-type gate BEFORE
calling the webauthn lib (``routes.ts:608``/``:801``).

py_webauthn 3.0 notes (the installed version; newer than the 2.x the parity spec mapped):
verify functions **raise** ``Invalid{Registration,Authentication}Response`` on failure (there is
no ``{verified}`` bool); result models are dataclasses (``credential_id: bytes``,
``credential_public_key: bytes``, ``sign_count``/``new_sign_count``, ``credential_device_type``
enum, ``aaguid`` UUID string). ``generate_*_options`` take a fixed ``challenge`` kwarg and no
``extensions`` kwarg — extensions are spliced into the serialized options
(``_serialize_options``). ``options_to_json_dict`` yields the exact camelCase/base64url wire dict.
"""

from __future__ import annotations

import base64
import inspect
import json
import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar
from urllib.parse import urlsplit

try:
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        verify_authentication_response,
        verify_registration_response,
    )
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "webauthn is not installed; install it with `pip install better-auth-server[passkey]`"
    ) from exc
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json_dict
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ..adapters.base import Where
from ..crypto import generate_random_string, sign_value, unsign_value
from ..plugins import Plugin
from ..schema import Field, Reference, Schema
from ..session import build_cookie, cookie_name, create_session
from ..types import APIError, AuthResponse, Ctx

logger = logging.getLogger("better_auth")

MAX_AGE_IN_SECONDS = 60 * 5  # 5 minutes (index.ts:31)
# @simplewebauthn offers [EdDSA, ES256, RS256]; pin the same set so pubKeyCredParams match TS.
_SUPPORTED_ALGS = [
    COSEAlgorithmIdentifier.EDDSA,  # -8
    COSEAlgorithmIdentifier.ECDSA_SHA_256,  # -7
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,  # -257
]
_DEVICE_TYPE_MAP = {"single_device": "singleDevice", "multi_device": "multiDevice"}
_VALID_TRANSPORTS = {t.value for t in AuthenticatorTransport}

PASSKEY_ERROR_CODES: dict[str, str] = {
    "CHALLENGE_NOT_FOUND": "Challenge not found",
    "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY": "You are not allowed to register this passkey",
    "FAILED_TO_VERIFY_REGISTRATION": "Failed to verify registration",
    "PASSKEY_NOT_FOUND": "Passkey not found",
    "AUTHENTICATION_FAILED": "Authentication failed",
    "UNABLE_TO_CREATE_SESSION": "Unable to create session",
    "FAILED_TO_UPDATE_PASSKEY": "Failed to update passkey",
    "PREVIOUSLY_REGISTERED": "Previously registered",
    "REGISTRATION_CANCELLED": "Registration cancelled",
    "AUTH_CANCELLED": "Auth cancelled",
    "UNKNOWN_ERROR": "Unknown error",
    "SESSION_REQUIRED": "Passkey registration requires an authenticated session",
    "RESOLVE_USER_REQUIRED": (
        "Passkey registration requires either an authenticated session or a resolveUser "
        "callback when requireSession is false"
    ),
    "RESOLVED_USER_INVALID": "Resolved user is invalid",
}


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


# --- encoding helpers (cross-runtime contract; unit-tested with fixed vectors) -----------


def _encode_public_key(cose_bytes: bytes) -> str:
    """Standard base64, PADDED (``base64.encode``, routes.ts:686) — NOT base64url."""
    return base64.b64encode(cose_bytes).decode()


def _encode_credential_id(credential_id: bytes) -> str:
    """base64url, no padding (``credential.id`` is a Base64URLString)."""
    return bytes_to_base64url(credential_id)


def _device_type(raw: str) -> str:
    """py_webauthn snake_case → TS camelCase; unknown values pass through unchanged."""
    return _DEVICE_TYPE_MAP.get(raw, raw)


def _transports_to_str(transports: list[str] | None) -> str:
    """``resp.response.transports?.join(",") ?? ""`` (routes.ts:694)."""
    return ",".join(transports or [])


def _transports_to_enums(transports: str | None) -> list[AuthenticatorTransport] | None:
    """Stored comma-joined tokens → descriptor transports; drop unknown tokens (empty → None)."""
    if not transports:
        return None
    tokens = [t for t in transports.split(",") if t in _VALID_TRANSPORTS]
    return [AuthenticatorTransport(t) for t in tokens] or None


class PasskeyPlugin(Plugin):
    id = "passkey"
    version = "1.3.0"
    error_codes: ClassVar[dict[str, str]] = PASSKEY_ERROR_CODES
    schema: ClassVar[Schema] = {
        "passkey": {
            "name": Field("string", required=False),
            "publicKey": Field("string", required=True),
            "userId": Field(
                "string", required=True, references=Reference("user", "id"), index=True
            ),
            "credentialID": Field("string", required=True, index=True),
            "counter": Field("number", required=True),
            "deviceType": Field("string", required=True),
            "backedUp": Field("boolean", required=True),
            "transports": Field("string", required=False),
            "createdAt": Field("datetime", required=False),
            "aaguid": Field("string", required=False),
        }
    }

    def __init__(
        self,
        *,
        rp_id: str | None = None,
        rp_name: str = "Better Auth",  # port has no appName; TS default is "Better Auth"
        origin: str | list[str] | None = None,
        authenticator_selection: dict[str, Any] | None = None,
        challenge_cookie: str = "better-auth-passkey",
        registration: dict[str, Any] | None = None,
        authentication: dict[str, Any] | None = None,
    ) -> None:
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        self.authenticator_selection = authenticator_selection or {}
        self.challenge_cookie = challenge_cookie
        reg = registration or {}
        self.require_session: bool = reg.get("require_session", True)
        self.resolve_user: Callable[..., Any] | None = reg.get("resolve_user")
        self.reg_after_verification: Callable[..., Any] | None = reg.get("after_verification")
        self.reg_extensions = reg.get("extensions")
        auth = authentication or {}
        self.auth_after_verification: Callable[..., Any] | None = auth.get("after_verification")
        self.auth_extensions = auth.get("extensions")

    def routes(self) -> list[tuple[str, str, Any]]:
        return [
            ("GET", "/passkey/generate-register-options", self._generate_register_options),
            ("POST", "/passkey/verify-registration", self._verify_registration),
            ("GET", "/passkey/generate-authenticate-options", self._generate_authenticate_options),
            ("POST", "/passkey/verify-authentication", self._verify_authentication),
            ("GET", "/passkey/list-user-passkeys", self._list_passkeys),
            ("POST", "/passkey/delete-passkey", self._delete_passkey),
            ("POST", "/passkey/update-passkey", self._update_passkey),
        ]

    # --- small helpers ------------------------------------------------------------------

    def _rp_id(self, ctx: Ctx) -> str:
        return self.rp_id or (urlsplit(ctx.auth.base_url).hostname or "localhost")

    def _expected_origin(self, ctx: Ctx) -> str | list[str]:
        # opts.origin || header("origin") || "" (routes.ts:567/:764)
        return self.origin or ctx.request.headers.get("origin") or ""

    def _challenge_cookie_name(self, ctx: Ctx) -> str:
        return cookie_name(ctx.auth, self.challenge_cookie)

    async def _resolve_extensions(self, resolver: Any, ctx: Ctx) -> dict[str, Any] | None:
        if not resolver:
            return None
        if callable(resolver):
            return await _maybe_await(resolver(ctx=ctx))
        return resolver

    async def _set_challenge(self, ctx: Ctx, response: AuthResponse, value: dict[str, Any]) -> None:
        """Mint a verification token, set the signed challenge cookie, store the row."""
        token = generate_random_string(32)
        signed = sign_value(ctx.auth.secret, token)
        response.set_cookie(
            build_cookie(ctx.auth, signed, MAX_AGE_IN_SECONDS, base=self.challenge_cookie)
        )
        now = datetime.now(timezone.utc)  # per-request expiry (passkey.test.ts:1303)
        await ctx.internal.create_verification_value(
            {
                "identifier": token,  # RAW token, not hashed (routes.ts:336)
                "value": json.dumps(value, separators=(",", ":")),
                "expiresAt": now + timedelta(seconds=MAX_AGE_IN_SECONDS),
            }
        )

    async def _consume_challenge(self, ctx: Ctx, ceremony: str) -> dict[str, Any]:
        """Unsign cookie → atomic consume → ceremony-type gate. Returns the stored value dict."""
        raw = ctx.request.cookies().get(self._challenge_cookie_name(ctx))
        token = unsign_value(ctx.auth.secret, raw) if raw else None
        if not token:
            raise APIError(400, "CHALLENGE_NOT_FOUND", PASSKEY_ERROR_CODES["CHALLENGE_NOT_FOUND"])
        data = await ctx.internal.consume_verification_value(token)
        if not data:
            raise APIError(400, "CHALLENGE_NOT_FOUND", PASSKEY_ERROR_CODES["CHALLENGE_NOT_FOUND"])
        value = json.loads(data["value"])
        # A legacy row (pre-marker) has no `type`; accept it in either verifier. Only reject a
        # challenge explicitly tagged for the OTHER ceremony — before touching the webauthn lib.
        stored_type = value.get("type")
        if stored_type is not None and stored_type != ceremony:
            raise APIError(400, "CHALLENGE_NOT_FOUND", PASSKEY_ERROR_CODES["CHALLENGE_NOT_FOUND"])
        return value

    async def _fresh_session(self, ctx: Ctx) -> dict[str, Any]:
        """Require a fresh session for the register endpoints (TS freshSessionMiddleware).

        ponytail: reuses SESSION_REQUIRED for both missing and stale (no freshness error code in
        the passkey table); swap in a dedicated code if a freshness test is ever added.
        """
        result = await ctx.get_session()
        if result is None:
            raise APIError(401, "SESSION_REQUIRED", PASSKEY_ERROR_CODES["SESSION_REQUIRED"])
        created = result["session"]["createdAt"]
        if isinstance(created, str):
            created = datetime.fromisoformat(created.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - created).total_seconds()
        if age > ctx.auth.session_options.fresh_age:
            raise APIError(401, "SESSION_REQUIRED", PASSKEY_ERROR_CODES["SESSION_REQUIRED"])
        return result

    async def _resolve_registration_user(
        self, ctx: Ctx
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """(resolvedUser, session) per resolveRegistrationUser (routes.ts:65)."""
        if self.require_session:
            session = await self._fresh_session(ctx)
            user = session["user"]
            name = user.get("email") or user["id"]
            return {"id": user["id"], "name": name, "displayName": name}, session
        session = await ctx.get_session()
        if session and session["user"].get("id"):
            user = session["user"]
            name = user.get("email") or user["id"]
            return {"id": user["id"], "name": name, "displayName": name}, session
        if not self.resolve_user:
            raise APIError(
                400, "RESOLVE_USER_REQUIRED", PASSKEY_ERROR_CODES["RESOLVE_USER_REQUIRED"]
            )
        context = ctx.request.query.get("context")
        resolved = await _maybe_await(self.resolve_user(ctx=ctx, context=context))
        if not resolved or not resolved.get("id") or not resolved.get("name"):
            raise APIError(
                400, "RESOLVED_USER_INVALID", PASSKEY_ERROR_CODES["RESOLVED_USER_INVALID"]
            )
        return resolved, None

    def _exclude_or_allow(
        self, passkeys: list[dict[str, Any]]
    ) -> list[PublicKeyCredentialDescriptor]:
        return [
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(pk["credentialID"]),
                transports=_transports_to_enums(pk.get("transports")),
            )
            for pk in passkeys
        ]

    # --- endpoints ----------------------------------------------------------------------

    async def _generate_register_options(self, ctx: Ctx) -> AuthResponse:
        user, _session = await self._resolve_registration_user(ctx)
        user_passkeys = await ctx.adapter.find_many("passkey", [Where("userId", user["id"])])
        extensions = await self._resolve_extensions(self.reg_extensions, ctx)

        selection: dict[str, Any] = {
            "resident_key": ResidentKeyRequirement.PREFERRED,
            "user_verification": UserVerificationRequirement.PREFERRED,
            **self.authenticator_selection,
        }
        attachment = ctx.request.query.get("authenticatorAttachment")
        if attachment:
            selection["authenticator_attachment"] = AuthenticatorAttachment(attachment)
        query_name = ctx.request.query.get("name")

        options = generate_registration_options(
            rp_id=self._rp_id(ctx),
            rp_name=self.rp_name,
            # fresh per-request handle; base64url'd into user.id by options_to_json (routes.ts:289)
            user_id=generate_random_string(32, "abcdefghijklmnopqrstuvwxyz0123456789").encode(),
            user_name=query_name or user["name"] or user["id"],
            user_display_name=user.get("displayName") or user["name"] or user["id"],
            authenticator_selection=AuthenticatorSelectionCriteria(**selection),
            exclude_credentials=self._exclude_or_allow(user_passkeys),
            supported_pub_key_algs=_SUPPORTED_ALGS,
        )
        wire = options_to_json_dict(options)
        if extensions is not None:
            wire["extensions"] = extensions
        response = AuthResponse(body=wire)
        await self._set_challenge(
            ctx,
            response,
            {
                "type": "registration",
                "expectedChallenge": bytes_to_base64url(options.challenge),
                "userData": {
                    "id": user["id"],
                    "name": user["name"],
                    "displayName": user.get("displayName"),
                },
                "context": ctx.request.query.get("context"),
            },
        )
        return response

    async def _generate_authenticate_options(self, ctx: Ctx) -> AuthResponse:
        session = await ctx.get_session()
        user_passkeys: list[dict[str, Any]] = []
        if session:
            user_passkeys = await ctx.adapter.find_many(
                "passkey", [Where("userId", session["user"]["id"])]
            )
        extensions = await self._resolve_extensions(self.auth_extensions, ctx)

        options = generate_authentication_options(
            rp_id=self._rp_id(ctx),
            user_verification=UserVerificationRequirement.PREFERRED,
            allow_credentials=self._exclude_or_allow(user_passkeys) or None,
        )
        wire = options_to_json_dict(options)
        # py_webauthn always emits allowCredentials:[]; TS omits it entirely when no session.
        if not user_passkeys:
            wire.pop("allowCredentials", None)
        if extensions is not None:
            wire["extensions"] = extensions
        response = AuthResponse(body=wire)
        await self._set_challenge(
            ctx,
            response,
            {
                "type": "authentication",
                "expectedChallenge": bytes_to_base64url(options.challenge),
                "userData": {"id": session["user"]["id"] if session else ""},
            },
        )
        return response

    async def _verify_registration(self, ctx: Ctx) -> AuthResponse:
        origin = self._expected_origin(ctx)
        if not origin:
            raise APIError(
                400,
                "FAILED_TO_VERIFY_REGISTRATION",
                PASSKEY_ERROR_CODES["FAILED_TO_VERIFY_REGISTRATION"],
            )
        body = ctx.body()
        resp = body["response"]
        name_body = (body.get("name") or "").strip() or None

        value = await self._consume_challenge(ctx, "registration")
        expected_challenge = value["expectedChallenge"]
        user_data = value["userData"]
        context = value.get("context")

        session = (
            await self._fresh_session(ctx) if self.require_session else await ctx.get_session()
        )
        session_uid = session["user"]["id"] if session else None
        if session_uid and user_data["id"] != session_uid:
            raise APIError(
                401,
                "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
                PASSKEY_ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"],
            )

        try:
            verification = verify_registration_response(
                credential=resp,
                expected_challenge=base64url_to_bytes(expected_challenge),
                expected_origin=origin,
                expected_rp_id=self._rp_id(ctx),
                require_user_verification=False,
            )
            resolved_user = {
                "id": user_data["id"],
                "name": user_data.get("name") or user_data["id"],
                "displayName": user_data.get("displayName"),
            }
            target_user_id = resolved_user["id"]
            resolved_name = name_body
            if self.reg_after_verification:
                result = await _maybe_await(
                    self.reg_after_verification(
                        ctx=ctx,
                        verification=verification,
                        user=resolved_user,
                        client_data=resp,
                        context=context,
                    )
                )
                if result and result.get("userId"):
                    uid = result["userId"]
                    if not isinstance(uid, str) or not uid:
                        raise APIError(
                            400,
                            "RESOLVED_USER_INVALID",
                            PASSKEY_ERROR_CODES["RESOLVED_USER_INVALID"],
                        )
                    if session_uid and uid != session_uid:
                        raise APIError(
                            401,
                            "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
                            PASSKEY_ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"],
                        )
                    target_user_id = uid
                if not resolved_name:
                    rn = (result or {}).get("name")
                    resolved_name = rn.strip() if rn else None
            if not target_user_id:
                raise APIError(
                    400, "RESOLVED_USER_INVALID", PASSKEY_ERROR_CODES["RESOLVED_USER_INVALID"]
                )

            new_passkey = {
                "name": resolved_name,
                "userId": target_user_id,
                "credentialID": _encode_credential_id(verification.credential_id),
                "publicKey": _encode_public_key(verification.credential_public_key),
                "counter": verification.sign_count,
                "deviceType": _device_type(verification.credential_device_type.value),
                "transports": _transports_to_str(resp.get("response", {}).get("transports")),
                "backedUp": verification.credential_backed_up,
                "createdAt": datetime.now(timezone.utc),
                "aaguid": verification.aaguid,
            }
            row = await ctx.adapter.create("passkey", new_passkey)
            return AuthResponse(body=row)
        except APIError:
            raise
        except InvalidRegistrationResponse:
            raise APIError(
                400,
                "FAILED_TO_VERIFY_REGISTRATION",
                PASSKEY_ERROR_CODES["FAILED_TO_VERIFY_REGISTRATION"],
            ) from None
        except Exception:
            logger.exception("Failed to verify registration")
            raise APIError(
                500,
                "FAILED_TO_VERIFY_REGISTRATION",
                PASSKEY_ERROR_CODES["FAILED_TO_VERIFY_REGISTRATION"],
            ) from None

    async def _verify_authentication(self, ctx: Ctx) -> AuthResponse:
        origin = self._expected_origin(ctx)
        if not origin:
            # TS: new APIError("BAD_REQUEST", {message:"origin missing"}) — not a passkey code.
            raise APIError(400, "BAD_REQUEST", "origin missing")
        resp = ctx.body()["response"]

        value = await self._consume_challenge(ctx, "authentication")
        expected_challenge = value["expectedChallenge"]

        passkey = await ctx.adapter.find_one("passkey", [Where("credentialID", resp["id"])])
        if not passkey:
            raise APIError(401, "PASSKEY_NOT_FOUND", PASSKEY_ERROR_CODES["PASSKEY_NOT_FOUND"])

        try:
            verification = verify_authentication_response(
                credential=resp,
                expected_challenge=base64url_to_bytes(expected_challenge),
                expected_origin=origin,
                expected_rp_id=self._rp_id(ctx),
                credential_public_key=base64.b64decode(passkey["publicKey"]),
                credential_current_sign_count=passkey["counter"],
                require_user_verification=False,
            )
            if self.auth_after_verification:
                await _maybe_await(
                    self.auth_after_verification(
                        ctx=ctx, verification=verification, client_data=resp
                    )
                )
            await ctx.adapter.update(
                "passkey",
                [Where("id", passkey["id"])],
                {"counter": verification.new_sign_count},
            )
            user = await ctx.adapter.find_one("user", [Where("id", passkey["userId"])])
            if not user:
                raise APIError(500, "INTERNAL_SERVER_ERROR", "User not found")
            session, cookies = await create_session(
                ctx.auth, passkey["userId"], ctx.request, user=user, ctx=ctx
            )
            response = AuthResponse(
                body={
                    "session": ctx.auth.parse_session_output(session),
                    "user": ctx.auth.parse_user_output(user),
                }
            )
            for cookie in cookies:
                response.set_cookie(cookie)
            return response
        except APIError:
            raise
        except InvalidAuthenticationResponse:
            raise APIError(
                401, "AUTHENTICATION_FAILED", PASSKEY_ERROR_CODES["AUTHENTICATION_FAILED"]
            ) from None
        except Exception:
            logger.exception("Failed to verify authentication")
            raise APIError(
                400, "AUTHENTICATION_FAILED", PASSKEY_ERROR_CODES["AUTHENTICATION_FAILED"]
            ) from None

    async def _list_passkeys(self, ctx: Ctx) -> list[dict[str, Any]]:
        session = await ctx.require_session()
        return await ctx.adapter.find_many("passkey", [Where("userId", session["user"]["id"])])

    async def _load_owned(self, ctx: Ctx, forbidden_code: str) -> dict[str, Any]:
        """Inline requireResourceOwnership: 404 PASSKEY_NOT_FOUND, 401 on user mismatch
        (GHSA-4vcf-q4xf-f48m). Returns the owned row."""
        session = await ctx.require_session()
        passkey_id = ctx.body().get("id")
        if not passkey_id:
            raise APIError(400, "BAD_REQUEST", "id is required")
        row = await ctx.adapter.find_one("passkey", [Where("id", passkey_id)])
        if not row:
            raise APIError(401, "PASSKEY_NOT_FOUND", PASSKEY_ERROR_CODES["PASSKEY_NOT_FOUND"])
        if row["userId"] != session["user"]["id"]:
            raise APIError(
                401, forbidden_code, PASSKEY_ERROR_CODES.get(forbidden_code, "Unauthorized")
            )
        return row

    async def _delete_passkey(self, ctx: Ctx) -> dict[str, Any]:
        row = await self._load_owned(ctx, "PASSKEY_NOT_FOUND")
        await ctx.adapter.delete("passkey", [Where("id", row["id"])])
        return {"status": True}

    async def _update_passkey(self, ctx: Ctx) -> AuthResponse:
        row = await self._load_owned(ctx, "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY")
        name = (ctx.body().get("name") or "").strip()
        if not name:  # zod .trim().min(1)
            raise APIError(400, "BAD_REQUEST", "name is required")
        updated = await ctx.adapter.update("passkey", [Where("id", row["id"])], {"name": name})
        if not updated:
            raise APIError(
                500, "FAILED_TO_UPDATE_PASSKEY", PASSKEY_ERROR_CODES["FAILED_TO_UPDATE_PASSKEY"]
            )
        return AuthResponse(body={"passkey": updated})
