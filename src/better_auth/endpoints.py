"""Core endpoint handlers, mirroring better-auth's routes and response shapes."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any
from urllib.parse import quote

import jwt as pyjwt

from .adapters.base import Where
from .config import UserOptions
from .crypto import (
    decode_email_verification_token,
    dummy_verify,
    generate_id,
    generate_random_string,
    hash_password,
    sign_email_verification_token,
    verify_password,
)
from .oauth import OAuthTokens, oauth_callback, sign_in_social
from .session import clear_cookie, create_session, get_session, refresh_session_cookie, utcnow
from .types import APIError, AuthResponse, Ctx

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
def require_fields(body: dict[str, Any], *names: str) -> None:
    for name in names:
        if body.get(name) in (None, ""):
            raise APIError(400, "INVALID_BODY", f"'{name}' is required")


def validate_email(email: str) -> str:
    if not EMAIL_RE.match(email):
        raise APIError(400, "INVALID_EMAIL", "Invalid email")
    return email.lower()


def validate_password(ctx: Ctx, password: str) -> None:
    cfg = ctx.auth.email_and_password
    if len(password) < cfg.min_password_length:
        raise APIError(400, "PASSWORD_TOO_SHORT", "Password is too short")
    if len(password) > cfg.max_password_length:
        raise APIError(400, "PASSWORD_TOO_LONG", "Password is too long")


def _require_email_password_enabled(ctx: Ctx) -> None:
    if not ctx.auth.email_and_password.enabled:
        raise APIError(400, "EMAIL_PASSWORD_DISABLED", "Email and password is not enabled")


async def _credential_account(ctx: Ctx, user_id: str) -> dict[str, Any] | None:
    return await ctx.adapter.find_one(
        "account", [Where("userId", user_id), Where("providerId", "credential")]
    )


async def _send_verification_email(ctx: Ctx, user: dict[str, Any], callback_url: str) -> bool:
    """Mints a signed HS256 JWT (no DB row — matches TS `email-verification.ts:15`,
    `createEmailVerificationToken`), so tokens are stateless and cross-runtime
    interoperable with a TS better-auth deployment sharing the same secret."""
    cfg = ctx.auth.email_verification
    if cfg.send_verification_email is None:
        return False
    token = sign_email_verification_token(ctx.auth.secret, user["email"], expires_in=cfg.expires_in)
    url = (
        f"{ctx.auth.base_url}{ctx.auth.base_path}/verify-email"
        f"?token={token}&callbackURL={quote(callback_url, safe='')}"
    )
    await cfg.send_verification_email(user, url, token)
    return True


def _user_options(ctx: Ctx) -> UserOptions:
    return ctx.auth.user


def _verify_email_url(ctx: Ctx, token: str, callback_url: str) -> str:
    return (
        f"{ctx.auth.base_url}{ctx.auth.base_path}/verify-email"
        f"?token={token}&callbackURL={quote(callback_url, safe='')}"
    )


# --- email & password -----------------------------------------------------------------


async def sign_up_email(ctx: Ctx) -> AuthResponse:
    cfg = ctx.auth.email_and_password
    if not cfg.enabled or cfg.disable_sign_up:
        raise APIError(
            400, "EMAIL_PASSWORD_SIGN_UP_DISABLED", "Email and password sign up is not enabled"
        )
    body = ctx.body()
    require_fields(body, "name", "email", "password")
    email = validate_email(body["email"])
    validate_password(ctx, body["password"])

    # sign-up.ts:235 — enumeration protection: when verification is required or
    # auto-sign-in is disabled, an existing email must be indistinguishable from
    # a fresh sign-up (fabricated user, 200) rather than leaking existence via 422.
    should_return_generic_duplicate = cfg.require_email_verification or not cfg.auto_sign_in
    existing = await ctx.adapter.find_one("user", [Where("email", email)])
    if existing is not None:
        hash_password(body["password"])  # equalize timing with the real-signup path
        if should_return_generic_duplicate:
            now = utcnow()
            synthetic_user = {
                "id": generate_id(),
                "name": body["name"],
                "email": email,
                "emailVerified": False,
                "image": body.get("image"),
                "createdAt": now,
                "updatedAt": now,
            }
            return AuthResponse(
                body={"token": None, "user": ctx.auth.parse_user_output(synthetic_user)}
            )
        raise APIError(
            422, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", "User already exists. Use another email."
        )

    now = utcnow()
    user = {
        "id": generate_id(),
        "name": body["name"],
        "email": email,
        "emailVerified": False,  # input:false in better-auth — never taken from the body
        "image": body.get("image"),
        "createdAt": now,
        "updatedAt": now,
    }
    await ctx.internal.create("user", user, ctx=ctx)
    await ctx.internal.create(
        "account",
        {
            "id": generate_id(),
            "accountId": user["id"],
            "providerId": "credential",
            "userId": user["id"],
            "password": hash_password(body["password"]),
            "createdAt": now,
            "updatedAt": now,
        },
        ctx=ctx,
    )

    if cfg.require_email_verification or ctx.auth.email_verification.send_on_sign_up:
        await _send_verification_email(ctx, user, body.get("callbackURL") or "/")

    if should_return_generic_duplicate:  # requireEmailVerification || autoSignIn===false
        return AuthResponse(body={"token": None, "user": ctx.auth.parse_user_output(user)})

    session, cookies = await create_session(
        ctx.auth, user["id"], ctx.request, body.get("rememberMe", True)
    )
    response = AuthResponse(
        body={"token": session["token"], "user": ctx.auth.parse_user_output(user)}
    )
    for cookie in cookies:
        response.set_cookie(cookie)
    return response


async def sign_in_email(ctx: Ctx) -> AuthResponse:
    _require_email_password_enabled(ctx)
    body = ctx.body()
    require_fields(body, "email", "password")
    email = body["email"].lower()
    password = body["password"]

    user = await ctx.adapter.find_one("user", [Where("email", email)])
    if user is None:
        dummy_verify(password)  # timing equalization, like better-auth
        raise APIError(401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password")
    account = await _credential_account(ctx, user["id"])
    if account is None or not account.get("password"):
        dummy_verify(password)
        raise APIError(401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password")
    if not verify_password(account["password"], password):
        raise APIError(401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password")

    if ctx.auth.email_and_password.require_email_verification and not user["emailVerified"]:
        await _send_verification_email(ctx, user, body.get("callbackURL") or "/")
        raise APIError(403, "EMAIL_NOT_VERIFIED", "Email not verified")

    callback_url = body.get("callbackURL")
    if callback_url:
        ctx.auth.ensure_trusted_url(callback_url)
    session, cookies = await create_session(
        ctx.auth, user["id"], ctx.request, body.get("rememberMe", True)
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
    return response


# --- session --------------------------------------------------------------------------


async def get_session_handler(ctx: Ctx) -> AuthResponse:
    result, cookies = await get_session(ctx.auth, ctx.request)
    if result is not None:
        result = {
            "session": ctx.auth.parse_session_output(result["session"]),
            "user": ctx.auth.parse_user_output(result["user"]),
        }
    response = AuthResponse(
        body=result,
        headers=[("cache-control", "no-store"), ("pragma", "no-cache")],
    )
    for cookie in cookies:
        response.set_cookie(cookie)
    return response


async def get_session_post(ctx: Ctx) -> AuthResponse:
    raise APIError(405, "METHOD_NOT_ALLOWED", "Method not allowed")


async def sign_out(ctx: Ctx) -> AuthResponse:
    result = await ctx.get_session()
    if result is None:
        raise APIError(400, "FAILED_TO_GET_SESSION", "Failed to get session")
    await ctx.adapter.delete_many("session", [Where("token", result["session"]["token"])])
    response = AuthResponse(body={"success": True})
    response.set_cookie(clear_cookie(ctx.auth))
    response.set_cookie(clear_cookie(ctx.auth, "dont_remember"))
    return response


async def list_sessions(ctx: Ctx) -> AuthResponse:
    result = await ctx.require_session()
    sessions = await ctx.adapter.find_many(
        "session",
        [Where("userId", result["user"]["id"]), Where("expiresAt", utcnow(), "gt")],
    )
    return AuthResponse(body=sessions)


async def revoke_session(ctx: Ctx) -> AuthResponse:
    """POST /revoke-session — anti-enumeration: an unknown or foreign token is a
    silent no-op, never an error (matches TS `session.ts:812`)."""
    result = await ctx.require_session()
    body = ctx.body()
    require_fields(body, "token")
    session = await ctx.adapter.find_one("session", [Where("token", body["token"])])
    if session is not None and session["userId"] == result["user"]["id"]:
        await ctx.adapter.delete_many("session", [Where("token", body["token"])])
    return AuthResponse(body={"status": True})


async def revoke_sessions(ctx: Ctx) -> AuthResponse:
    result = await ctx.require_session()
    await ctx.adapter.delete_many("session", [Where("userId", result["user"]["id"])])
    return AuthResponse(body={"status": True})


async def revoke_other_sessions(ctx: Ctx) -> AuthResponse:
    result = await ctx.require_session()
    await ctx.adapter.delete_many(
        "session",
        [
            Where("userId", result["user"]["id"]),
            Where("token", result["session"]["token"], "ne"),
        ],
    )
    return AuthResponse(body={"status": True})


async def update_session(ctx: Ctx) -> AuthResponse:
    """POST /update-session — writes configured additional session fields and
    refreshes the session cookie (update-session.ts).

    The body is filtered through the schema-driven input allowlist
    (`parse_session_input`): only configured additional fields whose `input`
    attribute permits writes pass through. Core columns and unknown keys are
    dropped — with no additional fields configured this yields nothing writable,
    which is the 400 "No fields to update". This closes a privilege-escalation
    vector where a client could pre-write plugin-owned authority fields.
    """
    result = await ctx.require_session()
    updates = ctx.auth.parse_session_input(ctx.body(), "update")
    if not updates:
        raise APIError(400, "BAD_REQUEST", "No fields to update")
    updates["updatedAt"] = utcnow()
    updated = await ctx.internal.update(
        "session", [Where("token", result["session"]["token"])], updates, ctx=ctx
    )
    new_session = updated or {**result["session"], **updates}
    response = AuthResponse(body={"session": ctx.auth.parse_session_output(new_session)})
    response.set_cookie(refresh_session_cookie(ctx.auth, ctx.request, result["session"]["token"]))
    return response


# --- user -----------------------------------------------------------------------------


async def update_user(ctx: Ctx) -> AuthResponse:
    """POST /update-user — `email` is never updatable here (use /change-email);
    refreshes the session cookie with the merged user afterwards, matching TS
    `update-user.ts`'s `setSessionCookie` call.

    Note: TS also throws `BODY_MUST_BE_AN_OBJECT` for a non-dict JSON body, but
    `ctx.body()`/`AuthRequest.json()` (types.py, out of scope for this change)
    already rejects non-object bodies earlier with `INVALID_BODY` — that TS
    error code is unreachable through this stack and is intentionally not
    duplicated here.
    """
    result = await ctx.require_session()
    body = ctx.body()
    if body.get("email"):
        raise APIError(400, "EMAIL_CAN_NOT_BE_UPDATED", "Email can not be updated")
    updates = {key: body[key] for key in ("name", "image") if key in body}
    updates.update(ctx.auth.parse_user_input(body, "update"))  # configured additionalFields
    if not updates:
        raise APIError(400, "BAD_REQUEST", "No fields to update")
    updates["updatedAt"] = utcnow()
    await ctx.internal.update("user", [Where("id", result["user"]["id"])], updates, ctx=ctx)
    response = AuthResponse(body={"status": True})
    response.set_cookie(refresh_session_cookie(ctx.auth, ctx.request, result["session"]["token"]))
    return response


async def change_password(ctx: Ctx) -> AuthResponse:
    result = await ctx.require_session()
    body = ctx.body()
    require_fields(body, "newPassword", "currentPassword")
    validate_password(ctx, body["newPassword"])
    user = result["user"]

    account = await _credential_account(ctx, user["id"])
    if account is None or not account.get("password"):
        raise APIError(400, "CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found")
    if not verify_password(account["password"], body["currentPassword"]):
        raise APIError(400, "INVALID_PASSWORD", "Invalid password")

    await ctx.internal.update(
        "account",
        [Where("id", account["id"])],
        {"password": hash_password(body["newPassword"]), "updatedAt": utcnow()},
        ctx=ctx,
    )
    token = None
    response = AuthResponse(body=None)
    if body.get("revokeOtherSessions"):
        # TS semantics: revoke ALL sessions (including the current one), then
        # mint a brand-new session and set its cookie (update-user.ts:291).
        await ctx.internal.delete_many("session", [Where("userId", user["id"])], ctx=ctx)
        new_session, cookies = await create_session(ctx.auth, user["id"], ctx.request)
        token = new_session["token"]
        for cookie in cookies:
            response.set_cookie(cookie)
    response.body = {"token": token, "user": ctx.auth.parse_user_output(user)}
    return response


async def set_password(ctx: Ctx) -> AuthResponse:
    """Let an OAuth-only user add a credential password."""
    result = await ctx.require_session()
    body = ctx.body()
    require_fields(body, "newPassword")
    validate_password(ctx, body["newPassword"])
    account = await _credential_account(ctx, result["user"]["id"])
    if account is not None and account.get("password"):
        raise APIError(400, "USER_ALREADY_HAS_PASSWORD", "User already has a password")
    now = utcnow()
    await ctx.internal.create(
        "account",
        {
            "id": generate_id(),
            "accountId": result["user"]["id"],
            "providerId": "credential",
            "userId": result["user"]["id"],
            "password": hash_password(body["newPassword"]),
            "createdAt": now,
            "updatedAt": now,
        },
        ctx=ctx,
    )
    return AuthResponse(body={"status": True})


async def verify_password_handler(ctx: Ctx) -> AuthResponse:
    """POST /verify-password — TS marks this ``scope:"server"`` (server-only,
    not client-callable) but still HTTP-routable; kept exposed here as the gap
    spec's documented default (see docs/plans/gap/01-core-http.md, open
    questions). Wire shape matches TS exactly: ``{status:true}`` on success,
    throws ``INVALID_PASSWORD`` (never ``{valid:false}``) on mismatch.
    """
    result = await ctx.require_session()
    body = ctx.body()
    require_fields(body, "password")
    account = await _credential_account(ctx, result["user"]["id"])
    if account is None or not account.get("password"):
        raise APIError(400, "CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found")
    if not verify_password(account["password"], body["password"]):
        raise APIError(400, "INVALID_PASSWORD", "Invalid password")
    return AuthResponse(body={"status": True})


# --- password reset -------------------------------------------------------------------


async def request_password_reset(ctx: Ctx) -> AuthResponse:
    _require_email_password_enabled(ctx)
    cfg = ctx.auth.email_and_password
    body = ctx.body()
    require_fields(body, "email")
    if cfg.send_reset_password is None:
        raise APIError(400, "RESET_PASSWORD_NOT_ENABLED", "Reset password isn't enabled")

    user = await ctx.adapter.find_one("user", [Where("email", body["email"].lower())])
    if user is None:
        # constant response — no user enumeration
        return AuthResponse(body={"status": True})

    now = utcnow()
    token = generate_random_string(32)
    await ctx.adapter.create(
        "verification",
        {
            "id": generate_id(),
            "identifier": f"reset-password:{token}",
            "value": user["id"],
            "expiresAt": now + timedelta(seconds=cfg.reset_password_token_expires_in),
            "createdAt": now,
            "updatedAt": now,
        },
    )
    redirect_to = body.get("redirectTo") or "/"
    ctx.auth.ensure_trusted_url(redirect_to)
    url = (
        f"{ctx.auth.base_url}{ctx.auth.base_path}/reset-password/{token}"
        f"?callbackURL={quote(redirect_to, safe='')}"
    )
    await cfg.send_reset_password(user, url, token)
    return AuthResponse(body={"status": True})


async def reset_password_redirect(ctx: Ctx) -> AuthResponse:
    """GET /reset-password/{token} — email-link landing, forwards the token."""
    token = ctx.params["token"]
    callback_url = ctx.request.query.get("callbackURL")
    if not callback_url:
        return AuthResponse(
            redirect_to=f"{ctx.auth.base_url}{ctx.auth.base_path}/error?error=invalid_token"
        )
    ctx.auth.ensure_trusted_url(callback_url)
    target = (
        callback_url if callback_url.startswith("http") else f"{ctx.auth.base_url}{callback_url}"
    )
    separator = "&" if "?" in target else "?"
    return AuthResponse(redirect_to=f"{target}{separator}token={token}")


async def reset_password(ctx: Ctx) -> AuthResponse:
    _require_email_password_enabled(ctx)
    body = ctx.body()
    require_fields(body, "newPassword")
    token = body.get("token") or ctx.request.query.get("token")
    if not token:
        raise APIError(400, "INVALID_TOKEN", "Invalid token")
    validate_password(ctx, body["newPassword"])

    row = await ctx.adapter.find_one(
        "verification", [Where("identifier", f"reset-password:{token}")]
    )
    if row is None:
        raise APIError(400, "INVALID_TOKEN", "Invalid token")
    await ctx.adapter.delete_many("verification", [Where("identifier", f"reset-password:{token}")])
    if row["expiresAt"] <= utcnow():
        raise APIError(400, "INVALID_TOKEN", "Invalid token")

    user_id = row["value"]
    now = utcnow()
    password_hash = hash_password(body["newPassword"])
    account = await _credential_account(ctx, user_id)
    if account is None:
        await ctx.adapter.create(
            "account",
            {
                "id": generate_id(),
                "accountId": user_id,
                "providerId": "credential",
                "userId": user_id,
                "password": password_hash,
                "createdAt": now,
                "updatedAt": now,
            },
        )
    else:
        await ctx.adapter.update(
            "account",
            [Where("id", account["id"])],
            {"password": password_hash, "updatedAt": now},
        )
    if ctx.auth.email_and_password.revoke_sessions_on_password_reset:
        await ctx.adapter.delete_many("session", [Where("userId", user_id)])
    return AuthResponse(body={"status": True})


# --- email verification ---------------------------------------------------------------


async def send_verification_email_handler(ctx: Ctx) -> AuthResponse:
    if ctx.auth.email_verification.send_verification_email is None:
        raise APIError(400, "VERIFICATION_EMAIL_NOT_ENABLED", "Verification email isn't enabled")
    body = ctx.body()
    require_fields(body, "email")
    email = validate_email(body["email"])
    user = await ctx.adapter.find_one("user", [Where("email", email)])
    if user is None:
        raise APIError(400, "USER_NOT_FOUND", "User not found")
    callback_url = body.get("callbackURL") or "/"
    ctx.auth.ensure_trusted_url(callback_url)
    await _send_verification_email(ctx, user, callback_url)
    return AuthResponse(body={"status": True})


async def verify_email(ctx: Ctx) -> AuthResponse:
    """GET /verify-email — token is a stateless HS256 JWT (email-verification.ts:224),
    decoded rather than looked up. On plain verification success TS returns
    `{"status": true, "user": null}` (line 484/540) — never the verified user —
    and the JWT isn't single-use (idempotent: re-verifying an already-verified
    user still succeeds, matching TS's `if (user.user.emailVerified) return
    {status:true, user:null}` early-out).

    When the JWT carries `updateTo`/`requestType`, this is the change-email flow
    (email-verification.ts:328-476): the email is moved to `updateTo`, with the
    two-step confirmation→verification handshake or the legacy immediate-update
    branch selected by `requestType`.
    """
    token = ctx.request.query.get("token")
    callback_url = ctx.request.query.get("callbackURL")
    if callback_url:
        ctx.auth.ensure_trusted_url(callback_url)

    def fail(code: str) -> AuthResponse:
        if callback_url:
            target = _absolute(ctx, callback_url)
            separator = "&" if "?" in target else "?"
            return AuthResponse(redirect_to=f"{target}{separator}error={code}")
        raise APIError(401, code, code.replace("_", " ").capitalize())

    def succeed(user: dict[str, Any] | None, cookies: list[str]) -> AuthResponse:
        if callback_url:
            response = AuthResponse(redirect_to=_absolute(ctx, callback_url))
        else:
            response = AuthResponse(body={"status": True, "user": user})
        for cookie in cookies:
            response.set_cookie(cookie)
        return response

    if not token:
        return fail("INVALID_TOKEN")
    try:
        payload = decode_email_verification_token(ctx.auth.secret, token)
    except pyjwt.ExpiredSignatureError:
        return fail("TOKEN_EXPIRED")
    except pyjwt.InvalidTokenError:
        return fail("INVALID_TOKEN")

    email = payload.get("email")
    update_to = payload.get("updateTo")
    request_type = payload.get("requestType")
    user = await ctx.adapter.find_one("user", [Where("email", email)]) if email else None
    if user is None:
        return fail("USER_NOT_FOUND")

    if update_to:
        return await _verify_change_email(
            ctx, user, email, update_to, request_type, callback_url, fail, succeed
        )

    if not user["emailVerified"]:
        await ctx.adapter.update(
            "user", [Where("id", user["id"])], {"emailVerified": True, "updatedAt": utcnow()}
        )

    cookies: list[str] = []
    if ctx.auth.email_verification.auto_sign_in_after_verification:
        _session, cookies = await create_session(ctx.auth, user["id"], ctx.request)

    return succeed(None, cookies)


async def _verify_change_email(
    ctx: Ctx,
    user: dict[str, Any],
    email: Any,
    update_to: Any,
    request_type: Any,
    callback_url: str | None,
    fail: Any,
    succeed: Any,
) -> AuthResponse:
    """Change-email confirmation/verification handshake (email-verification.ts:328-476).

    ponytail: `afterEmailVerification` hook is not called — that config field is
    gap item 8's out-of-scope superset (only `user.changeEmail`/`deleteUser` land
    this wave); wire it when `EmailVerification` grows the callback.
    """
    cfg = ctx.auth.email_verification
    session = await ctx.get_session()
    if session is not None and session["user"]["email"] != email:
        return fail("INVALID_USER")

    async def session_cookies(target_user: dict[str, Any]) -> list[str]:
        # refresh the existing session cookie, or mint a fresh session when the
        # link is opened without one (TS creates a session in that case)
        if session is not None:
            return [refresh_session_cookie(ctx.auth, ctx.request, session["session"]["token"])]
        _s, cookies = await create_session(ctx.auth, target_user["id"], ctx.request)
        return cookies

    if request_type == "change-email-confirmation":
        # step 1: user confirmed from the OLD address -> email the NEW address a
        # second token that actually performs the update
        new_token = sign_email_verification_token(
            ctx.auth.secret,
            email,
            update_to=update_to,
            expires_in=cfg.expires_in,
            extra_payload={"requestType": "change-email-verification"},
        )
        if cfg.send_verification_email is not None:
            url = _verify_email_url(ctx, new_token, callback_url or "/")
            await cfg.send_verification_email({**user, "email": update_to}, url, new_token)
        # TS returns {status:true} here (no user key), redirecting when a callbackURL is set
        if callback_url:
            return AuthResponse(redirect_to=_absolute(ctx, callback_url))
        return AuthResponse(body={"status": True})

    if request_type == "change-email-verification":
        # step 2: apply the change, keep the address verified
        updated = await ctx.adapter.update(
            "user",
            [Where("id", user["id"])],
            {"email": update_to, "emailVerified": True, "updatedAt": utcnow()},
        )
        updated_user = updated or {**user, "email": update_to, "emailVerified": True}
        return succeed(updated_user, await session_cookies(updated_user))

    # legacy single-step flow: update immediately (unverified) then re-verify the new address
    updated = await ctx.adapter.update(
        "user",
        [Where("id", user["id"])],
        {"email": update_to, "emailVerified": False, "updatedAt": utcnow()},
    )
    updated_user = updated or {**user, "email": update_to, "emailVerified": False}
    if cfg.send_verification_email is not None:
        new_token = sign_email_verification_token(
            ctx.auth.secret, update_to, expires_in=cfg.expires_in
        )
        url = _verify_email_url(ctx, new_token, callback_url or "/")
        await cfg.send_verification_email(updated_user, url, new_token)
    return succeed(updated_user, await session_cookies(updated_user))


def _absolute(ctx: Ctx, url: str) -> str:
    return f"{ctx.auth.base_url}{url}" if url.startswith("/") else url


async def change_email(ctx: Ctx) -> AuthResponse:
    """POST /change-email — request an email change (update-user.ts changeEmail).

    Picks one of three flows by session state / config, all returning
    ``{status:true}`` (never leaking whether the target email exists):
    immediate update (unverified current email + updateEmailWithoutVerification),
    a confirmation email to the current address (verified current email +
    sendChangeEmailConfirmation), or a verification email to the new address.
    """
    result = await ctx.require_session()
    user = result["user"]
    opts = _user_options(ctx).change_email
    if not opts.enabled:
        raise APIError(400, "CHANGE_EMAIL_DISABLED", "Change email is disabled")
    body = ctx.body()
    require_fields(body, "newEmail")
    new_email = validate_email(body["newEmail"])
    if new_email == user["email"]:
        raise APIError(400, "BAD_REQUEST", "Email is the same")

    cfg = ctx.auth.email_verification
    can_update_without_verification = (
        user["emailVerified"] is not True and opts.update_email_without_verification
    )
    can_send_verification = cfg.send_verification_email is not None
    can_send_confirmation = bool(
        can_send_verification and user["emailVerified"] and opts.send_change_email_confirmation
    )
    if (
        not can_update_without_verification
        and not can_send_confirmation
        and not can_send_verification
    ):
        raise APIError(400, "BAD_REQUEST", "Verification email isn't enabled")

    callback_url = body.get("callbackURL") or "/"

    existing = await ctx.adapter.find_one("user", [Where("email", new_email)])
    if existing is not None:
        # simulate token generation to keep timing indistinguishable from a fresh email
        sign_email_verification_token(
            ctx.auth.secret, user["email"], update_to=new_email, expires_in=cfg.expires_in
        )
        return AuthResponse(body={"status": True})

    if can_update_without_verification:
        await ctx.adapter.update(
            "user", [Where("id", user["id"])], {"email": new_email, "updatedAt": utcnow()}
        )
        response = AuthResponse(body={"status": True})
        response.set_cookie(
            refresh_session_cookie(ctx.auth, ctx.request, result["session"]["token"])
        )
        if can_send_verification:
            token = sign_email_verification_token(
                ctx.auth.secret, new_email, expires_in=cfg.expires_in
            )
            url = _verify_email_url(ctx, token, callback_url)
            await cfg.send_verification_email({**user, "email": new_email}, url, token)
        return response

    if can_send_confirmation:
        token = sign_email_verification_token(
            ctx.auth.secret,
            user["email"],
            update_to=new_email,
            expires_in=cfg.expires_in,
            extra_payload={"requestType": "change-email-confirmation"},
        )
        url = _verify_email_url(ctx, token, callback_url)
        await opts.send_change_email_confirmation(user, new_email, url, token)
        return AuthResponse(body={"status": True})

    # redundant guard mirroring TS's final `if (!canSendVerification) throw`
    if cfg.send_verification_email is None:
        raise APIError(400, "BAD_REQUEST", "Verification email isn't enabled")
    token = sign_email_verification_token(
        ctx.auth.secret,
        user["email"],
        update_to=new_email,
        expires_in=cfg.expires_in,
        extra_payload={"requestType": "change-email-verification"},
    )
    url = _verify_email_url(ctx, token, callback_url)
    await cfg.send_verification_email({**user, "email": new_email}, url, token)
    return AuthResponse(body={"status": True})


# --- user deletion --------------------------------------------------------------------


async def _purge_user(ctx: Ctx, user: dict[str, Any], *, cascade_accounts: bool) -> None:
    opts = _user_options(ctx).delete_user
    if opts.before_delete is not None:
        await opts.before_delete(user, ctx.request)
    await ctx.adapter.delete_many("user", [Where("id", user["id"])])
    await ctx.adapter.delete_many("session", [Where("userId", user["id"])])
    if cascade_accounts:
        await ctx.adapter.delete_many("account", [Where("userId", user["id"])])
    if opts.after_delete is not None:
        await opts.after_delete(user, ctx.request)


async def _consume_delete_token(ctx: Ctx, user: dict[str, Any], token: str | None) -> None:
    """Atomically burn a single-use delete token and verify it belongs to ``user``.

    Deletes the row before validating (like reset-password) so concurrent callbacks
    with the same token can only succeed once; a wrong-owner token is still burned.
    """
    identifier = f"delete-account-{token}"
    row = await ctx.adapter.find_one("verification", [Where("identifier", identifier)])
    if row is not None:
        await ctx.adapter.delete_many("verification", [Where("identifier", identifier)])
    if row is None or row["value"] != user["id"]:
        raise APIError(404, "INVALID_TOKEN", "Invalid token")


def _clear_session(response: AuthResponse, ctx: Ctx) -> None:
    response.set_cookie(clear_cookie(ctx.auth))
    response.set_cookie(clear_cookie(ctx.auth, "dont_remember"))


async def delete_user(ctx: Ctx) -> AuthResponse:
    """POST /delete-user — delete the current account (update-user.ts deleteUser).

    Requires `user.deleteUser.enabled` (else 404). A fresh session OR a valid
    password is required for immediate deletion; when
    `sendDeleteAccountVerification` is set, emails a callback link instead.
    """
    opts = _user_options(ctx).delete_user
    if not opts.enabled:
        raise APIError(404, "NOT_FOUND", "Not found")
    result = await ctx.require_session()
    user = result["user"]
    body = ctx.body()

    if body.get("password"):
        account = await _credential_account(ctx, user["id"])
        if account is None or not account.get("password"):
            raise APIError(400, "CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found")
        if not verify_password(account["password"], body["password"]):
            raise APIError(400, "INVALID_PASSWORD", "Invalid password")

    if body.get("token"):
        await _consume_delete_token(ctx, user, body["token"])
        await _purge_user(ctx, user, cascade_accounts=True)
        response = AuthResponse(body={"success": True, "message": "User deleted"})
        _clear_session(response, ctx)
        return response

    if opts.send_delete_account_verification is not None:
        now = utcnow()
        token = generate_random_string(32)
        await ctx.adapter.create(
            "verification",
            {
                "id": generate_id(),
                "identifier": f"delete-account-{token}",
                "value": user["id"],
                "expiresAt": now + timedelta(seconds=opts.delete_token_expires_in),
                "createdAt": now,
                "updatedAt": now,
            },
        )
        url = (
            f"{ctx.auth.base_url}{ctx.auth.base_path}/delete-user/callback"
            f"?token={token}&callbackURL={quote(body.get('callbackURL') or '/', safe='')}"
        )
        await opts.send_delete_account_verification(user, url, token)
        return AuthResponse(body={"success": True, "message": "Verification email sent"})

    # no password + no verification email: fall back to session freshness
    fresh_age = getattr(ctx.auth.session_options, "fresh_age", 86400)
    if not body.get("password") and fresh_age != 0:
        age = (utcnow() - result["session"]["createdAt"]).total_seconds()
        if age >= fresh_age:
            raise APIError(400, "SESSION_EXPIRED", "Session is not fresh")

    # main path mirrors TS exactly: user + sessions only (accounts are NOT cascaded here)
    await _purge_user(ctx, user, cascade_accounts=False)
    response = AuthResponse(body={"success": True, "message": "User deleted"})
    _clear_session(response, ctx)
    return response


async def delete_user_callback(ctx: Ctx) -> AuthResponse:
    """GET /delete-user/callback — complete deletion from the emailed token."""
    opts = _user_options(ctx).delete_user
    if not opts.enabled:
        raise APIError(404, "NOT_FOUND", "Not found")
    result = await ctx.get_session()
    if result is None:
        raise APIError(404, "FAILED_TO_GET_USER_INFO", "Failed to get user info")
    await _consume_delete_token(ctx, result["user"], ctx.request.query.get("token"))
    await _purge_user(ctx, result["user"], cascade_accounts=True)

    callback_url = ctx.request.query.get("callbackURL")
    if callback_url:
        ctx.auth.ensure_trusted_url(callback_url)
        response = AuthResponse(redirect_to=_absolute(ctx, callback_url))
    else:
        response = AuthResponse(body={"success": True, "message": "User deleted"})
    _clear_session(response, ctx)
    return response


# --- accounts -------------------------------------------------------------------------


async def list_accounts(ctx: Ctx) -> AuthResponse:
    result = await ctx.require_session()
    accounts = await ctx.adapter.find_many("account", [Where("userId", result["user"]["id"])])
    sanitized = []
    for account in accounts:
        # schema-driven output filter drops returned:false fields (tokens/password);
        # list-accounts additionally replaces the `scope` string with a `scopes` array.
        item = ctx.auth.parse_account_output(account)
        scope = item.pop("scope", None)
        item["scopes"] = scope.split(",") if scope else []
        sanitized.append(item)
    return AuthResponse(body=sanitized)


async def unlink_account(ctx: Ctx) -> AuthResponse:
    result = await ctx.require_session()
    body = ctx.body()
    require_fields(body, "providerId")
    accounts = await ctx.adapter.find_many("account", [Where("userId", result["user"]["id"])])
    matching = [
        account
        for account in accounts
        if account["providerId"] == body["providerId"]
        and (not body.get("accountId") or account["accountId"] == body["accountId"])
    ]
    if not matching:
        raise APIError(400, "ACCOUNT_NOT_FOUND", "Account not found")
    if len(accounts) - len(matching) < 1:
        raise APIError(400, "FAILED_TO_UNLINK_LAST_ACCOUNT", "You can't unlink your last account")
    for account in matching:
        await ctx.adapter.delete_many("account", [Where("id", account["id"])])
    return AuthResponse(body={"status": True})


async def account_info(ctx: Ctx) -> AuthResponse:
    """GET /account-info — the provider's user-info for one linked account (account.ts).

    Returns ``{user, data}`` (the provider `getUserInfo` shape). Every HTTP caller
    needs a valid session; the account must belong to the session user.

    ponytail: no token refresh and `data` is ``{}`` — `OAuthProvider.fetch_user`
    (oauth.py, out of scope) uses the stored access token and discards the raw
    provider payload; the refresh/`getAccessToken` machinery is Wave 2.
    """
    result = await ctx.require_session()
    user_id = result["user"]["id"]
    query = ctx.request.query
    provided_account_id = query.get("accountId")
    provided_provider_id = query.get("providerId")

    account: dict[str, Any] | None = None
    if provided_account_id:
        accounts = await ctx.adapter.find_many("account", [Where("userId", user_id)])
        matching = [
            acc
            for acc in accounts
            if acc["accountId"] == provided_account_id
            and (not provided_provider_id or acc["providerId"] == provided_provider_id)
        ]
        if len(matching) > 1:
            raise APIError(
                400,
                "AMBIGUOUS_ACCOUNT",
                "Multiple accounts share this account ID. Pass a providerId to disambiguate.",
            )
        account = matching[0] if matching else None
    # else: account-cookie lookup (storeAccountCookie) is unimplemented → no match

    if account is None:
        raise APIError(400, "ACCOUNT_NOT_FOUND", "Account not found")

    provider = ctx.auth.social_providers.get(account["providerId"])
    if provider is None:
        raise APIError(
            400,
            "PROVIDER_NOT_CONFIGURED",
            "Account is not associated with a configured social provider.",
        )

    access_token = account.get("accessToken")
    if not access_token:
        raise APIError(400, "ACCESS_TOKEN_NOT_FOUND", "Access token not found")

    tokens = OAuthTokens(
        access_token=access_token,
        refresh_token=account.get("refreshToken"),
        id_token=account.get("idToken"),
        scope=account.get("scope"),
        access_token_expires_at=account.get("accessTokenExpiresAt"),
    )
    info = await provider.fetch_user(tokens, ctx.auth.http)
    return AuthResponse(
        body={
            "user": {
                "id": info.id,
                "name": info.name,
                "email": info.email,
                "image": info.image,
                "emailVerified": info.email_verified,
            },
            "data": {},
        }
    )


# --- misc -----------------------------------------------------------------------------


async def ok(ctx: Ctx) -> AuthResponse:
    return AuthResponse(body={"ok": True})


_ERROR_PAGE = """<!DOCTYPE html>
<html><head><title>Authentication Error</title></head>
<body style="font-family: system-ui; display: grid; place-items: center; min-height: 80vh">
<div style="text-align: center">
<h1>Authentication Error</h1>
<p>{error}</p>
<a href="/">Go home</a>
</div>
</body></html>"""


async def error_page(ctx: Ctx) -> AuthResponse:
    error = re.sub(r"[^a-zA-Z0-9_\- .]", "", ctx.request.query.get("error", "Unknown error"))
    return AuthResponse(body=_ERROR_PAGE.format(error=error), media_type="text/html")


ROUTES: list[tuple[str, str, Any]] = [
    ("GET", "/ok", ok),
    ("GET", "/error", error_page),
    ("POST", "/sign-up/email", sign_up_email),
    ("POST", "/sign-in/email", sign_in_email),
    ("POST", "/sign-in/social", sign_in_social),
    ("GET", "/callback/{provider}", oauth_callback),
    ("POST", "/callback/{provider}", oauth_callback),
    ("GET", "/get-session", get_session_handler),
    ("POST", "/get-session", get_session_post),
    ("POST", "/sign-out", sign_out),
    ("GET", "/list-sessions", list_sessions),
    ("POST", "/revoke-session", revoke_session),
    ("POST", "/revoke-sessions", revoke_sessions),
    ("POST", "/revoke-other-sessions", revoke_other_sessions),
    ("POST", "/update-user", update_user),
    ("POST", "/update-session", update_session),
    ("POST", "/change-email", change_email),
    ("POST", "/delete-user", delete_user),
    ("GET", "/delete-user/callback", delete_user_callback),
    ("POST", "/change-password", change_password),
    ("POST", "/set-password", set_password),
    ("POST", "/verify-password", verify_password_handler),
    ("POST", "/request-password-reset", request_password_reset),
    ("POST", "/forget-password", request_password_reset),  # legacy alias
    ("GET", "/reset-password/{token}", reset_password_redirect),
    ("POST", "/reset-password", reset_password),
    ("POST", "/send-verification-email", send_verification_email_handler),
    ("GET", "/verify-email", verify_email),
    ("GET", "/list-accounts", list_accounts),
    ("POST", "/unlink-account", unlink_account),
    ("GET", "/account-info", account_info),
]
