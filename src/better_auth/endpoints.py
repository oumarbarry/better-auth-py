"""Core endpoint handlers, mirroring better-auth's routes and response shapes."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any
from urllib.parse import quote

from .adapters.base import Where
from .crypto import (
    dummy_verify,
    generate_id,
    generate_random_string,
    hash_password,
    verify_password,
)
from .oauth import oauth_callback, sign_in_social
from .session import clear_cookie, create_session, get_session, refresh_session_cookie, utcnow
from .types import APIError, AuthResponse, Ctx

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SENSITIVE_ACCOUNT_FIELDS = frozenset(
    {
        "password",
        "accessToken",
        "refreshToken",
        "idToken",
        "accessTokenExpiresAt",
        "refreshTokenExpiresAt",
    }
)


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
    cfg = ctx.auth.email_verification
    if cfg.send_verification_email is None:
        return False
    now = utcnow()
    token = generate_random_string(32)
    await ctx.adapter.create(
        "verification",
        {
            "id": generate_id(),
            "identifier": f"email-verification:{token}",
            "value": user["id"],
            "expiresAt": now + timedelta(seconds=cfg.expires_in),
            "createdAt": now,
            "updatedAt": now,
        },
    )
    url = (
        f"{ctx.auth.base_url}{ctx.auth.base_path}/verify-email"
        f"?token={token}&callbackURL={quote(callback_url, safe='')}"
    )
    await cfg.send_verification_email(user, url, token)
    return True


# --- email & password -----------------------------------------------------------------


async def sign_up_email(ctx: Ctx) -> AuthResponse:
    _require_email_password_enabled(ctx)
    body = ctx.body()
    require_fields(body, "name", "email", "password")
    email = validate_email(body["email"])
    validate_password(ctx, body["password"])

    if await ctx.adapter.find_one("user", [Where("email", email)]) is not None:
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
    await ctx.auth.run_hook("user_created_before", user)
    await ctx.adapter.create("user", user)
    await ctx.adapter.create(
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
    )
    await ctx.auth.run_hook("user_created_after", user)

    cfg = ctx.auth.email_and_password
    if cfg.require_email_verification or ctx.auth.email_verification.send_on_sign_up:
        await _send_verification_email(ctx, user, body.get("callbackURL") or "/")

    if cfg.require_email_verification or not cfg.auto_sign_in:
        return AuthResponse(body={"token": None, "user": user})

    session, cookies = await create_session(
        ctx.auth, user["id"], ctx.request, body.get("rememberMe", True)
    )
    response = AuthResponse(body={"token": session["token"], "user": user})
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
            "user": user,
        }
    )
    for cookie in cookies:
        response.set_cookie(cookie)
    return response


# --- session --------------------------------------------------------------------------


async def get_session_handler(ctx: Ctx) -> AuthResponse:
    result, cookies = await get_session(ctx.auth, ctx.request)
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
    if not updates:
        raise APIError(400, "BAD_REQUEST", "No fields to update")
    updates["updatedAt"] = utcnow()
    await ctx.adapter.update("user", [Where("id", result["user"]["id"])], updates)
    response = AuthResponse(body={"status": True})
    response.set_cookie(
        refresh_session_cookie(ctx.auth, ctx.request, result["session"]["token"])
    )
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

    await ctx.adapter.update(
        "account",
        [Where("id", account["id"])],
        {"password": hash_password(body["newPassword"]), "updatedAt": utcnow()},
    )
    token = None
    response = AuthResponse(body=None)
    if body.get("revokeOtherSessions"):
        # TS semantics: revoke ALL sessions (including the current one), then
        # mint a brand-new session and set its cookie (update-user.ts:291).
        await ctx.adapter.delete_many("session", [Where("userId", user["id"])])
        new_session, cookies = await create_session(ctx.auth, user["id"], ctx.request)
        token = new_session["token"]
        for cookie in cookies:
            response.set_cookie(cookie)
    response.body = {"token": token, "user": user}
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
    await ctx.adapter.create(
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
    token = ctx.request.query.get("token")
    callback_url = ctx.request.query.get("callbackURL")
    if callback_url:
        ctx.auth.ensure_trusted_url(callback_url)

    def fail() -> AuthResponse:
        if callback_url:
            target = _absolute(ctx, callback_url)
            separator = "&" if "?" in target else "?"
            return AuthResponse(redirect_to=f"{target}{separator}error=invalid_token")
        raise APIError(400, "INVALID_TOKEN", "Invalid token")

    if not token:
        return fail()
    identifier = f"email-verification:{token}"
    row = await ctx.adapter.find_one("verification", [Where("identifier", identifier)])
    if row is None:
        return fail()
    await ctx.adapter.delete_many("verification", [Where("identifier", identifier)])
    if row["expiresAt"] <= utcnow():
        return fail()

    user = await ctx.adapter.find_one("user", [Where("id", row["value"])])
    if user is None:
        return fail()
    await ctx.adapter.update(
        "user", [Where("id", user["id"])], {"emailVerified": True, "updatedAt": utcnow()}
    )
    user["emailVerified"] = True

    cookies: list[str] = []
    if ctx.auth.email_verification.auto_sign_in_after_verification:
        _session, cookies = await create_session(ctx.auth, user["id"], ctx.request)

    if callback_url:
        response = AuthResponse(redirect_to=_absolute(ctx, callback_url))
    else:
        response = AuthResponse(body={"status": True, "user": user})
    for cookie in cookies:
        response.set_cookie(cookie)
    return response


def _absolute(ctx: Ctx, url: str) -> str:
    return f"{ctx.auth.base_url}{url}" if url.startswith("/") else url


# --- accounts -------------------------------------------------------------------------


async def list_accounts(ctx: Ctx) -> AuthResponse:
    result = await ctx.require_session()
    accounts = await ctx.adapter.find_many("account", [Where("userId", result["user"]["id"])])
    sanitized = []
    for account in accounts:
        item = {
            key: value
            for key, value in account.items()
            if key not in SENSITIVE_ACCOUNT_FIELDS and key != "scope"
        }
        scope = account.get("scope")
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
]
