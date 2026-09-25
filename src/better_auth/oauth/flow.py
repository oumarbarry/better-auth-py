"""OAuth2 endpoints + the sign-in/register/link decision core.

Ports better-auth's ``sign-in.ts`` (social + idToken branches), ``callback.ts`` (sign-in
and link branches), ``account.ts`` (``/link-social``, ``/refresh-token``,
``/get-access-token``) and ``link-account.ts`` (``handleOAuthUserInfo`` — the single
find/register/link decision tree every callback routes through).

State uses the DB strategy only (verification-table row + separately signed CSRF cookie),
matching the pre-refactor Python port; the stateless ``"cookie"`` strategy is not ported.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import timedelta
from typing import Any

import httpx

from ..adapters.base import Where
from ..crypto import (
    generate_id,
    generate_random_string,
    is_likely_encrypted,
    sign_value,
    symmetric_decrypt,
    symmetric_encrypt,
    unsign_value,
)
from ..session import build_cookie, clear_cookie, cookie_name, create_session, utcnow
from ..types import APIError, AuthResponse, Ctx
from .machinery import OAuthFetchError
from .models import OAuthTokens, OAuthUserInfo
from .providers import ProviderConfig, call_verify_id_token

logger = logging.getLogger("better_auth")

STATE_EXPIRES_IN = 600  # seconds
STATE_COOKIE = "state"


class OAuthLinkError(Exception):
    """A sign-in/link decision failure with a stable error code (redirect or APIError).

    ``error_url`` set means the redirect target is fixed (TS redirects database failures
    to ``onAPIError.errorURL``); redirecting callers prefer it over their own error URL.
    """

    def __init__(self, code: str, error_url: str | None = None):
        self.code = code
        self.error_url = error_url
        super().__init__(code)


class _CallbackError(Exception):
    def __init__(self, code: str, error_url: str | None = None):
        self.code = code
        self.error_url = error_url
        super().__init__(code)


# --- token encryption at rest (account.encryptOAuthTokens) --------------------------------


def _encrypt(ctx: Ctx, token: str | None) -> str | None:
    if token and ctx.auth.account.encrypt_oauth_tokens:
        return symmetric_encrypt(ctx.auth.secret, token)
    return token


def _decrypt(ctx: Ctx, token: str | None) -> str | None:
    if token and ctx.auth.account.encrypt_oauth_tokens and is_likely_encrypted(token):
        return symmetric_decrypt(ctx.auth.secret, token)
    return token


def _token_fields(ctx: Ctx, tokens: OAuthTokens) -> dict[str, Any]:
    return {
        "accessToken": _encrypt(ctx, tokens.access_token),
        "refreshToken": _encrypt(ctx, tokens.refresh_token),
        "idToken": tokens.id_token,
        "accessTokenExpiresAt": tokens.access_token_expires_at,
        "refreshTokenExpiresAt": tokens.refresh_token_expires_at,
        # TS callback.ts:262-266 stores ``tokens.scopes?.join(",")``
        "scope": ",".join(tokens.scopes) if tokens.scopes else tokens.scope,
    }


def _fresh_token_fields(ctx: Ctx, tokens: OAuthTokens) -> dict[str, Any]:
    """Token columns for updating an existing account: ``scope`` left out (it only grows,
    through link-social) and fields the provider did not return keep their stored
    value (TS v1.7.6 link-account.ts:392-412 filters ``undefined``)."""
    fields = _token_fields(ctx, tokens)
    del fields["scope"]
    return {k: v for k, v in fields.items() if v is not None}


def parse_stored_scopes(scope: str | None) -> list[str]:
    """TS v1.7.6 api/routes/account.ts:37 ``parseStoredScopes`` (comma-joined). Whitespace
    also separates, so rows the 1.0 port wrote space-separated still parse; a scope token
    never contains a space (RFC 6749 section 3.3), so TS-written rows parse identically."""
    return [part for part in re.split(r"[,\s]+", scope or "") if part]


def merge_scopes(stored: str | None, incoming: list[str] | None) -> str:
    """Union of stored and incoming scopes in stored order, no duplicates (TS v1.7.6
    core/oauth2/utils.ts:71 ``mergeScopes``)."""
    scopes = parse_stored_scopes(stored) + [s.strip() for s in incoming or [] if s.strip()]
    return ",".join(dict.fromkeys(scopes))


# --- helpers ------------------------------------------------------------------------------


def _redirect_uri(ctx: Ctx, provider: ProviderConfig) -> str:
    return (
        provider.redirect_uri
        or f"{ctx.auth.base_url}{ctx.auth.base_path}/callback/{provider.provider_id}"
    )


def _absolute_url(ctx: Ctx, url: str) -> str:
    return f"{ctx.auth.base_url}{url}" if url.startswith("/") else url


async def _resolve_trusted_providers(ctx: Ctx) -> list[str]:
    trusted: Any = ctx.auth.account.account_linking.trusted_providers
    if callable(trusted):
        result = trusted(ctx.request)
        trusted = await result if hasattr(result, "__await__") else result
    return [str(p) for p in (trusted or [])]


async def _create_state(
    ctx: Ctx,
    *,
    callback_url: str,
    error_url: str | None,
    new_user_url: str | None,
    link: dict[str, str] | None = None,
    additional_data: dict[str, Any] | None = None,
    nonce: str | None = None,
) -> tuple[str, str]:
    """Write the state row (verification table) + return (state, code_verifier).

    ``code_verifier`` is always generated (cheap; lets a provider's PKCE-ness change
    without touching the state layer). A separately signed CSRF cookie is set by the caller.
    """
    state = generate_random_string(32)
    code_verifier = generate_random_string(128)
    now = utcnow()
    payload: dict[str, Any] = {
        "callbackURL": callback_url,
        "codeVerifier": code_verifier,
        "errorURL": error_url,
        "newUserURL": new_user_url,
        "expiresAt": int(now.timestamp() * 1000) + STATE_EXPIRES_IN * 1000,
    }
    if link is not None:
        payload["link"] = link
    if nonce is not None:
        payload["nonce"] = nonce
    if additional_data:
        payload["additionalData"] = additional_data
    await ctx.adapter.create(
        "verification",
        {
            "id": generate_id(),
            "identifier": state,
            "value": json.dumps(payload),
            "expiresAt": now + timedelta(seconds=STATE_EXPIRES_IN),
            "createdAt": now,
            "updatedAt": now,
        },
    )
    return state, code_verifier


def _state_cookie(ctx: Ctx, state: str) -> str:
    return build_cookie(ctx.auth, sign_value(ctx.auth.secret, state), 300, STATE_COOKIE)


# --- POST /sign-in/social -----------------------------------------------------------------


async def sign_in_social(ctx: Ctx) -> AuthResponse:
    body = ctx.body()
    provider = ctx.auth.social_providers.get(body.get("provider") or "")
    if provider is None:
        raise APIError(404, "PROVIDER_NOT_FOUND", "Provider not found")

    id_token = body.get("idToken")
    if id_token:
        return await _id_token_sign_in(ctx, provider, id_token, body)

    callback_url = body.get("callbackURL") or "/"
    ctx.auth.ensure_trusted_url(callback_url)
    error_url = body.get("errorCallbackURL")
    if error_url:
        ctx.auth.ensure_trusted_url(error_url)
    new_user_url = body.get("newUserCallbackURL")
    if new_user_url:
        ctx.auth.ensure_trusted_url(new_user_url)

    nonce = generate_random_string(32) if provider.use_nonce else None
    state, code_verifier = await _create_state(
        ctx,
        callback_url=callback_url,
        error_url=error_url,
        new_user_url=new_user_url,
        additional_data=body.get("additionalData"),
        nonce=nonce,
    )
    url = provider.authorization_url(
        state=state,
        redirect_uri=_redirect_uri(ctx, provider),
        code_verifier=code_verifier,
        extra_scopes=body.get("scopes"),
        login_hint=body.get("loginHint"),
        nonce=nonce,
    )
    disable_redirect = bool(body.get("disableRedirect"))
    response = AuthResponse(body={"url": url, "redirect": not disable_redirect})
    response.set_cookie(_state_cookie(ctx, state))
    return response


async def _id_token_sign_in(
    ctx: Ctx, provider: ProviderConfig, id_token: dict[str, Any], body: dict[str, Any]
) -> AuthResponse:
    """idToken direct sign-in — the client already holds a provider id-token (Google Identity
    Services / Sign in with Apple JS) and skips the redirect round-trip."""
    if not provider.supports_id_token:
        raise APIError(404, "ID_TOKEN_NOT_SUPPORTED", "id_token sign-in not supported")
    token = id_token.get("token") or ""
    claims = await call_verify_id_token(provider, ctx.auth.http, token, id_token.get("nonce"), ctx)
    if claims is None:
        raise APIError(401, "INVALID_TOKEN", "Invalid id token")
    info = provider.user_info_from_id_token(claims)
    if not info.email:
        raise APIError(401, "USER_EMAIL_NOT_FOUND", "Provider did not return an email")
    _require_account_subject(info)

    # TS v1.7.6 sign-in.ts:336-340: the account data is the key, accessToken and idToken
    # (no scope, no refreshToken).
    tokens = OAuthTokens(access_token=id_token.get("accessToken"), id_token=token)
    disable_sign_up = (
        provider.disable_implicit_sign_up and not body.get("requestSignUp")
    ) or provider.disable_sign_up
    try:
        user_id, _is_new = await handle_oauth_user_info(
            ctx, provider, info, tokens, disable_sign_up=disable_sign_up
        )
    except OAuthLinkError as err:
        raise APIError(401, "OAUTH_LINK_ERROR", err.code) from None
    session, cookies = await create_session(ctx.auth, user_id, ctx.request, ctx=ctx)
    user = await ctx.adapter.find_one("user", [Where("id", user_id)])
    response = AuthResponse(
        body={
            "redirect": False,
            "token": session["token"],
            "user": ctx.auth.parse_user_output(user) if user else None,
        }
    )
    for cookie in cookies:
        response.set_cookie(cookie)
    return response


# --- the find/register/link decision core (handleOAuthUserInfo) ---------------------------


def _database_error(ctx: Ctx) -> OAuthLinkError:
    """TS v1.7.6 link-account.ts:196-204 and :259-268: a failed lookup logs and redirects
    to ``onAPIError.errorURL || ${baseURL}/error`` with ``internal_server_error``."""
    logger.exception("Better auth was unable to query your database.")
    error_url = ctx.auth.on_api_error.error_url or f"{ctx.auth.base_url}{ctx.auth.base_path}/error"
    return OAuthLinkError("internal_server_error", error_url)


def _require_account_subject(info: OAuthUserInfo) -> None:
    """An empty provider subject never becomes an account id (TS v1.7.6
    oauth2/account-key.ts:29-37, surfaced by ``resolveOAuthAccountKeyForAPI``)."""
    if not info.id:
        raise APIError(401, "FAILED_TO_GET_USER_INFO", "Failed to get user info")


async def handle_oauth_user_info(
    ctx: Ctx,
    provider: ProviderConfig,
    info: OAuthUserInfo,
    tokens: OAuthTokens,
    *,
    disable_sign_up: bool = False,
    is_trusted_provider: bool | None = None,
    trust_provider_by_name: bool = True,
    override_user_info: bool | None = None,
) -> tuple[str, bool]:
    """Find/register/link decision tree (``link-account.ts``). Returns (user_id, is_register).

    Raises :class:`OAuthLinkError` with a stable code (``account_not_linked``,
    ``signup_disabled``, ``unable_to_link_account``, ``unable_to_create_user``,
    ``internal_server_error``) on a refused link/register; callers map it to a redirect
    (callback) or an APIError (idToken sign-in).

    The provider account is found by its exact ``(providerId, accountId)`` key only
    (TS v1.7.6 link-account.ts:191-268); email is consulted only when no account matches.

    Trust flags (extension for the SSO plugin; defaults preserve social/generic-oauth
    behavior, one shared change so all callers route through the same gate):

    - ``is_trusted_provider`` — a call-time trust signal (SSO passes verified
      domain-ownership). When truthy the implicit-linking gate treats the provider as
      trusted regardless of the name list.
    - ``trust_provider_by_name`` — when ``False`` the global
      ``accountLinking.trustedProviders`` list is NOT consulted (SSO providerIds are
      user-controlled and live in the social namespace, so a provider named after a
      trusted social provider must not launder that trust).
    - ``override_user_info`` — overrides ``provider.override_user_info_on_sign_in`` when
      not ``None`` (SSO passes the per-provider ``oidcConfig.overrideUserInfo``).
    """
    now = utcnow()
    override = (
        provider.override_user_info_on_sign_in if override_user_info is None else override_user_info
    )
    email = (info.email or "").lower()
    linking = ctx.auth.account.account_linking

    try:
        owner = await ctx.internal.find_account_owner_by_key(provider.provider_id, info.id)
    except Exception:
        raise _database_error(ctx) from None

    if owner is not None:
        account, user = owner
        if user is None:
            logger.error(
                "OAuth account references a missing user. Repair the account before "
                "retrying authentication."
            )
            raise OAuthLinkError("unable_to_link_account")
        if ctx.auth.account.update_account_on_sign_in:
            fresh = _fresh_token_fields(ctx, tokens)
            await ctx.internal.update(
                "account", [Where("id", account["id"])], {**fresh, "updatedAt": now}, ctx=ctx
            )
        user = await _maybe_promote_verified(ctx, user, info, email, now)
        if override and user is not None:
            user = await _override_user_info(ctx, user, info, email, now)
        return account["userId"], False

    try:
        user = await ctx.adapter.find_one("user", [Where("email", email)]) if email else None
    except Exception:
        raise _database_error(ctx) from None

    if user is None:  # register
        if disable_sign_up:
            raise OAuthLinkError("signup_disabled")
        token_fields = _token_fields(ctx, tokens)

        async def register(tx: Any) -> dict[str, Any]:
            created = await tx.create(
                "user",
                {
                    "id": generate_id(),
                    "name": info.name or email,
                    "email": email,
                    "emailVerified": info.email_verified,
                    "image": info.image,
                    "createdAt": now,
                    "updatedAt": now,
                },
                ctx=ctx,
            )
            if created is None:
                raise RuntimeError("user creation was aborted")
            await _create_account(
                ctx, provider, info, token_fields, created["id"], now, internal=tx
            )
            return created

        # TS v1.7.6 link-account.ts:542-588 (a83152e2e): user + first account commit
        # together; after-hooks run once the transaction commits.
        try:
            created = await ctx.internal.transaction(register)
        except APIError:
            raise
        except Exception:
            logger.exception("Unable to create OAuth user")
            raise OAuthLinkError("unable_to_create_user") from None
        return created["id"], True

    # user exists, this provider account is not yet linked → implicit-linking gate
    if is_trusted_provider:
        is_trusted = True
    elif trust_provider_by_name:
        is_trusted = provider.provider_id in (await _resolve_trusted_providers(ctx))
    else:
        is_trusted = False
    if (
        (not is_trusted and not info.email_verified)
        or (linking.require_local_email_verified and not user["emailVerified"])
        or linking.enabled is False
        or linking.disable_implicit_linking
    ):
        raise OAuthLinkError("account_not_linked")

    # TS v1.7.6 link-account.ts:317-359: a link that fails or is vetoed is refused.
    try:
        linked = await _create_account(
            ctx, provider, info, _token_fields(ctx, tokens), user["id"], now
        )
    except APIError:
        raise
    except Exception:
        logger.exception("Unable to link account")
        linked = None
    if linked is None:
        raise OAuthLinkError("unable_to_link_account")
    user = await _maybe_promote_verified(ctx, user, info, email, now) or user
    if linking.update_user_info_on_link and user is not None:
        user = await _apply_update_user_info_on_link(ctx, user, info, now)
    if override and user is not None:
        user = await _override_user_info(ctx, user, info, email, now)
    return user["id"], False


async def _create_account(
    ctx: Ctx,
    provider: ProviderConfig,
    info: OAuthUserInfo,
    token_fields: dict[str, Any],
    user_id: str,
    now: Any,
    *,
    internal: Any = None,
) -> dict[str, Any] | None:
    """``internal`` is the transaction-bound adapter when called inside one."""
    return await (internal or ctx.internal).create(
        "account",
        {
            "id": generate_id(),
            "accountId": info.id,
            "providerId": provider.provider_id,
            "userId": user_id,
            **token_fields,
            "createdAt": now,
            "updatedAt": now,
        },
        ctx=ctx,
    )


async def _maybe_promote_verified(
    ctx: Ctx, user: dict[str, Any] | None, info: OAuthUserInfo, email: str, now: Any
) -> dict[str, Any] | None:
    """Self-heal an unverified local row once the IdP proves the same email is verified."""
    if (
        user
        and info.email_verified
        and not user["emailVerified"]
        and email == (user["email"] or "").lower()
    ):
        await ctx.internal.update(
            "user", [Where("id", user["id"])], {"emailVerified": True, "updatedAt": now}, ctx=ctx
        )
        user = {**user, "emailVerified": True}
    return user


async def _apply_update_user_info_on_link(
    ctx: Ctx, user: dict[str, Any], info: OAuthUserInfo, now: Any
) -> dict[str, Any]:
    """account.accountLinking.updateUserInfoOnLink: copy name/image from the freshly linked
    provider profile onto the user — never touches email/emailVerified (identity anchors)."""
    updates = {"updatedAt": now}
    if info.name:
        updates["name"] = info.name
    if info.image:
        updates["image"] = info.image
    updated = await ctx.internal.update("user", [Where("id", user["id"])], updates, ctx=ctx)
    return updated or {**user, **updates}


async def _override_user_info(
    ctx: Ctx, user: dict[str, Any], info: OAuthUserInfo, email: str, now: Any
) -> dict[str, Any]:
    """overrideUserInfoOnSignIn: re-sync name/image/email/emailVerified on every sign-in.
    emailVerified never *downgrades* a verified local email for the same address."""
    if email == (user["email"] or "").lower():
        verified = user["emailVerified"] or info.email_verified
    else:
        verified = info.email_verified
    updates = {
        "name": info.name or user["name"],
        "image": info.image,
        "email": email or user["email"],
        "emailVerified": verified,
        "updatedAt": now,
    }
    updated = await ctx.internal.update("user", [Where("id", user["id"])], updates, ctx=ctx)
    if updated is None:
        # TS v1.7.6 link-account.ts:493-508 (06daf7011)
        logger.warning(
            "Could not update user info during OAuth sign in; preserving existing user for session."
        )
        return user
    return updated


# --- GET|POST /callback/:provider ---------------------------------------------------------


def _error_redirect(
    ctx: Ctx, error: str, error_url: str | None, description: str = ""
) -> AuthResponse:
    target = error_url or f"{ctx.auth.base_url}{ctx.auth.base_path}/error"
    separator = "&" if "?" in target else "?"
    query = f"error={error}"
    if description:
        query += f"&error_description={description}"
    return AuthResponse(redirect_to=f"{target}{separator}{query}")


def _callback_params(ctx: Ctx) -> dict[str, str]:
    """Callback params — from the query, plus (for a POST) the urlencoded body, so a
    ``response_mode=form_post`` provider (Apple) that POSTs code/state works."""
    params = dict(ctx.request.query)
    if ctx.request.method == "POST" and ctx.request.body:
        from urllib.parse import parse_qsl

        content_type = ctx.request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type:
            params.update(dict(parse_qsl(ctx.request.body.decode())))
    return params


def _parse_callback_user(raw: str | None) -> dict[str, Any] | None:
    """The callback's ``user`` field — Apple's one-time form_post name payload (TS
    callback.ts:131-139 ``safeJSONParse``). Malformed or absent JSON -> None. Threaded onto
    ``tokens.user`` generically (every provider gets it; only Apple's ``fetch_user`` reads
    it) so the port avoids a provider-specific branch here."""
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


async def oauth_callback(ctx: Ctx) -> AuthResponse:
    provider = ctx.auth.social_providers.get(ctx.params.get("provider", ""))
    if provider is None:
        return _error_redirect(ctx, "oauth_provider_not_found", None)

    params = _callback_params(ctx)
    state = params.get("state", "")
    row = (
        await ctx.adapter.find_one("verification", [Where("identifier", state)]) if state else None
    )
    if row is None:
        return _error_redirect(ctx, "state_not_found", None)
    await ctx.adapter.delete_many("verification", [Where("identifier", state)])
    data = json.loads(row["value"])
    error_url = data.get("errorURL") or data.get("callbackURL")

    try:
        if row["expiresAt"] <= utcnow():
            raise _CallbackError("state_invalid")
        if not ctx.auth.skip_state_cookie_check:
            raw = ctx.request.cookies().get(cookie_name(ctx.auth, STATE_COOKIE))
            if raw is None or unsign_value(ctx.auth.secret, raw) != state:
                raise _CallbackError("state_mismatch")
        if params.get("error"):
            raise _CallbackError(params["error"])
        code = params.get("code")
        if not code:
            raise _CallbackError("no_code")

        try:
            tokens = await provider.exchange(
                ctx.auth.http,
                code=code,
                redirect_uri=_redirect_uri(ctx, provider),
                code_verifier=data.get("codeVerifier"),
            )
        except OAuthFetchError:
            raise _CallbackError("invalid_code") from None
        tokens.user = _parse_callback_user(params.get("user"))
        try:
            info = await provider.fetch_user(tokens, ctx.auth.http)
        except (httpx.HTTPError, OAuthFetchError):
            raise _CallbackError("unable_to_get_user_info") from None
        if not info.id:  # TS v1.7.6 callback.ts:240-255: no account subject
            raise _CallbackError("unable_to_get_user_info")
        if not info.email:
            raise _CallbackError("email_not_found")

        link = data.get("link")
        if link is not None:
            return await _callback_link(ctx, provider, info, tokens, link, data)

        try:
            user_id, is_new_user = await handle_oauth_user_info(ctx, provider, info, tokens)
        except OAuthLinkError as err:
            raise _CallbackError(err.code, err.error_url) from None
    except _CallbackError as err:
        response = _error_redirect(ctx, err.code, err.error_url or error_url)
        response.set_cookie(clear_cookie(ctx.auth, STATE_COOKIE))
        return response

    _session, cookies = await create_session(ctx.auth, user_id, ctx.request, ctx=ctx)
    target = (
        (data.get("newUserURL") or data.get("callbackURL"))
        if is_new_user
        else data.get("callbackURL")
    )
    response = AuthResponse(redirect_to=_absolute_url(ctx, target or "/"))
    for cookie in [*cookies, clear_cookie(ctx.auth, STATE_COOKIE)]:
        response.set_cookie(cookie)
    return response


async def _callback_link(
    ctx: Ctx,
    provider: ProviderConfig,
    info: OAuthUserInfo,
    tokens: OAuthTokens,
    link: dict[str, str],
    data: dict[str, Any],
) -> AuthResponse:
    """Callback linking branch (state carries ``link``): attach the provider to the already
    signed-in user, no new session. Redirects to callbackURL (or ?error= on refusal)."""
    callback_url = data.get("callbackURL") or "/"
    error = await link_oauth_account(ctx, provider, info, tokens, link)
    if error is not None:
        response = _error_redirect(ctx, error, data.get("errorURL") or callback_url)
    else:
        response = AuthResponse(redirect_to=_absolute_url(ctx, callback_url))
    response.set_cookie(clear_cookie(ctx.auth, STATE_COOKIE))
    return response


async def link_oauth_account(
    ctx: Ctx,
    provider: ProviderConfig,
    info: OAuthUserInfo,
    tokens: OAuthTokens,
    link: dict[str, str],
) -> str | None:
    """Link the provider account to ``link["userId"]`` (TS v1.7.6 link-account.ts:67
    ``linkOAuthAccount``, the explicit link-social rules). Returns None once linked,
    else the callback error code."""
    now = utcnow()
    linking = ctx.auth.account.account_linking
    trusted = provider.provider_id in (await _resolve_trusted_providers(ctx))
    if (not trusted and not info.email_verified) or linking.enabled is False:
        logger.error("Unable to link account - untrusted provider")
        return "unable_to_link_account"
    if (info.email or "").lower() != (link.get("email") or "").lower() and not (
        linking.allow_different_emails
    ):
        return "email_does_not_match"

    existing = await ctx.internal.find_account_by_key(provider.provider_id, info.id)
    if existing is not None:
        if existing["userId"] != link["userId"]:
            return "account_already_linked_to_different_user"
        fields = {**_fresh_token_fields(ctx, tokens), "providerId": provider.provider_id}
        merged = merge_scopes(existing.get("scope"), tokens.scopes)
        if merged:
            fields["scope"] = merged
        await ctx.internal.update(
            "account", [Where("id", existing["id"])], {**fields, "updatedAt": now}, ctx=ctx
        )
    else:
        created = await _create_account(
            ctx, provider, info, _token_fields(ctx, tokens), link["userId"], now
        )
        if created is None:
            return "unable_to_link_account"

    if linking.update_user_info_on_link:
        user = await ctx.adapter.find_one("user", [Where("id", link["userId"])])
        if user is not None:
            await _apply_update_user_info_on_link(ctx, user, info, now)
    return None


# --- POST /link-social --------------------------------------------------------------------


async def link_social(ctx: Ctx) -> AuthResponse:
    result = await ctx.require_session()
    session_user = result["user"]
    body = ctx.body()
    provider = ctx.auth.social_providers.get(body.get("provider") or "")
    if provider is None:
        raise APIError(404, "PROVIDER_NOT_FOUND", "Provider not found")

    id_token = body.get("idToken")
    if id_token:
        return await _link_social_id_token(ctx, provider, id_token, session_user)

    callback_url = body.get("callbackURL") or "/"
    ctx.auth.ensure_trusted_url(callback_url)
    error_url = body.get("errorCallbackURL")
    if error_url:
        ctx.auth.ensure_trusted_url(error_url)

    nonce = generate_random_string(32) if provider.use_nonce else None
    state, code_verifier = await _create_state(
        ctx,
        callback_url=callback_url,
        error_url=error_url,
        new_user_url=None,
        link={"userId": session_user["id"], "email": session_user["email"]},
        additional_data=body.get("additionalData"),
        nonce=nonce,
    )
    url = provider.authorization_url(
        state=state,
        redirect_uri=_redirect_uri(ctx, provider),
        code_verifier=code_verifier,
        extra_scopes=body.get("scopes"),
        nonce=nonce,
    )
    disable_redirect = bool(body.get("disableRedirect"))
    response = AuthResponse(body={"url": url, "redirect": not disable_redirect})
    response.set_cookie(_state_cookie(ctx, state))
    return response


async def _link_social_id_token(
    ctx: Ctx, provider: ProviderConfig, id_token: dict[str, Any], session_user: dict[str, Any]
) -> AuthResponse:
    if not provider.supports_id_token:
        raise APIError(404, "ID_TOKEN_NOT_SUPPORTED", "id_token linking not supported")
    token = id_token.get("token") or ""
    claims = await call_verify_id_token(provider, ctx.auth.http, token, id_token.get("nonce"), ctx)
    if claims is None:
        raise APIError(401, "INVALID_TOKEN", "Invalid id token")
    info = provider.user_info_from_id_token(claims)
    if not info.email:
        raise APIError(401, "USER_EMAIL_NOT_FOUND", "Provider did not return an email")
    _require_account_subject(info)

    now = utcnow()
    tokens = OAuthTokens(
        access_token=id_token.get("accessToken"),
        refresh_token=id_token.get("refreshToken"),
        id_token=token,
    )
    # TS v1.7.6 api/routes/account.ts:327-364: the key lookup is global. Relinking your
    # own account refreshes its tokens (never ``scope``); someone else's is a conflict.
    existing = await ctx.internal.find_account_by_key(provider.provider_id, info.id)
    if existing is not None and existing["userId"] == session_user["id"]:
        fields = {**_fresh_token_fields(ctx, tokens), "providerId": provider.provider_id}
        await ctx.internal.update(
            "account", [Where("id", existing["id"])], {**fields, "updatedAt": now}, ctx=ctx
        )
        if ctx.auth.account.account_linking.update_user_info_on_link:
            await _apply_update_user_info_on_link(ctx, session_user, info, now)
        return AuthResponse(body={"url": "", "status": True, "redirect": False})
    if existing is not None:
        raise APIError(409, "SOCIAL_ACCOUNT_ALREADY_LINKED", "Social account already linked")

    linking = ctx.auth.account.account_linking
    trusted = await _resolve_trusted_providers(ctx)
    is_trusted = provider.provider_id in trusted
    if (not is_trusted and not info.email_verified) or linking.enabled is False:
        raise APIError(401, "LINKING_NOT_ALLOWED", "Account not linked - linking not allowed")
    if (info.email or "").lower() != (session_user["email"] or "").lower() and not (
        linking.allow_different_emails
    ):
        # TS v1.6.29 account.ts:322, v1.7.6 account.ts:387
        raise APIError(
            401,
            "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
            "Account not linked - different emails not allowed",
        )

    # TS v1.7.6 account.ts:390-408 creates the linked account without ``scope``.
    await _create_account(ctx, provider, info, _token_fields(ctx, tokens), session_user["id"], now)
    if linking.update_user_info_on_link:
        await _apply_update_user_info_on_link(ctx, session_user, info, now)
    return AuthResponse(body={"url": "", "status": True, "redirect": False})


# --- token endpoints ----------------------------------------------------------------------


def account_selection(data: dict[str, Any]) -> dict[str, Any]:
    """TS ``accountSelectionSchema`` (account.ts:547-571, v1.7.6): exactly
    ``{accountId}`` (the Better Auth account id) or ``{useAccountCookie: true}``, each
    with an optional ``userId``; any other key is refused."""
    keys = set(data) - {"userId"}
    if keys == {"accountId"} and isinstance(data["accountId"], str):
        return data
    if keys == {"useAccountCookie"} and data["useAccountCookie"] in (True, "true"):
        return data
    raise APIError(400, "INVALID_BODY", "Pass either accountId or useAccountCookie")


async def resolve_user_account(ctx: Ctx, user_id: str, selection: dict[str, Any]):
    """account.ts:600-632 ``resolveUserAccount``: the session user's account with that id.

    ponytail: ``useAccountCookie`` never matches because the account cookie store
    (``account.storeAccountCookie``) is not ported; resolve it here once it is.
    """
    if "accountId" in selection:
        accounts = await ctx.adapter.find_many("account", [Where("userId", user_id)])
        for account in accounts:
            if account["id"] == selection["accountId"]:
                return account
    raise APIError(400, "ACCOUNT_NOT_FOUND", "Account not found")


async def select_user_account(
    ctx: Ctx, user_id: str, data: dict[str, Any], *, require_refresh: bool = False
) -> dict[str, Any]:
    """The account a token route acts on: the TS selection, or the 1.0 port's
    ``{providerId, accountId?}`` body when ``account.legacy_account_selection`` is on."""
    if not (ctx.auth.account.legacy_account_selection and "providerId" in data):
        return await resolve_user_account(ctx, user_id, account_selection(data))
    provider_id = data["providerId"]
    provider = ctx.auth.social_providers.get(provider_id)
    if provider is None:
        raise APIError(400, "PROVIDER_NOT_SUPPORTED", f"Provider {provider_id} is not supported.")
    if require_refresh and not provider.supports_refresh:
        raise APIError(
            400,
            "TOKEN_REFRESH_NOT_SUPPORTED",
            f"Provider {provider_id} does not support token refreshing.",
        )
    account_id = data.get("accountId")
    for account in await ctx.adapter.find_many("account", [Where("userId", user_id)]):
        if account["providerId"] == provider_id and (
            not account_id or account["accountId"] == account_id
        ):
            return account
    raise APIError(400, "ACCOUNT_NOT_FOUND", "Account not found")


async def refresh_token(ctx: Ctx) -> AuthResponse:
    """POST /refresh-token — force a token refresh via the provider's refresh grant."""
    result = await ctx.require_session()
    # account.ts resolveUserId: over HTTP the session user ALWAYS wins; a body
    # userId is honored only for a trusted server-side call with no session.
    # These handlers always require a session, so the session user is authoritative:
    # never trust body.userId here (would be an IDOR onto another user's tokens).
    account = await select_user_account(ctx, result["user"]["id"], ctx.body(), require_refresh=True)
    provider_id = account["providerId"]
    provider = ctx.auth.social_providers.get(provider_id)
    if provider is None:
        raise APIError(400, "PROVIDER_NOT_SUPPORTED", f"Provider {provider_id} is not supported.")
    if not provider.supports_refresh:
        raise APIError(
            400,
            "TOKEN_REFRESH_NOT_SUPPORTED",
            f"Provider {provider_id} does not support token refreshing.",
        )
    refresh = account.get("refreshToken")
    if not refresh:
        raise APIError(400, "REFRESH_TOKEN_NOT_FOUND", "Refresh token not found")

    try:
        tokens = await provider.refresh(ctx.auth.http, _decrypt(ctx, refresh) or "")
    except OAuthFetchError:
        raise APIError(
            400, "FAILED_TO_REFRESH_ACCESS_TOKEN", "Failed to refresh access token"
        ) from None

    new_refresh = _encrypt(ctx, tokens.refresh_token) if tokens.refresh_token else refresh
    # TS v1.7.6 account.ts:909-934 (97903c9cc): ``scope`` is not written, a refresh
    # response may be narrower than the grant; the response echoes the stored scope.
    updated = await ctx.internal.update(
        "account",
        [Where("id", account["id"])],
        {
            "accessToken": _encrypt(ctx, tokens.access_token),
            "refreshToken": new_refresh,
            "accessTokenExpiresAt": tokens.access_token_expires_at,
            "refreshTokenExpiresAt": tokens.refresh_token_expires_at
            or account.get("refreshTokenExpiresAt"),
            "idToken": tokens.id_token or account.get("idToken"),
            "updatedAt": utcnow(),
        },
        ctx=ctx,
    )
    scope = (updated or {}).get("scope")
    if scope is None:
        scope = account.get("scope")
    return AuthResponse(
        body={
            "accessToken": tokens.access_token,
            "refreshToken": tokens.refresh_token or _decrypt(ctx, refresh),
            "accessTokenExpiresAt": tokens.access_token_expires_at,
            "refreshTokenExpiresAt": tokens.refresh_token_expires_at
            or account.get("refreshTokenExpiresAt"),
            "scope": scope,
            "idToken": tokens.id_token or account.get("idToken"),
            "providerId": account["providerId"],
            "accountId": account["accountId"],
        }
    )


async def _valid_access_token(ctx: Ctx, account: dict[str, Any], provider: ProviderConfig):
    """Return a live access token, refreshing first if it's within 5s of expiry
    (``getValidAccessToken``). Persists refreshed tokens back to the account row."""
    new_tokens: OAuthTokens | None = None
    expires_at = account.get("accessTokenExpiresAt")
    expired = expires_at is not None and (expires_at - utcnow()).total_seconds() < 5
    if account.get("refreshToken") and expired and provider.supports_refresh:
        new_tokens = await provider.refresh(
            ctx.auth.http, _decrypt(ctx, account["refreshToken"]) or ""
        )
        await ctx.internal.update(
            "account",
            [Where("id", account["id"])],
            {
                "accessToken": _encrypt(ctx, new_tokens.access_token),
                "accessTokenExpiresAt": new_tokens.access_token_expires_at,
                "refreshToken": _encrypt(ctx, new_tokens.refresh_token)
                if new_tokens.refresh_token
                else account.get("refreshToken"),
                "refreshTokenExpiresAt": new_tokens.refresh_token_expires_at
                or account.get("refreshTokenExpiresAt"),
                "idToken": new_tokens.id_token or account.get("idToken"),
                "updatedAt": utcnow(),
            },
            ctx=ctx,
        )
    access_token = (
        new_tokens.access_token if new_tokens else _decrypt(ctx, account.get("accessToken") or "")
    )
    return {
        "accessToken": access_token,
        "accessTokenExpiresAt": new_tokens.access_token_expires_at
        if new_tokens
        else account.get("accessTokenExpiresAt"),
        "scopes": parse_stored_scopes(account.get("scope")),
        "idToken": (new_tokens.id_token if new_tokens else None) or account.get("idToken"),
    }


async def get_access_token(ctx: Ctx) -> AuthResponse:
    """POST /get-access-token — a valid access token, doing a refresh only if near expiry."""
    result = await ctx.require_session()
    # Session user is authoritative (account.ts resolveUserId): never trust
    # body.userId over HTTP, else any user could read another's access token.
    account = await select_user_account(ctx, result["user"]["id"], ctx.body())
    provider_id = account["providerId"]
    provider = ctx.auth.social_providers.get(provider_id)
    if provider is None:
        raise APIError(400, "PROVIDER_NOT_SUPPORTED", f"Provider {provider_id} is not supported.")
    try:
        return AuthResponse(body=await _valid_access_token(ctx, account, provider))
    except OAuthFetchError:
        raise APIError(
            400, "FAILED_TO_GET_ACCESS_TOKEN", "Failed to get a valid access token"
        ) from None
