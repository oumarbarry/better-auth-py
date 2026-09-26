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
from urllib.parse import quote, urlencode

import httpx

from ..adapters.base import Where
from ..crypto import (
    generate_id,
    generate_random_string,
    is_likely_encrypted,
    sign_email_verification_token,
    sign_value,
    symmetric_decrypt,
    symmetric_encrypt,
    unsign_value,
)
from ..session import build_cookie, clear_cookie, cookie_name, create_session, utcnow
from ..types import APIError, AuthResponse, Ctx
from .machinery import RESERVED_AUTHORIZATION_PARAMS, OAuthFetchError
from .models import OAuthTokens, OAuthUserInfo
from .providers import (
    ProviderConfig,
    call_refresh,
    call_verify_id_token,
    is_valid_account_subject,
)
from .validate_user_info import assert_valid_user_info

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
    def __init__(self, code: str, error_url: str | None = None, *, description: str | None = None):
        self.code = code
        self.error_url = error_url
        self.description = description
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
    """``provider.redirect_uri`` or ``{baseURL}/callback/{id}`` from the per-request base
    URL (TS v1.7.6 oauth2/utils.ts:39-49 ``getOAuthCallbackPath``, 7c7313c81)."""
    path = provider.callback_path or f"/callback/{provider.provider_id}"
    if not path.startswith("/"):
        path = f"/{path}"
    return provider.redirect_uri or f"{ctx.auth.base_url}{ctx.auth.base_path}{path}"


def _absolute_url(ctx: Ctx, url: str) -> str:
    return f"{ctx.auth.base_url}{url}" if url.startswith("/") else url


def _default_error_url(ctx: Ctx) -> str:
    return ctx.auth.on_api_error.error_url or f"{ctx.auth.base_url}{ctx.auth.base_path}/error"


def append_query_params(url: str, params: dict[str, str]) -> str:
    """TS v1.7.6 core/utils/url.ts:61-92 ``appendQueryParams``: the query goes before any
    ``#fragment`` (79904f0be) and existing query text is kept verbatim."""
    query = urlencode(params)
    if not query:
        return url
    base, hash_sign, fragment = url.partition("#")
    joiner = "?" if "?" not in base else "" if base.endswith(("?", "&")) else "&"
    return f"{base}{joiner}{query}{hash_sign}{fragment}"


async def _resolve_trusted_providers(ctx: Ctx) -> list[str]:
    trusted: Any = ctx.auth.account.account_linking.trusted_providers
    if callable(trusted):
        result = trusted(ctx.request)
        trusted = await result if hasattr(result, "__await__") else result
    return [str(p) for p in (trusted or [])]


async def get_provider(ctx: Ctx, provider_id: str | None) -> ProviderConfig | None:
    """The registered provider for ``provider_id``, or None. A provider exposing an async
    ``ensure_ready(http) -> bool`` (generic-oauth discovery) is skipped while it cannot
    resolve its endpoints (TS v1.7.6 generic-oauth/index.ts:214-256, 5fe5bc21d)."""
    provider = ctx.auth.social_providers.get(provider_id or "")
    if provider is None:
        return None
    ensure_ready = getattr(provider, "ensure_ready", None)
    if ensure_ready is not None and not await ensure_ready(ctx.auth.http):
        return None
    return provider


def _authorization_url(provider: ProviderConfig, **kwargs: Any) -> str:
    """Call ``provider.authorization_url``; ``additional_params`` is only passed when the
    request carries some, so provider overrides written before e7eb45b06 keep working."""
    if not kwargs.get("additional_params"):
        kwargs.pop("additional_params", None)
    return provider.authorization_url(**kwargs)


def _additional_params(body: dict[str, Any]) -> dict[str, str] | None:
    """Validate the body's ``additionalParams`` (TS v1.7.6 authorization-params.ts:13-28):
    a record of strings that may not name a reserved OAuth parameter."""
    params = body.get("additionalParams")
    if params is None:
        return None
    if not isinstance(params, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in params.items()
    ):
        raise APIError(400, "VALIDATION_ERROR", "[body.additionalParams] Invalid input")
    if any(key in RESERVED_AUTHORIZATION_PARAMS for key in params):
        reserved = ", ".join(
            [
                "state",
                "client_id",
                "redirect_uri",
                "response_type",
                "code_challenge",
                "code_challenge_method",
                "nonce",
                "scope",
            ]
        )
        raise APIError(
            400,
            "VALIDATION_ERROR",
            "[body.additionalParams] additionalParams cannot include reserved OAuth "
            f"parameters: {reserved}",
        )
    return params


def _mint_id_token_nonce(provider: ProviderConfig) -> str | None:
    """TS v1.7.6 oauth2/state.ts:16-20 ``generateIdTokenNonce``."""
    return generate_random_string(32) if provider.binds_id_token_nonce else None


# --- request-scoped OAuth state (TS v1.7.6 api/state/oauth.ts, 0cbaf81be) ---------------

_STATE_ATTR = "_oauth_state"

#: The keys of TS's ``stateDataSchema`` (state.ts:11-46 ``INTERNAL_STATE_KEYS``): client
#: ``additionalData`` can never set them.
INTERNAL_STATE_KEYS = frozenset(
    {
        "callbackURL",
        "codeVerifier",
        "errorURL",
        "newUserURL",
        "expiresAt",
        "oauthState",
        "link",
        "requestSignUp",
        "idTokenNonce",
        "serverContext",
    }
)
_SERVER_CONTEXT_ATTR = "_oauth_server_context"


async def add_oauth_server_context(ctx: Ctx, values: dict[str, Any]) -> None:
    """Attach server-trusted data to the OAuth flow started by this request (call it from a
    before-hook on ``/sign-in/social`` or ``/link-social``). The values ride the state row
    under ``serverContext`` and are readable on the callback through
    :func:`get_oauth_state`; the request body can never set them."""
    current = getattr(ctx, _SERVER_CONTEXT_ATTR, None) or {}
    setattr(ctx, _SERVER_CONTEXT_ATTR, {**current, **values})


def get_oauth_state(ctx: Ctx) -> dict[str, Any] | None:
    """The OAuth state of this request: the state just written during sign-in, or the one
    parsed on the callback. Only ``serverContext`` is server-trusted; the client's
    ``additionalData`` keys sit at the top level and must not be trusted."""
    return getattr(ctx, _STATE_ATTR, None)


async def _create_state(
    ctx: Ctx,
    *,
    callback_url: str,
    error_url: str | None,
    new_user_url: str | None,
    link: dict[str, str] | None = None,
    additional_data: dict[str, Any] | None = None,
    id_token_nonce: str | None = None,
    request_sign_up: bool | None = None,
) -> tuple[str, str]:
    """Write the state through the verification storage + return (state, code_verifier).

    ``code_verifier`` is always generated (cheap; lets a provider's PKCE-ness change
    without touching the state layer). A separately signed CSRF cookie is set by the caller.
    ``serverContext`` is written after ``additionalData`` so a client cannot smuggle one
    in (TS v1.7.6 oauth2/state.ts:56-69). The row goes through ``createVerificationValue``
    so ``storeIdentifier`` hashing and secondary storage apply, and the stored value
    carries ``oauthState`` (TS v1.7.6 state.ts:135-156). Absent keys are omitted, as
    ``JSON.stringify`` drops ``undefined`` and TS's state schema rejects ``null``.
    """
    state = generate_random_string(32)
    code_verifier = generate_random_string(128)
    now = utcnow()
    payload: dict[str, Any] = {
        "callbackURL": callback_url,
        "codeVerifier": code_verifier,
        "errorURL": error_url,
        "newUserURL": new_user_url,
        "link": link,
        "serverContext": dict(getattr(ctx, _SERVER_CONTEXT_ATTR, None) or {}) or None,
        "expiresAt": int(now.timestamp() * 1000) + STATE_EXPIRES_IN * 1000,
        "requestSignUp": request_sign_up,
        "idTokenNonce": id_token_nonce or None,
    }
    # TS v1.7.6 oauth2/state.ts:56-69: client additionalData is spread at the top level
    # and every core key is written after it, so a client key named like one never lands
    # (an absent core value drops the key, as JSON.stringify drops undefined).
    extra = additional_data if isinstance(additional_data, dict) else {}
    client = {k: v for k, v in extra.items() if k not in INTERNAL_STATE_KEYS}
    payload = {**client, **{key: value for key, value in payload.items() if value is not None}}
    try:
        verification = await ctx.internal.create_verification_value(
            {
                "identifier": state,
                "value": json.dumps({**payload, "oauthState": state}),
                "expiresAt": now + timedelta(seconds=STATE_EXPIRES_IN),
            }
        )
    except Exception:
        verification = None
    if verification is None:
        # TS v1.7.6 oauth2/state.ts:73-81
        logger.error("Failed to create verification")
        raise APIError(500, "INTERNAL_SERVER_ERROR", "Unable to create verification")
    setattr(ctx, _STATE_ATTR, payload)
    return state, code_verifier


def _state_cookie(ctx: Ctx, state: str) -> str:
    return build_cookie(ctx.auth, sign_value(ctx.auth.secret, state), 300, STATE_COOKIE)


# --- POST /sign-in/social -----------------------------------------------------------------


async def sign_in_social(ctx: Ctx) -> AuthResponse:
    body = ctx.body()
    provider = await get_provider(ctx, body.get("provider"))
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
    additional_params = _additional_params(body)

    nonce = _mint_id_token_nonce(provider)
    state, code_verifier = await _create_state(
        ctx,
        callback_url=callback_url,
        error_url=error_url,
        new_user_url=new_user_url,
        additional_data=body.get("additionalData"),
        id_token_nonce=nonce,
        request_sign_up=body.get("requestSignUp"),
    )
    # TS v1.7.6 sign-in.ts:375-388
    url = _authorization_url(
        provider,
        state=state,
        redirect_uri=_redirect_uri(ctx, provider),
        code_verifier=code_verifier,
        extra_scopes=body.get("scopes"),
        login_hint=body.get("loginHint"),
        nonce=nonce,
        additional_params=additional_params,
    )
    disable_redirect = bool(body.get("disableRedirect"))
    response = AuthResponse(body={"url": url, "redirect": not disable_redirect})
    response.set_cookie(_state_cookie(ctx, state))
    return response


async def _id_token_user_info(
    ctx: Ctx, provider: ProviderConfig, claims: dict[str, Any], id_token: dict[str, Any]
) -> OAuthUserInfo:
    """Profile for a client-submitted id token. A provider exposing an async
    ``id_token_user_info(tokens, http)`` resolves it like its callback profile (TS
    sign-in.ts:296-310 calls ``getUserInfo``); others map the verified claims."""
    resolve = getattr(provider, "id_token_user_info", None)
    if resolve is None:
        return provider.user_info_from_id_token(claims)
    tokens = OAuthTokens(
        id_token=id_token.get("token"),
        access_token=id_token.get("accessToken"),
        refresh_token=id_token.get("refreshToken"),
        user=id_token.get("user"),
    )
    try:
        return await resolve(tokens, ctx.auth.http)
    except (OAuthFetchError, httpx.HTTPError, ValueError):
        raise APIError(401, "FAILED_TO_GET_USER_INFO", "Failed to get user info") from None


def _oauth_source(provider: ProviderConfig, info: OAuthUserInfo) -> dict[str, Any]:
    """The provisioning source handed to ``validateUserInfo`` (callback.ts:301-304)."""
    return {"method": "oauth", "oauth": {"providerId": provider.provider_id, "profile": info.raw}}


def _link_error_api(err: OAuthLinkError) -> APIError:
    """TS v1.7.6 sign-in.ts:350-361: an unverified email is a 403 EMAIL_NOT_VERIFIED; any
    other refusal is a 401 OAUTH_LINK_ERROR whose message is the space-separated reason."""
    if err.code == "email_not_verified":
        return APIError(403, "EMAIL_NOT_VERIFIED", "Email not verified")
    return APIError(401, "OAUTH_LINK_ERROR", err.code.replace("_", " "))


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
    info = await _id_token_user_info(ctx, provider, claims, id_token)
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
            ctx,
            provider,
            info,
            tokens,
            disable_sign_up=disable_sign_up,
            source=_oauth_source(provider, info),
            callback_url=body.get("callbackURL"),
        )
    except OAuthLinkError as err:
        raise _link_error_api(err) from None
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
    """An invalid provider subject never becomes an account id (TS v1.7.6
    oauth2/account-key.ts:28-62, surfaced by ``resolveOAuthAccountKeyForAPI``)."""
    if not is_valid_account_subject(info.id):
        raise APIError(401, "FAILED_TO_GET_USER_INFO", "Failed to get user info")


def _profile_fields(info: OAuthUserInfo, email: str) -> dict[str, Any]:
    """The provider profile ``validateUserInfo`` receives (mapped user fields)."""
    return {
        "name": info.name,
        "email": email,
        "emailVerified": info.email_verified,
        "image": info.image,
    }


def _profile_user_fields(ctx: Ctx, info: OAuthUserInfo, action: str) -> dict[str, Any]:
    """TS v1.7.6 db/schema.ts:225-238 ``parseAdditionalUserInputFromProviderProfile``: the
    mapped profile's configured user fields. A field closed to input is skipped (never
    refused); on ``create`` defaults apply and a missing required field is a 400."""
    schema = ctx.auth.schema["user"]
    allowed = {
        key: value
        for key, value in info.extra.items()
        if key not in schema or schema[key].input is not False
    }
    return ctx.auth.parse_user_input(allowed, action)


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
    source: dict[str, Any] | None = None,
    callback_url: str | None = None,
    selected_user: dict[str, str] | None = None,
    require_exact_account_binding: bool = False,
    defer_non_database_writes: bool = False,
) -> tuple[str, bool]:
    """Find/register/link decision tree (``link-account.ts``). Returns (user_id, is_register).

    Raises :class:`OAuthLinkError` with a stable code (``account_not_linked``,
    ``signup_disabled``, ``unable_to_link_account``, ``unable_to_create_user``,
    ``internal_server_error``, ``email_not_verified``) on a refused link/register; callers
    map it to a redirect (callback) or an APIError (idToken sign-in). A ``validateUserInfo``
    refusal raises its ``403`` :class:`APIError` (``source`` names the flow; the default is
    ``{"method": "oauth", "oauth": {"providerId": ...}}``).

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

    Resolution options (TS v1.7.6 link-account.ts:170-640, ed61b4798, the SSO
    ``resolveUser`` path):

    - ``selected_user``: ``{"userId", "profile": "preserve" | "update"}`` chosen by an
      application resolver. The identity links to that user without the implicit-linking
      gate; ``profile`` decides whether the provider profile overwrites the user.
    - ``require_exact_account_binding`` (implied by ``selected_user``): a database hook
      that rewrites the account key or owner is refused with ``409``.
    - ``defer_non_database_writes``: the verification email waits until the enclosing
      :meth:`InternalAdapter.transaction` commits and is dropped on rollback.
    """
    now = utcnow()
    exact = bool(selected_user) or require_exact_account_binding
    override = (
        provider.override_user_info_on_sign_in if override_user_info is None else override_user_info
    )
    email = (info.email or "").lower()
    linking = ctx.auth.account.account_linking
    source = source or {"method": "oauth", "oauth": {"providerId": provider.provider_id}}

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
        if selected_user and user["id"] != selected_user["userId"]:
            # TS v1.7.6 link-account.ts:222-230
            raise APIError(
                409, "account_ownership_conflict", "Account is already linked to another user"
            )
        # TS v1.7.6 link-account.ts:382-390: a returning user is re-validated with the
        # fresh provider profile.
        await assert_valid_user_info(
            ctx, {**_profile_fields(info, email), "id": user["id"]}, {**source, "action": "sign-in"}
        )
        if ctx.auth.account.update_account_on_sign_in:
            fresh = {"providerId": provider.provider_id, **_fresh_token_fields(ctx, tokens)}
            updated = await ctx.internal.update(
                "account", [Where("id", account["id"])], {**fresh, "updatedAt": now}, ctx=ctx
            )
            if updated is None:
                # TS v1.7.6 link-account.ts:423-433
                raise OAuthLinkError("unable_to_update_account")
            if exact:
                _assert_exact_binding(updated, provider, info, user["id"])
        if not selected_user:
            user = await _maybe_promote_verified(ctx, user, info, email, now)
        user = await _apply_profile_policy(ctx, user, info, email, now, override, selected_user)
        await _require_email_verification(
            ctx, provider, user, False, callback_url, defer_non_database_writes
        )
        return account["userId"], False

    try:
        if selected_user:
            user = await ctx.adapter.find_one("user", [Where("id", selected_user["userId"])])
        else:
            user = await ctx.adapter.find_one("user", [Where("email", email)]) if email else None
    except Exception:
        raise _database_error(ctx) from None
    if selected_user and user is None:
        # TS v1.7.6 link-account.ts:238-247
        raise APIError(404, "user_not_found", "User not found")

    if user is None:  # register
        if disable_sign_up:
            raise OAuthLinkError("signup_disabled")
        token_fields = _token_fields(ctx, tokens)
        # TS v1.7.6 link-account.ts:517-560: every caller passes `name || ""` (callback.ts:293,
        # sign-in.ts:333), then the mapped profile's configured user fields.
        user_data = {
            "name": info.name or "",
            "image": info.image,
            **_profile_user_fields(ctx, info, "create"),
            "email": email,
            "emailVerified": info.email_verified,
            "createdAt": now,
            "updatedAt": now,
        }

        async def register(tx: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
            # TS v1.7.6 internal-adapter.ts:282-306: createUser runs the gate first.
            await assert_valid_user_info(ctx, user_data, {**source, "action": "create-user"})
            created = await tx.create("user", {"id": generate_id(), **user_data}, ctx=ctx)
            if created is None:
                raise RuntimeError("user creation was aborted")
            created_account = await _create_account(
                ctx, provider, info, token_fields, created["id"], now, internal=tx
            )
            return created, created_account

        # TS v1.7.6 link-account.ts:542-588 (a83152e2e): user + first account commit
        # together; after-hooks run once the transaction commits.
        try:
            created, created_account = await ctx.internal.transaction(register)
        except APIError:
            raise
        except Exception:
            logger.exception("Unable to create OAuth user")
            raise OAuthLinkError("unable_to_create_user") from None
        if exact:
            _assert_exact_binding(created_account, provider, info, created["id"])
        await _require_email_verification(
            ctx, provider, created, True, callback_url, defer_non_database_writes
        )
        return created["id"], True

    # user exists, this provider account is not yet linked → implicit-linking gate
    if is_trusted_provider:
        is_trusted = True
    elif trust_provider_by_name:
        is_trusted = provider.provider_id in (await _resolve_trusted_providers(ctx))
    else:
        is_trusted = False
    if not selected_user and (
        (not is_trusted and not info.email_verified)
        or (linking.require_local_email_verified and not user["emailVerified"])
        or linking.enabled is False
        or linking.disable_implicit_linking
    ):
        raise OAuthLinkError("account_not_linked")

    # TS v1.7.6 link-account.ts:307-316: the gate runs before the implicit link.
    await assert_valid_user_info(
        ctx,
        {**_profile_fields(info, email), "id": user["id"]},
        {**source, "action": "link-account"},
    )
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
    if exact:
        _assert_exact_binding(linked, provider, info, user["id"])
    if not selected_user:
        user = await _maybe_promote_verified(ctx, user, info, email, now) or user
        if linking.update_user_info_on_link and user is not None:
            user = await _apply_update_user_info_on_link(ctx, user, info, now)
    user = await _apply_profile_policy(ctx, user, info, email, now, override, selected_user)
    await _require_email_verification(
        ctx, provider, user, False, callback_url, defer_non_database_writes
    )
    assert user is not None
    return user["id"], False


def _assert_exact_binding(
    row: dict[str, Any] | None, provider: ProviderConfig, info: OAuthUserInfo, user_id: str
) -> None:
    """TS v1.7.6 link-account.ts:333-345: a hook may not move the selected binding."""
    if row is not None and (
        row.get("accountId") != info.id
        or row.get("providerId") != provider.provider_id
        or row.get("userId") != user_id
    ):
        raise APIError(
            409,
            "account_hook_binding_conflict",
            "Account hook changed the selected authentication binding",
        )


async def _apply_profile_policy(
    ctx: Ctx,
    user: dict[str, Any] | None,
    info: OAuthUserInfo,
    email: str,
    now: Any,
    override: bool,
    selected_user: dict[str, str] | None,
) -> dict[str, Any] | None:
    """Profile overwrite: ``selected_user.profile == "update"`` for a resolver-selected
    user, else ``overrideUserInfo`` (TS v1.7.6 link-account.ts:471-518)."""
    wanted = selected_user["profile"] == "update" if selected_user else override
    if not wanted or user is None:
        return user
    updated = await _override_user_info(ctx, user, info, email, now)
    if selected_user and updated["id"] != selected_user["userId"]:
        raise APIError(409, "user_hook_selection_conflict", "User hook changed the selected user")
    return updated


async def _require_email_verification(
    ctx: Ctx,
    provider: ProviderConfig,
    user: dict[str, Any] | None,
    is_register: bool,
    callback_url: str | None,
    defer: bool = False,
) -> None:
    """Per-provider ``requireEmailVerification`` (TS v1.7.6 link-account.ts:598-630,
    91f235f86): a verification email goes out on sign-up (``sendOnSignUp`` falling back to
    the provider flag) and, when required, on sign-in with ``sendOnSignIn``; an unverified
    user then gets no session (``email_not_verified``). The flag is read from the
    registered provider with this id, as TS does."""
    if user is None or user.get("emailVerified"):
        return
    registered = ctx.auth.social_providers.get(provider.provider_id)
    required = bool(registered is not None and registered.require_email_verification)
    cfg = ctx.auth.email_verification
    send_on_sign_up = cfg.send_on_sign_up if cfg.send_on_sign_up is not None else required
    if is_register and send_on_sign_up:
        await _dispatch_verification_email(ctx, user, callback_url, defer)
    if required:
        if not is_register and cfg.send_on_sign_in:
            await _dispatch_verification_email(ctx, user, callback_url, defer)
        raise OAuthLinkError("email_not_verified")


async def _dispatch_verification_email(
    ctx: Ctx, user: dict[str, Any], callback_url: str | None, defer: bool = False
) -> None:
    """TS v1.7.6 link-account.ts:667-708: a failed send is logged, never fatal. ``defer``
    queues it after the enclosing transaction commits (``queueAfterTransactionHook``)."""
    cfg = ctx.auth.email_verification
    if cfg.send_verification_email is None:
        return
    # ponytail: reuses the InternalAdapter's after-commit queue (set while a transaction
    # runs); expose a public queue method if a second caller needs one.
    queue = ctx.internal._after_queue
    if defer and queue is not None:
        queue.append(lambda: _dispatch_verification_email(ctx, user, callback_url))
        return
    try:
        token = sign_email_verification_token(
            ctx.auth.secret, user["email"], expires_in=cfg.expires_in
        )
        url = (
            f"{ctx.auth.base_url}{ctx.auth.base_path}/verify-email"
            f"?token={token}&callbackURL={quote(callback_url or '/', safe='')}"
        )
        await cfg.send_verification_email(user, url, token)
    except Exception:
        logger.exception("Failed to send OAuth verification email")


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
    """account.accountLinking.updateUserInfoOnLink: copy name/image and the mapped profile's
    configured user fields (TS v1.7.6 link-account.ts:722-757) from the freshly linked
    provider profile onto the user. Never touches email/emailVerified (identity anchors)."""
    updates = {"updatedAt": now}
    if info.name:
        updates["name"] = info.name
    if info.image:
        updates["image"] = info.image
    updates.update(_profile_user_fields(ctx, info, "update"))
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
    # TS v1.7.6 link-account.ts:461-492: callers pass `name || ""`; updateUser drops an
    # undefined image, so a provider without one keeps the stored image.
    updates = {
        "name": info.name or "",
        **({"image": info.image} if info.image is not None else {}),
        **_profile_user_fields(ctx, info, "update"),
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
    ctx: Ctx, error: str, error_url: str | None, description: str | None = ""
) -> AuthResponse:
    """TS ``redirectOnError`` (oauth2/errors.ts:39-50): ``?error=`` plus an optional
    ``error_description``, URL-encoded, before any fragment."""
    params = {"error": error}
    if description:
        params["error_description"] = description
    target = error_url or _default_error_url(ctx)
    return AuthResponse(redirect_to=append_query_params(target, params))


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


class _StateError(Exception):
    def __init__(self, code: str, error_url: str, *, cookie_expired: bool = False):
        self.code = code
        self.error_url = error_url
        self.cookie_expired = cookie_expired
        super().__init__(code)


async def _parse_state(
    ctx: Ctx, state: str, *, skip_state_cookie_check: bool | None = None
) -> dict[str, Any]:
    """TS v1.7.6 state.ts:219-298 (database strategy) + oauth2/state.ts:84-117. The row is
    read with ``findVerificationValue`` and removed with ``deleteVerificationByIdentifier``
    once the CSRF cookie matched. Every state failure is ``state_mismatch`` (an unreadable
    row is ``internal_server_error``); the errorURL is the flow's own once the row is read.
    ``skip_state_cookie_check`` overrides ``auth.skip_state_cookie_check`` (oauth-proxy)."""
    default_error_url = _default_error_url(ctx)
    row = await ctx.internal.find_verification_value(state)
    if row is None:
        raise _StateError("state_mismatch", default_error_url)
    try:
        data = json.loads(row["value"])
        if not isinstance(data, dict):
            raise ValueError("state is not an object")
    except (TypeError, ValueError):
        logger.error("Failed to parse state")
        raise _StateError("internal_server_error", default_error_url) from None
    error_url = data.get("errorURL") or default_error_url
    oauth_state = data.get("oauthState")
    if oauth_state is not None and oauth_state != state:
        raise _StateError("state_mismatch", error_url)
    skip = (
        ctx.auth.skip_state_cookie_check
        if skip_state_cookie_check is None
        else skip_state_cookie_check
    )
    if not skip:
        raw = ctx.request.cookies().get(cookie_name(ctx.auth, STATE_COOKIE))
        if raw is None or unsign_value(ctx.auth.secret, raw) != state:
            raise _StateError("state_mismatch", error_url)
    await ctx.internal.delete_verification_by_identifier(state)
    if int(data.get("expiresAt") or 0) < int(utcnow().timestamp() * 1000):
        raise _StateError("state_mismatch", error_url, cookie_expired=True)
    data["errorURL"] = error_url
    # States written before additionalData was spread (TS oauth2/state.ts:56-69) nest it
    # under ``additionalData``. They live 10 minutes, so lift the nested keys to the top
    # level (core keys still win) so sign-ins in flight at upgrade read like new ones.
    legacy = data.get("additionalData")
    if isinstance(legacy, dict):
        for key, value in legacy.items():
            if key not in INTERNAL_STATE_KEYS:
                data.setdefault(key, value)
    setattr(ctx, _STATE_ATTR, data)
    return data


async def _idp_initiated_bounce(ctx: Ctx, provider: ProviderConfig) -> AuthResponse:
    """A stateless IdP-initiated callback restarts the flow with fresh state and PKCE
    (TS v1.7.6 callback.ts:106-123, 03e6c94e9). The state's callbackURL is the base URL,
    as ``generateState`` falls back to ``options.baseURL`` without a body."""
    nonce = _mint_id_token_nonce(provider)
    state, code_verifier = await _create_state(
        ctx,
        callback_url=ctx.auth.base_url,
        error_url=None,
        new_user_url=None,
        id_token_nonce=nonce,
    )
    url = _authorization_url(
        provider,
        state=state,
        redirect_uri=_redirect_uri(ctx, provider),
        code_verifier=code_verifier,
        nonce=nonce,
    )
    response = AuthResponse(redirect_to=url)
    response.set_cookie(_state_cookie(ctx, state))
    return response


async def oauth_callback(ctx: Ctx) -> AuthResponse:
    """GET|POST /callback/:id, in TS v1.7.6 callback.ts order: IdP bounce, state, provider
    error, code, provider, RFC 9207 ``iss``, nonce binding, code exchange, profile, account
    subject, link branch, email, sign-in/register."""
    provider_id = ctx.params.get("provider", "")
    params = _callback_params(ctx)
    state = params.get("state")
    if state is None and params.get("code"):
        idp_provider = await get_provider(ctx, provider_id)
        if idp_provider is not None and idp_provider.allow_idp_initiated:
            return await _idp_initiated_bounce(ctx, idp_provider)
    if not state:
        return _error_redirect(ctx, "state_not_found", None)
    try:
        data = await _parse_state(ctx, state)
    except _StateError as err:
        response = _error_redirect(ctx, err.code, err.error_url)
        if err.cookie_expired:
            response.set_cookie(clear_cookie(ctx.auth, STATE_COOKIE))
        return response

    try:
        response = await _complete_callback(ctx, provider_id, params, data)
    except _CallbackError as err:
        response = _error_redirect(
            ctx, err.code, err.error_url or data["errorURL"], err.description
        )
    response.set_cookie(clear_cookie(ctx.auth, STATE_COOKIE))
    return response


async def _complete_callback(
    ctx: Ctx, provider_id: str, params: dict[str, str], data: dict[str, Any]
) -> AuthResponse:
    if params.get("error"):
        raise _CallbackError(params["error"], description=params.get("error_description"))
    code = params.get("code")
    if not code:
        raise _CallbackError("no_code")
    provider = await get_provider(ctx, provider_id)
    if provider is None:
        raise _CallbackError("oauth_provider_not_found")
    iss = params.get("iss")
    if iss and provider.issuer and iss != provider.issuer:
        logger.error("OAuth issuer mismatch: expected %s, got %s", provider.issuer, iss)
        raise _CallbackError("issuer_mismatch")
    # generic-oauth ``require_issuer_validation`` (deprecated 1.x option, off by default)
    if not iss and provider.issuer and getattr(provider, "require_issuer", False):
        raise _CallbackError("issuer_missing")
    id_token_nonce = data.get("idTokenNonce")
    if provider.binds_id_token_nonce and not id_token_nonce:
        raise _CallbackError("nonce_binding_missing")

    try:
        tokens = await provider.exchange(
            ctx.auth.http,
            code=code,
            redirect_uri=_redirect_uri(ctx, provider),
            code_verifier=data.get("codeVerifier"),
        )
    except Exception:
        logger.exception("OAuth code exchange failed")
        raise _CallbackError("invalid_code") from None
    if tokens is None:
        raise _CallbackError("invalid_code")
    tokens.user = _parse_callback_user(params.get("user"))
    tokens.expected_id_token_nonce = id_token_nonce
    try:
        info = await provider.fetch_user(tokens, ctx.auth.http)
    except (httpx.HTTPError, OAuthFetchError, ValueError):
        raise _CallbackError("unable_to_get_user_info") from None
    # TS v1.7.6 callback.ts:232-255: no profile or no valid account subject
    if not is_valid_account_subject(info.id):
        raise _CallbackError("unable_to_get_user_info")

    link = data.get("link")
    if link is not None:
        return await _callback_link(ctx, provider, info, tokens, link, data)

    if not info.email:
        raise _CallbackError("email_not_found")
    disable_sign_up = (
        provider.disable_implicit_sign_up and not data.get("requestSignUp")
    ) or provider.disable_sign_up
    callback_url = data.get("callbackURL") or "/"
    try:
        user_id, is_new_user = await handle_oauth_user_info(
            ctx,
            provider,
            info,
            tokens,
            disable_sign_up=disable_sign_up,
            source=_oauth_source(provider, info),
            callback_url=callback_url,
        )
        _session, cookies = await create_session(ctx.auth, user_id, ctx.request, ctx=ctx)
    except OAuthLinkError as err:
        raise _CallbackError(err.code, err.error_url) from None
    except APIError as err:
        # TS v1.7.6 callback.ts:306-313 (d309e5d2b): app-defined rejections keep their code.
        raise _CallbackError(err.code, description=err.message) from None

    target = (data.get("newUserURL") or callback_url) if is_new_user else callback_url
    response = AuthResponse(redirect_to=_absolute_url(ctx, target))
    for cookie in cookies:
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
    signed-in user, no new session (TS v1.7.6 callback.ts:268-280). It runs before the
    email check, so a provider without email fails the email match instead."""
    try:
        error = await link_oauth_account(ctx, provider, info, tokens, link)
    except APIError as err:
        raise _CallbackError(err.code, description=err.message) from None
    if error is not None:
        raise _CallbackError(error)
    return AuthResponse(redirect_to=_absolute_url(ctx, data.get("callbackURL") or "/"))


async def link_oauth_account(
    ctx: Ctx,
    provider: ProviderConfig,
    info: OAuthUserInfo,
    tokens: OAuthTokens,
    link: dict[str, str],
) -> str | None:
    """Link the provider account to ``link["userId"]`` (TS v1.7.6 link-account.ts:67
    ``linkOAuthAccount``, the explicit link-social rules). Returns None once linked,
    else the callback error code. A ``validateUserInfo`` refusal raises its ``403``
    :class:`APIError` (link-account.ts:71-90)."""
    await assert_valid_user_info(
        ctx,
        {**_profile_fields(info, info.email or ""), "id": link["userId"]},
        {"action": "link-account", **_oauth_source(provider, info)},
    )
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
    provider = await get_provider(ctx, body.get("provider"))
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
    additional_params = _additional_params(body)

    nonce = _mint_id_token_nonce(provider)
    state, code_verifier = await _create_state(
        ctx,
        callback_url=callback_url,
        error_url=error_url,
        new_user_url=body.get("newUserCallbackURL"),
        link={"userId": session_user["id"], "email": session_user["email"]},
        additional_data=body.get("additionalData"),
        id_token_nonce=nonce,
        request_sign_up=body.get("requestSignUp"),
    )
    # TS v1.7.6 account.ts:423-441 (e7eb45b06, 7c7313c81)
    url = _authorization_url(
        provider,
        state=state,
        redirect_uri=_redirect_uri(ctx, provider),
        code_verifier=code_verifier,
        extra_scopes=body.get("scopes"),
        login_hint=body.get("loginHint"),
        nonce=nonce,
        additional_params=additional_params,
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
    info = await _id_token_user_info(ctx, provider, claims, id_token)
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
        tokens = await call_refresh(provider, ctx.auth.http, _decrypt(ctx, refresh) or "", ctx)
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
            # TS v1.7.6 account.ts:942-943: the Better Auth account row id
            "accountId": account["id"],
        }
    )


async def _valid_access_token(ctx: Ctx, account: dict[str, Any], provider: ProviderConfig):
    """Return a live access token, refreshing first if it's within 5s of expiry
    (``getValidAccessToken``). Persists refreshed tokens back to the account row."""
    new_tokens: OAuthTokens | None = None
    expires_at = account.get("accessTokenExpiresAt")
    expired = expires_at is not None and (expires_at - utcnow()).total_seconds() < 5
    if account.get("refreshToken") and expired and provider.supports_refresh:
        new_tokens = await call_refresh(
            provider, ctx.auth.http, _decrypt(ctx, account["refreshToken"]) or "", ctx
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
