"""generic-oauth plugin — a faithful port of better-auth's ``plugins/generic-oauth``.

Adds OAuth2/OIDC sign-in for arbitrary, user-configured providers (beyond the built-in
social providers): OIDC discovery, PKCE, custom token/userinfo endpoints, ``mapProfileToUser``,
and per-provider sign-up policy. Wire parity with the TS plugin
(``packages/better-auth/src/plugins/generic-oauth``):

- ``POST /sign-in/oauth2`` builds the provider authorization URL (discovery resolves the
  auth+token endpoints from one fetch) and stores the CSRF ``state`` (verification row +
  signed cookie), returning ``{url, redirect}``;
- ``GET|POST /oauth2/callback/{providerId}`` exchanges the code, validates ``iss`` (RFC 9207)
  when an issuer is configured/discovered, resolves the profile (``id_token`` decode or a
  bearer userinfo fetch), then runs the shared find/register/link decision core;
- ``POST /oauth2/link`` (session required) builds an authorization URL whose callback links
  the provider account to the current user.

The heavy lifting is reused from the read-only ``better_auth.oauth`` package: the authorize
URL builder / token exchange / refresh (``machinery``), the find/register/link decision tree
(``flow.handle_oauth_user_info``), token encryption + account create/link + state cookie
(``flow`` helpers). ``init()`` also registers each configured provider into
``auth.social_providers`` so it rides the core social machinery (e.g. ``/refresh-token``).

``ponytail`` notes:
- generic-oauth decodes the ``id_token`` WITHOUT verifying its signature (TS ``decodeJwt``):
  the token arrived over TLS from the token exchange, so the plugin trusts it. Not a JWKS path.
- no cross-call discovery cache: TS re-fetches the discovery doc once per endpoint call
  (a rotated doc is picked up next call); we match that rather than add a stale cache.
- ``sign-in/oauth2`` does not origin-check ``callbackURL`` (TS generic-oauth doesn't): the
  redirect targets the caller's own browser after their own sign-in, a low-risk self-redirect.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlencode

import httpx
import jwt

from ..adapters.base import Where
from ..crypto import generate_id, generate_random_string, unsign_value
from ..oauth.flow import (
    STATE_COOKIE,
    STATE_EXPIRES_IN,
    OAuthLinkError,
    _absolute_url,
    _apply_update_user_info_on_link,
    _create_account,
    _state_cookie,
    _token_fields,
    handle_oauth_user_info,
)
from ..oauth.machinery import (
    OAuthFetchError,
    build_authorization_url,
    exchange_code,
    get_oauth2_tokens,
    oauth_fetch,
    refresh_access_token,
)
from ..oauth.models import OAuthTokens, OAuthUserInfo
from ..oauth.providers import ProviderConfig
from ..plugins import Plugin, Route
from ..session import clear_cookie, cookie_name, create_session, utcnow
from ..types import APIError, AuthResponse, Ctx

logger = logging.getLogger("better_auth")

# Exact TS strings (packages/better-auth/src/plugins/generic-oauth/error-codes.ts).
GENERIC_OAUTH_ERROR_CODES: dict[str, str] = {
    "INVALID_OAUTH_CONFIGURATION": "Invalid OAuth configuration",
    "TOKEN_URL_NOT_FOUND": "Invalid OAuth configuration. Token URL not found.",
    "PROVIDER_CONFIG_NOT_FOUND": "No config found for provider",
    "PROVIDER_ID_REQUIRED": "Provider ID is required",
    "INVALID_OAUTH_CONFIG": "Invalid OAuth configuration.",
    "SESSION_REQUIRED": "Session is required",
    "ISSUER_MISMATCH": (
        "OAuth issuer mismatch. The authorization server issuer does not match the "
        "expected value (RFC 9207)."
    ),
    "ISSUER_MISSING": (
        "OAuth issuer parameter missing. The authorization server did not include the "
        "required iss parameter (RFC 9207)."
    ),
}


@dataclass
class GenericOAuthConfig:
    """One provider configuration (TS ``GenericOAuthConfig``). ``discovery_url`` OR explicit
    ``authorization_url``/``token_url``/``user_info_url`` must resolve the endpoints."""

    provider_id: str
    client_id: str | list[str]
    client_secret: str = ""
    discovery_url: str | None = None
    issuer: str | None = None
    require_issuer_validation: bool = False
    authorization_url: str | None = None
    token_url: str | None = None
    user_info_url: str | None = None
    scopes: list[str] = field(default_factory=list)
    redirect_uri: str | None = None
    response_type: str = "code"
    response_mode: str | None = None
    prompt: str | None = None
    pkce: bool = False
    access_type: str | None = None
    access_token_expires_in: int | None = None
    #: custom token exchange; ``(data) -> OAuthTokens|dict`` (may be async). Bypasses the
    #: standard code exchange.
    get_token: Callable[..., Any] | None = None
    #: custom userinfo; ``(tokens) -> dict|None`` (may be async). Bypasses id_token/userinfo.
    get_user_info: Callable[..., Any] | None = None
    #: ``(profile) -> partial user dict`` (may be async) — override mapped user fields/id.
    map_profile_to_user: Callable[..., Any] | None = None
    #: extra authorize params (dict or ``(ctx) -> dict``); overwrite defaults.
    authorization_url_params: dict[str, str] | Callable[[Ctx], dict[str, str]] | None = None
    #: extra token params (dict or ``(ctx) -> dict``).
    token_url_params: dict[str, str] | Callable[[Ctx], dict[str, str]] | None = None
    disable_implicit_sign_up: bool = False
    disable_sign_up: bool = False
    #: token-endpoint client auth: "post" (body) or "basic" (Authorization header).
    authentication: str = "post"
    discovery_headers: dict[str, str] | None = None
    authorization_headers: dict[str, str] | None = None
    override_user_info: bool = False


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _is_nonempty_id(value: Any) -> bool:
    """TS ``isNonEmptyOAuthId``: a string|number that is not None/"" ."""
    return value is not None and value != ""


def _apply_default_expiry(tokens: OAuthTokens, seconds: int | None) -> OAuthTokens:
    """TS ``applyDefaultAccessTokenExpiry`` — synthesize expiry only when the provider omitted
    ``expires_in`` (so ``getAccessToken`` can still track/refresh)."""
    if tokens.access_token_expires_at is None and seconds:
        tokens.access_token_expires_at = utcnow() + timedelta(seconds=int(seconds))
    return tokens


async def _discover(
    http: httpx.AsyncClient, url: str, headers: dict[str, str] | None
) -> dict[str, Any]:
    """Fetch an OIDC discovery document (``.well-known``). Returns ``{}`` on any failure —
    the caller then falls back to the explicit endpoints (and raises if none resolve),
    mirroring TS ``betterFetch`` whose ``.data`` is null on error."""
    try:
        response = await oauth_fetch(http, "GET", url, headers=headers or None)
    except (OAuthFetchError, httpx.HTTPError):
        logger.error("generic-oauth: discovery fetch failed for %s", url)
        return {}
    if response.status_code != 200:
        logger.error("generic-oauth: discovery returned %s for %s", response.status_code, url)
        return {}
    try:
        return response.json()
    except ValueError:
        return {}


def _decode_id_token(token: str) -> dict[str, Any] | None:
    """Decode (do NOT verify) an OIDC id token — TS ``decodeJwt``."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None


async def _resolve_user_info(
    config: GenericOAuthConfig,
    tokens: OAuthTokens,
    user_info_url: str | None,
    http: httpx.AsyncClient,
) -> dict[str, Any] | None:
    """Port of routes.ts ``getUserInfo``: prefer the id token's claims (decode only), else a
    bearer userinfo fetch. Returns a raw profile dict (``GenericOAuthUserInfo``) or None."""
    if tokens.id_token:
        decoded = _decode_id_token(tokens.id_token)
        if decoded and decoded.get("sub") and decoded.get("email"):
            return {
                "id": decoded["sub"],
                "emailVerified": decoded.get("email_verified"),
                "image": decoded.get("picture"),
                **decoded,
            }
    if not user_info_url:
        return None
    try:
        response = await oauth_fetch(
            http,
            "GET",
            user_info_url,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
    except (OAuthFetchError, httpx.HTTPError):
        return None
    if response.status_code != 200:
        return None
    try:
        profile = response.json()
    except ValueError:
        return None
    if not profile:
        return None
    profile_id = profile.get("id")
    if _is_nonempty_id(profile_id):
        subject: Any = profile_id
    elif _is_nonempty_id(profile.get("sub")):
        subject = profile.get("sub")
    else:
        subject = None
    result = {k: v for k, v in profile.items() if k != "id"}
    if subject is not None:
        result["id"] = subject
    result["email"] = profile.get("email")
    result["emailVerified"] = profile.get("email_verified", False)
    result["image"] = profile.get("picture")
    result["name"] = profile.get("name")
    return result


def _redirect_error(error_url: str, error: str, description: str | None = None) -> AuthResponse:
    """TS ``redirectOnError`` — 302 to ``error_url`` with ``?error=`` (+ ``error_description``),
    picking the ``?``/``&`` separator and URL-encoding in one place."""
    params = {"error": error}
    if description:
        params["error_description"] = description
    sep = "&" if "?" in error_url else "?"
    return AuthResponse(redirect_to=f"{error_url}{sep}{urlencode(params)}")


@dataclass
class _GenericProvider(ProviderConfig):
    """The generic provider registered into ``auth.social_providers`` (spec: ``init()``
    registers configured providers). Carries ``provider_id`` + ``override_user_info_on_sign_in``
    for the shared decision core, and a discovery-aware ``refresh`` for ``/refresh-token``."""

    generic: GenericOAuthConfig | None = None

    async def refresh(self, http: httpx.AsyncClient, refresh_token: str) -> OAuthTokens:
        token_endpoint = self.token_endpoint
        if not token_endpoint and self.generic and self.generic.discovery_url:
            doc = await _discover(http, self.generic.discovery_url, self.generic.discovery_headers)
            token_endpoint = doc.get("token_endpoint", "")
        tokens = await refresh_access_token(
            http,
            token_endpoint=token_endpoint,
            refresh_token=refresh_token,
            client_id=self.client_id,
            client_secret=self.client_secret,
            authentication=self.authentication,
        )
        return _apply_default_expiry(
            tokens, self.generic.access_token_expires_in if self.generic else None
        )


class GenericOAuthPlugin(Plugin):
    id = "generic-oauth"
    error_codes: ClassVar[dict[str, str]] = GENERIC_OAUTH_ERROR_CODES

    def __init__(self, *, config: list[GenericOAuthConfig]) -> None:
        self.config = list(config)
        # Duplicate providerIds warn (console.warn) but do not throw (TS index.ts).
        seen: set[str] = set()
        dupes: set[str] = set()
        for c in self.config:
            if c.provider_id in seen:
                dupes.add(c.provider_id)
            seen.add(c.provider_id)
        if dupes:
            logger.warning("Duplicate provider IDs found: %s", ", ".join(sorted(dupes)))
        self._providers: dict[str, _GenericProvider] = {}

    # --- lifecycle ----------------------------------------------------------------------

    def init(self, auth: Any) -> None:
        for c in self.config:
            provider = _GenericProvider(
                client_id=c.client_id,
                client_secret=c.client_secret or "",
                provider_id=c.provider_id,
                token_endpoint=c.token_url or "",
                userinfo_endpoint=c.user_info_url or "",
                authentication=c.authentication,
                override_user_info_on_sign_in=c.override_user_info,
                disable_sign_up=c.disable_sign_up,
                disable_implicit_sign_up=c.disable_implicit_sign_up,
                generic=c,
            )
            self._providers[c.provider_id] = provider
            # generic providers take precedence on id collision (TS concats them first).
            auth.social_providers[c.provider_id] = provider

    def routes(self) -> list[Route]:
        return [
            ("POST", "/sign-in/oauth2", self._sign_in),
            ("GET", "/oauth2/callback/{providerId}", self._callback),
            ("POST", "/oauth2/callback/{providerId}", self._callback),
            ("POST", "/oauth2/link", self._link),
        ]

    # --- helpers ------------------------------------------------------------------------

    def _find(self, provider_id: str | None) -> GenericOAuthConfig | None:
        if not provider_id:
            return None
        return next((c for c in self.config if c.provider_id == provider_id), None)

    def _callback_uri(self, ctx: Ctx, config: GenericOAuthConfig) -> str:
        # TS: config.redirectURI || `${baseURL}/oauth2/callback/${providerId}` (baseURL includes
        # the base path). Used identically for the authorize URL and the token exchange.
        return (
            config.redirect_uri
            or f"{ctx.auth.base_url}{ctx.auth.base_path}/oauth2/callback/{config.provider_id}"
        )

    def _default_error_url(self, ctx: Ctx) -> str:
        return (
            ctx.auth.on_api_error.error_url
            or f"{ctx.auth.base_url}{ctx.auth.base_path}/error"
        )

    async def _create_state(
        self,
        ctx: Ctx,
        *,
        callback_url: str,
        error_url: str | None,
        new_user_url: str | None,
        request_sign_up: bool | None = None,
        link: dict[str, str] | None = None,
        additional_data: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Write the CSRF state row (verification table) + return ``(state, code_verifier)``.

        Mirrors ``flow._create_state`` but carries ``requestSignUp`` (the reused helper has no
        slot for it — the sign-up decision happens in the callback and must round-trip through
        state). The signed state cookie is built by the shared ``flow._state_cookie``.
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
        if request_sign_up is not None:
            payload["requestSignUp"] = request_sign_up
        if link is not None:
            payload["link"] = link
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

    def _resolve_params(self, ctx: Ctx, params: Any) -> dict[str, str] | None:
        # params is dict | (ctx -> dict) | None (a precise union confuses the type checker's
        # narrowing because dict/callable overlap); Any keeps the call site clean.
        if callable(params):
            return params(ctx)
        return params

    # --- POST /sign-in/oauth2 -----------------------------------------------------------

    async def _sign_in(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        provider_id = body.get("providerId")
        config = self._find(provider_id)
        if config is None:
            raise APIError(
                400,
                "PROVIDER_CONFIG_NOT_FOUND",
                f"{GENERIC_OAUTH_ERROR_CODES['PROVIDER_CONFIG_NOT_FOUND']} {provider_id}",
            )

        final_auth_url = config.authorization_url
        final_token_url = config.token_url
        if config.discovery_url:
            doc = await _discover(ctx.auth.http, config.discovery_url, config.discovery_headers)
            if doc:
                final_auth_url = doc.get("authorization_endpoint")
                final_token_url = doc.get("token_endpoint")
        if not final_auth_url or not final_token_url:
            raise APIError(
                400,
                "INVALID_OAUTH_CONFIGURATION",
                GENERIC_OAUTH_ERROR_CODES["INVALID_OAUTH_CONFIGURATION"],
            )

        callback_url = body.get("callbackURL") or "/"
        state, code_verifier = await self._create_state(
            ctx,
            callback_url=callback_url,
            error_url=body.get("errorCallbackURL"),
            new_user_url=body.get("newUserCallbackURL"),
            request_sign_up=body.get("requestSignUp"),
            additional_data=body.get("additionalData"),
        )

        body_scopes = body.get("scopes")
        scopes = (
            [*body_scopes, *(config.scopes or [])]
            if body_scopes
            else list(config.scopes or [])
        )
        url = build_authorization_url(
            authorization_endpoint=final_auth_url,
            client_id=config.client_id,
            state=state,
            redirect_uri=self._callback_uri(ctx, config),
            scopes=scopes,
            response_type=config.response_type or "code",
            code_verifier=code_verifier if config.pkce else None,
            prompt=config.prompt,
            access_type=config.access_type,
            response_mode=config.response_mode,
            additional_params=self._resolve_params(ctx, config.authorization_url_params) or None,
        )
        response = AuthResponse(
            body={"url": url, "redirect": not bool(body.get("disableRedirect"))}
        )
        response.set_cookie(_state_cookie(ctx, state))
        return response

    # --- GET|POST /oauth2/callback/{providerId} -----------------------------------------

    def _callback_params(self, ctx: Ctx) -> dict[str, str]:
        params = dict(ctx.request.query)
        if ctx.request.method == "POST" and ctx.request.body:
            content_type = ctx.request.headers.get("content-type", "")
            if "application/x-www-form-urlencoded" in content_type:
                params.update(dict(parse_qsl(ctx.request.body.decode())))
        return params

    async def _callback(self, ctx: Ctx) -> AuthResponse:
        default_error_url = self._default_error_url(ctx)
        params = self._callback_params(ctx)

        if params.get("error") or not params.get("code"):
            return _redirect_error(
                default_error_url,
                params.get("error") or "oAuth_code_missing",
                params.get("error_description"),
            )

        provider_id = ctx.params.get("providerId")
        if not provider_id:
            raise APIError(
                400, "PROVIDER_ID_REQUIRED", GENERIC_OAUTH_ERROR_CODES["PROVIDER_ID_REQUIRED"]
            )
        config = self._find(provider_id)
        if config is None:
            raise APIError(
                400,
                "PROVIDER_CONFIG_NOT_FOUND",
                f"{GENERIC_OAUTH_ERROR_CODES['PROVIDER_CONFIG_NOT_FOUND']} {provider_id}",
            )

        # --- consume state (verification row + signed CSRF cookie) ----------------------
        state = params.get("state", "")
        row = (
            await ctx.adapter.find_one("verification", [Where("identifier", state)])
            if state
            else None
        )
        if row is None:
            return _redirect_error(default_error_url, "state_not_found")
        await ctx.adapter.delete_many("verification", [Where("identifier", state)])
        data = json.loads(row["value"])
        resolved_error_url = data.get("errorURL") or data.get("callbackURL") or default_error_url
        if row["expiresAt"] <= utcnow():
            return _redirect_error(resolved_error_url, "state_invalid")
        if not ctx.auth.skip_state_cookie_check:
            raw = ctx.request.cookies().get(cookie_name(ctx.auth, STATE_COOKIE))
            if raw is None or unsign_value(ctx.auth.secret, raw) != state:
                return _redirect_error(resolved_error_url, "state_mismatch")

        callback_url = data.get("callbackURL") or "/"
        code_verifier = data.get("codeVerifier")
        request_sign_up = data.get("requestSignUp")
        new_user_url = data.get("newUserURL")
        link = data.get("link")
        code = params["code"]

        final_token_url = config.token_url
        final_user_info_url = config.user_info_url
        expected_issuer = config.issuer
        if config.discovery_url:
            doc = await _discover(ctx.auth.http, config.discovery_url, config.discovery_headers)
            if doc:
                final_token_url = doc.get("token_endpoint")
                final_user_info_url = doc.get("userinfo_endpoint")
                if not expected_issuer and doc.get("issuer"):
                    expected_issuer = doc["issuer"]

        # --- iss (RFC 9207) -------------------------------------------------------------
        if expected_issuer:
            if params.get("iss"):
                if params["iss"] != expected_issuer:
                    return _redirect_error(resolved_error_url, "issuer_mismatch")
            elif config.require_issuer_validation:
                return _redirect_error(resolved_error_url, "issuer_missing")

        # --- token exchange -------------------------------------------------------------
        tokens = await self._exchange(
            ctx, config, code, code_verifier, final_token_url, resolved_error_url
        )
        if isinstance(tokens, AuthResponse):
            return _with_state_cleared(ctx, tokens)

        provider = self._providers[provider_id]

        # --- resolve profile ------------------------------------------------------------
        info = await self._handle_user_info(
            ctx, config, tokens, final_user_info_url, resolved_error_url
        )
        if isinstance(info, AuthResponse):
            return _with_state_cleared(ctx, info)

        if link is not None:
            return _with_state_cleared(
                ctx,
                await self._callback_link(
                    ctx, config, provider, info, tokens, link, callback_url, resolved_error_url
                ),
            )

        # --- sign-in / register ---------------------------------------------------------
        disable_sign_up = (
            config.disable_implicit_sign_up and not request_sign_up
        ) or config.disable_sign_up
        try:
            user_id, is_register = await handle_oauth_user_info(
                ctx, provider, info, tokens, disable_sign_up=disable_sign_up
            )
            _session, cookies = await create_session(ctx.auth, user_id, ctx.request, ctx=ctx)
        except OAuthLinkError as err:
            return _with_state_cleared(
                ctx, _redirect_error(resolved_error_url, err.code.replace(" ", "_"))
            )
        except APIError as err:
            return _with_state_cleared(
                ctx, _redirect_error(resolved_error_url, err.code, err.message)
            )

        target = (new_user_url or callback_url) if is_register else callback_url
        response = AuthResponse(redirect_to=_absolute_url(ctx, target))
        for cookie in [*cookies, clear_cookie(ctx.auth, STATE_COOKIE)]:
            response.set_cookie(cookie)
        return response

    async def _exchange(
        self,
        ctx: Ctx,
        config: GenericOAuthConfig,
        code: str,
        code_verifier: str | None,
        final_token_url: str | None,
        resolved_error_url: str,
    ) -> OAuthTokens | AuthResponse:
        """Token exchange (custom ``get_token`` or standard code exchange). Any exchange
        failure -> redirect ``oauth_code_verification_failed`` (TS ``catch`` block); a custom
        ``get_token`` returning falsy -> ``INVALID_OAUTH_CONFIG`` (TS ``if (!tokens)``)."""
        redirect_uri = self._callback_uri(ctx, config)
        try:
            if config.get_token is not None:
                raw = await _maybe_await(
                    config.get_token(
                        {
                            "code": code,
                            "redirectURI": redirect_uri,
                            "codeVerifier": code_verifier if config.pkce else None,
                        }
                    )
                )
                tokens = (
                    None
                    if raw is None
                    else (raw if isinstance(raw, OAuthTokens) else get_oauth2_tokens(dict(raw)))
                )
            elif not final_token_url:
                raise OAuthFetchError(GENERIC_OAUTH_ERROR_CODES["INVALID_OAUTH_CONFIG"])
            else:
                tokens = await exchange_code(
                    ctx.auth.http,
                    token_endpoint=final_token_url,
                    code=code,
                    redirect_uri=redirect_uri,
                    client_id=config.client_id,
                    client_secret=config.client_secret or "",
                    code_verifier=code_verifier if config.pkce else None,
                    authentication=config.authentication,
                    headers=config.authorization_headers,
                    additional_params=self._resolve_params(ctx, config.token_url_params),
                )
            if tokens is not None:
                tokens = _apply_default_expiry(tokens, config.access_token_expires_in)
        except (OAuthFetchError, httpx.HTTPError, ValueError):
            logger.error("generic-oauth: token exchange failed for %s", config.provider_id)
            return _redirect_error(resolved_error_url, "oauth_code_verification_failed")
        if tokens is None:
            raise APIError(
                400, "INVALID_OAUTH_CONFIG", GENERIC_OAUTH_ERROR_CODES["INVALID_OAUTH_CONFIG"]
            )
        return tokens

    async def _handle_user_info(
        self,
        ctx: Ctx,
        config: GenericOAuthConfig,
        tokens: OAuthTokens,
        final_user_info_url: str | None,
        resolved_error_url: str,
    ) -> OAuthUserInfo | AuthResponse:
        """Port of routes.ts ``handleUserInfo``: resolve profile, apply ``mapProfileToUser``,
        and derive a stable ``email``/``id``/``name`` (redirect on any missing)."""
        if config.get_user_info is not None:
            raw = await _maybe_await(config.get_user_info(tokens))
        else:
            raw = await _resolve_user_info(config, tokens, final_user_info_url, ctx.auth.http)
        if raw is None:
            return _redirect_error(resolved_error_url, "user_info_is_missing")

        map_user = (
            await _maybe_await(config.map_profile_to_user(raw))
            if config.map_profile_to_user is not None
            else raw
        )
        map_user = map_user or {}

        email = (map_user.get("email") or raw.get("email") or "")
        email = email.lower() if email else ""
        if not email:
            return _redirect_error(resolved_error_url, "email_is_missing")

        if _is_nonempty_id(map_user.get("id")):
            raw_id: Any = map_user.get("id")
        elif _is_nonempty_id(raw.get("id")):
            raw_id = raw.get("id")
        elif _is_nonempty_id(raw.get("sub")):
            raw_id = raw.get("sub")
        else:
            raw_id = None
        account_id = str(raw_id) if raw_id is not None else ""
        if not account_id:
            return _redirect_error(resolved_error_url, "id_is_missing")

        name = map_user.get("name") or raw.get("name")
        if not name:
            return _redirect_error(resolved_error_url, "name_is_missing")

        merged = {**raw, **map_user, "email": email, "id": account_id, "name": name}
        return OAuthUserInfo(
            id=account_id,
            email=email,
            name=name,
            image=merged.get("image"),
            email_verified=bool(merged.get("emailVerified")),
            raw=merged,
        )

    async def _callback_link(
        self,
        ctx: Ctx,
        config: GenericOAuthConfig,
        provider: _GenericProvider,
        info: OAuthUserInfo,
        tokens: OAuthTokens,
        link: dict[str, str],
        callback_url: str,
        resolved_error_url: str,
    ) -> AuthResponse:
        """State-carried ``link`` branch (routes.ts): attach the provider account to the
        already signed-in user, updating tokens if already linked. No new session."""
        linking = ctx.auth.account.account_linking
        if not linking.allow_different_emails and (link.get("email") or "").lower() != (
            info.email or ""
        ).lower():
            return _redirect_error(resolved_error_url, "email_doesn't_match")

        now = utcnow()
        existing = await ctx.adapter.find_one(
            "account",
            [Where("providerId", config.provider_id), Where("accountId", info.id)],
        )
        if existing is not None:
            if existing["userId"] != link["userId"]:
                return _redirect_error(
                    resolved_error_url, "account_already_linked_to_different_user"
                )
            update = {
                k: v for k, v in _token_fields(ctx, tokens).items() if v is not None
            }
            await ctx.internal.update(
                "account", [Where("id", existing["id"])], {**update, "updatedAt": now}, ctx=ctx
            )
        else:
            await _create_account(
                ctx, provider, info, _token_fields(ctx, tokens), link["userId"], now
            )

        if linking.update_user_info_on_link:
            user = await ctx.adapter.find_one("user", [Where("id", link["userId"])])
            if user is not None:
                await _apply_update_user_info_on_link(ctx, user, info, now)

        return AuthResponse(redirect_to=_absolute_url(ctx, callback_url))

    # --- POST /oauth2/link --------------------------------------------------------------

    async def _link(self, ctx: Ctx) -> AuthResponse:
        session = await ctx.get_session()
        if session is None:
            raise APIError(401, "SESSION_REQUIRED", GENERIC_OAUTH_ERROR_CODES["SESSION_REQUIRED"])
        body = ctx.body()
        config = self._find(body.get("providerId"))
        if config is None:
            raise APIError(404, "PROVIDER_NOT_FOUND", "Provider not found")

        final_auth_url = config.authorization_url
        if not final_auth_url:
            if not config.discovery_url:
                raise APIError(
                    400,
                    "INVALID_OAUTH_CONFIGURATION",
                    GENERIC_OAUTH_ERROR_CODES["INVALID_OAUTH_CONFIGURATION"],
                )
            doc = await _discover(ctx.auth.http, config.discovery_url, config.discovery_headers)
            if doc:
                final_auth_url = doc.get("authorization_endpoint")
        if not final_auth_url:
            raise APIError(
                400,
                "INVALID_OAUTH_CONFIGURATION",
                GENERIC_OAUTH_ERROR_CODES["INVALID_OAUTH_CONFIGURATION"],
            )

        session_user = session["user"]
        state, code_verifier = await self._create_state(
            ctx,
            callback_url=body["callbackURL"],
            error_url=body.get("errorCallbackURL"),
            new_user_url=None,
            link={"userId": session_user["id"], "email": session_user["email"]},
        )
        scopes = body.get("scopes") or config.scopes or []
        url = build_authorization_url(
            authorization_endpoint=final_auth_url,
            client_id=config.client_id,
            state=state,
            redirect_uri=self._callback_uri(ctx, config),
            scopes=scopes,
            code_verifier=code_verifier if config.pkce else None,
            prompt=config.prompt,
            access_type=config.access_type,
            additional_params=self._resolve_params(ctx, config.authorization_url_params) or None,
        )
        response = AuthResponse(body={"url": url, "redirect": True})
        response.set_cookie(_state_cookie(ctx, state))
        return response


def _with_state_cleared(ctx: Ctx, response: AuthResponse) -> AuthResponse:
    """Attach the state-cookie clear to any error redirect out of the callback."""
    response.set_cookie(clear_cookie(ctx.auth, STATE_COOKIE))
    return response


# --- provider presets (config-shape helpers) ---------------------------------------------
# ponytail: only the pure config-shape presets (discovery-based) are ported. The presets with
# a bespoke userinfo mapper (slack/line/hubspot/microsoft-entra-id/yandex/gumroad/patreon) are
# deferred — pass a raw GenericOAuthConfig with `get_user_info=`/`map_profile_to_user=` for those.


def _oidc_discovery_scopes() -> list[str]:
    return ["openid", "profile", "email"]


def okta(
    *,
    client_id: str,
    client_secret: str,
    issuer: str,
    scopes: list[str] | None = None,
    redirect_uri: str | None = None,
    pkce: bool = False,
    disable_implicit_sign_up: bool = False,
    disable_sign_up: bool = False,
    override_user_info: bool = False,
) -> GenericOAuthConfig:
    """Okta preset (TS ``okta``). ``issuer`` e.g. ``https://dev-xxx.okta.com/oauth2/default``."""
    issuer = issuer.rstrip("/")
    return GenericOAuthConfig(
        provider_id="okta",
        discovery_url=f"{issuer}/.well-known/openid-configuration",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes if scopes is not None else _oidc_discovery_scopes(),
        redirect_uri=redirect_uri,
        pkce=pkce,
        disable_implicit_sign_up=disable_implicit_sign_up,
        disable_sign_up=disable_sign_up,
        override_user_info=override_user_info,
    )


def auth0(
    *,
    client_id: str,
    client_secret: str,
    domain: str,
    scopes: list[str] | None = None,
    redirect_uri: str | None = None,
    pkce: bool = False,
    disable_implicit_sign_up: bool = False,
    disable_sign_up: bool = False,
    override_user_info: bool = False,
) -> GenericOAuthConfig:
    """Auth0 preset (TS ``auth0``). ``domain`` e.g. ``dev-xxx.eu.auth0.com`` (protocol stripped)."""
    import re

    domain = re.sub(r"^https?://", "", domain)
    return GenericOAuthConfig(
        provider_id="auth0",
        discovery_url=f"https://{domain}/.well-known/openid-configuration",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes if scopes is not None else _oidc_discovery_scopes(),
        redirect_uri=redirect_uri,
        pkce=pkce,
        disable_implicit_sign_up=disable_implicit_sign_up,
        disable_sign_up=disable_sign_up,
        override_user_info=override_user_info,
    )


def keycloak(
    *,
    client_id: str,
    client_secret: str,
    issuer: str,
    scopes: list[str] | None = None,
    redirect_uri: str | None = None,
    pkce: bool = False,
    disable_implicit_sign_up: bool = False,
    disable_sign_up: bool = False,
    override_user_info: bool = False,
) -> GenericOAuthConfig:
    """Keycloak preset (TS ``keycloak``). ``issuer`` e.g. ``https://host/realms/MyRealm``."""
    issuer = issuer.rstrip("/")
    return GenericOAuthConfig(
        provider_id="keycloak",
        discovery_url=f"{issuer}/.well-known/openid-configuration",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes if scopes is not None else _oidc_discovery_scopes(),
        redirect_uri=redirect_uri,
        pkce=pkce,
        disable_implicit_sign_up=disable_implicit_sign_up,
        disable_sign_up=disable_sign_up,
        override_user_info=override_user_info,
    )
