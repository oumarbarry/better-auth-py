"""generic-oauth plugin: any OAuth 2.0 / OIDC provider as a first-class social provider.

Port of better-auth v1.7.6 ``packages/better-auth/src/plugins/generic-oauth`` (the
c7d22539e rewrite and its follow-ups). Each configured provider is registered into
``auth.social_providers`` and runs through the core routes: ``POST /sign-in/social``
(``{"provider": "<providerId>"}``), ``GET|POST /callback/<providerId>`` and
``POST /link-social``. The plugin mounts no route of its own unless ``legacy_routes=True``
keeps the pre-1.7 ``/sign-in/oauth2``, ``/oauth2/callback/<id>`` and ``/oauth2/link``
paths working as thin aliases.

Per provider (TS index.ts:204-507):

- OIDC discovery (``discovery_url``) fills the endpoints, the RFC 9207 issuer and, when
  the document publishes ``jwks_uri``, id-token verification bound to a redirect nonce.
  A provider whose discovery leaves no usable endpoint is skipped (5fe5bc21d);
- PKCE is on by default (``pkce=True``); ``openid`` is added for OIDC providers;
- the account id comes from ``account_subject`` or the profile's ``sub`` (OIDC) / ``id``
  (plain OAuth). ``map_profile_to_user`` only maps local user fields, never the identity;
- token requests honor ``authentication`` / ``token_endpoint_auth`` (private_key_jwt,
  custom), ``token_url_params`` and, on refresh, ``refresh_token_params``;
- ``end_session_endpoint`` builds the RP-initiated logout URL (430c89549).

``ponytail`` notes:
- TS runs discovery once in ``init``; Python's ``init`` is synchronous, so discovery runs
  on the provider's first use and is cached once it succeeds (a failure is retried on the
  next request, the provider answering "not found" meanwhile, as TS does at startup).
"""

from __future__ import annotations

import inspect
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx
import jwt

from ..oauth.flow import link_social, oauth_callback, sign_in_social
from ..oauth.machinery import (
    OAuthFetchError,
    TokenEndpointAuth,
    create_placeholder_email,
    exchange_code,
    get_oauth2_tokens,
    oauth_fetch,
    refresh_access_token,
)
from ..oauth.models import OAuthTokens, OAuthUserInfo
from ..oauth.providers import ProviderConfig, is_valid_account_subject
from ..oauth.verify import verify_id_token
from ..plugins import Plugin, Route
from ..session import utcnow
from ..types import APIError, AuthResponse, Ctx

logger = logging.getLogger("better_auth")

# Exact TS strings (packages/better-auth/src/plugins/generic-oauth/error-codes.ts).
GENERIC_OAUTH_ERROR_CODES: dict[str, str] = {
    "INVALID_OAUTH_CONFIGURATION": "Invalid OAuth configuration",
    "TOKEN_URL_NOT_FOUND": "Invalid OAuth configuration. Token URL not found.",
}

_SECRETLESS_METHODS = ("private_key_jwt", "none")
_SECRET_METHODS = ("client_secret_basic", "client_secret_post")


@dataclass
class GenericOAuthConfig:
    """One provider configuration (TS v1.7.6 generic-oauth/types.ts ``GenericOAuthConfig``).

    ``discovery_url`` or explicit ``authorization_url`` + ``token_url`` (or ``get_token``)
    must resolve the endpoints. Deprecated, kept for 1.x configs: ``issuer`` (used as the
    RFC 9207 issuer when discovery provides none) and ``require_issuer_validation``
    (refuses a callback without ``iss`` with ``issuer_missing``). Callable
    ``authorization_url_params`` / ``token_url_params`` are no longer supported (TS only
    accepts a dict since c7d22539e).
    """

    provider_id: str
    client_id: str
    client_secret: str = ""
    #: display name (TS ``name``, defaults to the provider id)
    name: str | None = None
    #: ``({"tokens", "profile"}) -> str | int`` (may be async): the stable subject
    account_subject: Callable[..., Any] | None = None
    discovery_url: str | None = None
    #: skip the provider unless discovery yields an issuer and a JWKS
    require_id_token_verification: bool = False
    authorization_url: str | None = None
    token_url: str | None = None
    user_info_url: str | None = None
    end_session_endpoint: str | None = None
    post_logout_redirect_uri: str | None = None
    disable_provider_logout: bool = False
    token_endpoint_auth: TokenEndpointAuth | None = None
    scopes: list[str] = field(default_factory=list)
    redirect_uri: str | None = None
    response_type: str = "code"
    response_mode: str | None = None
    prompt: str | None = None
    #: OAuth 2.1 default (TS ``pkce ?? true``); set False for providers that reject PKCE
    pkce: bool = True
    access_type: str | None = None
    access_token_expires_in: int | None = None
    #: custom code exchange: ``({"code", "redirectURI", "codeVerifier", "deviceId"}) ->
    #: OAuthTokens | token-endpoint dict`` (may be async)
    get_token: Callable[..., Any] | None = None
    #: custom profile fetch: ``(tokens) -> dict | None`` (may be async)
    get_user_info: Callable[..., Any] | None = None
    #: ``(profile) -> dict`` of local user fields (may be async); never the account id
    map_profile_to_user: Callable[..., Any] | None = None
    authorization_url_params: dict[str, str] | None = None
    token_url_params: dict[str, str] | None = None
    #: extra refresh body params, or ``(ctx) -> dict`` resolved per refresh (3d04fabab)
    refresh_token_params: dict[str, str] | Callable[..., Any] | None = None
    disable_implicit_sign_up: bool = False
    disable_sign_up: bool = False
    #: token-endpoint client auth: "post" (body) or "basic" (Authorization header)
    authentication: str = "post"
    discovery_headers: dict[str, str] | None = None
    authorization_headers: dict[str, str] | None = None
    override_user_info: bool = False
    require_email_verification: bool = False
    #: accept stateless IdP-initiated callbacks by restarting the flow (03e6c94e9)
    allow_idp_initiated: bool = False
    disable_id_token_nonce_binding: bool = False
    #: deprecated: RFC 9207 issuer when discovery provides none
    issuer: str | None = None
    #: deprecated: refuse a callback without ``iss`` once an issuer is known
    require_issuer_validation: bool = False


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _apply_default_expiry(tokens: OAuthTokens, seconds: int | None) -> OAuthTokens:
    """TS ``applyDefaultAccessTokenExpiry``: synthesize expiry only when the provider
    omitted ``expires_in`` (so ``getAccessToken`` can still track and refresh)."""
    if tokens.access_token_expires_at is None and seconds:
        tokens.access_token_expires_at = utcnow() + timedelta(seconds=int(seconds))
    return tokens


async def _fetch_discovery(
    http: httpx.AsyncClient, url: str, headers: dict[str, str] | None
) -> dict[str, Any] | None:
    """TS index.ts:89-109 ``fetchDiscovery``: None on any failure or a non-URL issuer."""
    try:
        response = await oauth_fetch(http, "GET", url, headers=headers or None)
        doc = response.json() if response.status_code == 200 else None
    except (OAuthFetchError, httpx.HTTPError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    issuer = doc.get("issuer")
    if issuer and not urlsplit(str(issuer)).scheme:
        return None
    return doc


def _decode_id_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None


async def _fetch_user_info(
    tokens: OAuthTokens, user_info_url: str | None, http: httpx.AsyncClient
) -> dict[str, Any] | None:
    """TS index.ts:111-169 ``fetchUserInfo``: the id token's claims when they carry ``sub``
    and ``email`` (decoded only; a discovery JWKS has already verified it), else a bearer
    userinfo fetch."""
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
            http, "GET", user_info_url, headers={"authorization": f"Bearer {tokens.access_token}"}
        )
        data = response.json() if response.status_code == 200 else None
    except (OAuthFetchError, httpx.HTTPError, ValueError):
        return None
    if not isinstance(data, dict) or not data:
        return None
    return {
        **data,
        "email": data.get("email"),
        "emailVerified": data.get("email_verified", False),
        "image": data.get("picture"),
        "name": data.get("name"),
    }


def _set_query(url: str, params: dict[str, str]) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    return urlunsplit(parts._replace(query=urlencode(query)))


@dataclass
class _GenericProvider(ProviderConfig):
    """A generic-oauth provider registered into ``auth.social_providers``."""

    generic: GenericOAuthConfig | None = None
    #: ``{baseURL}{basePath}`` of the auth instance, for relative post-logout URIs
    auth_base: Callable[[], str] | None = None
    _ready: bool = field(default=False, repr=False)
    _is_oidc: bool = field(default=False, repr=False)
    _jwks_uri: str | None = field(default=None, repr=False)
    _id_token_issuer: str | None = field(default=None, repr=False)
    _id_token_algorithms: list[str] | None = field(default=None, repr=False)
    _end_session_endpoint: str | None = field(default=None, repr=False)

    @property
    def config(self) -> GenericOAuthConfig:
        assert self.generic is not None
        return self.generic

    @property
    def require_issuer(self) -> bool:
        return self.config.require_issuer_validation

    async def ensure_ready(self, http: httpx.AsyncClient) -> bool:
        """Resolve discovery once (TS index.ts:214-268). False while unusable."""
        if self._ready:
            return True
        c = self.config
        authorization = c.authorization_url
        token = c.token_url
        userinfo = c.user_info_url
        end_session = c.end_session_endpoint
        issuer = c.issuer
        is_oidc = False
        jwks_uri: str | None = None
        algorithms: list[str] | None = None
        if c.discovery_url:
            doc = await _fetch_discovery(http, c.discovery_url, c.discovery_headers)
            if doc is None:
                logger.error('Discovery fetch failed for "%s"', c.provider_id)
            else:
                authorization = authorization or doc.get("authorization_endpoint")
                token = token or doc.get("token_endpoint")
                userinfo = userinfo or doc.get("userinfo_endpoint")
                end_session = end_session or doc.get("end_session_endpoint")
                issuer = doc.get("issuer") or None
                signing = doc.get("id_token_signing_alg_values_supported")
                is_oidc = isinstance(signing, list) and len(signing) > 0
                if doc.get("jwks_uri") and doc.get("issuer"):
                    jwks_uri = urljoin(c.discovery_url, str(doc["jwks_uri"]))
                    if urlsplit(jwks_uri).scheme not in ("http", "https"):
                        logger.error(
                            'Provider "%s": invalid jwks_uri "%s" in discovery document. '
                            "Provider skipped.",
                            c.provider_id,
                            doc["jwks_uri"],
                        )
                        return False
                    algorithms = signing if is_oidc else None
            if not authorization or (not token and not c.get_token):
                logger.error(
                    'Provider "%s": discovery left no usable authorization endpoint or token '
                    "exchange. Provider skipped.",
                    c.provider_id,
                )
                return False
            if c.require_id_token_verification and not jwks_uri:
                logger.error(
                    'Provider "%s": requires verified ID tokens, but discovery did not provide '
                    "a usable issuer and jwks_uri. Provider skipped.",
                    c.provider_id,
                )
                return False
        self.authorization_endpoint = authorization or ""
        self.token_endpoint = token or ""
        self.userinfo_endpoint = userinfo or ""
        self._end_session_endpoint = end_session
        self.issuer = issuer
        self._is_oidc = is_oidc
        self._jwks_uri = jwks_uri
        self._id_token_issuer = issuer if jwks_uri else None
        self._id_token_algorithms = algorithms
        self.requires_id_token_nonce = bool(jwks_uri) and not c.disable_id_token_nonce_binding
        self._ready = True
        return True

    # --- authorize / exchange / refresh ----------------------------------------------------

    def authorization_url(
        self,
        *,
        state: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        extra_scopes: list[str] | None = None,
        login_hint: str | None = None,
        nonce: str | None = None,
        additional_params: dict[str, str] | None = None,
    ) -> str:
        """TS index.ts:359-395."""
        from ..oauth.machinery import build_authorization_url

        c = self.config
        if not self.authorization_endpoint:
            raise APIError(
                400,
                "INVALID_OAUTH_CONFIGURATION",
                GENERIC_OAUTH_ERROR_CODES["INVALID_OAUTH_CONFIGURATION"],
            )
        scopes = [*(extra_scopes or []), *(c.scopes or [])]
        if self._is_oidc and "openid" not in scopes:
            scopes.insert(0, "openid")
        return build_authorization_url(
            authorization_endpoint=self.authorization_endpoint,
            client_id=c.client_id,
            state=state,
            redirect_uri=c.redirect_uri or redirect_uri,
            scopes=scopes,
            response_type=c.response_type or "code",
            code_verifier=code_verifier if c.pkce else None,
            prompt=c.prompt,
            access_type=c.access_type,
            response_mode=c.response_mode,
            nonce=nonce,
            login_hint=login_hint,
            additional_params={**(c.authorization_url_params or {}), **(additional_params or {})},
        )

    async def exchange(
        self,
        http: httpx.AsyncClient,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> OAuthTokens:
        """TS index.ts:396-428."""
        c = self.config
        if c.get_token is not None:
            get_token: Any = c.get_token
            raw = await _maybe_await(
                get_token(
                    {
                        "code": code,
                        "redirectURI": redirect_uri,
                        "codeVerifier": code_verifier,
                        "deviceId": None,
                    }
                )
            )
            if raw is None:
                raise OAuthFetchError("getToken returned no tokens")
            tokens = raw if isinstance(raw, OAuthTokens) else get_oauth2_tokens(dict(raw))
            return _apply_default_expiry(tokens, c.access_token_expires_in)
        if not self.token_endpoint:
            raise APIError(
                400, "TOKEN_URL_NOT_FOUND", GENERIC_OAUTH_ERROR_CODES["TOKEN_URL_NOT_FOUND"]
            )
        tokens = await exchange_code(
            http,
            token_endpoint=self.token_endpoint,
            code=code,
            redirect_uri=c.redirect_uri or redirect_uri,
            client_id=c.client_id,
            client_secret=c.client_secret or "",
            code_verifier=code_verifier if c.pkce else None,
            authentication=c.authentication,
            token_endpoint_auth=c.token_endpoint_auth,
            headers=c.authorization_headers,
            additional_params=c.token_url_params,
        )
        return _apply_default_expiry(tokens, c.access_token_expires_in)

    async def refresh(
        self, http: httpx.AsyncClient, refresh_token: str, ctx: Ctx | None = None
    ) -> OAuthTokens:
        """TS index.ts:470-499: ``refresh_token_params`` (a dict, or a callable resolved
        with the request ``ctx``) join the body; ``grant_type``/``refresh_token`` stay."""
        c = self.config
        await self.ensure_ready(http)
        if not self.token_endpoint:
            raise OAuthFetchError(GENERIC_OAUTH_ERROR_CODES["TOKEN_URL_NOT_FOUND"])
        params: Any = c.refresh_token_params
        if callable(params):
            params = await _maybe_await(params(ctx))
        tokens = await refresh_access_token(
            http,
            token_endpoint=self.token_endpoint,
            refresh_token=refresh_token,
            client_id=c.client_id,
            client_secret=c.client_secret or "",
            authentication=c.authentication,
            token_endpoint_auth=c.token_endpoint_auth,
            extra_params=params or None,
        )
        return _apply_default_expiry(tokens, c.access_token_expires_in)

    # --- profile ----------------------------------------------------------------------------

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        """TS index.ts:429-469 plus the account key (``accountSubject``, index.ts:304-314):
        a discovery-verified id token is required when present; ``map_profile_to_user``
        maps local fields only. No profile (TS ``null``) raises :class:`OAuthFetchError`;
        an unusable subject yields an empty id. The callback answers both with
        ``unable_to_get_user_info``."""
        c = self.config
        if tokens.id_token and self._jwks_uri:
            claims = await verify_id_token(
                http,
                tokens.id_token,
                jwks_uri=self._jwks_uri,
                audience=c.client_id,
                issuers=[self._id_token_issuer] if self._id_token_issuer else [],
                nonce=tokens.expected_id_token_nonce,
                algorithms=self._id_token_algorithms,
            )
            if claims is None:
                logger.error(
                    'Provider "%s": id_token failed verification against the discovery JWKS '
                    "or expected nonce",
                    c.provider_id,
                )
                raise OAuthFetchError("id_token verification failed")
        getter: Any = c.get_user_info
        if isinstance(getter, _PresetUserInfo):
            raw = await getter.fetch(tokens, http)
        elif getter is not None:
            raw = await _maybe_await(getter(tokens))
        else:
            raw = await _fetch_user_info(tokens, self.userinfo_endpoint or None, http)
        if not raw:
            raise OAuthFetchError("no user info")
        mapper: Any = c.map_profile_to_user
        mapped = await _maybe_await(mapper(raw)) if mapper else None
        user = {
            "email": raw.get("email"),
            "emailVerified": raw.get("emailVerified"),
            "image": raw.get("image"),
            "name": raw.get("name"),
            **(mapped or {}),
        }
        try:
            resolver: Any = c.account_subject
            if resolver is not None:
                subject = await _maybe_await(resolver({"tokens": tokens, "profile": raw}))
            else:
                subject = raw.get("sub") if self._is_oidc else raw.get("id")
        except Exception:
            logger.exception('Provider "%s": accountSubject failed', c.provider_id)
            subject = None
        return OAuthUserInfo(
            id=str(subject) if is_valid_account_subject(subject) else "",
            email=user.get("email"),
            name=user.get("name") or "",
            image=user.get("image"),
            email_verified=bool(user.get("emailVerified")),
            raw=raw,
        )

    # --- client-submitted id_token (ec8a38c08) ---------------------------------------------

    @property
    def supports_id_token(self) -> bool:
        """TS ``supportsIdTokenSignIn``: only a discovery-published JWKS enables it."""
        return bool(self._jwks_uri)

    async def verify_id_token(
        self,
        http: httpx.AsyncClient,
        token: str,
        nonce: str | None = None,
        ctx: Ctx | None = None,
    ) -> dict[str, Any] | None:
        if not self._jwks_uri:
            return None
        return await verify_id_token(
            http,
            token,
            jwks_uri=self._jwks_uri,
            audience=self.config.client_id,
            issuers=[self._id_token_issuer] if self._id_token_issuer else [],
            nonce=nonce,
            algorithms=self._id_token_algorithms,
        )

    async def id_token_user_info(
        self, tokens: OAuthTokens, http: httpx.AsyncClient
    ) -> OAuthUserInfo:
        """The id-token sign-in profile goes through ``getUserInfo`` as in TS sign-in.ts:296-310
        (``get_user_info`` / claims, ``map_profile_to_user``, ``account_subject``)."""
        return await self.fetch_user(tokens, http)

    # --- RP-initiated logout (430c89549) ---------------------------------------------------

    async def create_end_session_url(
        self,
        *,
        id_token: str | None = None,
        post_logout_redirect_uri: str | None = None,
        state: str | None = None,
    ) -> str | None:
        """TS index.ts:320-358."""
        c = self.config
        if c.disable_provider_logout or not self._end_session_endpoint:
            return None
        if not urlsplit(self._end_session_endpoint).scheme:
            return None
        params: dict[str, str] = {}
        if id_token:
            params["id_token_hint"] = id_token
        configured = post_logout_redirect_uri or c.post_logout_redirect_uri
        if configured:
            base = self.auth_base() if self.auth_base else ""
            params["post_logout_redirect_uri"] = urljoin(base, configured)
            params["client_id"] = c.client_id
            if state:
                params["state"] = state
        elif not id_token:
            params["client_id"] = c.client_id
        return _set_query(self._end_session_endpoint, params)


class GenericOAuthPlugin(Plugin):
    """TS ``genericOAuth({config})``. ``legacy_routes=True`` keeps the pre-1.7 plugin routes
    (``/sign-in/oauth2``, ``/oauth2/callback/<id>``, ``/oauth2/link``) as aliases of the core
    routes and makes ``/oauth2/callback/<id>`` the default redirect URI again."""

    id = "generic-oauth"
    error_codes: ClassVar[dict[str, str]] = GENERIC_OAUTH_ERROR_CODES

    def __init__(self, *, config: list[GenericOAuthConfig], legacy_routes: bool = False) -> None:
        self.config = list(config)
        self.legacy_routes = legacy_routes
        # Duplicate providerIds warn (console.warn) but do not throw (TS index.ts:184-196).
        seen: set[str] = set()
        dupes: set[str] = set()
        for c in self.config:
            if c.provider_id in seen:
                dupes.add(c.provider_id)
            seen.add(c.provider_id)
        if dupes:
            logger.warning("Duplicate provider IDs found: %s", ", ".join(sorted(dupes)))

    # --- lifecycle ----------------------------------------------------------------------

    def init(self, auth: Any) -> None:
        for c in self.config:
            if c.require_id_token_verification and not c.discovery_url:
                raise ValueError(
                    f'Provider "{c.provider_id}": requires verified ID tokens, but discovery '
                    "did not provide a usable issuer and jwks_uri."
                )
            method = c.token_endpoint_auth.method if c.token_endpoint_auth else None
            if c.client_secret and method in _SECRETLESS_METHODS:
                raise ValueError(
                    f'Provider "{c.provider_id}": tokenEndpointAuth.method "{method}" cannot be '
                    "combined with clientSecret"
                )
            if not c.client_secret and method in _SECRET_METHODS:
                raise ValueError(
                    f'Provider "{c.provider_id}": tokenEndpointAuth.method "{method}" requires '
                    "clientSecret"
                )
            if not c.client_secret and method is None and c.authentication == "basic":
                raise ValueError(
                    f'Provider "{c.provider_id}": authentication "basic" requires clientSecret'
                )
            if c.provider_id in auth.social_providers:
                logger.warning(
                    'Generic OAuth provider "%s" shadows a built-in social provider with the '
                    "same ID",
                    c.provider_id,
                )
            provider = _GenericProvider(
                client_id=c.client_id,
                client_secret=c.client_secret or "",
                provider_id=c.provider_id,
                redirect_uri=c.redirect_uri,
                authorization_endpoint=c.authorization_url or "",
                token_endpoint=c.token_url or "",
                userinfo_endpoint=c.user_info_url or "",
                authentication=c.authentication,
                token_endpoint_auth=c.token_endpoint_auth,
                override_user_info_on_sign_in=c.override_user_info,
                disable_sign_up=c.disable_sign_up,
                disable_implicit_sign_up=c.disable_implicit_sign_up,
                require_email_verification=c.require_email_verification,
                allow_idp_initiated=c.allow_idp_initiated,
                issuer=c.issuer,
                generic=c,
                auth_base=lambda: f"{auth.base_url}{auth.base_path}",
            )
            if self.legacy_routes:
                provider.callback_path = f"/oauth2/callback/{c.provider_id}"
            # generic providers take precedence on id collision (TS concats them first).
            auth.social_providers[c.provider_id] = provider

    def routes(self) -> list[Route]:
        if not self.legacy_routes:
            return []
        return [
            ("POST", "/sign-in/oauth2", self._legacy_sign_in),
            ("GET", "/oauth2/callback/{providerId}", self._legacy_callback),
            ("POST", "/oauth2/callback/{providerId}", self._legacy_callback),
            ("POST", "/oauth2/link", self._legacy_link),
        ]

    # --- legacy aliases (pre-1.7 routes) --------------------------------------------------

    async def _legacy_sign_in(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        ctx._body = {**body, "provider": body.get("providerId")}
        return await sign_in_social(ctx)

    async def _legacy_callback(self, ctx: Ctx) -> AuthResponse:
        ctx.params = {**ctx.params, "provider": ctx.params.get("providerId", "")}
        return await oauth_callback(ctx)

    async def _legacy_link(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        ctx._body = {**body, "provider": body.get("providerId")}
        return await link_social(ctx)


# --- provider presets (TS v1.7.6 generic-oauth/providers) ---------------------------------


def _preset(
    provider_id: str,
    options: dict[str, Any],
    default_scopes: list[str],
    **fixed: Any,
) -> GenericOAuthConfig:
    """Shared ``BaseOAuthProviderOptions`` pass-through (TS index.ts:45-59)."""
    scopes = options.pop("scopes", None)
    return GenericOAuthConfig(
        provider_id=provider_id,
        scopes=list(default_scopes) if scopes is None else scopes,
        **fixed,
        **options,
    )


def _base_options(
    *,
    client_id: str,
    client_secret: str = "",
    token_endpoint_auth: TokenEndpointAuth | None = None,
    scopes: list[str] | None = None,
    redirect_uri: str | None = None,
    end_session_endpoint: str | None = None,
    post_logout_redirect_uri: str | None = None,
    disable_provider_logout: bool = False,
    pkce: bool = True,
    disable_implicit_sign_up: bool = False,
    disable_sign_up: bool = False,
    override_user_info: bool = False,
) -> dict[str, Any]:
    return {k: v for k, v in locals().items()}


def okta(*, issuer: str, **options: Any) -> GenericOAuthConfig:
    """Okta (TS providers/okta.ts). ``issuer`` e.g. ``https://dev-x.okta.com/oauth2/default``."""
    return _preset(
        "okta",
        _base_options(**options),
        ["openid", "profile", "email"],
        discovery_url=f"{issuer.rstrip('/')}/.well-known/openid-configuration",
    )


def auth0(*, domain: str, **options: Any) -> GenericOAuthConfig:
    """Auth0 (TS providers/auth0.ts). ``domain`` may carry a scheme or path; only the host
    is kept (c47b76517)."""
    domain_url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    host = urlsplit(domain_url).netloc
    return _preset(
        "auth0",
        _base_options(**options),
        ["openid", "profile", "email"],
        discovery_url=f"https://{host}/.well-known/openid-configuration",
    )


def keycloak(*, issuer: str, **options: Any) -> GenericOAuthConfig:
    """Keycloak (TS providers/keycloak.ts). ``issuer`` e.g. ``https://host/realms/MyRealm``."""
    return _preset(
        "keycloak",
        _base_options(**options),
        ["openid", "profile", "email"],
        discovery_url=f"{issuer.rstrip('/')}/.well-known/openid-configuration",
    )


class _PresetUserInfo:
    """A preset ``get_user_info``: GET ``url`` with the auth's HTTP client and map the JSON
    (None on failure). Callable with the tokens alone (TS ``getUserInfo(tokens)``), or
    through :meth:`fetch` with the client, which is how the provider calls it."""

    def __init__(
        self,
        url: str | Callable[[OAuthTokens], str],
        headers: Callable[[OAuthTokens], dict[str, str]],
        parse: Callable[[Any], dict[str, Any] | None],
        resolve: Callable[..., Any] | None = None,
    ) -> None:
        self.url = url
        self.headers = headers
        self.parse = parse
        #: ``(tokens, http, get_json) -> profile`` for presets with extra logic
        self.resolve = resolve

    async def get_json(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> Any:
        url: Any = self.url
        target = url(tokens) if callable(url) else url
        try:
            response = await oauth_fetch(http, "GET", target, headers=self.headers(tokens))
            return response.json() if response.status_code == 200 else None
        except (OAuthFetchError, httpx.HTTPError, ValueError):
            return None

    async def fetch(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> dict[str, Any] | None:
        if self.resolve is not None:
            return await self.resolve(tokens, http, self)
        data = await self.get_json(tokens, http)
        return self.parse(data) if data else None

    async def __call__(self, tokens: OAuthTokens) -> dict[str, Any] | None:
        async with httpx.AsyncClient(timeout=10) as http:
            return await self.fetch(tokens, http)


def _bearer(tokens: OAuthTokens) -> dict[str, str]:
    return {"authorization": f"Bearer {tokens.access_token}"}


def _profile_id(context: dict[str, Any]) -> Any:
    return context["profile"].get("id") or ""


def _profile_sub(context: dict[str, Any]) -> Any:
    return context["profile"].get("sub") or ""


def slack(**options: Any) -> GenericOAuthConfig:
    """Slack OpenID Connect (TS providers/slack.ts)."""

    def parse(p: dict[str, Any]) -> dict[str, Any]:
        return {
            "sub": p.get("sub"),
            "name": p.get("name"),
            "email": p.get("email"),
            "image": p.get("picture") or p.get("https://slack.com/user_image_512"),
            "emailVerified": p.get("email_verified") or False,
        }

    return _preset(
        "slack",
        _base_options(**options),
        ["openid", "profile", "email"],
        account_subject=_profile_sub,
        authorization_url="https://slack.com/openid/connect/authorize",
        token_url="https://slack.com/api/openid.connect.token",
        user_info_url="https://slack.com/api/openid.connect.userInfo",
        get_user_info=_PresetUserInfo(
            "https://slack.com/api/openid.connect.userInfo", _bearer, parse
        ),
    )


def line(*, provider_id: str = "line", **options: Any) -> GenericOAuthConfig:
    """LINE (TS providers/line.ts): id token claims, else the userinfo endpoint."""
    userinfo = "https://api.line.me/oauth2/v2.1/userinfo"

    def parse(p: dict[str, Any]) -> dict[str, Any]:
        return {
            "sub": p.get("sub"),
            "name": p.get("name"),
            "email": p.get("email"),
            "image": p.get("picture"),
            "emailVerified": False,
        }

    async def resolve(tokens: OAuthTokens, http: httpx.AsyncClient, preset: _PresetUserInfo):
        profile = _decode_id_token(tokens.id_token) if tokens.id_token else None
        if profile:
            return parse(profile)
        data = await preset.get_json(tokens, http)
        return parse(data) if data else None

    return _preset(
        provider_id,
        _base_options(**options),
        ["openid", "profile", "email"],
        account_subject=_profile_sub,
        authorization_url="https://access.line.me/oauth2/v2.1/authorize",
        token_url="https://api.line.me/oauth2/v2.1/token",
        user_info_url=userinfo,
        get_user_info=_PresetUserInfo(userinfo, _bearer, parse, resolve),
    )


def hubspot(**options: Any) -> GenericOAuthConfig:
    """HubSpot (TS providers/hubspot.ts): identity from the access-token info endpoint."""

    def parse(p: dict[str, Any]) -> dict[str, Any] | None:
        user_id = p.get("user_id") or (p.get("signed_access_token") or {}).get("userId")
        if not user_id:
            return None
        return {
            "id": user_id,
            "name": p.get("user"),
            "email": p.get("user"),
            "image": None,
            "emailVerified": False,
        }

    return _preset(
        "hubspot",
        _base_options(**options),
        ["oauth"],
        account_subject=_profile_id,
        authorization_url="https://app.hubspot.com/oauth/authorize",
        token_url="https://api.hubapi.com/oauth/v1/token",
        authentication="post",
        get_user_info=_PresetUserInfo(
            lambda t: f"https://api.hubapi.com/oauth/v1/access-tokens/{t.access_token}",
            lambda _t: {"content-type": "application/json"},
            parse,
        ),
    )


def gumroad(**options: Any) -> GenericOAuthConfig:
    """Gumroad (TS providers/gumroad.ts)."""

    def parse(p: dict[str, Any]) -> dict[str, Any] | None:
        user = p.get("user")
        if not p.get("success") or not user:
            return None
        return {
            "id": user.get("user_id"),
            "name": user.get("name"),
            "email": user.get("email"),
            "image": user.get("profile_url"),
            "emailVerified": False,
        }

    return _preset(
        "gumroad",
        _base_options(**options),
        ["view_profile"],
        account_subject=_profile_id,
        authorization_url="https://gumroad.com/oauth/authorize",
        token_url="https://api.gumroad.com/oauth/token",
        get_user_info=_PresetUserInfo("https://api.gumroad.com/v2/user", _bearer, parse),
    )


def patreon(**options: Any) -> GenericOAuthConfig:
    """Patreon (TS providers/patreon.ts)."""

    def parse(p: dict[str, Any]) -> dict[str, Any]:
        data = p.get("data") or {}
        attributes = data.get("attributes") or {}
        return {
            "id": data.get("id"),
            "name": attributes.get("full_name"),
            "email": attributes.get("email"),
            "image": attributes.get("image_url"),
            "emailVerified": attributes.get("is_email_verified"),
        }

    return _preset(
        "patreon",
        _base_options(**options),
        ["identity[email]"],
        account_subject=_profile_id,
        authorization_url="https://www.patreon.com/oauth2/authorize",
        token_url="https://www.patreon.com/api/oauth2/token",
        get_user_info=_PresetUserInfo(
            "https://www.patreon.com/api/oauth2/v2/identity"
            "?fields[user]=email,full_name,image_url,is_email_verified",
            _bearer,
            parse,
        ),
    )


def yandex(**options: Any) -> GenericOAuthConfig:
    """Yandex (TS providers/yandex.ts): no email means no profile (2df05582a)."""

    def parse(p: dict[str, Any]) -> dict[str, Any] | None:
        email = p.get("default_email") or next(iter(p.get("emails") or []), None)
        if not email:
            return None
        avatar = p.get("default_avatar_id")
        return {
            "id": p.get("id"),
            "name": p.get("display_name")
            or p.get("real_name")
            or p.get("first_name")
            or p.get("login"),
            "email": email,
            "emailVerified": False,
            "image": f"https://avatars.yandex.net/get-yapic/{avatar}/islands-200"
            if not p.get("is_avatar_empty") and avatar
            else None,
        }

    return _preset(
        "yandex",
        _base_options(**options),
        ["login:info", "login:email", "login:avatar"],
        account_subject=_profile_id,
        authorization_url="https://oauth.yandex.com/authorize",
        token_url="https://oauth.yandex.com/token",
        get_user_info=_PresetUserInfo(
            "https://login.yandex.ru/info?format=json",
            lambda t: {"authorization": f"OAuth {t.access_token}"},
            parse,
        ),
    )


_TENANT_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _microsoft_name(profile: dict[str, Any]) -> str | None:
    if profile.get("name") is not None:
        return profile["name"]
    given = profile.get("given_name") or profile.get("givenname") or ""
    family = profile.get("family_name") or profile.get("familyname") or ""
    return f"{given} {family}".strip() or None


def microsoft_entra_id(*, tenant_id: str, **options: Any) -> GenericOAuthConfig:
    """Microsoft Entra ID for one tenant (TS providers/microsoft-entra-id.ts, 0683a5f36):
    the account id is the ``oid`` claim and a verified discovery id token is required."""
    tenant = tenant_id.lower() if isinstance(tenant_id, str) else ""
    if not _TENANT_GUID.match(tenant):
        raise ValueError(
            "The generic microsoftEntraId helper requires a concrete Microsoft Entra tenant "
            "GUID. Use the built-in Microsoft provider for common, organizations, or consumers."
        )
    userinfo = "https://graph.microsoft.com/oidc/userinfo"

    def with_claims(token_profile: dict[str, Any], oid: str) -> dict[str, Any]:
        email = token_profile.get("email")
        return {
            **token_profile,
            "name": _microsoft_name(token_profile),
            "email": email
            or create_placeholder_email(identifier=oid, namespace="microsoft-entra-id"),
            "image": token_profile.get("picture"),
            "emailVerified": (token_profile.get("email_verified") or False) if email else False,
        }

    async def resolve(tokens: OAuthTokens, http: httpx.AsyncClient, preset: _PresetUserInfo):
        token_profile = _decode_id_token(tokens.id_token) if tokens.id_token else None
        if not token_profile:
            return None
        oid = token_profile.get("oid")
        if not isinstance(oid, str) or not oid.strip():
            return None
        token_user = with_claims(token_profile, oid)
        if not tokens.access_token:
            return token_user
        profile = await preset.get_json(tokens, http)
        if not isinstance(profile, dict) or not profile:
            return token_user
        sub = token_profile.get("sub")
        if not isinstance(sub, str) or profile.get("sub") != sub:
            return token_user
        email_claim = token_profile.get("email") or profile.get("email")
        verified = token_profile.get("email_verified")
        if verified is None:
            verified = profile.get("email_verified")
        return {
            **profile,
            **token_profile,
            "name": _microsoft_name(token_profile) or _microsoft_name(profile),
            "email": email_claim
            or create_placeholder_email(identifier=oid, namespace="microsoft-entra-id"),
            "image": token_profile.get("picture") or profile.get("picture"),
            "emailVerified": (verified or False) if email_claim is not None else False,
        }

    def oid_subject(context: dict[str, Any]) -> str:
        oid = context["profile"].get("oid")
        return oid if isinstance(oid, str) else ""

    base = f"https://login.microsoftonline.com/{tenant}"
    return _preset(
        "microsoft-entra-id",
        _base_options(**options),
        ["openid", "profile", "email"],
        account_subject=oid_subject,
        discovery_url=f"{base}/v2.0/.well-known/openid-configuration",
        require_id_token_verification=True,
        authorization_url=f"{base}/oauth2/v2.0/authorize",
        token_url=f"{base}/oauth2/v2.0/token",
        user_info_url=userinfo,
        get_user_info=_PresetUserInfo(userinfo, _bearer, lambda p: p, resolve),
    )
