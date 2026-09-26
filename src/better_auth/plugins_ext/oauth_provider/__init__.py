"""OAuth2/OIDC Provider plugin (``@better-auth/oauth-provider``).

Full authorization-server implementation: client registration/CRUD/DCR, the
``clientPrivileges`` gate, discovery documents, jwt-plugin wiring, the
``/oauth2/authorize`` flow (with signed-query consent resume), ``/oauth2/token``,
``/oauth2/introspect``, ``/oauth2/revoke``, ``/oauth2/userinfo``, and RP-initiated
logout. Ports TS ``packages/oauth-provider/src/``
(``oauth.ts`` factory/init/onRequest, ``register.ts``, ``oauthClient/``, ``metadata.ts``,
``signed-query.ts``, ``utils/index.ts``, ``schema.ts``) at v1.6.23.

Two signing modes: the default JWT-enabled path signs id/access tokens with the ``jwt`` plugin's
keys, on whatever alg it is configured with; ``disable_jwt_plugin=True`` installs no jwt plugin
and instead HS256-signs id tokens with each client's secret, storing client secrets ENCRYPTED at
rest (recoverable) rather than hashed. The init truth table (oauth.ts:157-178) enforces the
pairing: jwt-disabled rejects hashed/{hash} secrets, jwt-enabled rejects encrypted/{encrypt}.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import quote_plus, urlencode, urlsplit

from ...oauth.flow import add_oauth_server_context
from ...oauth.flow import get_oauth_state as get_flow_oauth_state
from ...plugins import HookSet, Plugin, PluginHook, RateLimitRule, Route
from ...schema import Schema
from ...types import APIError, AuthResponse, Ctx
from .authorize import (
    authorize_endpoint,
    form_query,
    get_oauth_state,
    request_query,
    set_oauth_state,
)
from .claims import STANDARD_CLAIM_NAMES, STANDARD_CLAIMS
from .client_crud import (
    delete_client_endpoint,
    get_client_endpoint,
    get_client_public_endpoint,
    get_client_public_prelogin_endpoint,
    get_clients_endpoint,
    rotate_client_secret_endpoint,
    update_client_endpoint,
)
from .consent import consent_endpoint
from .consent_crud import (
    delete_consent_endpoint,
    get_consent_endpoint,
    get_consents_endpoint,
    update_consent_endpoint,
)
from .introspect import introspect_endpoint
from .logout import (
    end_session_confirmation_endpoint,
    end_session_endpoint,
    session_delete_hooks,
)
from .metadata import (
    build_auth_server_metadata,
    build_oidc_server_metadata,
    metadata_response,
)
from .oauth_continue import continue_endpoint  # `continue` is a reserved word -> oauth_continue
from .register import NO_STORE_HEADERS, create_client_endpoint, register_endpoint
from .resource_crud import (
    create_resource_endpoint,
    delete_resource_endpoint,
    get_resource_endpoint,
    link_client_resource_endpoint,
    list_resources_endpoint,
    unlink_client_resource_endpoint,
    update_resource_endpoint,
)
from .resources import log_enforce_per_client_resources_resolution
from .revoke import revoke_endpoint
from .schema import OAUTH_PROVIDER_SCHEMA
from .signed_query import (
    POST_LOGIN_CLEARED_PARAM,
    SIGNED_QUERY_ISSUED_AT_PARAM,
    get_signed_query_issued_at,
    parse_query,
)
from .token import token_endpoint
from .userinfo import userinfo_endpoint
from .utils import (
    OAuthError,
    get_jwt_plugin,
    is_session_fresh_for_signed_query,
    remove_max_age_from_query,
    remove_prompt_from_query,
    search_params_to_query,
    verify_oauth_query_params,
)

if TYPE_CHECKING:
    from ...auth import BetterAuth

_DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"]

#: serverContext key for the signed query's issue time (TS oauth.ts:118).
_SIGNED_QUERY_ISSUED_AT_MS = "signedQueryIssuedAtMs"


def _server_context_issued_at(value: Any) -> datetime | None:
    """TS ``getServerContextSignedQueryIssuedAt`` (oauth.ts:120)."""
    try:
        issued_ms = float(value) if isinstance(value, (int, float, str)) else None
    except ValueError:
        return None
    if not issued_ms or not math.isfinite(issued_ms) or issued_ms <= 0:
        return None
    return datetime.fromtimestamp(issued_ms / 1000, tz=timezone.utc)


def _compute_claims(scopes: dict[str, None]) -> list[str]:
    """TS oauth.ts:201: protocol claims plus the standard claims whose scope is configured."""
    claims = ["sub", "iss", "aud", "exp", "iat", "sid", "scope", "azp"]
    return claims + [name for name in STANDARD_CLAIM_NAMES if STANDARD_CLAIMS[name][0] in scopes]


class OAuthProviderPlugin(Plugin):
    """TS ``oauthProvider()`` — the full authorization-server plugin (client management,
    authorize, token, introspect, revoke, userinfo, and RP-initiated logout)."""

    id = "oauth-provider"
    schema: ClassVar[Schema] = OAUTH_PROVIDER_SCHEMA

    def __init__(
        self,
        *,
        scopes: list[str] | None = None,
        valid_audiences: list[str] | None = None,
        advertised_metadata: dict[str, Any] | None = None,
        code_expires_in: int = 600,
        access_token_expires_in: int = 3600,
        m2m_access_token_expires_in: int = 3600,
        id_token_expires_in: int = 36000,
        refresh_token_expires_in: int = 2592000,
        refresh_token_reuse_interval: int = 0,
        assertion_max_lifetime: int = 300,
        bind_client_auth_method: bool = True,
        scope_expirations: dict[str, int] | None = None,
        allow_dynamic_client_registration: bool = False,
        allow_unauthenticated_client_registration: bool = False,
        client_registration_default_scopes: list[str] | None = None,
        client_registration_allowed_scopes: list[str] | None = None,
        client_registration_client_secret_expiration: Any = None,
        client_registration_require_pkce: bool = True,
        client_registration_default_resources: list[str] | None = None,
        client_registration_allowed_resources: list[str] | None = None,
        validate_initial_access_token: Any = None,
        grant_types: list[str] | None = None,
        client_credential_grant_default_scopes: list[str] | None = None,
        login_page: str | None = None,
        consent_page: str | None = None,
        signup: dict[str, Any] | None = None,
        select_account: dict[str, Any] | None = None,
        post_login: dict[str, Any] | None = None,
        store_client_secret: Any = None,
        store_tokens: Any = "hashed",
        format_refresh_token: dict[str, Any] | None = None,
        prefix: dict[str, str] | None = None,
        generate_client_id: Any = None,
        generate_client_secret: Any = None,
        generate_opaque_access_token: Any = None,
        generate_refresh_token: Any = None,
        custom_user_info_claims: Any = None,
        custom_id_token_claims: Any = None,
        custom_access_token_claims: Any = None,
        custom_token_response_fields: Any = None,
        client_reference: Any = None,
        client_privileges: Any = None,
        resource_privileges: Any = None,
        cached_trusted_clients: set[str] | None = None,
        pairwise_secret: str | None = None,
        request_uri_resolver: Any = None,
        resources: list[Any] | None = None,
        resource_seed_mode: str | None = None,
        cached_resources: set[str] | None = None,
        enforce_per_client_resources: bool | None = None,
        identifier_validator: Any = None,
        dpop: dict[str, Any] | None = None,
        allow_public_client_prelogin: bool = False,
        disable_jwt_plugin: bool = False,
        legacy_id_token_profile_claims: bool = False,
        silence_warnings: dict[str, Any] | None = None,
        rate_limit: dict[str, Any] | None = None,
    ) -> None:
        # Resolve the storeClientSecret default — TS oauth.ts:130: encrypted when the jwt plugin
        # is disabled (id tokens are HS256-signed WITH the secret, so it must be recoverable),
        # hashed otherwise. An explicit value overrides.
        if store_client_secret is None:
            store_client_secret = "encrypted" if disable_jwt_plugin else "hashed"

        # Init guard truth table — TS oauth.ts:157-178.
        #   disableJwtPlugin && (hashed | {hash})                -> throw  (secret unrecoverable)
        #   !disableJwtPlugin && (encrypted | {encrypt|decrypt}) -> throw  (use hashed/hash)
        if disable_jwt_plugin and (
            store_client_secret == "hashed"
            or (isinstance(store_client_secret, dict) and "hash" in store_client_secret)
        ):
            raise ValueError(
                "unable to store hashed secrets because id tokens will be signed with secret"
            )
        if not disable_jwt_plugin and (
            store_client_secret == "encrypted"
            or (
                isinstance(store_client_secret, dict)
                and ("encrypt" in store_client_secret or "decrypt" in store_client_secret)
            )
        ):
            raise ValueError(
                "encryption method not recommended, please use 'hashed' or the 'hash' function"
            )

        # Ordered like TS ``new Set(scopes)`` (oauth.ts:154): stored DCR scopes follow it.
        scope_set = dict.fromkeys(s for s in (scopes or _DEFAULT_SCOPES) if s)
        # TS oauth.ts:142: the default registration scopes join the allowed ones.
        if client_registration_default_scopes:
            merged = [
                *(client_registration_allowed_scopes or []),
                *client_registration_default_scopes,
            ]
            client_registration_allowed_scopes = list(dict.fromkeys(merged))

        if client_registration_allowed_scopes:
            for sc in client_registration_allowed_scopes:
                if sc not in scope_set:
                    raise ValueError(f"clientRegistrationAllowedScope {sc} not found in scopes")
        for sc in (advertised_metadata or {}).get("scopes_supported") or []:
            if sc not in scope_set:
                raise ValueError(f"advertisedMetadata.scopes_supported {sc} not found in scopes")

        configured_resources = {
            r if isinstance(r, str) else (r.get("identifier") if isinstance(r, dict) else None)
            for r in resources or []
        }
        for option_name, identifiers in (
            ("clientRegistrationDefaultResources", client_registration_default_resources),
            ("clientRegistrationAllowedResources", client_registration_allowed_resources),
        ):
            for identifier in identifiers or []:
                if identifier not in configured_resources:
                    raise ValueError(f"{option_name} resource {identifier} not found in resources")

        if pairwise_secret is not None and len(pairwise_secret) < 32:
            raise ValueError(
                "pairwiseSecret must be at least 32 characters long for adequate "
                "HMAC-SHA256 security"
            )

        resolved_grants = grant_types or [
            "authorization_code",
            "client_credentials",
            "refresh_token",
        ]
        if "refresh_token" in resolved_grants and "authorization_code" not in resolved_grants:
            raise ValueError("refresh_token grant requires authorization_code grant")

        self.scopes = list(scope_set)
        self.claims = _compute_claims(scope_set)
        # Port-only, kept from 1.0: resource identifiers accepted without an oauthResource row
        # (no policy, no client linkage). TS 1.7 removed validAudiences; unset by default.
        self.valid_audiences = valid_audiences
        self.advertised_metadata = advertised_metadata
        self.code_expires_in = code_expires_in
        self.access_token_expires_in = access_token_expires_in
        self.m2m_access_token_expires_in = m2m_access_token_expires_in
        self.id_token_expires_in = id_token_expires_in
        self.refresh_token_expires_in = refresh_token_expires_in
        # Seconds a rotated refresh token may be replayed for the same response (TS 5838df2f4).
        self.refresh_token_reuse_interval = refresh_token_reuse_interval
        # Max seconds between now and a private_key_jwt assertion's exp / iat (TS types:697).
        self.assertion_max_lifetime = assertion_max_lifetime
        # Port-only: False lets client_secret_basic and client_secret_post stand in for each
        # other, as in 1.0. TS always binds a client to its registered method (3ca2c08dc).
        self.bind_client_auth_method = bind_client_auth_method
        self.scope_expirations = scope_expirations
        self.allow_dynamic_client_registration = allow_dynamic_client_registration
        self.allow_unauthenticated_client_registration = allow_unauthenticated_client_registration
        self.client_registration_default_scopes = client_registration_default_scopes
        self.client_registration_allowed_scopes = client_registration_allowed_scopes
        self.client_registration_client_secret_expiration = (
            client_registration_client_secret_expiration
        )
        # Confidential DCR clients skip PKCE when False (TS types:810, a8200b297).
        self.client_registration_require_pkce = client_registration_require_pkce
        # Resources linked to, or requestable by, every DCR client (TS types:583-592).
        self.client_registration_default_resources = client_registration_default_resources
        self.client_registration_allowed_resources = client_registration_allowed_resources
        # RFC 7591 initial access token validator for protected DCR (TS types:758, 0143d6919):
        # called with {initialAccessToken, headers, clientMetadata}, returns
        # {"referenceId"?: str} to allow or False to reject.
        self.validate_initial_access_token = validate_initial_access_token
        self.grant_types = resolved_grants
        self.client_credential_grant_default_scopes = client_credential_grant_default_scopes
        self.login_page = login_page
        self.consent_page = consent_page
        self.signup = signup
        self.select_account = select_account
        self.post_login = post_login
        self.store_client_secret = store_client_secret
        self.store_tokens = store_tokens
        self.format_refresh_token = format_refresh_token
        self.prefix = prefix
        self.generate_client_id = generate_client_id
        self.generate_client_secret = generate_client_secret
        self.generate_opaque_access_token = generate_opaque_access_token
        self.generate_refresh_token = generate_refresh_token
        self.custom_user_info_claims = custom_user_info_claims
        self.custom_id_token_claims = custom_id_token_claims
        self.custom_access_token_claims = custom_access_token_claims
        self.custom_token_response_fields = custom_token_response_fields
        self.client_reference = client_reference
        self.client_privileges = client_privileges
        # Gate for the admin resource CRUD (TS types/index.ts:608).
        self.resource_privileges = resource_privileges
        self.cached_trusted_clients = cached_trusted_clients
        self.pairwise_secret = pairwise_secret
        self.request_uri_resolver = request_uri_resolver
        # OAuth protected resources (TS types/index.ts:539-601, d2a79bae7).
        self.resources = resources
        self.resource_seed_mode = resource_seed_mode
        self.cached_resources = cached_resources
        self.enforce_per_client_resources = enforce_per_client_resources
        self.identifier_validator = identifier_validator
        # DPoP proof settings {proofMaxAgeSeconds, signingAlgorithms} (TS types/index.ts:1370).
        self.dpop = dpop or {}
        self.allow_public_client_prelogin = allow_public_client_prelogin
        self.disable_jwt_plugin = disable_jwt_plugin
        # Deprecated, port-only: True puts the scope-based profile and email claims back in the
        # ID token, as the 1.0 port did. TS 1.7 serves them from UserInfo only (d368217ef).
        self.legacy_id_token_profile_claims = legacy_id_token_profile_claims
        # Accepted and ignored: TS 1.7 removed the option with its warnings (a7962147b).
        self.silence_warnings = silence_warnings or {}
        self.rate_limit_config = rate_limit
        # Grant handlers and discovery metadata contributed by companion plugins such as
        # OAuthDeviceAuthorizationPlugin (TS extendOAuthProvider, extensions.ts:220).
        self.extension_grants: dict[str, Any] = {}
        self.extension_metadata: list[Any] = []
        self._auth: BetterAuth | None = None

    # --- lifecycle ------------------------------------------------------------------

    def init(self, auth: BetterAuth) -> None:
        self._auth = auth
        # Resource rows are seeded on first resource lookup (resources.seed_resources_once).
        log_enforce_per_client_resources_resolution(self)
        # Back-channel logout on every session deletion, jwt plugin or not (oauth.ts:557-605).
        auth.internal.hooks.append(session_delete_hooks(self))
        # The disabled path signs with the client secret (HS256) and installs no jwt plugin.
        if self.disable_jwt_plugin:
            return
        get_jwt_plugin(auth)  # TS oauth.ts: the jwt plugin must be installed

    @property
    def auth(self) -> BetterAuth:
        assert self._auth is not None, "plugin.init() has not run yet"
        return self._auth

    # --- routes ---------------------------------------------------------------------

    def routes(self) -> list[Route]:
        raw = [
            ("POST", "/oauth2/register", self._register),
            ("POST", "/oauth2/create-client", self._create_client),
            ("GET", "/oauth2/get-client", self._get_client),
            ("GET", "/oauth2/public-client", self._public_client),
            ("POST", "/oauth2/public-client-prelogin", self._prelogin),
            ("GET", "/oauth2/get-clients", self._get_clients),
            ("POST", "/oauth2/update-client", self._update_client),
            ("POST", "/oauth2/client/rotate-secret", self._rotate),
            ("POST", "/oauth2/delete-client", self._delete),
            ("GET", "/oauth2/authorize", self._authorize),
            ("POST", "/oauth2/authorize", self._authorize_post),
            ("POST", "/oauth2/token", self._token),
            ("POST", "/oauth2/introspect", self._introspect),
            ("POST", "/oauth2/revoke", self._revoke),
            ("GET", "/oauth2/userinfo", self._userinfo),
            ("POST", "/oauth2/userinfo", self._userinfo),
            ("GET", "/oauth2/end-session", self._end_session),
            ("POST", "/oauth2/end-session", self._end_session),
            ("POST", "/oauth2/end-session/confirm", self._end_session_confirm),
            ("POST", "/oauth2/consent", self._consent),
            ("POST", "/oauth2/continue", self._continue),
            ("GET", "/oauth2/get-consent", self._get_consent),
            ("GET", "/oauth2/get-consents", self._get_consents),
            ("POST", "/oauth2/update-consent", self._update_consent),
            ("POST", "/oauth2/delete-consent", self._delete_consent),
        ]
        # TS ``metadata.noStore`` (2196ea65e): credential routes send no-store on errors too.
        # token, introspect, userinfo and end-session set it themselves, since their body
        # validation errors (raised before the TS handler runs) must stay without it.
        no_store = {"/oauth2/register", "/oauth2/create-client", "/oauth2/client/rotate-secret"}
        # TS ``use: [sessionMiddleware]`` (oauthClient/index.ts:228, 585) rejects first.
        session_first = {"/oauth2/create-client", "/oauth2/client/rotate-secret"}
        return [
            (
                method,
                path,
                self._oauth_guard(
                    handler, no_store=path in no_store, session_first=path in session_first
                ),
            )
            for method, path, handler in raw
        ]

    def rate_limit(self) -> list[RateLimitRule]:
        rules: list[RateLimitRule] = []
        for path, defaults in (
            ("/oauth2/register", (60, 5)),
            ("/oauth2/authorize", (60, 30)),
            ("/oauth2/token", (60, 20)),
            ("/oauth2/introspect", (60, 100)),
            ("/oauth2/revoke", (60, 30)),
            ("/oauth2/userinfo", (60, 60)),
        ):
            cfg = (self.rate_limit_config or {}).get(path.rsplit("/", 1)[-1])
            if cfg is False:
                continue
            window = (cfg or {}).get("window", defaults[0])
            max_requests = (cfg or {}).get("max", defaults[1])
            rules.append(RateLimitRule(window, max_requests, lambda p, _p=path: p == _p))
        return rules

    # --- signed-query resume hooks (TS oauth.ts:481-580) ----------------------------

    def hooks(self) -> HookSet:
        return HookSet(
            before=[PluginHook(self._has_oauth_query, self._before_stash_oauth_query)],
            after=[PluginHook(self._session_was_set, self._after_resume_authorize)],
        )

    def _has_oauth_query(self, ctx: Ctx) -> bool:
        try:
            return bool(ctx.body().get("oauth_query"))
        except Exception:
            return False

    async def _before_stash_oauth_query(self, ctx: Ctx) -> AuthResponse | None:
        query = ctx.body()["oauth_query"]
        if not verify_oauth_query_params(query, self.auth.secret):
            return AuthResponse(status=400, body={"error": "invalid_signature"})
        issued_at = get_signed_query_issued_at(query)
        pairs = parse_query(query)
        post_login_cleared = next((v for k, v in pairs if k == POST_LOGIN_CLEARED_PARAM), None)
        reserved = {"sig", "exp", SIGNED_QUERY_ISSUED_AT_PARAM, POST_LOGIN_CLEARED_PARAM}
        stripped = [(k, v) for k, v in pairs if k not in reserved]
        stripped_query = urlencode(stripped, quote_via=quote_plus)
        set_oauth_state(
            ctx,
            {
                "query": stripped_query,
                "signed_query_issued_at": issued_at,
                "post_login_cleared_for_session": post_login_cleared,
            },
        )
        # The social sign-in round trip carries the authorize query in the server-trusted OAuth
        # state channel, so a client cannot inject its own query through the request body
        # (TS oauth.ts:641, 0cbaf81be). /sign-in/oauth2 is the port's legacy generic-oauth alias
        # of /sign-in/social (generic_oauth.py), so it gets the same channel.
        if ctx.request.path in ("/sign-in/social", "/sign-in/oauth2"):
            await add_oauth_server_context(
                ctx,
                {
                    "query": stripped_query,
                    **(
                        {_SIGNED_QUERY_ISSUED_AT_MS: int(issued_at.timestamp() * 1000)}
                        if issued_at
                        else {}
                    ),
                },
            )
        return None

    def _session_was_set(self, ctx: Ctx) -> bool:
        return ctx.new_session is not None

    async def _after_resume_authorize(self, ctx: Ctx) -> AuthResponse | None:
        state = get_oauth_state(ctx)
        server_context = (get_flow_oauth_state(ctx) or {}).get("serverContext") or {}
        stashed = (state.get("query") if state else None) or server_context.get("query")
        if not stashed or not isinstance(stashed, str):
            return None
        issued_at = (state or {}).get("signed_query_issued_at") or _server_context_issued_at(
            server_context.get(_SIGNED_QUERY_ISSUED_AT_MS)
        )
        # Make the freshly created session visible to authorize's session lookup
        # (TS sets ctx.context.session from the just-set session cookie).
        ctx._session = ctx.new_session
        ctx._session_loaded = True
        headers = ctx.request.headers
        sec = (headers.get("sec-fetch-mode") or "").lower()
        accept = (headers.get("accept") or "").lower()
        is_navigation = sec == "navigate" or (
            not sec and ("text/html" in accept or "application/xhtml+xml" in accept)
        )
        if not is_navigation:
            headers["accept"] = "application/json"
        pairs = remove_prompt_from_query(parse_query(stashed), "login")
        # A login fresher than the signed query satisfies max_age (TS oauth.ts:703, 0e1770ac7).
        if is_session_fresh_for_signed_query(
            (ctx.new_session or {}).get("session", {}).get("createdAt"), issued_at
        ):
            pairs = remove_max_age_from_query(pairs)
        result = await authorize_endpoint(ctx, self, search_params_to_query(pairs), {})
        # Preserve the login's Set-Cookie headers on the resume redirect — replacing the
        # sign-in response wholesale would otherwise drop the freshly issued session cookie.
        if isinstance(result, AuthResponse) and ctx.response is not None:
            cookies = [(k, v) for k, v in ctx.response.headers if k.lower() == "set-cookie"]
            result.headers = cookies + result.headers
        return result

    def _oauth_guard(
        self, handler: Any, *, no_store: bool = False, session_first: bool = False
    ) -> Any:
        async def wrapped(ctx: Ctx) -> Any:
            if session_first:
                # Runs outside the noStore scope, like TS middleware before the handler.
                await ctx.require_session()
            try:
                return await handler(ctx)
            except OAuthError as error:
                response = error.to_response()
                if no_store:
                    present = {name.lower() for name, _ in response.headers}
                    response.headers += [
                        (k, v) for k, v in NO_STORE_HEADERS if k.lower() not in present
                    ]
                return response
            except APIError as error:
                # TS core api/index.ts:101-118: a noStore handler's APIError carries them too.
                if no_store:
                    headers = error.headers or []
                    present = {name.lower() for name, _ in headers}
                    error.headers = headers + [
                        (k, v) for k, v in NO_STORE_HEADERS if k.lower() not in present
                    ]
                raise

        return wrapped

    async def _register(self, ctx: Ctx) -> AuthResponse:
        return await register_endpoint(ctx, self)

    async def _create_client(self, ctx: Ctx) -> AuthResponse:
        return await create_client_endpoint(ctx, self)

    async def _get_client(self, ctx: Ctx) -> dict[str, Any]:
        return await get_client_endpoint(ctx, self)

    async def _public_client(self, ctx: Ctx) -> dict[str, Any]:
        session = await ctx.get_session()
        if session is None:
            raise APIError(401, "UNAUTHORIZED", "Not authenticated")
        client_id = ctx.request.query.get("client_id")
        if not client_id:
            raise APIError(400, "BAD_REQUEST", "client_id is required")
        return await get_client_public_endpoint(ctx, self, client_id)

    async def _prelogin(self, ctx: Ctx) -> dict[str, Any]:
        return await get_client_public_prelogin_endpoint(ctx, self)

    async def _get_clients(self, ctx: Ctx) -> Any:
        return await get_clients_endpoint(ctx, self)

    async def _update_client(self, ctx: Ctx) -> dict[str, Any]:
        return await update_client_endpoint(ctx, self, admin=False)

    async def _rotate(self, ctx: Ctx) -> AuthResponse:
        return await rotate_client_secret_endpoint(ctx, self)

    async def _delete(self, ctx: Ctx) -> AuthResponse:
        return await delete_client_endpoint(ctx, self)

    # --- authorization + consent + continue -----------------------------------------

    async def _authorize(self, ctx: Ctx) -> AuthResponse:
        return await authorize_endpoint(ctx, self, request_query(ctx), {"isAuthorize": True})

    async def _authorize_post(self, ctx: Ctx) -> AuthResponse:
        """Form-encoded POST authorization request (TS oauth.ts:267, 267229bd2)."""
        return await authorize_endpoint(ctx, self, form_query(ctx), {"isAuthorize": True})

    async def _token(self, ctx: Ctx) -> AuthResponse:
        return await token_endpoint(ctx, self)

    async def _introspect(self, ctx: Ctx) -> Any:
        return await introspect_endpoint(ctx, self)

    async def _revoke(self, ctx: Ctx) -> Any:
        return await revoke_endpoint(ctx, self)

    async def _userinfo(self, ctx: Ctx) -> Any:
        return await userinfo_endpoint(ctx, self)

    async def _end_session(self, ctx: Ctx) -> AuthResponse:
        return await end_session_endpoint(ctx, self)

    async def _end_session_confirm(self, ctx: Ctx) -> AuthResponse:
        return await end_session_confirmation_endpoint(ctx, self)

    async def _run_authorize(
        self, ctx: Ctx, query: dict[str, Any], settings: dict[str, Any]
    ) -> Any:
        return await authorize_endpoint(ctx, self, query, settings)

    async def _consent(self, ctx: Ctx) -> Any:
        return await consent_endpoint(ctx, self, self._run_authorize)

    async def _continue(self, ctx: Ctx) -> Any:
        return await continue_endpoint(ctx, self, self._run_authorize)

    async def _get_consent(self, ctx: Ctx) -> Any:
        return await get_consent_endpoint(ctx, self)

    async def _get_consents(self, ctx: Ctx) -> Any:
        return await get_consents_endpoint(ctx, self)

    async def _update_consent(self, ctx: Ctx) -> Any:
        return await update_consent_endpoint(ctx, self)

    async def _delete_consent(self, ctx: Ctx) -> Any:
        return await delete_consent_endpoint(ctx, self)

    # --- SERVER_ONLY endpoints (plain methods; not mounted on the HTTP router) -------

    async def admin_create_client(self, ctx: Ctx) -> AuthResponse:
        """POST /admin/oauth2/create-client (SERVER_ONLY)."""
        return await self._oauth_guard(
            lambda c: create_client_endpoint(c, self, admin=True), no_store=True
        )(ctx)

    async def admin_update_client(self, ctx: Ctx) -> dict[str, Any] | AuthResponse:
        """PATCH /admin/oauth2/update-client (SERVER_ONLY)."""
        try:
            return await update_client_endpoint(ctx, self, admin=True)
        except OAuthError as error:
            return error.to_response()

    # Admin CRUD for OAuth protected resources (TS oauthResource/index.ts, SERVER_ONLY).
    # Path params are passed as arguments and percent-decoded like TS decodePathParam.

    async def admin_create_oauth_resource(self, ctx: Ctx) -> AuthResponse:
        """POST /admin/oauth2/resources (SERVER_ONLY): 201 with the stored row."""
        try:
            return await create_resource_endpoint(ctx, self)
        except OAuthError as error:
            return error.to_response()

    async def admin_list_oauth_resources(self, ctx: Ctx) -> list[dict[str, Any]]:
        """GET /admin/oauth2/resources (SERVER_ONLY)."""
        return await list_resources_endpoint(ctx, self)

    async def admin_get_oauth_resource(
        self, ctx: Ctx, identifier: str
    ) -> dict[str, Any] | AuthResponse:
        """GET /admin/oauth2/resources/:identifier (SERVER_ONLY)."""
        try:
            return await get_resource_endpoint(ctx, self, identifier)
        except OAuthError as error:
            return error.to_response()

    async def admin_update_oauth_resource(
        self, ctx: Ctx, identifier: str
    ) -> dict[str, Any] | AuthResponse:
        """PATCH /admin/oauth2/resources/:identifier (SERVER_ONLY)."""
        try:
            return await update_resource_endpoint(ctx, self, identifier)
        except OAuthError as error:
            return error.to_response()

    async def admin_delete_oauth_resource(
        self, ctx: Ctx, identifier: str
    ) -> dict[str, Any] | AuthResponse:
        """DELETE /admin/oauth2/resources/:identifier (SERVER_ONLY)."""
        try:
            return await delete_resource_endpoint(ctx, self, identifier)
        except OAuthError as error:
            return error.to_response()

    async def admin_link_client_resource(
        self, ctx: Ctx, identifier: str, client_id: str
    ) -> dict[str, Any] | AuthResponse:
        """POST /admin/oauth2/resources/:identifier/clients/:client_id (SERVER_ONLY)."""
        try:
            return await link_client_resource_endpoint(ctx, self, identifier, client_id)
        except OAuthError as error:
            return error.to_response()

    async def admin_unlink_client_resource(
        self, ctx: Ctx, identifier: str, client_id: str
    ) -> dict[str, Any]:
        """DELETE /admin/oauth2/resources/:identifier/clients/:client_id (SERVER_ONLY)."""
        return await unlink_client_resource_endpoint(ctx, self, identifier, client_id)

    async def get_oauth_server_config(self) -> dict[str, Any]:
        """SERVER_ONLY — the auth-server (or OIDC, when ``openid`` is a scope) metadata body."""
        if "openid" in self.scopes:
            return build_oidc_server_metadata(self.auth, self)
        return build_auth_server_metadata(self.auth, self)

    async def get_openid_config(self) -> dict[str, Any]:
        """SERVER_ONLY — the OIDC discovery body (404 when ``openid`` is not a scope)."""
        if self.scopes and "openid" not in self.scopes:
            raise APIError(404, "NOT_FOUND")
        return build_oidc_server_metadata(self.auth, self)

    # --- discovery well-known router (onRequest) ------------------------------------

    def _issuer_path(self) -> str:
        base = f"{self.auth.base_url}{self.auth.base_path}"
        if self.disable_jwt_plugin:
            issuer = base
        else:
            issuer = getattr(get_jwt_plugin(self.auth), "issuer", None) or base
        try:
            return urlsplit(issuer).path.rstrip("/")
        except ValueError:
            return urlsplit(f"{self.auth.base_url}{self.auth.base_path}").path.rstrip("/")

    async def on_request(self, ctx: Ctx) -> AuthResponse | None:
        """Serve discovery at the issuer-path-relative well-known URLs (TS ``onRequest``).

        Fires before the router's own 404 (auth._dispatch runs on_request before route
        matching), so discovery is reachable even though the auth mount does not cover the
        issuer-relative paths. Matches both the RFC 8414 path-insertion alias and the
        issuer-appended alias, against the mount-relative path and its base-path-reconstructed
        full path. GET/HEAD only (405 with ``Allow: GET, HEAD``; HEAD = empty body).
        """
        request = ctx.request
        req_path = request.path
        if self.auth.skip_trailing_slashes:
            req_path = req_path.rstrip("/") or "/"
        base_path = self.auth.base_path
        candidates = {req_path}
        if base_path:
            candidates.add(f"{base_path}{req_path}")

        issuer_path = self._issuer_path()
        auth_server_paths = {
            f"/.well-known/oauth-authorization-server{issuer_path}",
            f"{issuer_path}/.well-known/oauth-authorization-server",
        }
        openid_config_path = f"{issuer_path}/.well-known/openid-configuration"
        has_openid = "openid" in self.scopes

        is_auth_server = bool(candidates & auth_server_paths)
        is_openid_config = has_openid and openid_config_path in candidates
        if not (is_auth_server or is_openid_config):
            return None

        if request.method not in ("GET", "HEAD"):
            return AuthResponse(status=405, headers=[("Allow", "GET, HEAD")])
        head = request.method == "HEAD"

        if is_openid_config or (is_auth_server and has_openid):
            return metadata_response(build_oidc_server_metadata(self.auth, self), head=head)
        return metadata_response(build_auth_server_metadata(self.auth, self), head=head)
