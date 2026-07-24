"""OAuth2/OIDC Provider plugin (``@better-auth/oauth-provider``) — Phase A.

Authorization-server side: client registration/CRUD/DCR, the ``clientPrivileges`` gate,
discovery documents, and jwt-plugin wiring. Ports TS ``packages/oauth-provider/src/``
(``oauth.ts`` factory/init/onRequest, ``register.ts``, ``oauthClient/``, ``metadata.ts``,
``signed-query.ts``, ``utils/index.ts``, ``schema.ts``) at v1.6.23.

Phase A scope: gap items 1-4, 6, 7-10. The authorization/token/introspection/userinfo/logout
flows are later phases. BINDING DECISIONS enforced at init: EdDSA-first (``disable_jwt_plugin``
and non-EdDSA jwt keys rejected); ``store_client_secret`` supports ``"hashed"`` (default) +
custom ``{hash, verify}`` only (``"encrypted"`` blocked).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import urlsplit

from ...plugins import Plugin, RateLimitRule, Route
from ...schema import Schema
from ...types import APIError, AuthResponse, Ctx
from .client_crud import (
    admin_create_client_endpoint,
    create_client_endpoint,
    delete_client_endpoint,
    get_client_endpoint,
    get_client_public_endpoint,
    get_client_public_prelogin_endpoint,
    get_clients_endpoint,
    rotate_client_secret_endpoint,
    update_client_endpoint,
)
from .metadata import (
    build_auth_server_metadata,
    build_oidc_server_metadata,
    metadata_response,
)
from .register import register_endpoint
from .schema import OAUTH_PROVIDER_SCHEMA
from .utils import OAuthError, get_jwt_plugin

if TYPE_CHECKING:
    from ...auth import BetterAuth

_DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"]


def _compute_claims(scopes: set[str]) -> list[str]:
    """TS oauth.ts:107 — base claims plus email/profile claims when those scopes are present."""
    claims = ["sub", "iss", "aud", "exp", "iat", "sid", "scope", "azp"]
    if "email" in scopes:
        claims += ["email", "email_verified"]
    if "profile" in scopes:
        claims += ["name", "picture", "family_name", "given_name"]
    return claims


class OAuthProviderPlugin(Plugin):
    """TS ``oauthProvider()`` — the authorization-server plugin (Phase A surface)."""

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
        scope_expirations: dict[str, int] | None = None,
        allow_dynamic_client_registration: bool = False,
        allow_unauthenticated_client_registration: bool = False,
        client_registration_default_scopes: list[str] | None = None,
        client_registration_allowed_scopes: list[str] | None = None,
        client_registration_client_secret_expiration: Any = None,
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
        cached_trusted_clients: set[str] | None = None,
        pairwise_secret: str | None = None,
        request_uri_resolver: Any = None,
        allow_public_client_prelogin: bool = False,
        disable_jwt_plugin: bool = False,
        silence_warnings: dict[str, Any] | None = None,
        rate_limit: dict[str, Any] | None = None,
    ) -> None:
        # BINDING DECISION: EdDSA-first — the JWT-disabled path (HS256 id tokens, encrypted
        # client secrets) is not ported.
        if disable_jwt_plugin:
            raise NotImplementedError(
                "oauth-provider: disable_jwt_plugin=True is not supported in this port "
                "(EdDSA-first; the HS256/encrypted-secret path is a follow-up)."
            )

        # BINDING DECISION: only "hashed" + custom {hash, verify}; "encrypted" is blocked.
        if store_client_secret == "encrypted" or (
            isinstance(store_client_secret, dict)
            and ("encrypt" in store_client_secret or "decrypt" in store_client_secret)
        ):
            raise ValueError(
                "oauth-provider: store_client_secret 'encrypted' is not supported in this port "
                "(blocked on secrets-rotation backlog); use 'hashed' or a custom {hash, verify}."
            )

        scope_set = {s for s in (scopes or _DEFAULT_SCOPES) if s}

        if client_registration_allowed_scopes:
            for sc in client_registration_allowed_scopes:
                if sc not in scope_set:
                    raise ValueError(f"clientRegistrationAllowedScope {sc} not found in scopes")
        for sc in (advertised_metadata or {}).get("scopes_supported") or []:
            if sc not in scope_set:
                raise ValueError(f"advertisedMetadata.scopes_supported {sc} not found in scopes")

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
        self.valid_audiences = valid_audiences
        self.advertised_metadata = advertised_metadata
        self.code_expires_in = code_expires_in
        self.access_token_expires_in = access_token_expires_in
        self.m2m_access_token_expires_in = m2m_access_token_expires_in
        self.id_token_expires_in = id_token_expires_in
        self.refresh_token_expires_in = refresh_token_expires_in
        self.scope_expirations = scope_expirations
        self.allow_dynamic_client_registration = allow_dynamic_client_registration
        self.allow_unauthenticated_client_registration = allow_unauthenticated_client_registration
        self.client_registration_default_scopes = client_registration_default_scopes
        self.client_registration_allowed_scopes = client_registration_allowed_scopes
        self.client_registration_client_secret_expiration = (
            client_registration_client_secret_expiration
        )
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
        self.cached_trusted_clients = cached_trusted_clients
        self.pairwise_secret = pairwise_secret
        self.request_uri_resolver = request_uri_resolver
        self.allow_public_client_prelogin = allow_public_client_prelogin
        self.disable_jwt_plugin = disable_jwt_plugin
        self.silence_warnings = silence_warnings or {}
        self.rate_limit_config = rate_limit
        self._auth: BetterAuth | None = None

    # --- lifecycle ------------------------------------------------------------------

    def init(self, auth: BetterAuth) -> None:
        self._auth = auth
        # jwt plugin is required (disable_jwt_plugin is rejected in __init__).
        jwt_plugin = get_jwt_plugin(auth)
        alg = (getattr(jwt_plugin, "key_pair_config", None) or {}).get("alg", "EdDSA")
        if alg != "EdDSA":
            raise NotImplementedError(
                f"oauth-provider: only EdDSA jwt keys are supported (got alg={alg!r}). "
                "The provider signs id/access tokens with the jwt plugin's keys."
            )

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
        ]
        return [(method, path, self._oauth_guard(handler)) for method, path, handler in raw]

    def rate_limit(self) -> list[RateLimitRule]:
        cfg = (self.rate_limit_config or {}).get("register")
        if cfg is False:
            return []
        window = (cfg or {}).get("window", 60)
        max_requests = (cfg or {}).get("max", 5)
        return [RateLimitRule(window, max_requests, lambda p: p == "/oauth2/register")]

    def _oauth_guard(self, handler: Any) -> Any:
        async def wrapped(ctx: Ctx) -> Any:
            try:
                return await handler(ctx)
            except OAuthError as error:
                return error.to_response()

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

    async def _rotate(self, ctx: Ctx) -> dict[str, Any]:
        return await rotate_client_secret_endpoint(ctx, self)

    async def _delete(self, ctx: Ctx) -> AuthResponse:
        return await delete_client_endpoint(ctx, self)

    # --- SERVER_ONLY endpoints (plain methods; not mounted on the HTTP router) -------

    async def admin_create_client(self, ctx: Ctx) -> AuthResponse:
        """POST /admin/oauth2/create-client (SERVER_ONLY)."""
        try:
            return await admin_create_client_endpoint(ctx, self)
        except OAuthError as error:
            return error.to_response()

    async def admin_update_client(self, ctx: Ctx) -> dict[str, Any] | AuthResponse:
        """PATCH /admin/oauth2/update-client (SERVER_ONLY)."""
        try:
            return await update_client_endpoint(ctx, self, admin=True)
        except OAuthError as error:
            return error.to_response()

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
        jwt_plugin = get_jwt_plugin(self.auth)
        issuer = getattr(jwt_plugin, "issuer", None) or f"{self.auth.base_url}{self.auth.base_path}"
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
