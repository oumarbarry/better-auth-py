"""Declarative provider config — the substrate for the 32 provider ports.

A provider is mostly *data* (endpoints, scopes, per-provider flags) plus a couple of
small overrides (``profile_mapper`` for the userinfo shape, ``id_token_mapper`` for the
OIDC claims shape, or a full ``fetch_user`` override for providers whose profile needs
several calls, e.g. GitHub's ``/user`` + ``/user/emails``). Everything shared —
authorize-URL building, token exchange, refresh, id-token verify — lives on the base and
routes every outbound fetch through :func:`oauth_fetch` (SSRF guard).

Adding a provider means declaring another :class:`ProviderConfig` (or a tiny subclass);
only genuinely non-standard providers need to override a method.
"""

from __future__ import annotations

import inspect
import math
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import jwt

from .machinery import (
    OAuthFetchError,
    TokenEndpointAuth,
    build_authorization_url,
    exchange_code,
    get_primary_client_id,
    oauth_fetch,
    refresh_access_token,
)
from .models import OAuthTokens, OAuthUserInfo
from .verify import verify_id_token

if TYPE_CHECKING:
    import httpx

    from ..types import Ctx

#: (profile_dict) -> OAuthUserInfo — maps a provider's userinfo/id-token payload.
ProfileMapper = Callable[[dict[str, Any]], OAuthUserInfo]


def _default_oidc_mapper(profile: dict[str, Any]) -> OAuthUserInfo:
    """Standard OIDC ``sub``/``email``/``name``/``picture`` mapping (userinfo or id-token)."""
    return OAuthUserInfo(
        id=str(profile.get("sub") or profile.get("id") or ""),
        email=profile.get("email"),
        name=profile.get("name") or profile.get("email") or "",
        image=profile.get("picture"),
        email_verified=bool(profile.get("email_verified", False)),
        raw=profile,
    )


@dataclass
class ProviderConfig:
    """A generic OAuth2/OIDC provider. Instantiate directly for custom providers, or use
    a built-in subclass (:class:`GitHub`, :class:`Google`, :class:`Discord`)."""

    client_id: str | list[str]
    client_secret: str = ""
    provider_id: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    scopes: list[str] = field(default_factory=list)
    #: joins scopes in the authorize URL (default space; a few providers use "," etc.)
    scope_joiner: str = " "
    #: per-provider PKCE (S256) — NOT a global flag (spec item 1)
    use_pkce: bool = False
    #: bind the redirect flow's id token to a nonce (TS ``requiresIdTokenNonce``): the
    #: nonce is minted into state, sent on the authorize URL, handed back to
    #: ``fetch_user`` as ``tokens.expected_id_token_nonce``, and a callback whose state
    #: carries none is refused with ``nonce_binding_missing``.
    requires_id_token_nonce: bool = False
    #: deprecated alias of ``requires_id_token_nonce`` (kept for custom providers)
    use_nonce: bool = False
    #: token-endpoint client auth: "post" (body) or "basic" (Authorization header)
    authentication: str = "post"
    #: explicit token endpoint client authentication (TS ``tokenEndpointAuth``); wins
    #: over ``authentication`` when set
    token_endpoint_auth: TokenEndpointAuth | None = None
    #: RFC 9207: the callback refuses an ``iss`` that differs from this (TS ``issuer``)
    issuer: str | None = None
    #: accept a callback without ``state`` by restarting the flow (TS ``allowIdpInitiated``)
    allow_idp_initiated: bool = False
    #: refuse a session while the user's email is unverified (TS
    #: ``options.requireEmailVerification``, link-account.ts:598-630)
    require_email_verification: bool = False
    #: overrides the computed {baseURL}/callback/{provider_id}
    redirect_uri: str | None = None
    #: path under the per-request base URL where this provider's callback is mounted
    #: (TS ``callbackPath``, 7c7313c81); default ``/callback/{provider_id}``
    callback_path: str | None = None
    #: raw extra authorize-URL params (access_type/hd/prompt/display/...) — additionalParams
    authorize_params: dict[str, str] = field(default_factory=dict)
    #: wipe baked-in default scopes before adding config/per-call scopes
    disable_default_scope: bool = False
    #: hard-disable sign-up via this provider (even with requestSignUp)
    disable_sign_up: bool = False
    #: require requestSignUp:true to register a new user via this provider
    disable_implicit_sign_up: bool = False
    #: re-sync the user profile from the provider on every sign-in, not just first link
    override_user_info_on_sign_in: bool = False
    #: whether the shared refresh helper is wired (every built-in provider: yes)
    supports_refresh: bool = True
    #: OIDC id-token verification (blank = provider has no id token)
    jwks_url: str = ""
    issuers: list[str] = field(default_factory=list)
    #: accepted JWS algorithms (TS ``idToken.algorithms``); unset accepts the header's alg
    id_token_algorithms: list[str] | None = None
    #: maximum id-token age in seconds (TS ``idToken.maxTokenAge``)
    id_token_max_age: int | None = None
    #: ``"exact"`` or ``"exact-or-sha256"`` (TS ``idToken.nonceComparison``)
    id_token_nonce_comparison: str = "exact"
    #: userinfo-profile → OAuthUserInfo (base fetch_user); defaults to the OIDC mapping
    profile_mapper: ProfileMapper | None = None
    #: id-token-claims → OAuthUserInfo (idToken sign-in); defaults to the OIDC mapping
    id_token_mapper: ProfileMapper | None = None

    # --- authorize / exchange / refresh (shared) --------------------------------------

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
        """``additional_params`` are the per-request extras (TS ``additionalParams``,
        e7eb45b06); they win over the configured ``authorize_params``. ``nonce`` is the
        redirect flow's id-token nonce, sent only when the provider binds one."""
        scopes = [] if self.disable_default_scope else list(self.scopes)
        scopes += list(extra_scopes or [])
        deduped = list(dict.fromkeys(scopes))
        params = {**self.authorize_params, **(additional_params or {})}
        return build_authorization_url(
            authorization_endpoint=self.authorization_endpoint,
            client_id=self.client_id,
            state=state,
            redirect_uri=redirect_uri,
            scopes=deduped or None,
            scope_joiner=self.scope_joiner,
            code_verifier=code_verifier if self.use_pkce else None,
            login_hint=login_hint,
            nonce=nonce if self.binds_id_token_nonce else None,
            additional_params=params or None,
        )

    @property
    def binds_id_token_nonce(self) -> bool:
        return self.requires_id_token_nonce or self.use_nonce

    async def exchange(
        self,
        http: httpx.AsyncClient,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> OAuthTokens:
        return await exchange_code(
            http,
            token_endpoint=self.token_endpoint,
            code=code,
            redirect_uri=redirect_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
            code_verifier=code_verifier if self.use_pkce else None,
            authentication=self.authentication,
            token_endpoint_auth=self.token_endpoint_auth,
        )

    async def refresh(self, http: httpx.AsyncClient, refresh_token: str) -> OAuthTokens:
        return await refresh_access_token(
            http,
            token_endpoint=self.token_endpoint,
            refresh_token=refresh_token,
            client_id=self.client_id,
            client_secret=self.client_secret,
            authentication=self.authentication,
            token_endpoint_auth=self.token_endpoint_auth,
        )

    async def create_end_session_url(
        self,
        *,
        id_token: str | None = None,
        post_logout_redirect_uri: str | None = None,
        state: str | None = None,
    ) -> str | None:
        """OIDC RP-initiated logout URL (TS ``createEndSessionURL``); ``None`` when the
        provider has no logout endpoint."""
        return None

    # --- user info --------------------------------------------------------------------

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        """OIDC-style bearer-token userinfo fetch. Providers with a non-standard profile
        override this (see :class:`GitHub`, :class:`Discord`); most just set
        ``profile_mapper``."""
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        response.raise_for_status()
        return self.map_profile(response.json())

    def map_profile(self, profile: dict[str, Any]) -> OAuthUserInfo:
        return (self.profile_mapper or _default_oidc_mapper)(profile)

    # --- id-token (OIDC direct sign-in) -----------------------------------------------

    @property
    def supports_id_token(self) -> bool:
        return bool(self.jwks_url)

    async def verify_id_token(
        self,
        http: httpx.AsyncClient,
        token: str,
        nonce: str | None = None,
        ctx: Ctx | None = None,
    ) -> dict[str, Any] | None:
        """``ctx`` is the request context (headers, body, auth) so an override can
        branch on the request — TS ``verifyIdToken(token, nonce, ctx)``. Call this
        through :func:`call_verify_id_token`, never directly."""
        if not self.jwks_url:
            return None
        return await verify_id_token(
            http,
            token,
            jwks_uri=self.jwks_url,
            audience=self.client_id,
            issuers=self.issuers,
            nonce=nonce,
            max_age=self.id_token_max_age,
            algorithms=self.id_token_algorithms,
            nonce_comparison=self.id_token_nonce_comparison,
        )

    def user_info_from_id_token(self, claims: dict[str, Any]) -> OAuthUserInfo:
        return (self.id_token_mapper or _default_oidc_mapper)(claims)


#: Back-compat alias for the pre-refactor public name.
OAuthProvider = ProviderConfig


def _accepts_ctx(fn: Callable[..., Any]) -> bool:
    """Whether a ``verify_id_token`` override takes the ``ctx`` argument.

    Third-party providers written before ``ctx`` existed have the 3-arg
    ``(http, token, nonce)`` signature; adapt to the callable's arity so both
    spellings work (same seam as ``plugins_ext/magic_link._accepts_ctx`` and
    ``internal_adapter._call_hook``).
    """
    try:
        params = inspect.signature(fn).parameters
    except (ValueError, TypeError):
        return True
    if "ctx" in params:
        return True
    return any(p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in params.values())


async def call_verify_id_token(
    provider: ProviderConfig,
    http: httpx.AsyncClient,
    token: str,
    nonce: str | None = None,
    ctx: Ctx | None = None,
) -> dict[str, Any] | None:
    """Invoke ``provider.verify_id_token``, passing ``ctx`` only if it is accepted."""
    fn = provider.verify_id_token
    if _accepts_ctx(fn):
        return await fn(http, token, nonce, ctx)
    return await fn(http, token, nonce)


async def call_refresh(
    provider: ProviderConfig, http: httpx.AsyncClient, refresh_token: str, ctx: Ctx | None
) -> OAuthTokens:
    """Invoke ``provider.refresh``, passing the request ``ctx`` only to overrides that
    accept it (TS ``refreshAccessToken(refreshToken, ctx)``, 3d04fabab)."""
    fn: Any = provider.refresh
    try:
        takes_ctx = "ctx" in inspect.signature(fn).parameters
    except (ValueError, TypeError):
        takes_ctx = False
    if takes_ctx:
        return await fn(http, refresh_token, ctx=ctx)
    return await fn(http, refresh_token)


def is_valid_account_subject(value: Any) -> bool:
    """TS v1.7.6 oauth2/account-key.ts:28-38: a subject that stringifies to blank,
    ``"undefined"`` or ``"null"`` (or a non-finite number) never becomes an account id."""
    if isinstance(value, float) and not math.isfinite(value):
        return False
    text = "" if value is None else str(value)
    return bool(text.strip()) and text not in ("undefined", "null")


@dataclass
class GitHub(ProviderConfig):
    provider_id: str = "github"
    authorization_endpoint: str = "https://github.com/login/oauth/authorize"
    token_endpoint: str = "https://github.com/login/oauth/access_token"
    userinfo_endpoint: str = "https://api.github.com/user"
    scopes: list[str] = field(default_factory=lambda: ["read:user", "user:email"])

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        headers = {
            "authorization": f"Bearer {tokens.access_token}",
            "user-agent": "better-auth-py",
            "accept": "application/vnd.github+json",
        }
        response = await oauth_fetch(http, "GET", self.userinfo_endpoint, headers=headers)
        response.raise_for_status()
        profile = response.json()
        emails_response = await oauth_fetch(
            http, "GET", f"{self.userinfo_endpoint}/emails", headers=headers
        )
        emails = emails_response.json() if emails_response.status_code == 200 else None
        # github.ts:160-165: the emails list only fills a missing profile email, and the
        # verified flag comes from the entry matching the chosen email
        if not profile.get("email") and emails:
            chosen = next((e for e in emails if e.get("primary")), emails[0])
            profile["email"] = chosen.get("email")
        verified = next(
            (
                bool(e.get("verified"))
                for e in emails or []
                if e.get("email") == profile.get("email")
            ),
            False,
        )
        return OAuthUserInfo(
            id=str(profile["id"]),
            email=profile.get("email"),
            name=profile.get("name") or profile.get("login") or "",
            image=profile.get("avatar_url"),
            email_verified=verified,
            raw=profile,
        )


@dataclass
class Google(ProviderConfig):
    provider_id: str = "google"
    authorization_endpoint: str = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint: str = "https://oauth2.googleapis.com/token"
    userinfo_endpoint: str = "https://openidconnect.googleapis.com/v1/userinfo"
    scopes: list[str] = field(default_factory=lambda: ["email", "profile", "openid"])
    use_pkce: bool = True
    # id-token verify + direct sign-in (spec-noted gap closed)
    jwks_url: str = "https://www.googleapis.com/oauth2/v3/certs"
    issuers: list[str] = field(
        default_factory=lambda: ["https://accounts.google.com", "accounts.google.com"]
    )
    #: google.ts:72-86: id tokens are RS256 only and at most one hour old
    id_token_algorithms: list[str] | None = field(default_factory=lambda: ["RS256"])
    id_token_max_age: int | None = 3600
    #: TS ``prompt``, ``accessType``, ``display`` authorize options
    prompt: str | None = None
    access_type: str | None = None
    display: str | None = None
    #: Workspace hosted domain (TS ``hd``): sent as the authorize hint and enforced on the
    #: id token ``hd`` claim; ``"*"`` accepts any hosted domain. Defaults to
    #: ``authorize_params["hd"]`` so the older spelling keeps working.
    hd: str | None = None
    #: send ``include_granted_scopes=true`` (TS ``includeGrantedScopes``, 3a79aff58)
    include_granted_scopes: bool = True

    def __post_init__(self) -> None:
        if self.hd is None:
            self.hd = self.authorize_params.get("hd") or None

    @staticmethod
    def hosted_domain_allowed(configured: str | None, token_hd: Any) -> bool:
        """google.ts:141-150 ``isGoogleHostedDomainAllowed``."""
        if not configured:
            return True
        if not isinstance(token_hd, str) or not token_hd:
            return False
        return configured == "*" or token_hd == configured

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
        """google.ts:153-199. No nonce: TS google sends none in the redirect flow."""

        if not get_primary_client_id(self.client_id) or not self.client_secret:
            raise ValueError("CLIENT_ID_AND_SECRET_REQUIRED")
        if not code_verifier:
            raise ValueError("codeVerifier is required for Google")
        scopes = [] if self.disable_default_scope else list(self.scopes)
        scopes += list(extra_scopes or [])
        granted = {"include_granted_scopes": "true"} if self.include_granted_scopes else {}
        return build_authorization_url(
            authorization_endpoint=self.authorization_endpoint,
            client_id=self.client_id,
            state=state,
            redirect_uri=redirect_uri,
            scopes=list(dict.fromkeys(scopes)) or None,
            scope_joiner=self.scope_joiner,
            code_verifier=code_verifier,
            prompt=self.prompt,
            access_type=self.access_type,
            display=self.display,
            login_hint=login_hint,
            hd=self.hd,
            additional_params={**granted, **self.authorize_params, **(additional_params or {})},
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        """google.ts:236-265: the profile is the decoded (unverified, TS ``decodeJwt``) id
        token, no userinfo call; a hosted-domain mismatch fails the sign-in."""

        if not tokens.id_token:
            raise OAuthFetchError("Google getUserInfo requires an id_token")
        profile = jwt.decode(
            tokens.id_token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
        if not self.hosted_domain_allowed(self.hd, profile.get("hd")):
            raise OAuthFetchError(
                f'Google sign-in rejected: id token hosted domain (hd) "{profile.get("hd")}" '
                f'does not satisfy the configured "hd" option "{self.hd}".'
            )
        return self.map_profile(profile)

    async def verify_id_token(
        self,
        http: httpx.AsyncClient,
        token: str,
        nonce: str | None = None,
        ctx: Ctx | None = None,
    ) -> dict[str, Any] | None:
        # google.ts:218-234 idToken config: the verified ``hd`` claim is authoritative
        return await verify_id_token(
            http,
            token,
            jwks_uri=self.jwks_url,
            audience=self.client_id,
            issuers=self.issuers,
            nonce=nonce,
            max_age=self.id_token_max_age,
            algorithms=self.id_token_algorithms,
            nonce_comparison=self.id_token_nonce_comparison,
            verify_claims=(
                (lambda claims: self.hosted_domain_allowed(self.hd, claims.get("hd")))
                if self.hd
                else None
            ),
        )


@dataclass
class Discord(ProviderConfig):
    provider_id: str = "discord"
    authorization_endpoint: str = "https://discord.com/api/oauth2/authorize"
    token_endpoint: str = "https://discord.com/api/oauth2/token"
    userinfo_endpoint: str = "https://discord.com/api/users/@me"
    scopes: list[str] = field(default_factory=lambda: ["identify", "email"])
    #: TS ``prompt`` ("none" when unset) and ``permissions`` (sent with the bot scope)
    prompt: str | None = None
    permissions: int | None = None

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
        """discord.ts:92-111 (e7eb45b06): shared builder, no PKCE, no login hint."""
        scopes = [] if self.disable_default_scope else list(self.scopes)
        scopes += list(extra_scopes or [])
        scopes = list(dict.fromkeys(scopes))
        permissions = (
            {"permissions": str(self.permissions)}
            if "bot" in scopes and self.permissions is not None
            else {}
        )
        return build_authorization_url(
            authorization_endpoint=self.authorization_endpoint,
            client_id=self.client_id,
            state=state,
            redirect_uri=redirect_uri,
            scopes=scopes or None,
            scope_joiner=self.scope_joiner,
            prompt=self.prompt or "none",
            additional_params={
                **permissions,
                **self.authorize_params,
                **(additional_params or {}),
            },
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        response.raise_for_status()
        profile = response.json()
        if profile.get("avatar"):
            # discord.ts:148-150: animated avatars ("a_" hash) are served as gif
            ext = "gif" if profile["avatar"].startswith("a_") else "png"
            image = f"https://cdn.discordapp.com/avatars/{profile['id']}/{profile['avatar']}.{ext}"
        else:
            # default-avatar CDN fallback (spec-noted gap): new users use (id>>22)%6,
            # legacy discriminator users use discriminator%5.
            discriminator = profile.get("discriminator") or "0"
            if discriminator != "0":
                index = int(discriminator) % 5
            else:
                index = (int(profile["id"]) >> 22) % 6
            image = f"https://cdn.discordapp.com/embed/avatars/{index}.png"
        profile["image_url"] = image  # TS sets it on the profile it returns as data
        return OAuthUserInfo(
            id=str(profile["id"]),
            email=profile.get("email"),
            name=profile.get("global_name") or profile.get("username") or "",
            image=image,
            email_verified=bool(profile.get("verified", False)),
            raw=profile,
        )
