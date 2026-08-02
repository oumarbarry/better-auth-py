"""Declarative provider config — the substrate for the 32 provider ports.

A provider is mostly *data* (endpoints, scopes, per-provider flags) plus a couple of
small overrides (``profile_mapper`` for the userinfo shape, ``id_token_mapper`` for the
OIDC claims shape, or a full ``fetch_user`` override for providers whose profile needs
several calls, e.g. GitHub's ``/user`` + ``/user/emails``). Everything shared —
authorize-URL building, token exchange, refresh, id-token verify — lives on the base and
routes every outbound fetch through :func:`oauth_fetch` (SSRF guard).

Wave-2B adds providers by declaring another :class:`ProviderConfig` (or a tiny subclass);
only genuinely non-standard providers need to override a method.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .machinery import (
    build_authorization_url,
    exchange_code,
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
    #: per-provider OIDC nonce — generated, sent on the authorize URL, checked at verify
    use_nonce: bool = False
    #: token-endpoint client auth: "post" (body) or "basic" (Authorization header)
    authentication: str = "post"
    #: overrides the computed {baseURL}/callback/{provider_id}
    redirect_uri: str | None = None
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
    ) -> str:
        scopes = [] if self.disable_default_scope else list(self.scopes)
        scopes += list(extra_scopes or [])
        deduped = list(dict.fromkeys(scopes))
        params = dict(self.authorize_params)
        if nonce and self.use_nonce:
            params["nonce"] = nonce
        return build_authorization_url(
            authorization_endpoint=self.authorization_endpoint,
            client_id=self.client_id,
            state=state,
            redirect_uri=redirect_uri,
            scopes=deduped or None,
            scope_joiner=self.scope_joiner,
            code_verifier=code_verifier if self.use_pkce else None,
            login_hint=login_hint,
            additional_params=params or None,
        )

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
        )

    async def refresh(self, http: httpx.AsyncClient, refresh_token: str) -> OAuthTokens:
        return await refresh_access_token(
            http,
            token_endpoint=self.token_endpoint,
            refresh_token=refresh_token,
            client_id=self.client_id,
            client_secret=self.client_secret,
            authentication=self.authentication,
        )

    # --- user info --------------------------------------------------------------------

    async def fetch_user(
        self, tokens: OAuthTokens, http: httpx.AsyncClient
    ) -> OAuthUserInfo:
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


@dataclass
class GitHub(ProviderConfig):
    provider_id: str = "github"
    authorization_endpoint: str = "https://github.com/login/oauth/authorize"
    token_endpoint: str = "https://github.com/login/oauth/access_token"
    userinfo_endpoint: str = "https://api.github.com/user"
    scopes: list[str] = field(default_factory=lambda: ["read:user", "user:email"])

    async def fetch_user(
        self, tokens: OAuthTokens, http: httpx.AsyncClient
    ) -> OAuthUserInfo:
        headers = {
            "authorization": f"Bearer {tokens.access_token}",
            "user-agent": "better-auth-py",
            "accept": "application/vnd.github+json",
        }
        response = await oauth_fetch(http, "GET", self.userinfo_endpoint, headers=headers)
        response.raise_for_status()
        profile = response.json()
        email, verified = profile.get("email"), False
        emails_response = await oauth_fetch(
            http, "GET", f"{self.userinfo_endpoint}/emails", headers=headers
        )
        if emails_response.status_code == 200:
            emails = emails_response.json()
            primary = next((e for e in emails if e.get("primary")), None) or next(
                iter(emails), None
            )
            if primary:
                email = primary.get("email") or email
                verified = bool(primary.get("verified", False))
        return OAuthUserInfo(
            id=str(profile["id"]),
            email=email,
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
    scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])
    use_pkce: bool = True
    use_nonce: bool = True
    # id-token verify + direct sign-in (spec-noted gap closed)
    jwks_url: str = "https://www.googleapis.com/oauth2/v3/certs"
    issuers: list[str] = field(
        default_factory=lambda: ["https://accounts.google.com", "accounts.google.com"]
    )


@dataclass
class Discord(ProviderConfig):
    provider_id: str = "discord"
    authorization_endpoint: str = "https://discord.com/oauth2/authorize"
    token_endpoint: str = "https://discord.com/api/oauth2/token"
    userinfo_endpoint: str = "https://discord.com/api/users/@me"
    scopes: list[str] = field(default_factory=lambda: ["identify", "email"])

    async def fetch_user(
        self, tokens: OAuthTokens, http: httpx.AsyncClient
    ) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        response.raise_for_status()
        profile = response.json()
        if profile.get("avatar"):
            image = (
                f"https://cdn.discordapp.com/avatars/{profile['id']}/{profile['avatar']}.png"
            )
        else:
            # default-avatar CDN fallback (spec-noted gap): new users use (id>>22)%6,
            # legacy discriminator users use discriminator%5.
            discriminator = profile.get("discriminator") or "0"
            if discriminator != "0":
                index = int(discriminator) % 5
            else:
                index = (int(profile["id"]) >> 22) % 6
            image = f"https://cdn.discordapp.com/embed/avatars/{index}.png"
        return OAuthUserInfo(
            id=str(profile["id"]),
            email=profile.get("email"),
            name=profile.get("global_name") or profile.get("username") or "",
            image=image,
            email_verified=bool(profile.get("verified", False)),
            raw=profile,
        )
