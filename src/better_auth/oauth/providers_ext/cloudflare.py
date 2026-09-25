"""Cloudflare: ports ``social-providers/cloudflare.ts`` (TS v1.7.6, 76d311f4b).

Quirks vs. the generic :class:`ProviderConfig`:
  * PKCE always; the authorize URL carries no login hint and no per-request extras
    (TS ``createAuthorizationURL`` for Cloudflare forwards neither).
  * Token endpoint auth defaults to ``client_secret_basic`` with a secret and ``none``
    (public PKCE client) without one; ``token_endpoint_auth_method`` overrides it.
  * The OIDC userinfo endpoint only returns ``sub``, so the profile comes from the
    Cloudflare API ``/user`` endpoint (needs the ``user-details.read`` scope) and is
    wrapped in the ``{success, errors, result}`` envelope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..machinery import OAuthFetchError, TokenEndpointAuth, build_authorization_url, oauth_fetch
from ..models import OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

    from ..models import OAuthTokens


def _cloudflare_mapper(profile: dict[str, Any]) -> OAuthUserInfo:
    name = " ".join(p for p in (profile.get("first_name"), profile.get("last_name")) if p)
    return OAuthUserInfo(
        id=str(profile.get("id") or ""),
        email=profile.get("email"),
        name=name or profile.get("email") or "",
        email_verified=False,  # Cloudflare does not expose email verification status
        raw=profile,
    )


@dataclass
class Cloudflare(ProviderConfig):
    provider_id: str = "cloudflare"
    authorization_endpoint: str = "https://dash.cloudflare.com/oauth2/auth"
    token_endpoint: str = "https://dash.cloudflare.com/oauth2/token"
    userinfo_endpoint: str = "https://api.cloudflare.com/client/v4/user"
    scopes: list[str] = field(default_factory=lambda: ["user-details.read"])
    use_pkce: bool = True
    #: TS ``tokenEndpointAuthMethod``: "client_secret_basic" | "client_secret_post" | "none"
    token_endpoint_auth_method: str | None = None

    def __post_init__(self) -> None:
        if self.profile_mapper is None:
            self.profile_mapper = _cloudflare_mapper
        if self.token_endpoint_auth is None:
            # cloudflare.ts:127-134 getTokenEndpointAuth
            default = "client_secret_basic" if self.client_secret else "none"
            self.token_endpoint_auth = TokenEndpointAuth(self.token_endpoint_auth_method or default)

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
        scopes = [] if self.disable_default_scope else list(self.scopes)
        scopes += list(extra_scopes or [])
        return build_authorization_url(
            authorization_endpoint=self.authorization_endpoint,
            client_id=self.client_id,
            state=state,
            redirect_uri=redirect_uri,
            scopes=list(dict.fromkeys(scopes)) or None,
            code_verifier=code_verifier,
            additional_params=self.authorize_params or None,
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        data = response.json() if response.status_code == 200 else None
        if not data or not data.get("success") or not data.get("result"):
            raise OAuthFetchError("Failed to fetch user info from Cloudflare")
        return self.map_profile(data["result"])
