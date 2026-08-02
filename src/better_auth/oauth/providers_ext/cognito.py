"""Amazon Cognito — port of ``social-providers/cognito.ts``.

Per-pool config: ``domain``/``region``/``user_pool_id`` are required at construction (raises
``ValueError`` immediately, like TS's ``DOMAIN_AND_REGION_REQUIRED``). The authorize/token/
userinfo endpoints derive from ``domain``; JWKS/issuer derive from ``region``/``user_pool_id``.
PKCE (S256), id-token verified with a 1h max age. AWS wants scopes ``%20``-encoded (not ``+``),
so the authorize URL's ``scope`` param is re-encoded. Userinfo prefers the decoded ``id_token``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit, urlunsplit

import jwt

from ..machinery import oauth_fetch
from ..models import OAuthTokens, OAuthUserInfo
from ..providers import ProviderConfig
from ..verify import verify_id_token as _verify_id_token

if TYPE_CHECKING:
    import httpx


def _map(p: dict[str, Any]) -> OAuthUserInfo:
    name = p.get("name") or p.get("given_name") or p.get("username") or ""
    return OAuthUserInfo(
        id=str(p.get("sub") or ""),
        name=name,
        email=p.get("email"),
        image=p.get("picture"),
        email_verified=bool(p.get("email_verified", False)),
        raw={**p, "name": name},
    )


@dataclass
class Cognito(ProviderConfig):
    provider_id: str = "cognito"
    domain: str = ""
    region: str = ""
    user_pool_id: str = ""
    require_client_secret: bool = False
    disable_id_token_sign_in: bool = False
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    use_pkce: bool = True

    def __post_init__(self) -> None:
        if not self.domain or not self.region or not self.user_pool_id:
            raise ValueError("domain, region and user_pool_id are required for Amazon Cognito")
        clean = re.sub(r"^https?://", "", self.domain)
        self.authorization_endpoint = f"https://{clean}/oauth2/authorize"
        self.token_endpoint = f"https://{clean}/oauth2/token"
        self.userinfo_endpoint = f"https://{clean}/oauth2/userinfo"
        self.jwks_url = (
            f"https://cognito-idp.{self.region}.amazonaws.com/"
            f"{self.user_pool_id}/.well-known/jwks.json"
        )
        self.issuers = [f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"]
        if self.profile_mapper is None:
            self.profile_mapper = _map
        if self.id_token_mapper is None:
            self.id_token_mapper = _map

    @property
    def supports_id_token(self) -> bool:
        return bool(self.jwks_url) and not self.disable_id_token_sign_in

    def authorization_url(self, **kwargs: Any) -> str:
        url = super().authorization_url(**kwargs)
        # AWS Cognito requires scopes encoded with %20, but urlencode emits '+'. Re-encode
        # every param (harmless — %20 is valid everywhere) so scope comes out %20-joined.
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        query = "&".join(
            f"{quote_plus(k)}={quote(v, safe='') if k == 'scope' else quote_plus(v)}"
            for k, v in pairs
        )
        return urlunsplit(parts._replace(query=query))

    async def verify_id_token(
        self, http: httpx.AsyncClient, token: str, nonce: str | None = None
    ) -> dict[str, Any] | None:
        if self.disable_id_token_sign_in:
            return None
        return await _verify_id_token(
            http,
            token,
            jwks_uri=self.jwks_url,
            audience=self.client_id,
            issuers=self.issuers,
            nonce=nonce,
            max_age=3600,  # TS maxTokenAge: "1h"
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        if tokens.id_token:
            try:
                claims = jwt.decode(tokens.id_token, options={"verify_signature": False})
                return self.map_profile(claims)
            except jwt.PyJWTError:
                pass
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        response.raise_for_status()
        return self.map_profile(response.json())
