"""Salesforce OAuth2 provider — port of ``social-providers/salesforce.ts``.

Quirks vs. the OAuth2 norm:
- Base host is configurable: ``login_url`` overrides everything, otherwise
  ``environment`` picks ``login.salesforce.com`` (production) or
  ``test.salesforce.com`` (sandbox). Authorize/token/userinfo all live on that host.
- PKCE (S256) required.
- Profile maps ``user_id`` (not ``sub``) to the user id and pulls the avatar from
  ``photos.picture``/``photos.thumbnail``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


@dataclass
class Salesforce(ProviderConfig):
    provider_id: str = "salesforce"
    #: "production" (login.salesforce.com) or "sandbox" (test.salesforce.com).
    environment: str = "production"
    #: my-domain host (e.g. "acme.my.salesforce.com") — overrides environment.
    login_url: str | None = None
    use_pkce: bool = True

    def __post_init__(self) -> None:
        if self.login_url:
            host = self.login_url
        elif self.environment == "sandbox":
            host = "test.salesforce.com"
        else:
            host = "login.salesforce.com"
        base = f"https://{host}/services/oauth2"
        self.authorization_endpoint = f"{base}/authorize"
        self.token_endpoint = f"{base}/token"
        self.userinfo_endpoint = f"{base}/userinfo"
        if not self.scopes:
            self.scopes = ["openid", "email", "profile"]

    def map_profile(self, profile: dict[str, Any]) -> OAuthUserInfo:
        photos = profile.get("photos") or {}
        return OAuthUserInfo(
            id=str(profile["user_id"]),
            email=profile.get("email"),
            name=profile.get("name") or "",
            image=photos.get("picture") or photos.get("thumbnail"),
            email_verified=bool(profile.get("email_verified", False)),
            raw=profile,
        )
