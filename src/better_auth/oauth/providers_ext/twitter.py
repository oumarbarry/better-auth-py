"""Twitter (X) OAuth2 provider — port of ``social-providers/twitter.ts``.

Quirks vs. the OAuth2 norm:
- PKCE (S256) required.
- ``basic`` client auth at the token endpoint (X rejects base64url basic; the
  shared helper uses standard base64, RFC 7617).
- Profile needs **two** calls to ``/2/users/me``: one for the profile, one for the
  ``confirmed_email`` field (X only returns email under a separate field query).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..machinery import oauth_fetch
from ..models import OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

    from ..models import OAuthTokens


@dataclass
class Twitter(ProviderConfig):
    provider_id: str = "twitter"
    authorization_endpoint: str = "https://x.com/i/oauth2/authorize"
    token_endpoint: str = "https://api.x.com/2/oauth2/token"
    scopes: list[str] = field(
        default_factory=lambda: [
            "users.read",
            "tweet.read",
            "offline.access",
            "users.email",
        ]
    )
    use_pkce: bool = True
    authentication: str = "basic"

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        headers = {"authorization": f"Bearer {tokens.access_token}"}
        resp = await oauth_fetch(
            http,
            "GET",
            "https://api.x.com/2/users/me?user.fields=profile_image_url",
            headers=headers,
        )
        resp.raise_for_status()
        profile = resp.json()
        data = profile["data"]

        email = data.get("email")
        email_verified = False
        email_resp = await oauth_fetch(
            http,
            "GET",
            "https://api.x.com/2/users/me?user.fields=confirmed_email",
            headers=headers,
        )
        if email_resp.status_code == 200:
            confirmed = (email_resp.json().get("data") or {}).get("confirmed_email")
            if confirmed:
                email = confirmed
                email_verified = True

        return OAuthUserInfo(
            id=str(data["id"]),
            email=email or data.get("username") or None,
            name=data.get("name") or "",
            image=data.get("profile_image_url"),
            email_verified=email_verified,
            raw=profile,
        )
