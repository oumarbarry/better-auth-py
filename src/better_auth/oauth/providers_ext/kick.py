"""Kick — ``packages/core/src/social-providers/kick.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
- Userinfo endpoint returns ``{"data": [profile, ...]}`` (an array) — the caller takes
  ``data[0]`` rather than a single-object body.
- Kick never returns an ``email_verified`` claim; TS hardcodes ``emailVerified: false``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..machinery import OAuthFetchError, oauth_fetch
from ..models import OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

    from ..models import OAuthTokens


@dataclass
class Kick(ProviderConfig):
    provider_id: str = "kick"
    authorization_endpoint: str = "https://id.kick.com/oauth/authorize"
    token_endpoint: str = "https://id.kick.com/oauth/token"
    userinfo_endpoint: str = "https://api.kick.com/public/v1/users"
    scopes: list[str] = field(default_factory=lambda: ["user:read"])
    use_pkce: bool = True

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        response.raise_for_status()
        items = response.json().get("data") or []
        if not items:
            raise OAuthFetchError("kick userinfo returned no users")
        return self.map_profile(items[0])

    def map_profile(self, profile: dict) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(profile.get("user_id") or ""),
            email=profile.get("email"),
            name=profile.get("name") or "",
            image=profile.get("profile_picture"),
            email_verified=False,
            raw=profile,
        )
