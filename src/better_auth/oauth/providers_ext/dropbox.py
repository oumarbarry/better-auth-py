"""Dropbox — ``packages/core/src/social-providers/dropbox.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
- ``getUserInfo`` is a ``POST`` to ``/2/users/get_current_account`` (Dropbox's userinfo
  endpoint takes no query/body but requires ``POST``, not ``GET``).
- ``accessType`` (``offline``/``online``/``legacy``) is forwarded as the authorize-URL's
  ``token_access_type`` param when set (Dropbox-specific, not a generic OAuth2 knob).
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
class Dropbox(ProviderConfig):
    provider_id: str = "dropbox"
    authorization_endpoint: str = "https://www.dropbox.com/oauth2/authorize"
    token_endpoint: str = "https://api.dropboxapi.com/oauth2/token"
    userinfo_endpoint: str = "https://api.dropboxapi.com/2/users/get_current_account"
    scopes: list[str] = field(default_factory=lambda: ["account_info.read"])
    use_pkce: bool = True
    #: "offline" | "online" | "legacy" -> authorize URL's `token_access_type` param
    access_type: str = ""

    def __post_init__(self) -> None:
        if self.access_type:
            self.authorize_params = {
                **self.authorize_params,
                "token_access_type": self.access_type,
            }

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "POST",
            self.userinfo_endpoint,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        response.raise_for_status()
        return self.map_profile(response.json())

    def map_profile(self, profile: dict) -> OAuthUserInfo:
        name = profile.get("name") or {}
        return OAuthUserInfo(
            id=str(profile.get("account_id") or ""),
            email=profile.get("email"),
            name=name.get("display_name") or "",
            image=profile.get("profile_photo_url"),
            email_verified=bool(profile.get("email_verified", False)),
            raw=profile,
        )
