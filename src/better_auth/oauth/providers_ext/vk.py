"""VK (VK ID) — port of ``social-providers/vk.ts``.

PKCE (S256). Userinfo is a ``POST`` with a form body (``access_token`` + ``client_id``),
**not** a bearer header, and the profile is nested under ``user``. VK is the only provider
that hard-fails the sign-in when no email is present (TS returns ``null``); here the mapped
``email`` is left ``None`` so the callback's email-required gate rejects it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..machinery import get_primary_client_id, oauth_fetch
from ..models import OAuthTokens, OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

_USER_INFO_ENDPOINT = "https://id.vk.com/oauth2/user_info"


def _map(p: dict[str, Any]) -> OAuthUserInfo:
    user = p.get("user") or {}
    first, last = user.get("first_name") or "", user.get("last_name") or ""
    return OAuthUserInfo(
        id=str(user.get("user_id") or ""),
        name=f"{first} {last}",
        email=user.get("email"),
        image=user.get("avatar"),
        email_verified=False,
        raw=p,
    )


@dataclass
class VK(ProviderConfig):
    provider_id: str = "vk"
    authorization_endpoint: str = "https://id.vk.com/authorize"
    token_endpoint: str = "https://id.vk.com/oauth2/auth"
    userinfo_endpoint: str = _USER_INFO_ENDPOINT
    scopes: list[str] = field(default_factory=lambda: ["email", "phone"])
    use_pkce: bool = True
    #: ponytail: part of TS's VkOption surface but its factory never reads it (UI hint only)
    scheme: str | None = None

    def __post_init__(self) -> None:
        if self.profile_mapper is None:
            self.profile_mapper = _map

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "POST",
            _USER_INFO_ENDPOINT,
            data={
                "access_token": tokens.access_token or "",
                "client_id": get_primary_client_id(self.client_id),
            },
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        return self.map_profile(response.json())
