"""Naver — port of ``social-providers/naver.ts``.

No PKCE. Userinfo is wrapped in a ``{resultcode, message, response}`` envelope; the port
rejects the sign-in (like TS returning ``null``) unless ``resultcode == "00"``, then maps
the nested ``response`` object. ``emailVerified`` is always ``False``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..machinery import OAuthFetchError, oauth_fetch
from ..models import OAuthTokens, OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx


def _map(p: dict[str, Any]) -> OAuthUserInfo:
    res = p.get("response") or {}
    return OAuthUserInfo(
        id=str(res.get("id") or ""),
        name=res.get("name") or res.get("nickname") or "",
        email=res.get("email"),
        image=res.get("profile_image"),
        email_verified=False,
        raw=p,
    )


@dataclass
class Naver(ProviderConfig):
    provider_id: str = "naver"
    authorization_endpoint: str = "https://nid.naver.com/oauth2.0/authorize"
    token_endpoint: str = "https://nid.naver.com/oauth2.0/token"
    userinfo_endpoint: str = "https://openapi.naver.com/v1/nid/me"
    scopes: list[str] = field(default_factory=lambda: ["profile", "email"])

    def __post_init__(self) -> None:
        if self.profile_mapper is None:
            self.profile_mapper = _map

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        response.raise_for_status()
        profile = response.json()
        # TS returns null on a non-"00" resultcode; surface it as a fetch failure so the
        # callback rejects the sign-in rather than mapping a garbage/empty response.
        if profile.get("resultcode") != "00":
            raise OAuthFetchError(f"naver userinfo resultcode {profile.get('resultcode')}")
        return self.map_profile(profile)
