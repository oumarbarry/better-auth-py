"""LinkedIn OIDC provider (port of ``social-providers/linkedin.ts``).

Fully standard: shared authorize-URL builder (no PKCE, ``post`` client auth) and a plain
bearer-token GET against the OIDC userinfo endpoint. Only the profile mapping needs a
override — LinkedIn's ``email_verified`` can be absent (defaults ``False``, not spread
against the generic OIDC mapper's ``name`` fallback).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


@dataclass
class LinkedIn(ProviderConfig):
    provider_id: str = "linkedin"
    authorization_endpoint: str = "https://www.linkedin.com/oauth/v2/authorization"
    token_endpoint: str = "https://www.linkedin.com/oauth/v2/accessToken"
    userinfo_endpoint: str = "https://api.linkedin.com/v2/userinfo"
    scopes: list[str] = field(default_factory=lambda: ["profile", "email", "openid"])

    def map_profile(self, profile: dict[str, Any]) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(profile["sub"]),
            email=profile.get("email"),
            name=profile.get("name") or "",
            image=profile.get("picture"),
            email_verified=bool(profile.get("email_verified", False)),
            raw=profile,
        )
