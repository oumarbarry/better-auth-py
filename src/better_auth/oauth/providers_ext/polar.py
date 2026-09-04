"""Polar — ports ``social-providers/polar.ts``.

Standard OIDC shape (PKCE, ``post`` client auth). ``options.prompt`` (TS passes it
straight through to ``createAuthorizationURL``) is covered by the base class's generic
``authorize_params`` escape hatch — e.g. ``Polar(..., authorize_params={"prompt": "consent"})``
— no override needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


def _polar_mapper(profile: dict[str, Any]) -> OAuthUserInfo:
    return OAuthUserInfo(
        id=str(profile.get("id") or ""),
        email=profile.get("email"),
        name=profile.get("public_name") or profile.get("username") or "",
        image=profile.get("avatar_url"),
        # Polar may send email_verified, but it's not guaranteed — default False.
        email_verified=bool(profile.get("email_verified", False)),
        raw=profile,
    )


@dataclass
class Polar(ProviderConfig):
    provider_id: str = "polar"
    authorization_endpoint: str = "https://polar.sh/oauth2/authorize"
    token_endpoint: str = "https://api.polar.sh/v1/oauth2/token"
    userinfo_endpoint: str = "https://api.polar.sh/v1/oauth2/userinfo"
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    use_pkce: bool = True

    def __post_init__(self) -> None:
        if self.profile_mapper is None:
            self.profile_mapper = _polar_mapper
