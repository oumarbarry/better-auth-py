"""Railway — ports ``social-providers/railway.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * Client auth is **basic** (``Authorization: Basic``) for both token exchange and
    refresh — the base's ``authentication`` field already covers both call sites, no
    override needed beyond setting it.
  * Railway's userinfo never returns an ``email_verified`` claim; TS hardcodes
    ``emailVerified: false`` unconditionally rather than reading anything from the
    profile ("default to false for security consistency").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


def _railway_mapper(profile: dict[str, Any]) -> OAuthUserInfo:
    return OAuthUserInfo(
        id=str(profile.get("sub") or ""),
        email=profile.get("email"),
        name=profile.get("name") or "",
        image=profile.get("picture"),
        email_verified=False,  # Railway never reports this; TS always defaults to False.
        raw=profile,
    )


@dataclass
class Railway(ProviderConfig):
    provider_id: str = "railway"
    authorization_endpoint: str = "https://backboard.railway.com/oauth/auth"
    token_endpoint: str = "https://backboard.railway.com/oauth/token"
    userinfo_endpoint: str = "https://backboard.railway.com/oauth/me"
    scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])
    use_pkce: bool = True
    authentication: str = "basic"

    def __post_init__(self) -> None:
        if self.profile_mapper is None:
            self.profile_mapper = _railway_mapper
