"""Figma — ``packages/core/src/social-providers/figma.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
- Token endpoint uses **basic** client auth (``Authorization: Basic``), not the default
  body-post, for both the code exchange and refresh.
- TS throws if ``codeVerifier`` is missing before building the authorize URL; not
  reproduced here since this codebase's OAuth flow always generates a PKCE verifier
  up-front regardless of ``use_pkce`` (see ``flow.py``), so the guarded case never occurs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


@dataclass
class Figma(ProviderConfig):
    provider_id: str = "figma"
    authorization_endpoint: str = "https://www.figma.com/oauth"
    token_endpoint: str = "https://api.figma.com/v1/oauth/token"
    userinfo_endpoint: str = "https://api.figma.com/v1/me"
    scopes: list[str] = field(default_factory=lambda: ["current_user:read"])
    use_pkce: bool = True
    authentication: str = "basic"

    def map_profile(self, profile: dict) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(profile.get("id") or ""),
            email=profile.get("email"),
            name=profile.get("handle") or "",
            image=profile.get("img_url"),
            email_verified=False,
            raw=profile,
        )
