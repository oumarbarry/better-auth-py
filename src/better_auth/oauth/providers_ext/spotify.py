"""Spotify provider (port of ``social-providers/spotify.ts``).

Fully standard shape: shared authorize-URL builder + PKCE (the one thing distinguishing
it from LinkedIn/Notion/Slack among this batch) + plain bearer-token GET userinfo.
``images`` is a size-ordered array; TS takes ``images[0]?.url`` (largest, per Spotify's
API docs), mapped to ``None`` when the list is empty. ``emailVerified`` is always
``False`` — Spotify's userinfo response has no such claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


@dataclass
class Spotify(ProviderConfig):
    provider_id: str = "spotify"
    authorization_endpoint: str = "https://accounts.spotify.com/authorize"
    token_endpoint: str = "https://accounts.spotify.com/api/token"
    userinfo_endpoint: str = "https://api.spotify.com/v1/me"
    scopes: list[str] = field(default_factory=lambda: ["user-read-email"])
    use_pkce: bool = True

    def map_profile(self, profile: dict[str, Any]) -> OAuthUserInfo:
        images = profile.get("images") or []
        return OAuthUserInfo(
            id=str(profile["id"]),
            email=profile.get("email"),
            name=profile.get("display_name") or "",
            image=images[0]["url"] if images else None,
            email_verified=False,
            raw=profile,
        )
