"""Hugging Face — ``packages/core/src/social-providers/huggingface.ts``.

Standard OIDC-shaped provider: bearer-token GET userinfo, no unusual verification or
endpoint quirks. Only the profile field names (``sub``/``preferred_username``) differ
from the generic OIDC default mapper, hence the ``map_profile`` override.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


@dataclass
class Huggingface(ProviderConfig):
    provider_id: str = "huggingface"
    authorization_endpoint: str = "https://huggingface.co/oauth/authorize"
    token_endpoint: str = "https://huggingface.co/oauth/token"
    userinfo_endpoint: str = "https://huggingface.co/oauth/userinfo"
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    use_pkce: bool = True

    def map_profile(self, profile: dict) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(profile.get("sub") or ""),
            email=profile.get("email"),
            name=profile.get("name") or profile.get("preferred_username") or "",
            image=profile.get("picture"),
            email_verified=bool(profile.get("email_verified", False)),
            raw=profile,
        )
