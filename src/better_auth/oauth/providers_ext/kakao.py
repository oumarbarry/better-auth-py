"""Kakao — port of ``social-providers/kakao.ts``.

No PKCE. Profile is nested under ``kakao_account`` (and ``kakao_account.profile``);
``emailVerified`` is the AND of ``is_email_valid`` and ``is_email_verified``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


def _map(p: dict[str, Any]) -> OAuthUserInfo:
    account = p.get("kakao_account") or {}
    profile = account.get("profile") or {}
    return OAuthUserInfo(
        id=str(p.get("id")),
        name=profile.get("nickname") or account.get("name") or "",
        email=account.get("email"),
        image=profile.get("profile_image_url") or profile.get("thumbnail_image_url"),
        email_verified=bool(account.get("is_email_valid"))
        and bool(account.get("is_email_verified")),
        raw=p,
    )


@dataclass
class Kakao(ProviderConfig):
    provider_id: str = "kakao"
    authorization_endpoint: str = "https://kauth.kakao.com/oauth/authorize"
    token_endpoint: str = "https://kauth.kakao.com/oauth/token"
    userinfo_endpoint: str = "https://kapi.kakao.com/v2/user/me"
    scopes: list[str] = field(
        default_factory=lambda: ["account_email", "profile_image", "profile_nickname"]
    )

    def __post_init__(self) -> None:
        if self.profile_mapper is None:
            self.profile_mapper = _map
