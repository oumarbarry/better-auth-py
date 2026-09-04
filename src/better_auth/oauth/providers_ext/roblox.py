"""Roblox provider (port of ``social-providers/roblox.ts``).

TS builds the authorize URL by hand (raw string interpolation); the Python port reuses
the shared builder instead since the *values* are identical — the base builder's default
``scope_joiner=" "`` and ``urlencode`` (which encodes a literal space as ``+``, stdlib
``quote_plus`` default) already produce Roblox's ``scope=openid+profile`` byte-for-byte,
and the non-default ``prompt`` param is just the generic ``authorize_params`` passthrough.
No functional divergence, less code (ladder rung 2 — reuse what's already here).

Roblox never returns an email/``email_verified`` claim; TS maps ``email`` to the
username (``preferred_username``) as a placeholder and hardcodes ``emailVerified: false``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


@dataclass
class Roblox(ProviderConfig):
    provider_id: str = "roblox"
    authorization_endpoint: str = "https://apis.roblox.com/oauth/v1/authorize"
    token_endpoint: str = "https://apis.roblox.com/oauth/v1/token"
    userinfo_endpoint: str = "https://apis.roblox.com/oauth/v1/userinfo"
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile"])
    authorize_params: dict[str, str] = field(
        default_factory=lambda: {"prompt": "select_account consent"}
    )

    def map_profile(self, profile: dict[str, Any]) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(profile["sub"]),
            email=profile.get("preferred_username"),
            name=profile.get("nickname") or profile.get("preferred_username") or "",
            image=profile.get("picture"),
            email_verified=False,
            raw=profile,
        )
