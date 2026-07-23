"""Slack provider (port of ``social-providers/slack.ts``), OIDC (``openid.connect``) flavor.

TS hand-builds the authorize URL via ``URLSearchParams`` instead of the shared helper, but
the params (scope/response_type/client_id/redirect_uri/state, no PKCE, no extras) are the
exact shape the base builder already produces — reused as-is (ladder rung 2).

Slack's userinfo profile keys most fields under literal ``https://slack.com/...`` URIs
(OIDC namespaced custom claims) rather than plain names — the only real quirk, handled in
``map_profile``. Falls back to the 512px team-scoped avatar when ``picture`` is absent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


@dataclass
class Slack(ProviderConfig):
    provider_id: str = "slack"
    authorization_endpoint: str = "https://slack.com/openid/connect/authorize"
    token_endpoint: str = "https://slack.com/api/openid.connect.token"
    userinfo_endpoint: str = "https://slack.com/api/openid.connect.userInfo"
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])

    def map_profile(self, profile: dict[str, Any]) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(profile["https://slack.com/user_id"]),
            email=profile.get("email"),
            name=profile.get("name") or "",
            image=profile.get("picture") or profile.get("https://slack.com/user_image_512"),
            email_verified=bool(profile.get("email_verified", False)),
            raw=profile,
        )
