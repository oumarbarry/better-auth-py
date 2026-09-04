"""Atlassian — port of ``social-providers/atlassian.ts``.

Standard OIDC-shaped: PKCE (S256), ``audience=api.atlassian.com`` on the authorize URL,
bearer-token userinfo at ``api.atlassian.com/me``. ``emailVerified`` is always ``False``
(Atlassian's ``/me`` doesn't expose a verification flag).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


def _map(p: dict[str, Any]) -> OAuthUserInfo:
    return OAuthUserInfo(
        id=str(p.get("account_id") or ""),
        email=p.get("email"),
        name=p.get("name") or "",
        image=p.get("picture"),
        email_verified=False,
        raw=p,
    )


@dataclass
class Atlassian(ProviderConfig):
    provider_id: str = "atlassian"
    authorization_endpoint: str = "https://auth.atlassian.com/authorize"
    token_endpoint: str = "https://auth.atlassian.com/oauth/token"
    userinfo_endpoint: str = "https://api.atlassian.com/me"
    scopes: list[str] = field(default_factory=lambda: ["read:jira-user", "offline_access"])
    use_pkce: bool = True
    authorize_params: dict[str, str] = field(
        default_factory=lambda: {"audience": "api.atlassian.com"}
    )

    def __post_init__(self) -> None:
        if self.profile_mapper is None:
            self.profile_mapper = _map
