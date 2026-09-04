"""GitLab — ``packages/core/src/social-providers/gitlab.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
- Self-hosted ``issuer`` overrides the base host for all three endpoints (default
  ``https://gitlab.com``), run through TS's ``cleanDoubleSlashes`` (collapses repeated
  ``/`` within each ``://``-separated segment — guards against a trailing-slash issuer).
- ``getUserInfo`` rejects (raises) when the account ``state`` isn't ``"active"`` or the
  account is ``locked`` — GitLab-specific account-health gate before sign-in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..machinery import OAuthFetchError, oauth_fetch
from ..models import OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

    from ..models import OAuthTokens

_MULTI_SLASH = re.compile(r"/{2,}")


def _clean_double_slashes(url: str) -> str:
    return "://".join(_MULTI_SLASH.sub("/", part) for part in url.split("://"))


def _gitlab_endpoints(issuer: str) -> tuple[str, str, str]:
    base = issuer or "https://gitlab.com"
    return (
        _clean_double_slashes(f"{base}/oauth/authorize"),
        _clean_double_slashes(f"{base}/oauth/token"),
        _clean_double_slashes(f"{base}/api/v4/user"),
    )


@dataclass
class Gitlab(ProviderConfig):
    provider_id: str = "gitlab"
    scopes: list[str] = field(default_factory=lambda: ["read_user"])
    use_pkce: bool = True
    #: self-hosted GitLab base URL; default `https://gitlab.com`
    issuer: str = ""

    def __post_init__(self) -> None:
        auth_ep, token_ep, userinfo_ep = _gitlab_endpoints(self.issuer)
        self.authorization_endpoint = auth_ep
        self.token_endpoint = token_ep
        self.userinfo_endpoint = userinfo_ep

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        response.raise_for_status()
        profile = response.json()
        if profile.get("state") != "active" or profile.get("locked"):
            raise OAuthFetchError("gitlab account is not active")
        return self.map_profile(profile)

    def map_profile(self, profile: dict) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(profile.get("id") or ""),
            email=profile.get("email"),
            name=profile.get("name") or profile.get("username") or "",
            image=profile.get("avatar_url"),
            email_verified=bool(profile.get("email_verified", False)),
            raw=profile,
        )
