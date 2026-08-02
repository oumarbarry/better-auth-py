"""Linear — ``packages/core/src/social-providers/linear.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
- No PKCE: TS's ``createAuthorizationURL``/``validateAuthorizationCode`` calls for Linear
  never forward ``codeVerifier`` (``use_pkce`` stays ``False``, the dataclass default).
- Userinfo is a GraphQL query (``POST /graphql`` with a ``viewer { ... }`` query), not a
  REST bearer-token GET.
- Linear never returns an ``email_verified`` claim; TS hardcodes ``emailVerified: false``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..machinery import OAuthFetchError, oauth_fetch
from ..models import OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

    from ..models import OAuthTokens

_VIEWER_QUERY = """
    query {
        viewer {
            id
            name
            email
            avatarUrl
            active
            createdAt
            updatedAt
        }
    }
"""


@dataclass
class Linear(ProviderConfig):
    provider_id: str = "linear"
    authorization_endpoint: str = "https://linear.app/oauth/authorize"
    token_endpoint: str = "https://api.linear.app/oauth/token"
    userinfo_endpoint: str = "https://api.linear.app/graphql"
    scopes: list[str] = field(default_factory=lambda: ["read"])

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "POST",
            self.userinfo_endpoint,
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {tokens.access_token}",
            },
            json={"query": _VIEWER_QUERY},
        )
        response.raise_for_status()
        viewer = (response.json().get("data") or {}).get("viewer")
        if not viewer:
            raise OAuthFetchError("linear graphql response missing viewer")
        return self.map_profile(viewer)

    def map_profile(self, profile: dict) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(profile.get("id") or ""),
            email=profile.get("email"),
            name=profile.get("name") or "",
            image=profile.get("avatarUrl"),
            email_verified=False,
            raw=profile,
        )
