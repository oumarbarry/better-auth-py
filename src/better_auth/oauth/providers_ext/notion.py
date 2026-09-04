"""Notion provider (port of ``social-providers/notion.ts``).

Quirks vs. the standard shape:
- No default scopes at all (Notion's permission model lives in the integration's
  capabilities, not OAuth scopes).
- ``owner=user`` is a mandatory authorize-URL param (``additionalParams`` in TS) —
  modeled here via the generic ``authorize_params`` passthrough.
- Token endpoint uses ``basic`` client auth (RFC 7617) — Notion rejects base64url.
- Userinfo is a single ``GET /v1/users/me`` call requiring a ``Notion-Version`` header,
  with the actual profile nested three levels down (``bot.owner.user``) because the
  endpoint describes the *integration*, and for a user-facing OAuth integration that
  bot is "owned" by the authorizing user. ``email`` may be entirely absent (bot
  integrations, or a user profile with no verified email on file) — mapped to ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..machinery import OAuthFetchError, oauth_fetch
from ..models import OAuthTokens, OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx


@dataclass
class Notion(ProviderConfig):
    provider_id: str = "notion"
    authorization_endpoint: str = "https://api.notion.com/v1/oauth/authorize"
    token_endpoint: str = "https://api.notion.com/v1/oauth/token"
    userinfo_endpoint: str = "https://api.notion.com/v1/users/me"
    scopes: list[str] = field(default_factory=list)
    authentication: str = "basic"
    authorize_params: dict[str, str] = field(default_factory=lambda: {"owner": "user"})

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={
                "authorization": f"Bearer {tokens.access_token}",
                "notion-version": "2022-06-28",
            },
        )
        response.raise_for_status()
        payload = response.json()
        profile: dict[str, Any] | None = (payload.get("bot") or {}).get("owner", {}).get("user")
        if not profile:
            raise OAuthFetchError("notion: userinfo response is missing bot.owner.user")
        person = profile.get("person") or {}
        return OAuthUserInfo(
            id=str(profile["id"]),
            email=person.get("email"),
            name=profile.get("name") or "",
            image=profile.get("avatar_url"),
            email_verified=False,
            raw=profile,
        )
