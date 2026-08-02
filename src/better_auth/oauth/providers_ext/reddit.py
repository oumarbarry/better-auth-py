"""Reddit provider (port of ``social-providers/reddit.ts``).

Quirks vs. the standard shape (Reddit's API is unusually hostile to default HTTP clients):
- Token exchange bypasses the shared body-builder's normal ``accept: application/json`` —
  Reddit wants ``basic`` client auth (RFC 7617) plus ``accept: text/plain`` and a mandatory
  non-default ``User-Agent`` (Reddit blocks/rate-limits requests carrying no or a generic
  UA). Still routed through :func:`exchange_code`/:func:`oauth_fetch` for the SSRF guard.
- Userinfo (``GET /api/v1/me``) also requires the same ``User-Agent`` header.
- The ``identity`` scope never returns an email — a stable, non-routable placeholder
  (``{id}@reddit.invalid``, RFC 2606) is synthesized so the (email-required) callback flow
  doesn't reject the sign-in; always unverified.
- ``duration`` (Reddit's ``permanent``/``temporary`` authorize param, for refresh-token
  issuance) isn't a named kwarg here — pass it via the inherited ``authorize_params``
  passthrough, e.g. ``Reddit(..., authorize_params={"duration": "permanent"})``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..machinery import exchange_code, oauth_fetch
from ..models import OAuthTokens, OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

_USER_AGENT = "better-auth-py"


@dataclass
class Reddit(ProviderConfig):
    provider_id: str = "reddit"
    authorization_endpoint: str = "https://www.reddit.com/api/v1/authorize"
    token_endpoint: str = "https://www.reddit.com/api/v1/access_token"
    userinfo_endpoint: str = "https://oauth.reddit.com/api/v1/me"
    scopes: list[str] = field(default_factory=lambda: ["identity"])
    authentication: str = "basic"

    async def exchange(
        self,
        http: httpx.AsyncClient,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> OAuthTokens:
        return await exchange_code(
            http,
            token_endpoint=self.token_endpoint,
            code=code,
            redirect_uri=redirect_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
            authentication="basic",
            headers={"accept": "text/plain", "user-agent": _USER_AGENT},
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={
                "authorization": f"Bearer {tokens.access_token}",
                "user-agent": _USER_AGENT,
            },
        )
        response.raise_for_status()
        profile = response.json()
        image = profile.get("icon_img")
        if image:
            image = image.split("?")[0]
        return OAuthUserInfo(
            id=str(profile["id"]),
            email=f"{profile['id']}@reddit.invalid",
            name=profile.get("name") or "",
            image=image,
            email_verified=False,
            raw=profile,
        )
