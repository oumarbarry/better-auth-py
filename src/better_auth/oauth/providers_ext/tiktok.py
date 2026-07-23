"""TikTok OAuth2 provider — port of ``social-providers/tiktok.ts``.

Quirks vs. the OAuth2 norm:
- ``client_key`` replaces ``client_id`` everywhere (auth URL, token exchange, refresh);
  TikTok never uses ``client_id``.
- Authorize URL is hand-built with non-standard param ordering and **comma**-joined
  scopes (not the shared builder).
- Refresh sends ``client_key`` as an extra POST param.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import quote

from ..machinery import exchange_code, oauth_fetch, refresh_access_token
from ..models import OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

    from ..models import OAuthTokens


@dataclass
class TikTok(ProviderConfig):
    provider_id: str = "tiktok"
    #: TikTok uses client_key, not client_id (TS ``clientId?: never``).
    client_id: str | list[str] = ""
    client_key: str = ""
    authorization_endpoint: str = "https://www.tiktok.com/v2/auth/authorize"
    token_endpoint: str = "https://open.tiktokapis.com/v2/oauth/token/"
    userinfo_endpoint: str = "https://open.tiktokapis.com/v2/user/info/"
    scopes: list[str] = field(default_factory=lambda: ["user.info.profile"])
    scope_joiner: str = ","

    def authorization_url(
        self,
        *,
        state: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        extra_scopes: list[str] | None = None,
        login_hint: str | None = None,
        nonce: str | None = None,
    ) -> str:
        scopes = [] if self.disable_default_scope else list(self.scopes)
        scopes += list(extra_scopes or [])
        scope = self.scope_joiner.join(dict.fromkeys(scopes))
        return (
            f"{self.authorization_endpoint}?scope={scope}"
            f"&response_type=code&client_key={self.client_key}"
            f"&redirect_uri={quote(redirect_uri, safe='')}&state={state}"
        )

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
            client_id="",
            client_secret=self.client_secret,
            client_key=self.client_key,
            authentication="post",
        )

    async def refresh(self, http: httpx.AsyncClient, refresh_token: str) -> OAuthTokens:
        return await refresh_access_token(
            http,
            token_endpoint=self.token_endpoint,
            refresh_token=refresh_token,
            client_id="",
            client_secret=self.client_secret,
            authentication="post",
            extra_params={"client_key": self.client_key},
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        fields = ["open_id", "avatar_large_url", "display_name", "username"]
        resp = await oauth_fetch(
            http,
            "GET",
            f"{self.userinfo_endpoint}?fields={','.join(fields)}",
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        resp.raise_for_status()
        profile = resp.json()
        user = profile["data"]["user"]
        return OAuthUserInfo(
            id=str(user["open_id"]),
            email=user.get("email") or user.get("username"),
            name=user.get("display_name") or user.get("username") or "",
            image=user.get("avatar_large_url"),
            email_verified=False,
            raw=profile,
        )
