"""TikTok OAuth2 provider — port of ``social-providers/tiktok.ts``.

Quirks vs. the OAuth2 norm:
- ``client_key`` replaces ``client_id`` everywhere (auth URL, token exchange, refresh);
  TikTok never uses ``client_id``.
- Authorize URL is hand-built with non-standard param ordering and **comma**-joined
  scopes (not the shared builder).
- Exchange and refresh authenticate through a custom strategy that puts ``client_key``
  and ``client_secret`` in the body.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

from ..machinery import (
    RESERVED_AUTHORIZATION_PARAMS,
    TokenEndpointAuth,
    create_placeholder_email,
    exchange_code,
    oauth_fetch,
    refresh_access_token,
)
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
        additional_params: dict[str, str] | None = None,
    ) -> str:
        scopes = [] if self.disable_default_scope else list(self.scopes)
        scopes += list(extra_scopes or [])
        params = {
            "scope": self.scope_joiner.join(dict.fromkeys(scopes)),
            "response_type": "code",
            "client_key": self.client_key,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        # tiktok.ts:163-169 (e7eb45b06): extras never replace a reserved key or client_key
        for key, value in {**self.authorize_params, **(additional_params or {})}.items():
            if key not in RESERVED_AUTHORIZATION_PARAMS and key != "client_key":
                params[key] = value
        return f"{self.authorization_endpoint}?{urlencode(params)}"

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
            client_secret="",
            code_verifier=code_verifier,  # tiktok.ts:173-177 forwards it
            token_endpoint_auth=self._token_endpoint_auth(),
        )

    async def refresh(self, http: httpx.AsyncClient, refresh_token: str) -> OAuthTokens:
        return await refresh_access_token(
            http,
            token_endpoint=self.token_endpoint,
            refresh_token=refresh_token,
            client_id="",
            client_secret="",
            token_endpoint_auth=self._token_endpoint_auth(),
        )

    def _token_endpoint_auth(self) -> TokenEndpointAuth:
        """TS v1.7.6 tiktok.ts:141-147 (baa08f4ee): every token request carries
        ``client_key`` + ``client_secret`` in the body through a custom strategy."""

        def customize(request: dict[str, Any]) -> None:
            request["body"]["client_key"] = self.client_key
            request["body"]["client_secret"] = self.client_secret

        return TokenEndpointAuth(method="custom", customize_request=customize)

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
            # tiktok.ts:219-224 (b4ad5a110)
            email=user.get("email")
            or create_placeholder_email(identifier=str(user["open_id"]), namespace="tiktok"),
            name=user.get("display_name") or user.get("username") or "",
            image=user.get("avatar_large_url"),
            email_verified=False,
            raw=profile,
        )
