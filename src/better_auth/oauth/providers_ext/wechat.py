"""WeChat OAuth2 provider — port of ``social-providers/wechat.ts``.

The most non-standard provider:
- ``appid``/``secret`` replace ``client_id``/``client_secret`` everywhere.
- Authorize URL is hand-built (``appid``, ``#wechat_redirect`` fragment).
- Token exchange **and** refresh are ``GET`` with query-string params (not POST body).
- The userinfo endpoint needs the ``openid`` returned *alongside* the access token,
  so it is stashed on ``OAuthTokens.raw`` and read back in ``fetch_user``.
- WeChat never returns an email; a stable ``@wechat.placeholder.invalid`` placeholder
  is synthesized so the (email-required) callback does not reject the sign-in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from ...session import utcnow
from ..machinery import (
    RESERVED_AUTHORIZATION_PARAMS,
    OAuthFetchError,
    create_placeholder_email,
    oauth_fetch,
)
from ..models import OAuthTokens, OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx


@dataclass
class WeChat(ProviderConfig):
    provider_id: str = "wechat"
    scopes: list[str] = field(default_factory=lambda: ["snsapi_login"])
    scope_joiner: str = ","
    supports_refresh: bool = True
    #: UI language for the login page ("cn" | "en").
    lang: str = "cn"

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
            "appid": self.client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "lang": self.lang,
        }
        # wechat.ts:78-85 (e7eb45b06): extras never replace a reserved key or appid
        for key, value in {**self.authorize_params, **(additional_params or {})}.items():
            if key not in RESERVED_AUTHORIZATION_PARAMS and key != "appid":
                params[key] = value
        query = urlencode(params)
        return f"https://open.weixin.qq.com/connect/qrconnect?{query}#wechat_redirect"

    async def exchange(
        self,
        http: httpx.AsyncClient,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> OAuthTokens:
        params = urlencode(
            {
                "appid": self.client_id,
                "secret": self.client_secret,
                "code": code,
                "grant_type": "authorization_code",
            }
        )
        resp = await oauth_fetch(
            http,
            "GET",
            f"https://api.weixin.qq.com/sns/oauth2/access_token?{params}",
        )
        data = resp.json()
        if data.get("errcode") or not data.get("access_token"):
            raise OAuthFetchError(
                f"Failed to validate authorization code: {data.get('errmsg', 'Unknown error')}"
            )
        return self._tokens(data)

    async def refresh(self, http: httpx.AsyncClient, refresh_token: str) -> OAuthTokens:
        params = urlencode(
            {
                "appid": self.client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }
        )
        resp = await oauth_fetch(
            http,
            "GET",
            f"https://api.weixin.qq.com/sns/oauth2/refresh_token?{params}",
        )
        data = resp.json()
        if data.get("errcode") or not data.get("access_token"):
            raise OAuthFetchError(
                f"Failed to refresh access token: {data.get('errmsg', 'Unknown error')}"
            )
        return self._tokens(data)

    @staticmethod
    def _tokens(data: dict) -> OAuthTokens:
        scope = data.get("scope") or ""
        expires_in = data.get("expires_in")
        return OAuthTokens(
            token_type="Bearer",
            access_token=data.get("access_token"),
            refresh_token=data.get("refresh_token"),
            scope=scope,
            scopes=scope.split(",") if scope else [],
            access_token_expires_at=(
                utcnow() + timedelta(seconds=int(expires_in)) if expires_in else None
            ),
            raw=data,
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        openid = tokens.raw.get("openid")
        if not openid:
            raise OAuthFetchError("WeChat token response is missing openid")

        params = urlencode(
            {
                "access_token": tokens.access_token or "",
                "openid": openid,
                "lang": "zh_CN",
            }
        )
        resp = await oauth_fetch(http, "GET", f"https://api.weixin.qq.com/sns/userinfo?{params}")
        profile = resp.json()
        if profile.get("errcode"):
            raise OAuthFetchError(
                f"WeChat userinfo failed: {profile.get('errmsg', 'Unknown error')}"
            )

        # wechat.ts:63 accountSubject reads the profile only; the placeholder email also
        # falls back to the token's openid (wechat.ts:209-218, b4ad5a110)
        subject = profile.get("unionid") or profile.get("openid") or ""
        return OAuthUserInfo(
            id=str(subject),
            email=profile.get("email")
            or create_placeholder_email(identifier=str(subject or openid), namespace="wechat"),
            name=profile.get("nickname") or "",
            image=profile.get("headimgurl"),
            email_verified=False,
            raw=profile,
        )
