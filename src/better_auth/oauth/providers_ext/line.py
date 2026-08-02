"""LINE Login v2.1 — port of ``social-providers/line.ts``.

PKCE (S256). Userinfo prefers the ``id_token`` (decoded, no network call) and falls back to
the userinfo endpoint. ``verifyIdToken`` does **not** use JWKS — it POSTs to LINE's own
``/oauth2/v2.1/verify`` endpoint and checks ``aud``/``nonce`` (per TS). LINE never exposes an
email-verification flag, so ``emailVerified`` is always ``False``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import jwt

from ..machinery import get_primary_client_id, oauth_fetch
from ..models import OAuthTokens, OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

    from ...types import Ctx

_VERIFY_ENDPOINT = "https://api.line.me/oauth2/v2.1/verify"


def _map(p: dict[str, Any]) -> OAuthUserInfo:
    return OAuthUserInfo(
        id=str(p.get("sub") or p.get("userId") or ""),
        name=p.get("name") or p.get("displayName") or "",
        email=p.get("email"),
        image=p.get("picture") or p.get("pictureUrl"),
        email_verified=False,
        raw=p,
    )


@dataclass
class Line(ProviderConfig):
    provider_id: str = "line"
    authorization_endpoint: str = "https://access.line.me/oauth2/v2.1/authorize"
    token_endpoint: str = "https://api.line.me/oauth2/v2.1/token"
    userinfo_endpoint: str = "https://api.line.me/oauth2/v2.1/userinfo"
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    use_pkce: bool = True
    disable_id_token_sign_in: bool = False

    def __post_init__(self) -> None:
        if self.profile_mapper is None:
            self.profile_mapper = _map
        if self.id_token_mapper is None:
            self.id_token_mapper = _map

    @property
    def supports_id_token(self) -> bool:
        # LINE verifies via its own /verify endpoint (no jwks_url), so gate on the opt-out.
        return not self.disable_id_token_sign_in

    async def verify_id_token(
        self,
        http: httpx.AsyncClient,
        token: str,
        nonce: str | None = None,
        ctx: Ctx | None = None,
    ) -> dict[str, Any] | None:
        if self.disable_id_token_sign_in:
            return None
        body = {"id_token": token, "client_id": get_primary_client_id(self.client_id)}
        if nonce:
            body["nonce"] = nonce
        response = await oauth_fetch(
            http,
            "POST",
            _VERIFY_ENDPOINT,
            data=body,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        if response.status_code != 200:
            return None
        data = response.json()
        if data.get("aud") != get_primary_client_id(self.client_id):
            return None
        if data.get("nonce") and data.get("nonce") != nonce:
            return None
        return data

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        if tokens.id_token:
            try:
                claims = jwt.decode(tokens.id_token, options={"verify_signature": False})
                return self.map_profile(claims)
            except jwt.PyJWTError:
                pass
        response = await oauth_fetch(
            http,
            "GET",
            self.userinfo_endpoint,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        response.raise_for_status()
        return self.map_profile(response.json())
