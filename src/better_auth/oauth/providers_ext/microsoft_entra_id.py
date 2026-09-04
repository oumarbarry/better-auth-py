"""Microsoft Entra ID — ports ``social-providers/microsoft-entra-id.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * Endpoints are built from a configurable ``authority`` (trailing slashes trimmed)
    and ``tenant`` (``common`` by default). No client secret required — public
    clients (SPA/native + PKCE) are supported.
  * Multi-tenant issuer validation is hand-rolled: ``common``/``organizations``/
    ``consumers`` can't have a single expected ``iss``, so jose's issuer check is
    skipped for them and the token's own ``tid`` is cross-checked against ``iss``,
    plus the organizations (not the fixed consumer tenant) / consumers (must be it)
    account-class rules.
  * Profile photo is fetched from Microsoft Graph and inlined as a ``data:`` URI.
  * ``email_verified`` is defaulted from ``verified_primary_email`` /
    ``verified_secondary_email`` when the optional claim is absent.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import jwt
from jwt import PyJWK

from ..machinery import OAuthFetchError, oauth_fetch
from ..models import OAuthUserInfo
from ..providers import ProviderConfig
from ..verify import _cache as _jwks_cache

if TYPE_CHECKING:
    import httpx

    from ...types import Ctx
    from ..models import OAuthTokens

#: Fixed ``tid`` carried by every personal (consumer) Microsoft account token.
_CONSUMER_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad"
_MULTI_TENANT = ("common", "organizations", "consumers")


def _decode_unverified(token: str) -> dict[str, Any]:
    """Mirror jose's ``decodeJwt`` — base64-decode the payload, no signature check."""
    return jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_aud": False,
            "verify_iss": False,
        },
    )


@dataclass
class MicrosoftEntraId(ProviderConfig):
    provider_id: str = "microsoft"
    scopes: list[str] = field(
        default_factory=lambda: [
            "openid",
            "profile",
            "email",
            "User.Read",
            "offline_access",
        ]
    )
    use_pkce: bool = True
    tenant_id: str | None = None
    authority: str | None = None
    profile_photo_size: int = 48
    disable_profile_photo: bool = False
    prompt: str | None = None
    disable_id_token_sign_in: bool = False

    def __post_init__(self) -> None:
        self._tenant = self.tenant_id or "common"
        authority = self.authority or "https://login.microsoftonline.com"
        while authority.endswith("/"):
            authority = authority[:-1]
        self._authority = authority
        self.authorization_endpoint = f"{authority}/{self._tenant}/oauth2/v2.0/authorize"
        self.token_endpoint = f"{authority}/{self._tenant}/oauth2/v2.0/token"
        self.jwks_url = f"{authority}/{self._tenant}/discovery/v2.0/keys"
        if self.prompt:
            self.authorize_params = {**self.authorize_params, "prompt": self.prompt}

    async def verify_id_token(
        self,
        http: httpx.AsyncClient,
        token: str,
        nonce: str | None = None,
        ctx: Ctx | None = None,
    ) -> dict[str, Any] | None:
        if self.disable_id_token_sign_in:
            return None
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            return None
        kid, alg = header.get("kid"), header.get("alg")
        if not kid or not alg:
            return None
        jwk = await _jwks_cache.find(http, self.jwks_url, kid)
        if jwk is None:
            return None
        try:
            key = PyJWK.from_dict(jwk).key
            decode_kwargs: dict[str, Any] = {
                "algorithms": [alg],
                "audience": self.client_id,
            }
            # Issuer varies per tenant for the multi-tenant endpoints — validate it
            # via jose only for a specific tenant; otherwise cross-check tid below.
            if self._tenant not in _MULTI_TENANT:
                decode_kwargs["issuer"] = f"{self._authority}/{self._tenant}/v2.0"
            claims = jwt.decode(token, key, **decode_kwargs)
        except jwt.PyJWTError:
            return None
        # maxTokenAge "1h"
        iat = claims.get("iat")
        if iat is None or time.time() - int(iat) > 3600:
            return None
        if nonce and claims.get("nonce") != nonce:
            return None
        # Explicit tenant binding for the multi-tenant endpoints.
        tid = claims.get("tid")
        if not isinstance(tid, str) or claims.get("iss") != f"{self._authority}/{tid}/v2.0":
            return None
        if self._tenant == "organizations" and tid == _CONSUMER_TENANT_ID:
            return None
        if self._tenant == "consumers" and tid != _CONSUMER_TENANT_ID:
            return None
        return claims

    def _map(self, user: dict[str, Any]) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(user.get("sub") or ""),
            email=user.get("email"),
            name=user.get("name") or "",
            image=user.get("picture"),
            email_verified=self._email_verified(user),
            raw=user,
        )

    @staticmethod
    def _email_verified(user: dict[str, Any]) -> bool:
        verified = user.get("email_verified")
        if verified is not None:
            return bool(verified)
        email = user.get("email")
        return bool(
            email
            and (
                email in (user.get("verified_primary_email") or [])
                or email in (user.get("verified_secondary_email") or [])
            )
        )

    def user_info_from_id_token(self, claims: dict[str, Any]) -> OAuthUserInfo:
        return self._map(claims)

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        if not tokens.id_token:
            raise OAuthFetchError("Microsoft getUserInfo requires an id_token")
        user = _decode_unverified(tokens.id_token)
        if not self.disable_profile_photo and tokens.access_token:
            size = self.profile_photo_size or 48
            try:
                response = await oauth_fetch(
                    http,
                    "GET",
                    f"https://graph.microsoft.com/v1.0/me/photos/{size}x{size}/$value",
                    headers={"authorization": f"Bearer {tokens.access_token}"},
                )
                if response.status_code == 200:
                    encoded = base64.b64encode(response.content).decode()
                    user["picture"] = f"data:image/jpeg;base64, {encoded}"
            except Exception:  # best-effort — a photo failure never blocks sign-in
                pass
        return self._map(user)
