"""Paybin — ports ``social-providers/paybin.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * Configurable ``issuer`` (default ``https://idp.paybin.io``) — authorize/token
    endpoints are derived from it unless explicitly overridden.
  * ``createAuthorizationURL`` throws if ``clientId``/``clientSecret`` is missing (not
    deferred to the token exchange) and if no ``codeVerifier`` is available (PKCE
    required, like Vercel).
  * User info comes from decoding the (unverified, per TS's ``decodeJwt``) id token —
    no network userinfo call at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import jwt

from ..machinery import OAuthFetchError
from ..models import OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

    from ..models import OAuthTokens


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


def _paybin_mapper(profile: dict[str, Any]) -> OAuthUserInfo:
    return OAuthUserInfo(
        id=str(profile.get("sub") or ""),
        email=profile.get("email"),
        name=profile.get("name") or profile.get("preferred_username") or "",
        image=profile.get("picture"),
        email_verified=bool(profile.get("email_verified", False)),
        raw=profile,
    )


@dataclass
class Paybin(ProviderConfig):
    provider_id: str = "paybin"
    issuer: str = "https://idp.paybin.io"
    scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])
    use_pkce: bool = True

    def __post_init__(self) -> None:
        if not self.authorization_endpoint:
            self.authorization_endpoint = f"{self.issuer}/oauth2/authorize"
        if not self.token_endpoint:
            self.token_endpoint = f"{self.issuer}/oauth2/token"
        if self.profile_mapper is None:
            self.profile_mapper = _paybin_mapper

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
        if not self.client_id or not self.client_secret:
            raise ValueError("CLIENT_ID_AND_SECRET_REQUIRED")
        if not code_verifier:
            raise ValueError("codeVerifier is required for Paybin")
        return super().authorization_url(
            state=state,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            extra_scopes=extra_scopes,
            login_hint=login_hint,
            nonce=nonce,
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        if not tokens.id_token:
            raise OAuthFetchError("Paybin getUserInfo requires an id_token")
        profile = _decode_unverified(tokens.id_token)
        return self.map_profile(profile)
