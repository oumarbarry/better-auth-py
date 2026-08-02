"""Twitch — ports ``social-providers/twitch.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * No PKCE (Twitch's ``createAuthorizationURL``/``validateAuthorizationCode`` never
    forward ``codeVerifier``).
  * Sends an OIDC ``claims`` param requesting extra id-token claims (the only provider
    that does) — defaults to ``email, email_verified, preferred_username, picture``,
    overridable via ``options.claims``.
  * User info comes from decoding the (unverified, per TS's ``decodeJwt``) id token —
    no network userinfo call at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import jwt

from ..machinery import OAuthFetchError, build_authorization_url
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


@dataclass
class Twitch(ProviderConfig):
    provider_id: str = "twitch"
    authorization_endpoint: str = "https://id.twitch.tv/oauth2/authorize"
    token_endpoint: str = "https://id.twitch.tv/oauth2/token"
    scopes: list[str] = field(default_factory=lambda: ["user:read:email", "openid"])
    #: extra OIDC id-token claims requested via the ``claims`` authorize param.
    claims: list[str] = field(
        default_factory=lambda: ["email", "email_verified", "preferred_username", "picture"]
    )

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
        deduped = list(dict.fromkeys(scopes))
        return build_authorization_url(
            authorization_endpoint=self.authorization_endpoint,
            client_id=self.client_id,
            state=state,
            redirect_uri=redirect_uri,
            scopes=deduped or None,
            scope_joiner=self.scope_joiner,
            # Twitch never forwards codeVerifier — no PKCE.
            code_verifier=None,
            login_hint=login_hint,
            claims=self.claims,
            additional_params=self.authorize_params or None,
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        if not tokens.id_token:
            raise OAuthFetchError("Twitch getUserInfo requires an id_token")
        profile = _decode_unverified(tokens.id_token)
        return self.map_profile(profile)

    def map_profile(self, profile: dict[str, Any]) -> OAuthUserInfo:
        if self.profile_mapper:
            return self.profile_mapper(profile)
        return OAuthUserInfo(
            id=str(profile.get("sub") or ""),
            email=profile.get("email"),
            name=profile.get("preferred_username") or "",
            image=profile.get("picture"),
            email_verified=bool(profile.get("email_verified", False)),
            raw=profile,
        )
