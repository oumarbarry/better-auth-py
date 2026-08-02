"""Apple — ports ``social-providers/apple.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * ``createAuthorizationURL`` uses ``response_type=code id_token`` +
    ``response_mode=form_post`` (Apple POSTs the callback), and requires
    ``clientId``/``clientSecret`` up front. It also forwards the PKCE
    ``code_challenge`` so the callback exchange's ``code_verifier`` matches
    (TS ``apple.ts`` ``createAuthorizationURL({... codeVerifier })``).
  * ``verifyIdToken`` accepts the nonce either raw **or** as ``sha256hex(nonce)``
    (Apple's native SDKs sometimes hash it client-side), and coerces the
    ``email_verified``/``is_private_email`` claims to real booleans.
  * Audience for id-token verification falls back
    ``audience`` → ``appBundleIdentifier`` → ``clientId`` (native iOS uses the
    bundle id as the token audience, not the service id).
  * User info comes from decoding the (unverified) id token — no userinfo endpoint.
  * ``generate_client_secret`` builds the ES256 JWT Apple wants as ``clientSecret``
    (docs' ``generateAppleClientSecret`` — not in the TS provider file, but the
    canonical Apple flow; cryptography/pyjwt do the ES256 signing).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import jwt

from ..machinery import OAuthFetchError, build_authorization_url, get_primary_client_id
from ..models import OAuthUserInfo
from ..providers import ProviderConfig
from ..verify import verify_id_token as _verify_id_token

if TYPE_CHECKING:
    import httpx

    from ...types import Ctx
    from ..models import OAuthTokens

_APPLE_ISSUER = "https://appleid.apple.com"
#: Apple rejects client-secret JWTs expiring more than six months out.
_SIX_MONTHS = 180 * 24 * 60 * 60


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


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _nonce_matches(jwt_nonce: Any, nonce: str) -> bool:
    """Port of ``nonceMatches`` — raw match, or the token carries ``sha256hex(nonce)``."""
    if not isinstance(jwt_nonce, str):
        return False
    if jwt_nonce == nonce:
        return True
    return jwt_nonce == _sha256_hex(nonce)


def _email_verified(value: Any) -> bool:
    """``email_verified`` may arrive as a bool or the string ``"true"``/``"false"``."""
    if isinstance(value, str):
        return value == "true"
    return bool(value)


@dataclass
class Apple(ProviderConfig):
    provider_id: str = "apple"
    authorization_endpoint: str = "https://appleid.apple.com/auth/authorize"
    token_endpoint: str = "https://appleid.apple.com/auth/token"
    scopes: list[str] = field(default_factory=lambda: ["email", "name"])
    jwks_url: str = "https://appleid.apple.com/auth/keys"
    issuers: list[str] = field(default_factory=lambda: [_APPLE_ISSUER])
    #: native iOS uses the app bundle id as the id-token audience, not the service id.
    app_bundle_identifier: str | None = None
    #: explicit accepted audience(s); overrides ``app_bundle_identifier``/``client_id``.
    audience: str | list[str] | None = None
    disable_id_token_sign_in: bool = False
    #: Apple accepts (and the callback exchange requires) an S256 PKCE challenge.
    use_pkce: bool = True

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
        if not get_primary_client_id(self.client_id) or not self.client_secret:
            raise ValueError("CLIENT_ID_AND_SECRET_REQUIRED")
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
            response_type="code id_token",
            response_mode="form_post",
            code_verifier=code_verifier if self.use_pkce else None,
            login_hint=login_hint,
            additional_params=self.authorize_params or None,
        )

    def _effective_audience(self) -> str | list[str]:
        if self.audience:  # non-empty str or non-empty list
            return self.audience
        if self.app_bundle_identifier:
            return self.app_bundle_identifier
        return self.client_id

    async def verify_id_token(
        self,
        http: httpx.AsyncClient,
        token: str,
        nonce: str | None = None,
        ctx: Ctx | None = None,
    ) -> dict[str, Any] | None:
        if self.disable_id_token_sign_in:
            return None
        claims = await _verify_id_token(
            http,
            token,
            jwks_uri=self.jwks_url,
            audience=self._effective_audience(),
            issuers=self.issuers,
            nonce=None,  # Apple's nonce needs the sha256 fallback below, not plain equality
            max_age=3600,
        )
        if claims is None:
            return None
        for field_name in ("email_verified", "is_private_email"):
            if claims.get(field_name) is not None:
                claims[field_name] = bool(claims[field_name])
        if nonce and not _nonce_matches(claims.get("nonce"), nonce):
            return None
        return claims

    def user_info_from_id_token(self, claims: dict[str, Any]) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(claims.get("sub") or ""),
            email=claims.get("email"),
            name=claims.get("name") or "",
            image=claims.get("picture"),
            email_verified=_email_verified(claims.get("email_verified")),
            raw=claims,
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        if not tokens.id_token:
            raise OAuthFetchError("Apple getUserInfo requires an id_token")
        return self.user_info_from_id_token(_decode_unverified(tokens.id_token))

    @staticmethod
    def generate_client_secret(
        *,
        client_id: str,
        team_id: str,
        key_id: str,
        private_key: str,
        expires_in: int = _SIX_MONTHS,
    ) -> str:
        """Build the ES256 JWT Apple accepts as the ``clientSecret``.

        ``private_key`` is the PEM contents of the ``.p8`` key from the Apple
        developer portal. Claims mirror the docs' ``generateAppleClientSecret``:
        ``iss=team_id``, ``sub=client_id``, ``aud=appleid.apple.com``.
        """
        now = int(time.time())
        return jwt.encode(
            {
                "iss": team_id,
                "iat": now,
                "exp": now + expires_in,
                "aud": _APPLE_ISSUER,
                "sub": client_id,
            },
            private_key,
            algorithm="ES256",
            headers={"kid": key_id, "alg": "ES256"},
        )
