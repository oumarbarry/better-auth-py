"""PayPal — ports ``social-providers/paypal.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * ``environment`` (``sandbox`` default / ``live``) selects every endpoint host
    (authorize, token, userinfo, issuer, JWKS).
  * No OAuth2 scopes — permissions are configured in the PayPal dashboard, so the
    authorize URL carries an empty ``scope`` param.
  * Token exchange and refresh are hand-rolled: HTTP Basic auth + custom headers,
    and the exchange body deliberately omits ``code_verifier``.
  * Dual-algorithm id-token verification — ``RS256`` via the published JWKS, or
    ``HS256`` verified with the raw ``clientSecret`` as the HMAC key; any other alg
    is rejected.
  * ``getUserInfo`` cross-checks the userinfo ``sub``/``user_id`` against the id
    token's ``sub`` (OIDC UserInfo-to-IDToken binding).
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import jwt
from jwt import PyJWK

from ..machinery import OAuthFetchError, build_authorization_url, get_oauth2_tokens, oauth_fetch
from ..models import OAuthTokens, OAuthUserInfo
from ..providers import ProviderConfig
from ..verify import _cache as _jwks_cache

if TYPE_CHECKING:
    import httpx

#: alg allowlist advertised by PayPal's OpenID configuration.
_PAYPAL_ALGORITHMS = ("RS256", "HS256")


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
class Paypal(ProviderConfig):
    provider_id: str = "paypal"
    #: "sandbox" (default) or "live".
    environment: str = "sandbox"
    #: defined in TS for parity; not referenced by the provider flow.
    request_shipping_address: bool = False
    use_pkce: bool = True
    prompt: str | None = None
    disable_id_token_sign_in: bool = False

    def __post_init__(self) -> None:
        sandbox = self.environment == "sandbox"
        if sandbox:
            self.authorization_endpoint = "https://www.sandbox.paypal.com/signin/authorize"
            self.token_endpoint = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
            self.userinfo_endpoint = "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo"
            self._issuer = "https://www.sandbox.paypal.com"
            self.jwks_url = "https://api.sandbox.paypal.com/v1/oauth2/certs"
        else:
            self.authorization_endpoint = "https://www.paypal.com/signin/authorize"
            self.token_endpoint = "https://api-m.paypal.com/v1/oauth2/token"
            self.userinfo_endpoint = "https://api-m.paypal.com/v1/identity/oauth2/userinfo"
            self._issuer = "https://www.paypal.com"
            self.jwks_url = "https://api.paypal.com/v1/oauth2/certs"

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
        return build_authorization_url(
            authorization_endpoint=self.authorization_endpoint,
            client_id=self.client_id,
            state=state,
            redirect_uri=redirect_uri,
            scopes=[],  # PayPal: permissions live in the dashboard, not OAuth scopes
            code_verifier=code_verifier,  # PKCE
            prompt=self.prompt,
        )

    def _basic_auth(self) -> str:
        raw = f"{self.client_id}:{self.client_secret}".encode()
        return base64.b64encode(raw).decode()

    async def exchange(
        self,
        http: httpx.AsyncClient,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> OAuthTokens:
        response = await oauth_fetch(
            http,
            "POST",
            self.token_endpoint,
            headers={
                "authorization": f"Basic {self._basic_auth()}",
                "accept": "application/json",
                "accept-language": "en_US",
                "content-type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
        payload = response.json() if response.status_code == 200 else {}
        if "access_token" not in payload:
            raise OAuthFetchError("FAILED_TO_GET_ACCESS_TOKEN")
        return get_oauth2_tokens(payload)

    async def refresh(self, http: httpx.AsyncClient, refresh_token: str) -> OAuthTokens:
        response = await oauth_fetch(
            http,
            "POST",
            self.token_endpoint,
            headers={
                "authorization": f"Basic {self._basic_auth()}",
                "accept": "application/json",
                "accept-language": "en_US",
                "content-type": "application/x-www-form-urlencoded",
            },
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        )
        payload = response.json() if response.status_code == 200 else {}
        if "access_token" not in payload:
            raise OAuthFetchError("FAILED_TO_REFRESH_ACCESS_TOKEN")
        return get_oauth2_tokens(payload)

    async def verify_id_token(
        self, http: httpx.AsyncClient, token: str, nonce: str | None = None
    ) -> dict[str, Any] | None:
        if self.disable_id_token_sign_in:
            return None
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            return None
        alg, kid = header.get("alg"), header.get("kid")
        if not alg or alg not in _PAYPAL_ALGORITHMS:
            return None
        # Select the key by algorithm so each alg is only ever verified with its key.
        key: Any
        if alg == "HS256":
            key = self.client_secret.encode()
        elif kid:
            jwk = await _jwks_cache.find(http, self.jwks_url, kid)
            if jwk is None:
                return None
            key = PyJWK.from_dict(jwk).key
        else:
            return None
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[alg],
                issuer=self._issuer,
                audience=self.client_id,
            )
        except jwt.PyJWTError:
            return None
        iat = claims.get("iat")
        if iat is None or time.time() - int(iat) > 3600:
            return None
        if nonce and claims.get("nonce") != nonce:
            return None
        return claims

    def _map(self, info: dict[str, Any]) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(info.get("user_id") or ""),
            email=info.get("email"),
            name=info.get("name") or "",
            image=info.get("picture"),
            email_verified=bool(info.get("email_verified", False)),
            raw=info,
        )

    def user_info_from_id_token(self, claims: dict[str, Any]) -> OAuthUserInfo:
        # Direct id-token path: PayPal id tokens are OIDC and carry the profile claims.
        return OAuthUserInfo(
            id=str(claims.get("user_id") or claims.get("sub") or ""),
            email=claims.get("email"),
            name=claims.get("name") or "",
            image=claims.get("picture"),
            email_verified=bool(claims.get("email_verified", False)),
            raw=claims,
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        if not tokens.access_token:
            raise OAuthFetchError("PayPal getUserInfo requires an access token")
        response = await oauth_fetch(
            http,
            "GET",
            f"{self.userinfo_endpoint}?schema=paypalv1.1",
            headers={
                "authorization": f"Bearer {tokens.access_token}",
                "accept": "application/json",
            },
        )
        response.raise_for_status()
        info = response.json()
        if tokens.id_token:
            try:
                id_subject = _decode_unverified(tokens.id_token).get("sub")
            except jwt.PyJWTError as exc:
                raise OAuthFetchError("Failed to decode PayPal ID token") from exc
            # OIDC binds UserInfo to the ID token by `sub` (user_id is the fallback).
            info_subject = info.get("sub") or info.get("user_id")
            if not id_subject or info_subject != id_subject:
                raise OAuthFetchError("PayPal user info subject does not match ID token subject")
        return self._map(info)
