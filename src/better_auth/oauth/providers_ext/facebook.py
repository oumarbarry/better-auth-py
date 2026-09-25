"""Facebook — ports ``social-providers/facebook.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * Two entirely different id-token / user-info paths:
      - a 3-segment JWT is a **limited-login** token, verified against Facebook's
        separate ``limited.facebook.com`` JWKS (RS256, issuer ``www.facebook.com``);
      - anything else is opaque (TS v1.7.6 ``allowOpaqueToken``): identity then comes
        from ``idToken.accessToken``, which carries no app binding at the Graph ``/me``
        endpoint, so it is validated through ``debug_token``
        (``verifyFacebookAccessToken``) before the profile it returns is trusted.
  * ``configId`` (``config_id`` authorize param) selects a Facebook login config.
  * Extra profile ``fields`` are appended to the Graph ``/me`` request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx
import jwt

from ...types import APIError
from ..machinery import OAuthFetchError, get_primary_client_id, oauth_fetch
from ..models import OAuthTokens, OAuthUserInfo
from ..providers import ProviderConfig
from ..verify import verify_id_token as _verify_id_token

if TYPE_CHECKING:
    from ...types import Ctx

_LIMITED_JWKS = "https://limited.facebook.com/.well-known/oauth/openid/jwks/"
_DEBUG_TOKEN = "https://graph.facebook.com/debug_token"


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
class Facebook(ProviderConfig):
    provider_id: str = "facebook"
    authorization_endpoint: str = "https://www.facebook.com/v24.0/dialog/oauth"
    token_endpoint: str = "https://graph.facebook.com/v24.0/oauth/access_token"
    userinfo_endpoint: str = "https://graph.facebook.com/me"
    scopes: list[str] = field(default_factory=lambda: ["email", "public_profile"])
    #: limited-login JWTs are verified against this (separate from the main JWKS).
    jwks_url: str = _LIMITED_JWKS
    issuers: list[str] = field(default_factory=lambda: ["https://www.facebook.com"])
    #: TS v1.7.6 facebook.ts:158 pins the limited-login algorithm
    id_token_algorithms: list[str] | None = field(default_factory=lambda: ["RS256"])
    #: extra Graph profile fields beyond id/name/email/picture.
    fields: list[str] = field(default_factory=list)
    #: Facebook login config id (``config_id`` authorize param).
    config_id: str | None = None
    disable_id_token_sign_in: bool = False

    def __post_init__(self) -> None:
        # TS v1.7.6 facebook.ts:137-140 `{config_id, ...additionalParams}`: the base
        # merge lets a per-request extra override the configured id.
        if self.config_id:
            self.authorize_params = {**self.authorize_params, "config_id": self.config_id}

    @property
    def supports_id_token(self) -> bool:
        return not self.disable_id_token_sign_in

    async def _verify_access_token(self, http: httpx.AsyncClient, access_token: str) -> str | None:
        """Port of ``verifyFacebookAccessToken`` — bind an opaque token to this app.

        Returns the token's ``user_id`` when it is valid and bound to a configured
        client id, else ``None``.
        """
        primary = get_primary_client_id(self.client_id)
        if not primary or not self.client_secret:
            return None
        client_ids = self.client_id if isinstance(self.client_id, list) else [self.client_id]
        app_access_token = f"{primary}|{self.client_secret}"
        try:
            response = await oauth_fetch(
                http,
                "GET",
                _DEBUG_TOKEN,
                params={"input_token": access_token, "access_token": app_access_token},
            )
        except OAuthFetchError:
            return None
        if response.status_code != 200:
            return None
        data = response.json().get("data")
        if not data:
            return None
        if (
            data.get("is_valid") is not True
            or not data.get("app_id")
            or data.get("app_id") not in client_ids
            or not data.get("user_id")
        ):
            return None
        return data.get("user_id")

    async def verify_id_token(
        self,
        http: httpx.AsyncClient,
        token: str,
        nonce: str | None = None,
        ctx: Ctx | None = None,
    ) -> dict[str, Any] | None:
        if self.disable_id_token_sign_in:
            return None
        # A 3-segment token is a limited-login JWT; verify it cryptographically.
        if token.count(".") == 2:
            return await _verify_id_token(
                http,
                token,
                jwks_uri=self.jwks_url,
                audience=self.client_id,
                issuers=self.issuers,
                nonce=nonce or None,
                algorithms=self.id_token_algorithms,
            )
        # TS v1.7.6 facebook.ts:159-161 `allowOpaqueToken`: an opaque token passes, and
        # sign-in.ts:296-310 then resolves identity from `idToken.accessToken` with
        # getUserInfo; null there is FAILED_TO_GET_USER_INFO. The port's flow maps the
        # returned claims, so the Graph profile is fetched here.
        id_token = (ctx.body().get("idToken") if ctx is not None else None) or {}
        try:
            info = await self.fetch_user(
                OAuthTokens(access_token=id_token.get("accessToken"), id_token=token), http
            )
        except (OAuthFetchError, httpx.HTTPError):
            raise APIError(401, "FAILED_TO_GET_USER_INFO", "Failed to get user info") from None
        return info.raw

    def user_info_from_id_token(self, claims: dict[str, Any]) -> OAuthUserInfo:
        """Maps a limited-login token or a Graph profile (opaque sign-in).

        TS v1.7.6 facebook.ts:109-110 accountSubject `"sub" in profile ? sub : id`."""
        if "sub" not in claims:
            return self._map_graph(claims)
        # Limited-login id tokens carry no email_verified claim, default False.
        return OAuthUserInfo(
            id=str(claims.get("sub") or ""),
            email=claims.get("email"),
            name=claims.get("name") or "",
            image=claims.get("picture"),
            email_verified=False,
            raw=claims,
        )

    @staticmethod
    def _map_graph(profile: dict[str, Any]) -> OAuthUserInfo:
        picture = (profile.get("picture") or {}).get("data") or {}
        return OAuthUserInfo(
            id=str(profile.get("id") or ""),
            email=profile.get("email"),
            name=profile.get("name") or "",
            image=picture.get("url"),
            email_verified=bool(profile.get("email_verified", False)),
            raw=profile,
        )

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        # Limited-login path: user info comes from the (already verified) id token.
        if tokens.id_token and tokens.id_token.count(".") == 2:
            return self.user_info_from_id_token(_decode_unverified(tokens.id_token))

        access_token = tokens.access_token
        if not access_token:
            raise OAuthFetchError("Facebook getUserInfo requires an access token")
        # The Graph /me endpoint is not app-bound, so validate this exact token first.
        token_user_id = await self._verify_access_token(http, access_token)
        if not token_user_id:
            raise OAuthFetchError("Facebook access token failed app-binding check")

        fields = ["id", "name", "email", "picture", *self.fields]
        response = await oauth_fetch(
            http,
            "GET",
            f"{self.userinfo_endpoint}?fields={','.join(fields)}",
            headers={"authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        profile = response.json()
        # Bind the validated token to the profile it returned.
        if profile.get("id") != token_user_id:
            raise OAuthFetchError("Facebook profile id does not match token user_id")
        return self._map_graph(profile)
