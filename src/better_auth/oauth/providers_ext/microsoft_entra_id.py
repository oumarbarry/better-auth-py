"""Microsoft Entra ID — ports ``social-providers/microsoft-entra-id.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * Endpoints are built from a configurable ``authority`` (trailing slashes trimmed)
    and ``tenant`` (``common`` by default). No client secret required — public
    clients (SPA/native + PKCE) are supported.
  * Multi-tenant issuer validation: ``common``/``organizations``/``consumers`` can't
    have a single expected ``iss``, so the issuer check is skipped for them and the
    token's own ``tid`` is cross-checked against ``iss`` (``verify_claims``), plus the
    organizations (not the fixed consumer tenant) / consumers (must be it)
    account-class rules.
  * ``client_assertion`` (TS ``clientAssertion``) authenticates token requests with
    ``private_key_jwt`` instead of ``client_secret``.
  * Profile photo is fetched from Microsoft Graph and inlined as a ``data:`` URI.
  * ``email_verified`` is defaulted from ``verified_primary_email`` /
    ``verified_secondary_email`` when the optional claim is absent.
  * The account id is the ``oid`` claim (TS v1.7.6, 0683a5f36). ``account_id_claim``
    is a port-only option: ``"sub"`` keeps the pre-1.1 ids for unmigrated rows.
"""

from __future__ import annotations

import base64
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import jwt

from ..machinery import OAuthFetchError, TokenEndpointAuth, oauth_fetch, refresh_access_token
from ..models import OAuthUserInfo
from ..providers import ProviderConfig
from ..verify import verify_id_token as _verify_id_token

if TYPE_CHECKING:
    import httpx

    from ...types import Ctx
    from ..models import OAuthTokens

logger = logging.getLogger("better_auth")

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
    #: Claim used as ``account.accountId``. ``"oid"`` matches TS v1.7.6; ``"sub"`` keeps
    #: the ids stored before 1.1 until they are migrated.
    account_id_claim: str = "oid"
    #: TS ``clientAssertion`` (7fe0e2b16): returns the signed JWT for each token request,
    #: given ``{"clientId", "tokenEndpoint", "grantType"}``; may be async.
    client_assertion: Callable[[dict[str, str]], Any] | None = None
    #: TS v1.7.6 microsoft-entra-id.ts:231 ``maxTokenAge: "1h"``
    id_token_max_age: int | None = 3600

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
        # TS v1.7.6 microsoft-entra-id.ts:175-186
        if self.client_secret and self.client_assertion:
            raise ValueError(
                "Microsoft Entra ID clientAssertion cannot be combined with clientSecret"
            )
        if self.client_assertion and self.token_endpoint_auth is None:
            self.token_endpoint_auth = TokenEndpointAuth(
                "private_key_jwt", get_client_assertion=self.client_assertion
            )

    @property
    def supports_id_token(self) -> bool:
        return not self.disable_id_token_sign_in

    async def refresh(self, http: httpx.AsyncClient, refresh_token: str) -> OAuthTokens:
        # TS v1.7.6 microsoft-entra-id.ts:343-357: the scopes ride on every refresh.
        scopes = [] if self.disable_default_scope else list(self.scopes)
        return await refresh_access_token(
            http,
            token_endpoint=self.token_endpoint,
            refresh_token=refresh_token,
            client_id=self.client_id,
            client_secret=self.client_secret,
            authentication=self.authentication,
            extra_params={"scope": " ".join(scopes)},
            token_endpoint_auth=self.token_endpoint_auth,
        )

    async def verify_id_token(
        self,
        http: httpx.AsyncClient,
        token: str,
        nonce: str | None = None,
        ctx: Ctx | None = None,
    ) -> dict[str, Any] | None:
        if self.disable_id_token_sign_in:
            return None
        # TS v1.7.6 microsoft-entra-id.ts:229-272 `idToken`: the issuer is only fixed for
        # a specific tenant; the multi-tenant endpoints bind it through verifyClaims.
        specific = self._tenant not in _MULTI_TENANT
        return await _verify_id_token(
            http,
            token,
            jwks_uri=self.jwks_url,
            audience=self.client_id,
            issuers=[f"{self._authority}/{self._tenant}/v2.0"] if specific else [],
            nonce=nonce,
            max_age=self.id_token_max_age,
            algorithms=self.id_token_algorithms,
            nonce_comparison=self.id_token_nonce_comparison,
            verify_claims=self._tenant_bound,
        )

    def _tenant_bound(self, claims: dict[str, Any]) -> bool:
        tid = claims.get("tid")
        if not isinstance(tid, str) or claims.get("iss") != f"{self._authority}/{tid}/v2.0":
            return False
        if self._tenant == "organizations" and tid == _CONSUMER_TENANT_ID:
            return False
        return not (self._tenant == "consumers" and tid != _CONSUMER_TENANT_ID)

    def _map(self, user: dict[str, Any]) -> OAuthUserInfo:
        # TS v1.7.6 microsoft-entra-id.ts:281-286: no usable oid, no account identity.
        account_id = user.get(self.account_id_claim)
        if not isinstance(account_id, str) or not account_id.strip():
            logger.error(
                "Microsoft Entra ID token did not include a valid %s claim; unable to "
                "resolve a stable account identifier.",
                self.account_id_claim,
            )
            account_id = ""
        return OAuthUserInfo(
            id=account_id,
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
