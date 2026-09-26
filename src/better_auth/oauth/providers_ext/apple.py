"""Apple — ports ``social-providers/apple.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * ``createAuthorizationURL`` uses ``response_type=code id_token`` +
    ``response_mode=form_post`` (Apple POSTs the callback), and requires
    ``clientId``/``clientSecret`` up front. It also forwards the PKCE
    ``code_challenge`` so the callback exchange's ``code_verifier`` matches
    (TS ``apple.ts`` ``createAuthorizationURL({... codeVerifier })``).
  * id-token verification accepts the nonce either raw **or** as ``sha256hex(nonce)``
    (Apple's native SDKs sometimes hash it client-side): TS v1.7.6 ``idToken`` config
    ``nonceComparison: "exact-or-sha256"``, ``maxTokenAge: "1h"``.
  * Audience for id-token verification falls back
    ``audience`` → ``appBundleIdentifier`` → ``clientId`` (native iOS uses the
    bundle id as the token audience, not the service id).
  * User info comes from decoding the (unverified) id token — no userinfo endpoint.
  * ``generate_client_secret`` builds the ES256 JWT Apple wants as ``clientSecret``
    (docs' ``generateAppleClientSecret`` — not in the TS provider file, but the
    canonical Apple flow; cryptography/pyjwt do the ES256 signing).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
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


def _email_verified(value: Any) -> bool:
    """``email_verified`` may arrive as a bool or the string ``"true"``/``"false"``."""
    if isinstance(value, str):
        return value == "true"
    return bool(value)


def _name_from_token_user(user: dict[str, Any] | None) -> str | None:
    """Port of apple.ts:198-206's ``if (token.user?.name)`` branch. Returns None when the
    else-branch (id-token-derived name) should apply instead.

    ``firstName``/``lastName`` are independently optional — a missing one folds to ``""``
    and the join trims the resulting extra space, so either field alone survives on its own.

    ponytail: JS truthy-object semantics mean ``token.user.name = {}`` (present but both names
    missing) still takes this branch and blanks the name to ``""``; Python dict-truthiness
    falls back to the id-token name instead for that one corner. Harmless in practice — Apple's
    id token never carries a ``name`` claim, so both paths land on ``""`` there anyway.
    """
    name_obj = (user or {}).get("name")
    if not name_obj:
        return None
    first = name_obj.get("firstName") if isinstance(name_obj, dict) else None
    last = name_obj.get("lastName") if isinstance(name_obj, dict) else None
    return f"{first or ''} {last or ''}".strip()


@dataclass
class Apple(ProviderConfig):
    provider_id: str = "apple"
    forwards_login_hint = False  # TS createAuthorizationURL drops loginHint
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
    #: TS v1.7.6 apple.ts:125-136 ``idToken`` config
    id_token_max_age: int | None = 3600
    id_token_nonce_comparison: str = "exact-or-sha256"

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
            # TS v1.7.6 apple.ts:112 forwards the per-request extras (e7eb45b06)
            additional_params={**self.authorize_params, **(additional_params or {})} or None,
        )

    def _effective_audience(self) -> str | list[str]:
        if self.audience:  # non-empty str or non-empty list
            return self.audience
        if self.app_bundle_identifier:
            return self.app_bundle_identifier
        return self.client_id

    @property
    def supports_id_token(self) -> bool:
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
        return await _verify_id_token(
            http,
            token,
            jwks_uri=self.jwks_url,
            audience=self._effective_audience(),
            issuers=self.issuers,
            nonce=nonce,
            max_age=self.id_token_max_age,
            algorithms=self.id_token_algorithms,
            nonce_comparison=self.id_token_nonce_comparison,
        )

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
        info = self.user_info_from_id_token(_decode_unverified(tokens.id_token))
        name = _name_from_token_user(tokens.user)
        return replace(info, name=name) if name is not None else info

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
