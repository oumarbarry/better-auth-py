"""Zoom — ports ``social-providers/zoom.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * Hand-builds the authorize URL: ``response_type``, ``redirect_uri``, ``client_id``,
    ``state`` — **no ``scope`` param at all**, ever (TS's ``createAuthorizationURL`` for
    Zoom ignores ``options.scope``/per-call ``scopes`` entirely).
  * The only provider with an *optional* PKCE toggle (``options.pkce``, default
    ``True``) rather than PKCE being an unconditional per-provider fact — modeled here
    as the base ``use_pkce`` field (default ``True``), so ``Zoom(..., use_pkce=False)``
    disables it.
  * Token exchange forwards ``code_verifier`` unconditionally when present (TS's
    ``validateAuthorizationCode`` call never gates it on ``options.pkce`` — only the
    authorize-URL side does), so the base's PKCE-gated ``exchange()`` is overridden.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

from ..machinery import code_challenge, exchange_code, get_primary_client_id
from ..models import OAuthUserInfo
from ..providers import ProviderConfig

if TYPE_CHECKING:
    import httpx

    from ..models import OAuthTokens


def _zoom_mapper(profile: dict[str, Any]) -> OAuthUserInfo:
    return OAuthUserInfo(
        id=str(profile.get("id") or ""),
        email=profile.get("email"),
        name=profile.get("display_name") or "",
        image=profile.get("pic_url"),
        email_verified=bool(profile.get("verified", False)),
        raw=profile,
    )


@dataclass
class Zoom(ProviderConfig):
    provider_id: str = "zoom"
    authorization_endpoint: str = "https://zoom.us/oauth/authorize"
    token_endpoint: str = "https://zoom.us/oauth/token"
    userinfo_endpoint: str = "https://api.zoom.us/v2/users/me"
    use_pkce: bool = True  # Zoom's ``options.pkce``, default True

    def __post_init__(self) -> None:
        if self.profile_mapper is None:
            self.profile_mapper = _zoom_mapper

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
        params = {
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "client_id": get_primary_client_id(self.client_id),
            "state": state,
        }
        if self.use_pkce and code_verifier:
            params["code_challenge_method"] = "S256"
            params["code_challenge"] = code_challenge(code_verifier)
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    async def exchange(
        self,
        http: httpx.AsyncClient,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> OAuthTokens:
        # TS forwards codeVerifier to the token exchange unconditionally, regardless of
        # options.pkce (only the authorize URL side gates it) — no `if self.use_pkce` here.
        return await exchange_code(
            http,
            token_endpoint=self.token_endpoint,
            code=code,
            redirect_uri=redirect_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
            code_verifier=code_verifier,
            authentication="post",
        )
