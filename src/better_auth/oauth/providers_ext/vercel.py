"""Vercel — ports ``social-providers/vercel.ts``.

Quirks vs. the generic :class:`ProviderConfig`:
  * PKCE is **required** — ``createAuthorizationURL`` throws if no ``codeVerifier`` is
    available (every other PKCE provider just omits the challenge silently).
  * No default scopes at all — TS only sends a ``scope`` param when
    ``options.scope``/per-call ``scopes`` is explicitly given (an empty ``scopes: []``
    already yields this via the base class, so no override is needed for that part).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import OAuthUserInfo
from ..providers import ProviderConfig


def _vercel_mapper(profile: dict[str, Any]) -> OAuthUserInfo:
    return OAuthUserInfo(
        id=str(profile.get("sub") or ""),
        email=profile.get("email"),
        name=profile.get("name") or profile.get("preferred_username") or "",
        image=profile.get("picture"),
        email_verified=bool(profile.get("email_verified", False)),
        raw=profile,
    )


@dataclass
class Vercel(ProviderConfig):
    provider_id: str = "vercel"
    authorization_endpoint: str = "https://vercel.com/oauth/authorize"
    token_endpoint: str = "https://api.vercel.com/login/oauth/token"
    userinfo_endpoint: str = "https://api.vercel.com/login/oauth/userinfo"
    scopes: list[str] = field(default_factory=list)
    use_pkce: bool = True

    def __post_init__(self) -> None:
        if self.profile_mapper is None:
            self.profile_mapper = _vercel_mapper

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
        if not code_verifier:
            raise ValueError("codeVerifier is required for Vercel")
        return super().authorization_url(
            state=state,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            extra_scopes=extra_scopes,
            login_hint=login_hint,
            nonce=nonce,
        )
