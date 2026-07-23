"""Social sign-in: OAuth2/OIDC machinery, providers and the sign-in/callback/link endpoints.

Package layout:
- ``models`` — ``OAuthTokens`` / ``OAuthUserInfo`` data shapes.
- ``machinery`` — authorize-URL builder, token exchange/refresh, SSRF-guarded ``oauth_fetch``.
- ``verify`` — JWKS fetch/cache + RS256/ES256 id-token verification.
- ``providers`` — declarative ``ProviderConfig`` base + built-in GitHub/Google/Discord.
- ``flow`` — endpoints (sign-in/social, callback, link-social, refresh/get-access-token)
  and ``handle_oauth_user_info`` (the find/register/link decision tree).
"""

from __future__ import annotations

from .flow import (
    get_access_token,
    handle_oauth_user_info,
    link_social,
    oauth_callback,
    refresh_token,
    sign_in_social,
)
from .machinery import OAuthFetchError, oauth_fetch
from .models import OAuthTokens, OAuthUserInfo
from .providers import Discord, GitHub, Google, OAuthProvider, ProviderConfig
from .verify import verify_id_token

__all__ = [
    "Discord",
    "GitHub",
    "Google",
    "OAuthFetchError",
    "OAuthProvider",
    "OAuthTokens",
    "OAuthUserInfo",
    "ProviderConfig",
    "get_access_token",
    "handle_oauth_user_info",
    "link_social",
    "oauth_callback",
    "oauth_fetch",
    "refresh_token",
    "sign_in_social",
    "verify_id_token",
]
