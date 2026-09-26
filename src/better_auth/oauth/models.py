"""Shared OAuth data shapes (kept dependency-free to avoid import cycles)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class OAuthTokens:
    """Normalized token-endpoint response (``OAuth2Tokens``). ``.raw`` keeps the
    provider's original JSON so providers can read non-standard fields."""

    access_token: str | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    token_type: str | None = None
    scope: str | None = None
    scopes: list[str] = field(default_factory=list)
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    #: form_post callback's ``user`` payload (TS threads it via ``getUserInfo({...tokens,
    #: user})``, callback.ts:141-149). Only Apple's ``fetch_user`` reads it — Apple sends the
    #: user's name ONLY on first consent, via this field, never in the id token.
    user: dict[str, Any] | None = None
    #: the redirect flow's id-token nonce recovered from state (TS ``expectedIdTokenNonce``,
    #: 27b5d8022); a provider that binds one must check the id token against it
    expected_id_token_nonce: str | None = None


#: The user keys ``OAuthUserInfo`` carries as attributes; any other mapped key is ``extra``.
CORE_USER_KEYS = frozenset({"id", "email", "emailVerified", "name", "image"})


@dataclass
class OAuthUserInfo:
    """Provider profile mapped to core user fields. ``.raw`` is the untouched provider
    profile (the ``data`` half of TS's ``{user, data}``), fed to the additional-fields
    pipeline later."""

    id: str
    email: str | None
    name: str
    image: str | None = None
    email_verified: bool = False
    raw: dict[str, Any] = field(default_factory=dict)
    #: mapped user fields beyond id/email/emailVerified/name/image (a generic-oauth
    #: ``map_profile_to_user`` result, SSO ``mapping.extraFields``): TS's
    #: ``providerProfile`` rest, written to configured user fields (link-account.ts:461-588)
    extra: dict[str, Any] = field(default_factory=dict)
