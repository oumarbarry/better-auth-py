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
