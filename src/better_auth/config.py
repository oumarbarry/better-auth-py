"""Configuration dataclasses, mirroring better-auth's options."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

#: async callback(user, url, token) used for verification / reset-password emails.
SendEmail = Callable[[dict[str, Any], str, str], Awaitable[None]]

DAY = 60 * 60 * 24


@dataclass
class EmailAndPassword:
    enabled: bool = False
    #: disable /sign-up/email while still allowing sign-in (throws
    #: EMAIL_PASSWORD_SIGN_UP_DISABLED, distinct from `enabled=False`'s
    #: EMAIL_PASSWORD_DISABLED on sign-in/reset)
    disable_sign_up: bool = False
    min_password_length: int = 8
    max_password_length: int = 128
    require_email_verification: bool = False
    #: create a session right after sign-up (ignored when email verification is required)
    auto_sign_in: bool = True
    send_reset_password: SendEmail | None = None
    reset_password_token_expires_in: int = 60 * 60
    revoke_sessions_on_password_reset: bool = False


@dataclass
class EmailVerification:
    send_verification_email: SendEmail | None = None
    send_on_sign_up: bool = False
    auto_sign_in_after_verification: bool = False
    expires_in: int = 60 * 60


@dataclass
class SessionOptions:
    expires_in: int = 7 * DAY
    #: refresh `expiresAt` when the session is older than this
    update_age: int = 1 * DAY


#: generate_id: True = default 32-char base62; False = let the DB generate; "uuid" =
#: crypto UUID4; "serial" = numeric auto-increment (DB-generated); callable(model) -> str.
GenerateId = "bool | str | Callable[[str], str]"


@dataclass
class AdvancedDatabase:
    """``advanced.database`` options (mirrors better-auth).

    ponytail: configured on the adapter directly this wave (auth.py is owned by another
    track); wire ``BetterAuth(advanced=...)`` through to the adapter when that seam lands.
    """

    #: default row cap applied by ``find_many`` when no explicit ``limit`` is passed
    default_find_many_limit: int = 100
    #: how ``id`` is generated for rows created without one (see ``GenerateId``)
    generate_id: bool | str | Callable[[str], str] = True


@dataclass
class RateLimit:
    """Fixed-window in-memory rate limiting, keyed by client IP + path.

    ponytail: in-memory only — use one worker or put stricter limits at the proxy;
    a shared-storage backend can come later if needed.
    """

    enabled: bool = False
    window: int = 10  # seconds
    max: int = 100
    #: per-path overrides, e.g. {"/sign-in/email": (10, 3)}
    custom_rules: dict[str, tuple[int, int]] = field(default_factory=dict)
