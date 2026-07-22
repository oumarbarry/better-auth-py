"""Configuration dataclasses, mirroring better-auth's options."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

#: async callback(user, url, token) used for verification / reset-password emails.
SendEmail = Callable[[dict[str, Any], str, str], Awaitable[None]]
#: async callback(user, new_email, url, token) for change-email confirmation emails.
SendChangeEmail = Callable[[dict[str, Any], str, str, str], Awaitable[None]]
#: async callback(user, request) run before/after a user is deleted.
DeleteHook = Callable[[dict[str, Any], Any], Awaitable[None]]

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


@dataclass
class ChangeEmailOptions:
    """``user.changeEmail`` options (mirrors better-auth)."""

    enabled: bool = False
    #: callback(user, new_email, url, token) — sent to the CURRENT address to confirm
    #: a change when the email is already verified
    send_change_email_confirmation: SendChangeEmail | None = None
    #: skip verification and update immediately when the current email is unverified
    update_email_without_verification: bool = False


@dataclass
class DeleteUserOptions:
    """``user.deleteUser`` options (mirrors better-auth)."""

    enabled: bool = False
    #: callback(user, url, token) — when set, /delete-user emails a confirmation link
    #: instead of deleting immediately
    send_delete_account_verification: SendEmail | None = None
    before_delete: DeleteHook | None = None
    after_delete: DeleteHook | None = None
    delete_token_expires_in: int = DAY  # 86400s


@dataclass
class UserOptions:
    """``user`` option group. Attach to a ``BetterAuth`` instance as ``auth.user``."""

    change_email: ChangeEmailOptions = field(default_factory=ChangeEmailOptions)
    delete_user: DeleteUserOptions = field(default_factory=DeleteUserOptions)


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
    """Fixed-window rate limiting, keyed by client IP + path.

    ``storage`` selects where counters live: ``"memory"`` (in-process, default),
    ``"database"`` (the ``rateLimit`` table), or ``"secondary-storage"`` (a KV store).
    The storage backends live in ``adapters.rate_limit``; the limiter algorithm that
    drives them is a separate concern.
    """

    enabled: bool = False
    window: int = 10  # seconds
    max: int = 100
    #: per-path overrides, e.g. {"/sign-in/email": (10, 3)}
    custom_rules: dict[str, tuple[int, int]] = field(default_factory=dict)
    #: "memory" | "database" | "secondary-storage"
    storage: str = "memory"
    #: bring-your-own storage backend (implements adapters.rate_limit.RateLimitStorage)
    custom_storage: Any | None = None


#: Per-model database hooks (mirrors better-auth's ``databaseHooks``). Shape:
#: ``{"user": {"create": {"before": fn, "after": fn}, "update": {...}, "delete": {...}}, ...}``
#: — a ``before`` hook returns ``False`` to abort or ``{"data": {...}}`` to merge; ``after``
#: hooks run post-commit. Consumed by ``InternalAdapter``. Distinct from the legacy generic
#: ``hooks`` dict (arbitrary named app callbacks).
DatabaseHooks = "dict[str, Any]"
