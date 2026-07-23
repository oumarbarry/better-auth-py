"""Configuration dataclasses, mirroring better-auth's options."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .schema import Field

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
class CookieCache:
    """``session.cookieCache`` — cache the ``{session, user}`` payload in a signed,
    short-TTL ``session_data`` cookie so ``/get-session`` can skip the DB (mirrors
    better-auth). Only the ``compact`` strategy is implemented (base64url + a
    ``base64urlnopad`` HMAC-SHA256 signature), which is the TS default.
    """

    enabled: bool = False
    max_age: int = 300  # seconds
    #: "compact" only for now (jwt/jwe are TS strategies not yet ported)
    strategy: str = "compact"
    version: str = "1"


@dataclass
class SessionOptions:
    expires_in: int = 7 * DAY
    #: refresh `expiresAt` when the session is older than this
    update_age: int = 1 * DAY
    #: a session is "fresh" when its `createdAt` is within this many seconds; gates
    #: fresh-only routes (/list-sessions, /unlink-account, /delete-user). 0 = always fresh.
    fresh_age: int = 1 * DAY
    #: signed short-TTL {session, user} cookie cache (mirrors better-auth session.cookieCache)
    cookie_cache: CookieCache = field(default_factory=CookieCache)
    #: extra columns merged into the `session` schema and emitted by parse_session_output
    #: (mirrors better-auth's `session.additionalFields`)
    additional_fields: dict[str, Field] = field(default_factory=dict)


@dataclass
class AccountLinking:
    """``account.accountLinking`` — the implicit-linking policy surface (mirrors better-auth).

    Security-sensitive: these gates guard account-takeover via a pre-registered local row.
    ``require_local_email_verified`` defaults ``True`` (``@deprecated`` in TS, slated to
    become unconditional): even a *verified* IdP email won't auto-link into a local row
    whose own email was never verified.
    """

    enabled: bool = True
    #: static list, or a (request) -> list[str] callable resolved per-request
    trusted_providers: list[str] | Callable[[Any], Any] = field(default_factory=list)
    #: allow linking when the provider email differs from the local email
    allow_different_emails: bool = False
    #: allow /unlink-account to remove the user's last account
    allow_unlinking_all: bool = False
    #: gate a verified IdP email against an unverified local row (account-preemption guard)
    require_local_email_verified: bool = True
    #: turn off implicit linking on sign-in entirely (only /link-social can link)
    disable_implicit_linking: bool = False
    #: copy name/image from the freshly linked provider profile onto the user row
    update_user_info_on_link: bool = False


@dataclass
class AccountOptions:
    """``account`` option group (mirrors better-auth)."""

    #: extra columns merged into the `account` schema and emitted by parse_account_output
    additional_fields: dict[str, Field] = field(default_factory=dict)
    account_linking: AccountLinking = field(default_factory=AccountLinking)
    #: refresh stored tokens on every re-sign-in (default true, matching TS)
    update_account_on_sign_in: bool = True
    #: AES-256-GCM encrypt access/refresh tokens at rest (account.encryptOAuthTokens)
    encrypt_oauth_tokens: bool = False


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
    #: extra columns merged into the `user` schema and emitted by parse_user_output
    #: (mirrors better-auth's `user.additionalFields`)
    additional_fields: dict[str, Field] = field(default_factory=dict)


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
    """Rolling-window rate limiting, keyed by client IP + path (mirrors better-auth).

    The window is ``lastRequest``-based: a key's counter resets once ``window`` seconds
    have elapsed since its last request, otherwise the count increments until ``max``.

    ``enabled`` defaults to production-only: ``None`` means "on when NODE_ENV/BETTER_AUTH_ENV
    == production", matching TS. ``storage`` selects where counters live: ``"memory"``
    (in-process, default), ``"database"`` (the ``rateLimit`` table), or
    ``"secondary-storage"`` (a KV store).

    ``custom_rules`` maps a path (exact, or a ``*`` wildcard pattern) to a ``(window, max)``
    tuple, ``False`` (skip rate limiting for that path), or a callable
    ``(request, {window, max}) -> (window, max) | False``.
    """

    enabled: bool | None = None
    window: int = 10  # seconds
    max: int = 100
    #: per-path overrides: (window, max) | False (skip) | callable(request, defaults)
    custom_rules: dict[str, Any] = field(default_factory=dict)
    #: "memory" | "database" | "secondary-storage"
    storage: str = "memory"
    #: bring-your-own storage backend (implements adapters.rate_limit.RateLimitStorage)
    custom_storage: Any | None = None


@dataclass
class OnAPIError:
    """``onAPIError`` — how the router surfaces errors (mirrors better-auth).

    - ``throw``: re-raise the ``APIError`` to the caller instead of serializing a response.
    - ``on_error(error, ctx)``: async hook run on every error (logging, reporting).
    - ``error_url``: the ``/error`` page 302-redirects here with ``?error=&error_description=``.
    """

    throw: bool = False
    on_error: Callable[[Any, Any], Awaitable[None]] | None = None
    error_url: str | None = None
    #: when set, the default /error page renders even in production (else prod redirects to /)
    customize_default_error_page: bool = False


@dataclass
class CrossSubDomainCookies:
    """``advanced.crossSubDomainCookies`` — widen auth cookies to a shared parent domain."""

    enabled: bool = False
    #: explicit cookie Domain; defaults to the baseURL hostname when enabled
    domain: str | None = None


#: Per-model database hooks (mirrors better-auth's ``databaseHooks``). Shape:
#: ``{"user": {"create": {"before": fn, "after": fn}, "update": {...}, "delete": {...}}, ...}``
#: — a ``before`` hook returns ``False`` to abort or ``{"data": {...}}`` to merge; ``after``
#: hooks run post-commit. Consumed by ``InternalAdapter``. Distinct from the legacy generic
#: ``hooks`` dict (arbitrary named app callbacks).
DatabaseHooks = "dict[str, Any]"
