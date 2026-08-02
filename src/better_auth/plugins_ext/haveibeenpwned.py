"""Have I Been Pwned plugin — reject passwords found in the HIBP breach corpus via a
k-anonymity range query, before they're hashed.

Port of better-auth's ``plugins/haveibeenpwned`` (v1.6.23; index.ts). TS wraps
``context.password.hash``; the Python foundation seam for that (W3-A) is
``auth.password_checks`` — a list of async ``(password, path) -> None`` callables run
by ``auth.hash_password_checked`` before every password hash. This plugin's ``init``
appends one such check, closing over the configured options and ``auth.http``.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING

import httpx

from ..plugins import Plugin
from ..types import APIError

if TYPE_CHECKING:
    from ..auth import BetterAuth

logger = logging.getLogger("better_auth.haveibeenpwned")

#: exact TS strings (haveibeenpwned/index.ts ERROR_CODES) — surfaced on ``auth.error_codes``.
ERROR_CODES: dict[str, str] = {
    "PASSWORD_COMPROMISED": (
        "The password you entered has been compromised. Please choose a different password."
    ),
}

_FAILURE_MESSAGE = "Failed to check password. Please try again later."

#: paths checked by default. Some (admin/*, email-otp, phone-number resets) belong to
#: plugins not yet ported in this Python tree — listing them is harmless: the check is
#: keyed on the *request* path, so it simply never matches until those routes exist.
DEFAULT_PATHS: list[str] = [
    "/sign-up/email",
    "/change-password",
    "/reset-password",
    "/email-otp/reset-password",
    "/phone-number/reset-password",
    "/admin/create-user",
    "/admin/set-user-password",
]


async def _check_password_compromise(
    http: httpx.AsyncClient, password: str, custom_message: str | None
) -> None:
    if not password:
        return
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    try:
        response = await http.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true", "User-Agent": "BetterAuth Password Checker"},
        )
        if not response.is_success:
            raise RuntimeError(f"HIBP range query failed with status {response.status_code}")
        found = any(
            line.strip().split(":")[0].upper() == suffix
            for line in response.text.splitlines()
            if line.strip()
        )
    except Exception as exc:
        logger.error("haveibeenpwned check failed: %s", exc)
        raise APIError(500, "INTERNAL_SERVER_ERROR", _FAILURE_MESSAGE) from exc
    if found:
        raise APIError(
            400, "PASSWORD_COMPROMISED", custom_message or ERROR_CODES["PASSWORD_COMPROMISED"]
        )


class HaveIBeenPwnedPlugin(Plugin):
    """Blocks compromised passwords on the configured paths (TS ``have-i-been-pwned``).

    Constructor kwargs mirror the TS ``HaveIBeenPwnedOptions`` (snake_case) with
    identical defaults.
    """

    id = "have-i-been-pwned"
    error_codes = ERROR_CODES

    def __init__(
        self,
        *,
        custom_password_compromised_message: str | None = None,
        paths: list[str] | None = None,
        enabled: bool = True,
    ) -> None:
        self.custom_password_compromised_message = custom_password_compromised_message
        self.paths = paths if paths is not None else list(DEFAULT_PATHS)
        self.enabled = enabled

    def init(self, auth: BetterAuth) -> None:
        async def check(password: str, path: str) -> None:
            if not self.enabled or path not in self.paths:
                return
            await _check_password_compromise(
                auth.http, password, self.custom_password_compromised_message
            )

        auth.password_checks.append(check)
