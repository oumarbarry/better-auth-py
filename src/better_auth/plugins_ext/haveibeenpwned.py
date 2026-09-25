"""Have I Been Pwned plugin — reject passwords found in the HIBP breach corpus via a
k-anonymity range query, before they're hashed.

Port of better-auth's ``plugins/haveibeenpwned`` (v1.7.6; index.ts). TS wraps
``context.password.hash``; this port's equivalent seam is ``auth.password_checks``,
a list of async ``(password, path) -> None`` callables run by
``auth.hash_password_checked`` before every password hash. This plugin's ``init``
appends one such check, closing over the configured options and ``auth.http``.
"""

from __future__ import annotations

import hashlib
import logging
import re
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

#: paths checked by default (mirrors better-auth's default path list). Some (admin/*,
#: email-otp, phone-number resets) belong to plugins the integrator may not register
#: on a given instance: listing them is harmless, since the check is keyed on the
#: *request* path and simply never matches when the plugin isn't registered.
DEFAULT_PATHS: list[str] = [
    "/sign-up/email",
    "/change-password",
    "/reset-password",
    "/email-otp/reset-password",
    "/phone-number/reset-password",
    "/admin/create-user",
    "/admin/set-user-password",
]


_MAX_SAFE_INTEGER = 2**53 - 1
_COUNT_RE = re.compile(r"0|[1-9][0-9]*")


def _compromise_count(response: str, hash_suffix: str) -> int:
    """TS ``getPasswordCompromiseCount`` (v1.7.6 index.ts:23-43): the count on the line
    whose suffix matches; padding lines carry 0, a malformed count raises."""
    entry_prefix = f"{hash_suffix.upper()}:"
    for line in re.split(r"\r?\n", response):
        if line[: len(entry_prefix)].upper() != entry_prefix:
            continue
        count_text = line[len(entry_prefix) :]
        if not _COUNT_RE.fullmatch(count_text) or int(count_text) > _MAX_SAFE_INTEGER:
            raise ValueError("Invalid password compromise count")
        return int(count_text)
    return 0


async def is_password_compromised(password: str, *, http: httpx.AsyncClient | None = None) -> bool:
    """Whether ``password`` appears in the Have I Been Pwned corpus (TS
    ``isPasswordCompromised``, v1.7.6 index.ts:54). Only the first five characters of its
    SHA-1 hash leave the process. Raises a 500 :class:`APIError` when the check cannot
    complete. ``http`` defaults to a one-off client; plugins pass ``auth.http``."""
    try:
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        client = http or httpx.AsyncClient()
        try:
            response = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true", "User-Agent": "BetterAuth Password Checker"},
            )
        finally:
            if http is None:
                await client.aclose()
        if not response.is_success:
            raise APIError(
                500,
                "INTERNAL_SERVER_ERROR",
                f"Failed to check password. Status: {response.status_code}",
            )
        return _compromise_count(response.text, suffix) > 0
    except APIError:
        raise
    except Exception as exc:
        logger.error("haveibeenpwned check failed: %s", exc)
        raise APIError(500, "INTERNAL_SERVER_ERROR", _FAILURE_MESSAGE) from exc


async def _reject_compromised_password(
    http: httpx.AsyncClient, password: str, custom_message: str | None
) -> None:
    if await is_password_compromised(password, http=http):
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
            await _reject_compromised_password(
                auth.http, password, self.custom_password_compromised_message
            )

        auth.password_checks.append(check)
