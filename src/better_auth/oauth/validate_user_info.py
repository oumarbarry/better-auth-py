"""``user.validateUserInfo`` provisioning gate (TS v1.7.6 utils/validate-user-info.ts).

The application hook sees the incoming identity just before Better Auth creates a user,
links a provider account, or signs a returning OAuth user in. ``source`` tells it why:
``{"action": "create-user" | "link-account" | "sign-in", "method": "oauth" | ...,
"oauth": {"providerId", "profile"}}``. A refusal becomes a ``403`` :class:`APIError`
whose code is the hook's ``error``; redirect flows forward it as ``?error=``.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any

from ..types import APIError, Ctx

logger = logging.getLogger("better_auth")


def assert_valid_user_info_source(source: dict[str, Any] | None) -> None:
    """validate-user-info.ts:8-32: a hook never runs without a usable source."""
    source = source or {}
    method = source.get("method")
    if not method:
        raise APIError(403, "validation_source_missing", "User validation source is required")
    if method == "oauth" and not (source.get("oauth") or {}).get("providerId"):
        raise APIError(
            403,
            "validation_source_missing",
            "OAuth user validation source requires oauth.providerId",
        )
    if method in ("sso-oidc", "sso-saml") and not (source.get("sso") or {}).get("providerId"):
        raise APIError(
            403,
            "validation_source_missing",
            "SSO user validation source requires sso.providerId",
        )


async def assert_valid_user_info(ctx: Ctx, user: dict[str, Any], source: dict[str, Any]) -> None:
    """Run ``user.validate_user_info`` and raise a ``403`` when it refuses. Fails closed:
    a hook that raises rejects provisioning (validate-user-info.ts:41-71)."""
    validate = ctx.auth.user.validate_user_info
    if validate is None:
        return
    assert_valid_user_info_source(source)
    try:
        result = validate({"user": user, "source": source}, ctx)
        if inspect.isawaitable(result):
            result = await result
    except Exception:
        logger.exception("validateUserInfo callback threw")
        raise APIError(403, "validation_failed", "User validation failed") from None
    if result and result.get("error"):
        raise APIError(403, result["error"], result.get("errorDescription") or result["error"])
