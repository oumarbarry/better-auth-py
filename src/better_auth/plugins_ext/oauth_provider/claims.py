"""Claim authority for the oauth-provider plugin: the standard claim registry, the OIDC
``claims`` request parameter, and the reserved claim names the authorization server owns.

Ports TS ``packages/oauth-provider/src/standard-claims.ts``, ``claims-request.ts``,
``claims.ts`` and ``authentication-context.ts`` (v1.7.6; e3125e872, 335cda702, a966815b1,
2fd3d5850). Standard claims resolve at the UserInfo endpoint only, never in the ID token.

ponytail: extension claim contributors (TS ``extensions.ts``) are not ported, so the extension
tier of every merge is empty; add it with the extension surface.
"""

from __future__ import annotations

import inspect
import json
import logging
from typing import Any

from ...types import Ctx

logger = logging.getLogger("better_auth")

#: OIDC ACR for authentication below ISO/IEC 29115 level 1 (authentication-context.ts:10).
LEVEL_0_ACR = "0"


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _split_display_name(name: Any) -> tuple[str | None, str | None]:
    parts = [p for p in str(name or "").split(" ") if p]
    if len(parts) <= 1:
        return None, None
    return " ".join(parts[:-1]), parts[-1]


#: TS ``STANDARD_CLAIMS`` (standard-claims.ts:44): claim name -> (scope, resolver).
STANDARD_CLAIMS: dict[str, tuple[str, Any]] = {
    "name": ("profile", lambda user: user.get("name")),
    "picture": ("profile", lambda user: user.get("image")),
    "given_name": ("profile", lambda user: _split_display_name(user.get("name"))[0]),
    "family_name": ("profile", lambda user: _split_display_name(user.get("name"))[1]),
    "email": ("email", lambda user: user.get("email")),
    "email_verified": (
        "email",
        lambda user: user.get("emailVerified") if user.get("emailVerified") is not None else False,
    ),
}

STANDARD_CLAIM_NAMES = list(STANDARD_CLAIMS)


def get_supported_claims(opts: Any) -> list[str]:
    """TS ``getSupportedClaims``: ``advertisedMetadata.claims_supported`` or the init set."""
    advertised = (getattr(opts, "advertised_metadata", None) or {}).get("claims_supported")
    if advertised is not None:
        return list(advertised)
    return list(getattr(opts, "claims", None) or [])


def user_normal_claims(
    user: dict[str, Any], scopes: list[str], requested_claims: list[str] | None = None
) -> dict[str, Any]:
    """TS ``userNormalClaims`` (userinfo.ts:32): ``sub`` plus every standard claim whose scope
    was granted or that ``claims.userinfo`` named. ``None`` values are dropped by the caller."""
    requested = set(requested_claims or [])
    claims: dict[str, Any] = {"sub": user.get("id")}
    for name, (scope, resolve) in STANDARD_CLAIMS.items():
        if scope in scopes or name in requested:
            claims[name] = resolve(user)
    return claims


def pick_claims(
    claims: dict[str, Any] | None, base: dict[str, Any] | None = None
) -> dict[str, Any]:
    """TS ``pickClaims`` (userinfo.ts:72): defined values, minus keys ``base`` already owns."""
    return {
        k: v for k, v in (claims or {}).items() if v is not None and (base is None or k not in base)
    }


# --- OIDC claims request parameter (claims-request.ts) --------------------------------


def _is_member(value: Any) -> bool:
    """``z.record(z.string(), z.unknown()).nullable()``."""
    return value is None or isinstance(value, dict)


def _parse_claims_request(value: Any) -> dict[str, Any] | None:
    """TS ``parseOidcClaimsRequestObject``: the parsed object, or ``None`` when invalid."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if not isinstance(value, dict):
        return None
    userinfo = value.get("userinfo")
    if "userinfo" in value and not (
        isinstance(userinfo, dict) and all(_is_member(v) for v in userinfo.values())
    ):
        return None
    id_token = value.get("id_token")
    if "id_token" in value:
        if not isinstance(id_token, dict):
            return None
        for key, member in id_token.items():
            if key != "acr":
                if not _is_member(member):
                    return None
                continue
            if member is None:
                continue
            if not isinstance(member, dict):
                return None
            if "essential" in member and not isinstance(member["essential"], bool):
                return None
            if "value" in member and not isinstance(member["value"], str):
                return None
            if "values" in member and not (
                isinstance(member["values"], list)
                and all(isinstance(v, str) for v in member["values"])
            ):
                return None
    return value


def is_claims_request_input(value: Any) -> bool:
    """TS ``claimsRequestInputSchema``: a string or an object."""
    return isinstance(value, (str, dict))


def is_valid_oidc_claims_request(value: Any) -> bool:
    """TS ``isValidOidcClaimsRequest``."""
    return value is None or _parse_claims_request(value) is not None


def get_requested_user_info_claims(value: Any, supported: Any = None) -> list[str]:
    """TS ``getRequestedUserInfoClaims``: ``claims.userinfo`` names, bounded to ``supported``."""
    request = _parse_claims_request(value)
    userinfo = (request or {}).get("userinfo")
    if not userinfo:
        return []
    names = list(userinfo)
    if supported is None:
        return names
    allowed = set(supported)
    return [n for n in names if n in allowed]


def can_satisfy_essential_acr_request(value: Any, current_acr: str) -> bool:
    """TS ``canSatisfyEssentialAcrRequest``: a voluntary ``acr`` never blocks; an essential one
    must accept ``current_acr``."""
    request = _parse_claims_request(value)
    if request is None:
        return value is None
    acr = (request.get("id_token") or {}).get("acr")
    if not acr or acr.get("essential") is not True:
        return True
    value_ok = "value" not in acr or acr["value"] == current_acr
    values_ok = "values" not in acr or current_acr in acr["values"]
    return value_ok and values_ok


def filter_claims_request_user_info_claims(value: Any, allowed: list[str]) -> dict[str, Any] | None:
    """TS ``filterClaimsRequestUserInfoClaims``: keep only the accepted ``userinfo`` names."""
    request = _parse_claims_request(value)
    if request is None:
        return None
    allowed_set = set(allowed)
    userinfo = {k: v for k, v in (request.get("userinfo") or {}).items() if k in allowed_set}
    if userinfo:
        filtered = {**request, "userinfo": userinfo}
    else:
        filtered = {k: v for k, v in request.items() if k != "userinfo"}
    return filtered or None


# --- reserved claims -----------------------------------------------------------------

#: Claim names the AS owns on a JWT access token (claims.ts:19).
RESERVED_ACCESS_TOKEN_CLAIMS = frozenset(
    {"iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope", "auth_time", "acr", "amr"}
    | {"cnf"}
)

#: Claim names the AS owns on an ID token (authentication-context.ts:12).
RESERVED_ID_TOKEN_CLAIMS = frozenset(
    {"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "auth_time", "nonce", "acr", "amr"}
    | {"azp", "sid", "at_hash", "c_hash", "s_hash"}
)


def _strip(claims: dict[str, Any] | None, reserved: frozenset, kind: str) -> dict[str, Any]:
    claims = claims or {}
    stripped = [k for k in claims if k in reserved]
    if stripped:
        logger.warning(
            "oauth-provider: stripped reserved %s claim name(s): %s. "
            "The AS owns these claim values.",
            kind,
            ", ".join(stripped),
        )
    return {k: v for k, v in claims.items() if k not in reserved}


def strip_reserved_access_token_claims(claims: dict[str, Any] | None) -> dict[str, Any]:
    """TS ``stripReservedClaims`` (claims.ts:40)."""
    return _strip(claims, RESERVED_ACCESS_TOKEN_CLAIMS, "access-token")


def strip_reserved_id_token_claims(claims: dict[str, Any] | None) -> dict[str, Any]:
    """TS ``stripReservedIdTokenClaims`` (authentication-context.ts:40)."""
    return _strip(claims, RESERVED_ID_TOKEN_CLAIMS, "id-token")


async def resolve_access_token_claims(
    ctx: Ctx,
    opts: Any,
    *,
    user: dict[str, Any] | None,
    scopes: list[str],
    resources: list[str] | None,
    reference_id: str | None,
    metadata: Any,
    per_request_claims: dict[str, Any] | None = None,
    resource_policy_claims: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """TS ``resolveAccessTokenClaims`` (claims.ts:108): the one authority for the enriched
    access-token claims, shared by the JWT mint and opaque introspection. Precedence, low to
    high: per-issuance claims, ``custom_access_token_claims``, resource ``customClaims``."""
    custom = getattr(opts, "custom_access_token_claims", None)
    plugin_claims = (
        await _await(
            custom(
                {
                    "user": user,
                    "scopes": scopes,
                    "resources": resources,
                    # Port-only: the 1.0 single ``resource`` key, kept so existing callbacks
                    # keep working (TS 1.7 passes ``resources`` only).
                    "resource": resources[0] if resources else None,
                    "referenceId": reference_id,
                    "metadata": metadata,
                }
            )
        )
        if custom
        else {}
    )
    return strip_reserved_access_token_claims(
        {**(per_request_claims or {}), **(plugin_claims or {}), **(resource_policy_claims or {})}
    )
